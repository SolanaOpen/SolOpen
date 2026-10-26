#!/usr/bin/env python3
"""Per-function AI reconstruction driven by solopen's byte-level scorer.

Each round picks ONE function of yours that doesn't match yet (bottom-up: ones
whose callees already match first), shows the model the original's assembly
for the place that function belongs next to what your source compiles to, as
a diff with shared names, plus the panic line:column sites both sides carry
and the source file with line numbers. The model proposes an edit; it is
built (dependencies cached), re-ordered, relinked and re-targeted. The edit is
kept only if that function got closer (or now matches) and nothing that
matched before stopped matching. Rejected attempts, with their compiler
errors, go back into the next prompt for that function. When the whole program
matches, a clean uncached build confirms it.

Environment:
  SOLOPEN_AI_API_KEY        key for the endpoint (MOONSHOT_API_KEY / OPENAI_API_KEY are
                            used only when --base-url is that provider's host)
  SOLOPEN_AI_BASE_URL       OpenAI-compatible base URL (default https://api.moonshot.ai/v1)
  SOLOPEN_AI_MODEL          model name (or --model)

Builds execute model-written Rust (and Cargo build scripts of dependencies):
run this in a disposable VM/container with no keys or secrets. Stdlib only.
"""
import argparse
from collections import Counter
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import solopen  # noqa: E402

SOURCE_SUFFIXES = {".rs"}
MANIFEST_SUFFIXES = {".toml"}
SKIP_DIRS = {".git", "target", "__pycache__", "vendor", ".cargo"}
# Things a reconstruction must not use: they can smuggle the original's bytes
# into the build (or run code at build time) instead of reproducing it.
FORBIDDEN = [
    # by NAME, not just the macro call: `use core::include_bytes as ib; ib!(..)` is the same thing
    (re.compile(r"\b(?:include_bytes|include_str|include)\s*!|\binclude_bytes\b|\binclude_str\b"),
     "include_*! macros"),
    (re.compile(r"\b(?:global_asm|naked_asm|asm)\s*!|\b(?:global_asm|naked_asm)\b|\b(?:core|std)\s*::\s*arch\b"),
     "inline/global assembly"),
    (re.compile(r"\.incbin\b|\blink_section\b"), "raw section/binary embedding"),
    (re.compile(r"#\s*!\s*\[[^\]]*\bfeature\s*\("), "unstable #![feature] (also via cfg_attr)"),
    (re.compile(r"(?m)^\s*\[build-dependencies\]|^\s*build\s*="), "build scripts"),
    (re.compile(r"(?m)^\s*\[patch|^\s*\[replace\]|git\s*=\s*\""), "dependency patching / git sources"),
]

SYSTEM = """You are reconstructing the Rust source of a deployed Solana program so that it compiles to
EXACTLY the same bytes. You work on one function at a time. You are shown the original's
assembly for the place your function belongs, next to the assembly your current source compiles
to, as a unified diff ('-' original only, '+' yours only). Calls, strings, panic locations and
branch targets are given symbolic names so equal code reads equal; branch targets are offsets
inside the function. A matching function has an empty diff.

Rules:
- Change source semantics, control flow, types, operation order and arithmetic to make the diff
  vanish. Look at what the original computes, not just which lines differ.
- panic_location(file:line:col) values are compiled in. The original's list tells you which line
  and column every overflow check / unwrap / index / expect sits on. Put code on exactly those
  lines and columns. Never reformat code that is not part of your change.
- Edit only Rust files. Do not add include_bytes!/include_str!/include!, asm!, #![feature], build
  scripts or dependencies. Never try to embed or read the original binary.
- Keep everything else compiling and unchanged.

Return ONLY one JSON object:
{"summary": "what you changed and why",
 "edits": [{"path": "relative/path.rs", "replace": [{"old": "exact existing text", "new": "replacement"}]},
           {"path": "relative/other.rs", "content": "COMPLETE file content"}]}
Prefer "replace" with an "old" string copied exactly from the file (without the line-number
gutter) that occurs exactly once. No markdown fences, no diffs."""


# ------------------------------------------------------------------ edits ---
def safe_file(root, relative, allow_manifests=False):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("edit path must be a non-empty workspace-relative path")
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if root != path and root not in path.parents:
        raise ValueError(f"edit escapes workspace: {relative}")
    rel_parts = path.relative_to(root).parts
    import evidence
    if any(p in SKIP_DIRS for p in rel_parts) or evidence.skipped(Path(*rel_parts)):
        raise ValueError(f"edit path is not editable source (not part of the measured build inputs): {relative}")
    allowed = SOURCE_SUFFIXES | (MANIFEST_SUFFIXES if allow_manifests else set())
    if path.suffix not in allowed or path.name == "build.rs":
        raise ValueError(f"unsupported edit file type: {relative}")
    return path


def provenance_counts(text):
    return {why: len(rx.findall(text)) for rx, why in FORBIDDEN}


def provenance_problems(path, text, before=""):
    """Forbidden constructs this edit ADDS (by count, so an existing
    include_str! doc attribute doesn't let a new include_bytes! through)."""
    new, old = provenance_counts(text), provenance_counts(before)
    return [f"{path}: {why}" for why, n in new.items() if n > old.get(why, 0)]


def new_content(path, edit):
    if isinstance(edit.get("content"), str):
        return edit["content"]
    reps = edit.get("replace")
    if not isinstance(reps, list) or not reps:
        raise ValueError(f"edit for {edit.get('path')} needs 'content' or a non-empty 'replace' list")
    if not path.exists():
        raise ValueError(f"cannot apply replacements to a missing file: {edit.get('path')}")
    text = path.read_text()
    for r in reps:
        old, new = r.get("old") if isinstance(r, dict) else None, r.get("new") if isinstance(r, dict) else None
        if not isinstance(old, str) or not isinstance(new, str) or not old:
            raise ValueError("each replacement needs non-empty 'old' and string 'new'")
        n = text.count(old)
        if n != 1:
            raise ValueError(f"'old' text occurs {n} times in {edit.get('path')} (must be exactly once): {old[:80]!r}")
        text = text.replace(old, new, 1)
    return text


def apply_edits(root, edits, max_edits=24, max_file_bytes=1_000_000, allow_manifests=False):
    """Apply all edits or none. Returns a backup for rollback()."""
    if not isinstance(edits, list):
        raise ValueError("edits must be a list")
    if len(edits) > max_edits:
        raise ValueError(f"too many edits ({len(edits)} > {max_edits})")
    planned, seen = [], set()
    for edit in edits:
        if not isinstance(edit, dict):
            raise ValueError("every edit must be an object")
        path = safe_file(root, edit.get("path"), allow_manifests)
        if str(path) in seen:
            raise ValueError(f"duplicate edit for {edit.get('path')}")
        seen.add(str(path))
        text = new_content(path, edit)
        if len(text.encode()) > max_file_bytes:
            raise ValueError(f"edited file is too large: {edit.get('path')}")
        old = path.read_text(errors="replace") if path.exists() else ""
        problems = provenance_problems(edit.get("path"), text, old)
        if problems:
            raise ValueError("edit rejected: " + "; ".join(problems))
        planned.append((path, text))
    backup = {}
    try:
        for path, text in planned:
            backup[path] = path.read_bytes() if path.exists() else None
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".solopen-tmp")
            tmp.write_text(text)
            os.replace(tmp, path)
    except BaseException:                 # including Ctrl-C half-way through the writes
        rollback(backup)
        raise
    return backup


def rollback(backup):
    for path, content in backup.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(content)


def parse_response(text):
    """Strict JSON; tolerates a surrounding markdown fence or prose around one object."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        a, b = text.find("{"), text.rfind("}")
        if a < 0 or b <= a:
            raise
        value = json.loads(text[a:b + 1])
    if not isinstance(value, dict) or not isinstance(value.get("edits"), list):
        raise ValueError("AI response must be an object containing an edits array")
    if not isinstance(value.get("summary", ""), str):
        raise ValueError("AI summary must be a string")
    return value


# ----------------------------------------------------------------- client ---
PROVIDER_KEYS = {"moonshot.ai": "MOONSHOT_API_KEY", "moonshot.cn": "MOONSHOT_API_KEY",
                 "openai.com": "OPENAI_API_KEY"}


def api_key_for(base_url):
    """SOLOPEN_AI_API_KEY, else the provider's own variable only for that provider's host."""
    if os.environ.get("SOLOPEN_AI_API_KEY"):
        return os.environ["SOLOPEN_AI_API_KEY"]
    host = urllib.parse.urlparse(base_url).hostname or ""
    for suffix, var in PROVIDER_KEYS.items():
        if host == suffix or host.endswith("." + suffix):
            return os.environ.get(var)
    return None


class AIClient:
    def __init__(self, base_url, model, api_key=None, timeout=300, max_tokens=16000, retries=4):
        self.url = base_url.rstrip("/")
        if not self.url.endswith("/chat/completions"):
            self.url += "/chat/completions"
        self.model, self.api_key, self.timeout = model, api_key, timeout
        self.max_tokens, self.retries = max_tokens, retries
        self.send_temperature = True     # some models refuse the parameter; dropped once they say so

    def complete(self, prompt, system=SYSTEM, temperature=0.2):
        request = {"model": self.model, "max_tokens": self.max_tokens,
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
        if temperature is not None and self.send_temperature:
            request["temperature"] = temperature
        body = json.dumps(request).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "solopen-ai-rebuild/2"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        last = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(self.url, body, headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    payload = json.load(response)
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read(2000).decode("utf-8", "replace")
                last = RuntimeError(f"AI endpoint returned HTTP {exc.code}: {detail}")
                if exc.code == 400 and "temperature" in detail and "temperature" in request:
                    # e.g. "`temperature` is deprecated for this model": retry without it, and stop sending it
                    self.send_temperature = False
                    del request["temperature"]
                    body = json.dumps(request).encode()
                    continue
                if exc.code not in (408, 409, 429) and exc.code < 500:
                    raise last from exc
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                last = RuntimeError(f"AI request failed: {exc}")
            except json.JSONDecodeError as exc:
                last = RuntimeError(f"AI endpoint did not return JSON: {exc}")
            if attempt < self.retries:
                time.sleep(min(60, 3 * 2 ** attempt))
        else:
            raise last
        try:
            choice = payload["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("AI endpoint response has no choices[0].message.content") from exc
        if choice.get("finish_reason") == "length":
            raise RuntimeError("AI response was cut off at max_tokens; prefer 'replace' edits or raise --max-tokens")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError(f"AI endpoint returned no text (finish_reason {choice.get('finish_reason')!r})")
        return content


# ---------------------------------------------------------------- scoring ---
def read_json(path, default=None):
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else default


def trial_result(run_dir):
    run_dir = Path(run_dir)
    mapping = read_json(run_dir / "order" / "order-mapping.json", {})
    relink = read_json(run_dir / "relinked" / "relink-report.json", {})
    summary = mapping.get("summary", {})
    return {
        "run_dir": str(run_dir),
        "built": (run_dir / "capture" / "baseline.unstripped.so").exists(),
        "ordered": bool(mapping),
        "identical": bool(relink.get("identical", False)),
        "coverage_pct": summary.get("coverage_pct", 0.0),
        "covered_bytes": summary.get("covered_bytes", 0),
        "unmatched": summary.get("unmatched"),
        "uncovered_ranges": summary.get("uncovered_ranges"),
        "differing_bytes": relink.get("differing_bytes"),
        "first_diff_section": relink.get("first_diff_section"),
    }


def rank(result):
    """Lexicographic program-level objective. A build failure never beats a clean build."""
    infinite = 10 ** 18
    return (
        bool(result.get("identical")), bool(result.get("built")),
        float(result.get("coverage_pct") or 0),
        -int(result.get("unmatched") if result.get("unmatched") is not None else infinite),
        -int(result.get("uncovered_ranges") if result.get("uncovered_ranges") is not None else infinite),
        -int(result.get("differing_bytes") if result.get("differing_bytes") is not None else infinite),
    )


def matched_symbols(run_dir):
    mapping = read_json(Path(run_dir) / "order" / "order-mapping.json", {})
    return Counter(r["symbol"] for r in mapping.get("rows", []))


def all_symbols(run_dir):
    import linkorder as LO
    so = Path(run_dir) / "capture" / "baseline.unstripped.so"
    return {nm for nm, _, _, _ in LO.functions_of(so.read_bytes())[0]} if so.exists() else None


def regressions(before_dir, after_dir, before_targets=None, after_targets=None, current_offset=None):
    """What an edit broke elsewhere. By FULL symbol, so one generic instance
    can't hide another's loss; a symbol that only got renamed (its hash
    changed with the edit) is forgiven when a brand-new symbol of the same name
    took its place. Also counts functions whose code still matches but that
    now load different constants (usually: a line added or removed above them
    moved their panic locations) — linkorder can't see those."""
    import target as TG
    lost = matched_symbols(before_dir) - matched_symbols(after_dir)
    existed = all_symbols(before_dir) if lost else None
    if lost and existed is not None:          # unknown history: forgive nothing
        renamed = Counter(TG.demangle(s)[0] for s in matched_symbols(after_dir) if s not in existed)
        for sym in list(lost.elements()):
            n = TG.demangle(sym)[0]
            if renamed[n] > 0:
                renamed[n] -= 1
                lost[sym] -= 1
    out = sorted(TG.demangle(s)[0] for s in (+lost).elements())
    if before_targets is not None and after_targets is not None:
        had = {t["original_offset"] for t in before_targets.get("targets", [])}
        out += sorted(f"{t['name']} (now loads different constants)" for t in after_targets.get("targets", [])
                      if t.get("kind") == "data" and t["original_offset"] not in had
                      and t["original_offset"] != current_offset)
    return out


def target_status(targets, mapping, name, original_offset):
    """(matched, distance) of THIS function at its original place. If
    something else now occupies that place, or it moved, there's no
    comparable distance (None)."""
    import target as TG
    for t in targets.get("targets", []):
        if t["original_offset"] == original_offset:
            return (False, t["distance"]) if t["name"] == name else (False, None)
    for r in mapping.get("rows", []):
        if r["original"] == original_offset:
            return (True, 0) if TG.demangle(r["symbol"])[0] == name else (False, None)
    return False, None


# ---------------------------------------------------------------- prompts ---
def numbered(text):
    return "\n".join(f"{i:5}| {line}" for i, line in enumerate(text.splitlines(), 1))


def site_lines(sites):
    out = {}
    for s in sites:
        f, line, col = s.rsplit(":", 2)
        out.setdefault(f, []).append(f"{line}:{col}")
    return out


def editable_files(workspace, target):
    """Source files in the workspace this target can be fixed in: its own file, and
    the files of the panic sites the original carries. Empty for library generics
    (alloc::raw_vec::finish_grow, …) whose differences come from code elsewhere."""
    import target as TG
    ws = Path(workspace)
    files = [target["source_file"]] if target.get("source_file") else []
    files += [s.rsplit(":", 2)[0] for s in target.get("panic_sites_original", [])]
    return [f for f in dict.fromkeys(files) if TG.inside(ws, f)]


def make_prompt(args, target, diff_text, history, budget):
    ws = Path(args.workspace)
    orig_sites, my_sites = target["panic_sites_original"], target["panic_sites_yours"]
    missing = [s for s in orig_sites if s not in my_sites]
    extra = [s for s in my_sites if s not in orig_sites]
    files = []
    if target.get("source_file"):
        files.append(target["source_file"])
    import target as TG
    for s in orig_sites:
        f = s.rsplit(":", 2)[0]
        if f not in files and TG.inside(ws, f):
            files.append(f)
    files = [f for f in files if TG.inside(ws, f)]
    hist = []
    for h in history[-6:]:
        line = f"- attempt {h['attempt']}: {h.get('summary', '')[:300]} -> {h['outcome']}"
        if h.get("error"):
            line += "\n  " + h["error"][-1500:].replace("\n", "\n  ")
        hist.append(line)
    if len(diff_text) > budget // 2:
        diff_text = diff_text[:budget // 2] + "\n... DIFF TRUNCATED ..."
    parts = [
        f"Program {args.id}. Make this ONE function match the original.",
        "",
        f"Function: {target['name']}",
        f"Defined in (best guess): {target.get('source_file') or 'unknown — search the files below'}",
        f"Your build: {target['your_size']} bytes. Original: {target['original_size']} bytes. "
        f"Distance: {target['distance']} differing instructions.",
        *(["Its instructions ALREADY MATCH. Only the constants it loads differ (shown below): usually a "
           "panic location's line/column, so move the operation to that exact line and column, or a "
           "string/number literal."] if target.get("kind") == "data" else []),
        "Why this is its place in the original: " + "; ".join(f"{e['kind']} {e['detail']}" for e in target["evidence"]),
        "",
        "Panic sites (file:line:col) the ORIGINAL has in this function:",
        json.dumps(site_lines(orig_sites), indent=1) if orig_sites else "  none",
        "Panic sites YOUR version has:",
        json.dumps(site_lines(my_sites), indent=1) if my_sites else "  none",
    ]
    if missing or extra:
        parts += [f"Original-only sites: {missing or 'none'}", f"Yours-only sites: {extra or 'none'}"]
    if target.get("missing_callees"):
        parts += ["The original calls functions your build doesn't produce here (orig_fn_* in the diff). "
                  "Each may be a helper in your source that ends up unused, or one you still have to write:"]
        for m in target["missing_callees"][:12]:
            parts.append(f"  {m['name']}: {m['size']} B; panic sites {m['panic_sites'] or 'none'}; "
                         f"strings {m['strings'] or 'none'}; calls {m['callees'] or 'nothing named'}")
    if target.get("unmatched_callees"):
        parts += ["Functions it calls that don't match yet either (fix later; keep their names): "
                  + ", ".join(target["unmatched_callees"][:10])]
    parts += ["", "--- ASSEMBLY DIFF (original -, yours +) ---", diff_text]
    if hist:
        parts += ["", "--- YOUR EARLIER ATTEMPTS ON THIS FUNCTION (all rolled back unless noted) ---", *hist,
                  "Do something different from the rejected attempts."]
    used = sum(len(p) for p in parts)
    parts += ["", "--- SOURCE (line numbers are a gutter, not part of the file) ---"]
    for f in files[:4]:
        text = (ws / f).read_text(errors="replace")
        block = f"\n=== {f} ===\n{numbered(text)}"
        if used + len(block) > budget:
            parts.append(f"\n=== {f} === (omitted: over the prompt budget)")
            continue
        parts.append(block)
        used += len(block)
    return "\n".join(parts) + "\n"


# ------------------------------------------------------------------- loop ---
def run_trial(args, run_dir, cache=True):
    argv = ["--id", args.id, "--capture-root", str(args.capture_root),
            "--workspace", str(args.workspace), "--toolchain", str(args.toolchain),
            "--program", args.program, "--run-dir", str(run_dir), "--quiet"]
    if args.vendor:
        argv += ["--vendor", str(args.vendor)]
    if args.rustflags is not None:
        argv += ["--rustflags=" + args.rustflags]
    for opt in ("target", "package", "features"):
        if getattr(args, opt, None):
            argv += [f"--{opt}", getattr(args, opt)]
    if cache:
        argv += ["--target-cache", str(args.target_cache)]
    t0 = time.time()
    rc = solopen.try_round(argv)
    result = trial_result(run_dir)
    result["exit_code"], result["seconds"] = rc, round(time.time() - t0, 1)
    Path(run_dir).mkdir(parents=True, exist_ok=True)
    (Path(run_dir) / "trial-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def analyze(args, run_dir):
    import target as TG
    res = TG.write(TG.analyze_run(run_dir, args.capture_root / args.id / "program.so"), Path(run_dir) / "targets")
    return res


def build_error_tail(run_dir):
    log = Path(run_dir) / "build.log"
    if not log.exists():
        return ""
    text = log.read_text(errors="replace")
    errs = [m.start() for m in re.finditer(r"(?m)^error", text)]
    return text[errs[0]:errs[0] + 3000] if errs else text[-2000:]


def save_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def main(argv=None):
    sys.stdout.reconfigure(line_buffering=True)   # progress shows up in logs as it happens
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True)
    ap.add_argument("--capture-root", type=Path, default=Path("capture"))
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--toolchain", default=None,
                    help="platform-tools directory or release version; default: detect it from the capture")
    ap.add_argument("--program", required=True)
    ap.add_argument("--out", required=True, type=Path, help="fresh directory for prompts, responses and attempts")
    ap.add_argument("--decompile", type=Path, default=None, help="(optional) decompile output; not required")
    ap.add_argument("--model", default=os.environ.get("SOLOPEN_AI_MODEL"))
    ap.add_argument("--base-url", default=os.environ.get("SOLOPEN_AI_BASE_URL", "https://api.moonshot.ai/v1"))
    ap.add_argument("--max-iters", type=int, default=40, help="model calls in total")
    ap.add_argument("--max-per-target", type=int, default=4, help="attempts on one function before moving on")
    ap.add_argument("--max-failures", type=int, default=6, help="stop after this many endpoint errors in a row")
    ap.add_argument("--prompt-budget", type=int, default=90000, help="characters of diff + source per prompt")
    ap.add_argument("--focus", default=None, help="only work on targets whose name contains this text")
    ap.add_argument("--include-unattributed", action="store_true",
                    help="also prompt for targets with no source file in the workspace (library generics); "
                         "the model gets no source to edit for those")
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("--max-tokens", type=int, default=16000)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--target-cache", type=Path, default=None, help="default: <out>/target-cache")
    ap.add_argument("--vendor", type=Path)
    ap.add_argument("--rustflags", default=None)
    ap.add_argument("--target", default=None, help="Rust target triple (default: what the toolchain ships)")
    ap.add_argument("--package", default=None)
    ap.add_argument("--features", default=None)
    ap.add_argument("--allow-manifest-edits", action="store_true", help="let the model edit Cargo.toml files")
    ap.add_argument("--baseline-only", action="store_true", help="build, score and target once; no AI")
    args = ap.parse_args(argv)
    if args.out.exists():
        raise SystemExit(f"{args.out} exists — use a fresh output directory")
    if not args.workspace.is_dir():
        raise SystemExit(f"workspace not found: {args.workspace}")
    if not args.baseline_only and not args.model:
        raise SystemExit("pass --model or set SOLOPEN_AI_MODEL")
    import pick_toolchain
    original = args.capture_root / args.id / "program.so"
    args.toolchain, auto_target = pick_toolchain.resolve_for(args.toolchain, original)
    import sbf
    version = sbf.elf_version(original.read_bytes())
    args.target = args.target or auto_target or (f"sbpfv{version}-solana-solana" if version else None)
    args.out.mkdir(parents=True)
    args.target_cache = (args.target_cache or args.out / "target-cache").resolve()
    log = []

    def note(entry):
        log.append(entry)
        save_json(args.out / "history.json", log)

    print("== baseline (no edits)")
    best = run_trial(args, args.out / "attempt-000")
    if not best["built"]:
        print(build_error_tail(best["run_dir"])[-3000:])
        raise SystemExit("the starting workspace doesn't build; fix that first")
    targets = analyze(args, best["run_dir"])
    print(f"   coverage {best['coverage_pct']}%, {targets['summary']['targets']} targets, "
          f"total distance {targets['summary']['total_distance']} ({best['seconds']}s)")
    note(dict(attempt=0, outcome="baseline", result=best, targets=targets["summary"]))
    if best["identical"] or args.baseline_only:
        save_json(args.out / "best-result.json", best)
        return 0 if best["identical"] else 1

    client = AIClient(args.base_url, args.model, api_key_for(args.base_url), args.timeout, args.max_tokens)
    per_target, stuck, failures, attempt = {}, set(), 0, 0
    pending = None
    try:
        while attempt < args.max_iters and not best["identical"]:
            choices = [t for t in targets["targets"]
                       if (t["name"], t["original_offset"]) not in stuck
                       and (not args.focus or args.focus in t["name"])
                       and (args.include_unattributed or editable_files(args.workspace, t))]
            if not choices:
                if not targets["targets"]:
                    rel = read_json(Path(best["run_dir"]) / "relinked" / "relink-report.json", {})
                    print(f"no targets, yet not identical: first difference at 0x{rel.get('first_diff', 0):x} in "
                          f"{rel.get('first_diff_section')} ({rel.get('differing_bytes')} bytes) — not "
                          "attributable to one function; see compare.py")
                else:
                    print("no workable targets left (all stuck)")
                break
            t = choices[0]
            key = (t["name"], t["original_offset"])
            hist = per_target.setdefault(key, [])
            attempt += 1
            diff_text = (Path(best["run_dir"]) / "targets" / t["diff_file"]).read_text()
            prompt = make_prompt(args, t, diff_text, hist, args.prompt_budget)
            (args.out / f"prompt-{attempt:03d}.txt").write_text(prompt)
            print(f"\n== attempt {attempt}/{args.max_iters}: {t['name'][:90]} (distance {t['distance']})")
            entry = dict(attempt=attempt, target=t["name"], original_offset=t["original_offset"],
                         distance_before=t["distance"])
            try:
                response = client.complete(prompt, temperature=args.temperature)
                (args.out / f"response-{attempt:03d}.txt").write_text(response)
                failures = 0                      # the endpoint answered; what follows is the model's fault
                proposal = parse_response(response)
                if not proposal["edits"]:
                    raise ValueError("no edits proposed")
                pending = apply_edits(args.workspace, proposal["edits"], allow_manifests=args.allow_manifest_edits)
            except (RuntimeError, ValueError, TypeError, OSError) as exc:
                bad_endpoint = isinstance(exc, RuntimeError)
                failures = failures + 1 if bad_endpoint else 0
                print(f"   proposal unusable: {exc}")
                hist.append(dict(attempt=attempt, summary="(no usable edit)", outcome="rejected: invalid proposal",
                                 error=str(exc)))
                note(dict(entry, outcome="invalid proposal", error=str(exc)))
                if failures >= args.max_failures:
                    print("   too many endpoint failures in a row; stopping")
                    break
                if len(hist) >= args.max_per_target:
                    stuck.add(key)
                continue
            summary = proposal.get("summary", "")
            print("   AI: " + summary[:200])
            run_dir = args.out / f"attempt-{attempt:03d}"
            result = run_trial(args, run_dir)
            outcome, error = None, None
            if not result["built"]:
                outcome, error = "rejected: does not compile", build_error_tail(run_dir)
            elif result["identical"]:
                outcome = "accepted: program is byte-identical"
            elif not result["ordered"]:
                outcome = "rejected: built, but link-order recovery failed (see the .try.log next to the attempt)"
            else:
                new_targets = analyze(args, run_dir)
                lost = regressions(best["run_dir"], run_dir, targets, new_targets, t["original_offset"])
                mapping = read_json(run_dir / "order" / "order-mapping.json", {})
                matched, dist = target_status(new_targets, mapping, t["name"], t["original_offset"])
                entry.update(distance_after=0 if matched else dist, regressions=lost[:20])
                if lost:
                    outcome = (f"rejected: broke {len(lost)} function(s) that matched — keep every other line "
                               f"where it is ({'; '.join(lost[:3])})")
                elif matched:
                    outcome = "accepted: function now matches"
                elif dist is not None and dist < t["distance"]:
                    outcome = f"accepted: distance {t['distance']} -> {dist}"
                elif result["covered_bytes"] > best.get("covered_bytes", 0):
                    outcome = "accepted: more of the original is reproduced"
                else:
                    outcome = f"rejected: no improvement (distance {t['distance']} -> {dist})"
            accepted = outcome.startswith("accepted")
            print(f"   {outcome}  [{result['coverage_pct']}% coverage, {result['seconds']}s]")
            hist.append(dict(attempt=attempt, summary=summary, outcome=outcome, error=error))
            note(dict(entry, outcome=outcome, summary=summary, edits=[e.get("path") for e in proposal["edits"]],
                      result=result))
            if accepted:
                best, pending = result, None
                if not best["identical"]:
                    targets = new_targets
                per_target[key] = []
            else:
                rollback(pending)
                pending = None
                if len(hist) >= args.max_per_target:
                    stuck.add(key)
                    print(f"   giving up on this function for now after {len(hist)} attempts")
    finally:
        if pending is not None:          # interrupted mid-trial: never leave an unscored edit behind
            rollback(pending)
    save_json(args.out / "best-result.json", best)
    if best["identical"]:
        print("\n== confirming with a clean build (no cache)")
        clean = run_trial(args, args.out / "final-clean", cache=False)
        best["clean_build_identical"] = clean["identical"]
        save_json(args.out / "best-result.json", best)
        print("DONE — byte-identical from a clean build." if clean["identical"] else
              "WARNING: cached build matched but the clean build did not; see final-clean/")
        return 0 if clean["identical"] else 1
    print(f"\nstopped: best coverage {best['coverage_pct']}%; history in {args.out / 'history.json'}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
