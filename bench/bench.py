#!/usr/bin/env python3
"""
bench.py — measure the reconstruction loop on a program whose source is known.

Takes a workspace that already rebuilds byte-for-byte (e.g. daosfun-source),
removes or perturbs one function (keeping every line number, so nothing else
moves), then runs `solopen.py rebuild` on the damaged copy and records whether
it gets back to a byte-identical program, how many model calls and how long.

  # list the built-in cases
  python3 bench/bench.py list
  # run one case with a real model
  python3 bench/bench.py run blank-liquidity-b --pristine daosfun-source \\
      --id 4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM --capture-root capture \\
      --program dao_v1 \\
      --vendor daosfun-source/vendor --model <model> --out bench-runs/
  # check the harness itself with a model that knows the answer
  python3 bench/bench.py run blank-liquidity-b ... --oracle            (or --oracle decoy)

The oracle is a local OpenAI-compatible server that returns the removed code
(after one deliberately broken and one wrong answer with --oracle decoy). It
proves the pipeline — targeting, prompting, edit, build, scoring, rollback,
clean confirmation — works end to end; it says nothing about a real model.
stdlib only.
"""
import argparse, json, os, shutil, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import rebuild  # noqa: E402

DAO = "programs/dao-v1/src/"
CASES = {
    # small semantic slips in otherwise-correct code
    "perturb-redeem-compare": dict(
        file=DAO + "instructions/redeem_sol.rs", kind="replace",
        old="dao_burn_redeemed + amount > ctx", new="dao_burn_redeemed + amount >= ctx",
        note="one comparison operator wrong in an instruction handler"),
    "perturb-liquidity-shift": dict(
        file=DAO + "math/migration_math.rs", kind="replace",
        old="<< 128usize", new="<< 127usize", note="one constant wrong in a math helper"),
    "perturb-unwrap-column": dict(
        file=DAO + "math/migration_math.rs", kind="replace", count=2,
        old="value.to_u128()                   .unwrap()", new="value.to_u128().unwrap()",
        note="right code, wrong panic column (formatting) — twice"),
    # a whole function body missing
    "blank-liquidity-b": dict(
        file=DAO + "math/migration_math.rs", kind="blank", fn="liquidity_from_b",
        note="#[inline(never)] math helper body removed"),
    "blank-redeem-sol": dict(
        file=DAO + "instructions/redeem_sol.rs", kind="blank", fn="handle_redeem_sol",
        note="an instruction handler body removed (it may inline into Anchor's dispatcher)"),
    "blank-start-raise": dict(
        file=DAO + "instructions/start_raise.rs", kind="blank", fn="handle_start_raise",
        note="handler with two CPIs removed"),
    "blank-init-curve": dict(
        file=DAO + "instructions/init_curve.rs", kind="blank", fn="initialize",
        note="the largest handler (~100 lines) removed"),
}


# ------------------------------------------------------------ rust editing ---
def rust_tokens(text):
    """Yield (kind, start, end) for code tokens, skipping comments (nested),
    strings (incl. raw r#".."#, byte strings) and char literals. Lifetimes are
    not chars. Raises on unterminated input instead of looping."""
    import re
    i, n = 0, len(text)
    ident = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            depth, i = 1, i + 2
            while depth:
                if i >= n:
                    raise SystemExit("unterminated block comment")
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif re.match(r"b?r(#*)\"", text[i:i + 260]):
            m = re.match(r"b?r(#*)\"", text[i:])
            close = '"' + m.group(1)
            j = text.find(close, i + m.end())
            if j < 0:
                raise SystemExit("unterminated raw string")
            i = j + len(close)
        elif c == '"' or text.startswith('b"', i):
            i += 1 if c == '"' else 2
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                raise SystemExit("unterminated string")
            i += 1
        elif c == "'" or text.startswith("b'", i):
            k = i + (2 if c == "b" else 1)
            m = re.match(r"(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'])'", text[k:k + 12])
            if m:                                     # a char literal
                i = k + m.end()
            else:                                     # a lifetime / label
                yield "punct", i, i + 1
                i += 1
        elif ident.match(text, i):
            m = ident.match(text, i)
            yield "ident", i, m.end()
            i = m.end()
        elif c.isspace():
            i += 1
        else:
            yield "punct", i, i + 1
            i += 1


def find_fn(text, name):
    """(index of the body's '{', index after its '}') for the first `fn name`
    that has a body, ignoring comments, strings and bodiless declarations."""
    toks = list(rust_tokens(text))
    for k in range(len(toks) - 1):
        kind, a, b = toks[k]
        if kind != "ident" or text[a:b] != "fn":
            continue
        k2, a2, b2 = toks[k + 1]
        if k2 != "ident" or text[a2:b2] != name:
            continue
        depth, start = 0, None          # () [] <> before the body; the body is the first { at depth 0
        for kind3, a3, b3 in toks[k + 2:]:
            ch = text[a3:b3]
            if start is None:
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    depth -= 1
                elif ch == ";" and depth == 0:
                    break                   # a declaration without a body: keep looking
                elif ch == "{" and depth == 0:
                    start, depth = a3, 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return start, b3
        else:
            raise SystemExit(f"unbalanced braces after fn {name}")
    raise SystemExit(f"fn {name} with a body not found")


def blank_body(text, name):
    """Replace the body with todo!() while keeping the same number of lines."""
    a, b = find_fn(text, name)
    lines = text[a:b].count("\n")
    return text[:a] + "{ todo!()" + "\n" * lines + "}" + text[b:], text[a:b]


def make_case(case, pristine, out):
    spec = CASES[case]
    if out.exists():
        raise SystemExit(f"{out} exists")
    # copy (not copy2): fresh timestamps, so Cargo never mistakes these files for
    # ones it already compiled from another case sharing the dependency cache
    shutil.copytree(pristine, out, ignore=shutil.ignore_patterns("target", "vendor", ".git", "runs", ".build"),
                    copy_function=shutil.copy)
    path = out / spec["file"]
    text = path.read_text()
    if spec["kind"] == "replace":
        k = text.count(spec["old"])
        if k != spec.get("count", 1):
            raise SystemExit(f"{case}: expected {spec.get('count', 1)} occurrence(s) of the old text, found {k}")
        damaged, removed = text.replace(spec["old"], spec["new"]), spec["old"]
    else:
        damaged, removed = blank_body(text, spec["fn"])
    if damaged.count("\n") != text.count("\n"):
        raise SystemExit("internal error: the ablation changed the number of lines")
    path.write_text(damaged)
    info = dict(case=case, **spec, pristine_file=text, damaged_file=damaged, removed=removed)
    (out.parent / f"{out.name}.case.json").write_text(json.dumps(info, indent=1) + "\n")
    return info


# ----------------------------------------------------------------- oracle ---
def oracle_answers(info, mode):
    """The responses the oracle hands out, in order."""
    fix = {"summary": "restore the code (oracle)",
           "edits": [{"path": info["file"], "content": info["pristine_file"]}]}
    if mode != "decoy":
        return [fix]
    broken = {"summary": "decoy: does not compile",
              "edits": [{"path": info["file"], "content": info["damaged_file"] + "\nfn decoy() -> u8 { \"x\" }\n"}]}
    same = {"summary": "decoy: no real change",
            "edits": [{"path": info["file"], "content": info["damaged_file"]}]}
    shifted = {"summary": "decoy: right code, but one extra line at the top shifts every panic location below",
               "edits": [{"path": info["file"], "content": "\n" + info["pristine_file"]}]}
    return [broken, same, shifted, fix]


def start_oracle(info, mode):
    answers = oracle_answers(info, mode)
    calls = {"n": 0, "prompts": []}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls["prompts"].append(req["messages"][-1]["content"])
            ans = answers[min(calls["n"], len(answers) - 1)]
            calls["n"] += 1
            body = json.dumps({"choices": [{"finish_reason": "stop",
                                            "message": {"content": json.dumps(ans)}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, calls


# -------------------------------------------------------------------- run ---
def run_case(a):
    out = a.out.resolve() / f"{a.case}-{time.strftime('%Y%m%d-%H%M%S')}"
    out.parent.mkdir(parents=True, exist_ok=True)
    ws = out / "workspace"
    info = make_case(a.case, a.pristine.resolve(), ws)
    argv = ["--id", a.id, "--capture-root", str(a.capture_root.resolve()), "--workspace", str(ws),
            "--program", a.program, "--out", str(out / "loop"),
            "--max-iters", str(a.max_iters), "--max-per-target", str(a.max_per_target)]
    if a.toolchain:
        argv += ["--toolchain", str(a.toolchain)]
    if a.vendor:
        argv += ["--vendor", str(a.vendor.resolve())]
    if a.target_cache:
        argv += ["--target-cache", str(a.target_cache.resolve())]
    srv = calls = None
    if a.oracle:
        srv, calls = start_oracle(info, a.oracle)
        argv += ["--model", "oracle", "--base-url", f"http://127.0.0.1:{srv.server_port}/v1"]
    else:
        argv += ["--model", a.model] + (["--base-url", a.base_url] if a.base_url else [])
    t0 = time.time()
    try:
        rc = rebuild.main(argv)
    finally:
        if srv:
            srv.shutdown()
    hist = json.loads((out / "loop" / "history.json").read_text())
    best = json.loads((out / "loop" / "best-result.json").read_text())
    restored = (ws / info["file"]).read_text() == info["pristine_file"]
    no_effect = len(hist) == 1 and best.get("identical")
    if no_effect:
        print("NOTE: the damaged workspace already matched — this case doesn't exercise the loop")
    report = dict(case=a.case, note=info["note"], model="oracle:" + a.oracle if a.oracle else a.model,
                  case_had_no_effect=bool(no_effect),
                  solved=bool(best.get("identical") and best.get("clean_build_identical")),
                  source_restored_exactly=restored, model_calls=len(hist) - 1,
                  accepted=sum(1 for h in hist[1:] if str(h.get("outcome", "")).startswith("accepted")),
                  seconds=round(time.time() - t0), baseline=hist[0].get("targets"),
                  first_target=hist[1].get("target") if len(hist) > 1 else None,
                  outcomes=[h.get("outcome") for h in hist[1:]], exit_code=rc)
    if calls:
        report["damaged_file_in_first_prompt"] = bool(calls["prompts"]) and f"=== {info['file']} ===" in calls["prompts"][0]
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["solved"] else 1


def main():
    sys.stdout.reconfigure(line_buffering=True)   # progress shows up in logs as it happens
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    mk = sub.add_parser("make", help="only create the damaged workspace")
    mk.add_argument("case", choices=sorted(CASES))
    mk.add_argument("--pristine", required=True, type=Path)
    mk.add_argument("--out", required=True, type=Path)
    r = sub.add_parser("run")
    r.add_argument("case", choices=sorted(CASES))
    r.add_argument("--pristine", required=True, type=Path, help="workspace that rebuilds byte-for-byte")
    r.add_argument("--id", required=True)
    r.add_argument("--capture-root", type=Path, default=Path("capture"))
    r.add_argument("--toolchain", default=None, help="directory or release version; default: detect it")
    r.add_argument("--program", required=True)
    r.add_argument("--vendor", type=Path)
    r.add_argument("--target-cache", type=Path, help="share one dependency cache across cases")
    r.add_argument("--out", type=Path, default=Path("bench-runs"))
    r.add_argument("--model", default=os.environ.get("SOLOPEN_AI_MODEL"))
    r.add_argument("--base-url", default=None)
    r.add_argument("--oracle", nargs="?", const="direct", choices=["direct", "decoy"],
                   help="answer with the removed code instead of calling a model (harness check)")
    r.add_argument("--max-iters", type=int, default=20)
    r.add_argument("--max-per-target", type=int, default=4)
    a = ap.parse_args()
    if a.cmd == "list":
        for k, v in CASES.items():
            print(f"{k:26} {v['note']}")
        return 0
    if a.cmd == "make":
        info = make_case(a.case, a.pristine, a.out)
        print(f"damaged {info['file']} in {a.out}")
        return 0
    if not a.oracle and not a.model:
        raise SystemExit("pass --model (or --oracle to check the harness)")
    return run_case(a)


if __name__ == "__main__":
    sys.exit(main())
