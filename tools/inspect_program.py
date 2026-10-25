#!/usr/bin/env python3
"""
inspect_program.py — read a Solana program's executable and report what it does.

This is the "understand it" layer. It works on ANY program without recovering
compilable source: Anchor and most native programs leak their instruction
names, error messages, account/seed strings and the other programs they call.

  python3 inspect_program.py <program.so | program.elf.so> [--idl idl.json] [--json out.json]

Prints a human report and, with --json, a machine report. stdlib only.
"""
import sys, os, re, json, argparse, hashlib, struct

# Well-known program IDs worth flagging when a program calls into them.
KNOWN = {
    "11111111111111111111111111111111": "System Program",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "SPL Token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "Token-2022",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "Associated Token Account",
    "ComputeBudget111111111111111111111111111111": "Compute Budget",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr": "Memo",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "pump.fun",
    "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA": "PumpSwap AMM",
    "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN": "Meteora Dynamic Bonding Curve",
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK": "Raydium CLMM",
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C": "Raydium CP-Swap",
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": "Jupiter v6",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": "Orca Whirlpool",
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s": "Metaplex Token Metadata",
    "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m": "Streamflow",
    "BPFLoaderUpgradeab1e11111111111111111111111": "BPF Upgradeable Loader",
    "Sysvar1nstructions1111111111111111111111111": "Instructions sysvar",
    "SysvarRent111111111111111111111111111111111": "Rent sysvar",
    "SysvarC1ock11111111111111111111111111111111": "Clock sysvar",
}

_B58 = re.compile(rb"[1-9A-HJ-NP-Za-km-z]{32,44}")
_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_ok(s):
    return all(chr(c) in _ALPH for c in s)


def _b58_to_bytes(s):
    try:
        n = 0
        for ch in s:
            n = n * 58 + _ALPH.index(ch)
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        pad = len(s) - len(s.lstrip("1"))
        out = b"\x00" * pad + raw
        return out if len(out) == 32 else None
    except Exception:
        return None


def b58_is_pubkey(s):
    """A real Solana address decodes to exactly 32 bytes. Reject the long
    alphanumeric runs that string extraction otherwise mistakes for addresses."""
    try:
        n = 0
        for ch in s:
            n = n * 58 + _ALPH.index(ch)
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        pad = len(s) - len(s.lstrip("1"))
        return pad + len(raw) == 32
    except Exception:
        return False


def strings(b, minlen=4):
    out, cur = [], bytearray()
    for c in b:
        if 32 <= c < 127:
            cur.append(c)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode())
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode())
    return out


def exact_strings(b):
    """Rust string literals are packed back to back with no terminator, so
    plain string extraction glues neighbours together. Recover exact ones from
    the code instead: a 64-bit load of a .rodata address followed within a few
    instructions by `mov rX, <len>` is a (pointer, length) pair — the shape of
    every sol_log("…") and most &'static str uses."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import linkorder as LO
        sec, text = LO.text_of(b)
        img = LO.image_of(b)
    except BaseException:
        return set()
    ro = [(a, sz, raw) for nm, a, sz, raw in img["data"] if nm.startswith(".rodata")]
    out = set()
    lw = LO.decode_lddw(text, img.get("version", 0))
    for pc, v in lw.items():
        hit = next(((a, raw) for a, sz, raw in ro if a <= v < a + sz), None)
        if not hit:
            continue
        a, raw = hit
        for k in range(1, 5):
            q = pc + 8 + 8 * k
            if q + 8 > len(text):
                break
            if text[q] == 0xB7:                      # mov64 dst, imm
                n = struct.unpack_from("<i", text, q + 4)[0]
                if 1 <= n <= 300:
                    s = raw[v - a:v - a + n]
                    if len(s) == n and all(32 <= c < 127 for c in s):
                        out.add(s.decode())
                break
    return out


def anchor_discriminator(kind, name):
    """Anchor 8-byte discriminator: sha256('<kind>:<name>')[:8]. kind='global' for ixs,
    'account' for account structs."""
    return hashlib.sha256(f"{kind}:{name}".encode()).digest()[:8]


def inspect(path, idl_path=None):
    with open(path, "rb") as f:
        b = f.read()
    rep = {"file": path, "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    ss = strings(b)
    joined = "\n".join(ss)

    # 1) Anchor "Instruction: X" log strings (emitted by the dispatcher)
    exact = exact_strings(b)
    ix_exact = sorted({m.group(1) for x in exact for m in [re.match(r"^Instruction: ([A-Za-z][A-Za-z0-9_]*)$", x)] if m})
    ix_logs = ix_exact or sorted(set(re.findall(r"Instruction:\s*([A-Za-z][A-Za-z0-9_]*)", joined)))
    rep["instruction_log_strings"] = ix_logs
    rep["instruction_names_exact"] = bool(ix_exact)
    rep["exact_string_literals"] = len(exact)

    # 2) Error messages — Anchor error enums and require! messages.
    #    Two clean forms: short space-separated sentences containing an error
    #    word, and well-formed multi-word CamelCase identifiers. Drop fragments,
    #    file paths and the giant separator-less enum blobs the binary carries.
    ERRWORD = re.compile(r"(?i)\b(not|invalid|unauthorized|exceed(s|ed)?|overflow|already|missing|insufficient|expired|cannot|must|too\s|mismatch|forbidden|closed|paused|required|denied|disabled|unsupported|wrong|out of)\b")
    CAMEL = re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+){1,6}$")
    def noise(s):
        return (".rs" in s or "library/" in s or "platform-tools" in s
                or len(s) > 100 or s.count(" ") > 14)
    sentences = sorted({
        s for s in ss
        if 8 <= len(s) <= 100 and " " in s and ERRWORD.search(s) and not noise(s)
        and s[0].isupper()
    })
    idents = sorted({s for s in ss if 6 <= len(s) <= 48 and CAMEL.match(s) and not noise(s)})
    exact_sent = sorted({x for x in exact if 8 <= len(x) <= 200 and " " in x and ERRWORD.search(x)
                         and not noise(x) and x[0].isupper()})
    rep["candidate_error_messages"] = (exact_sent or sentences)[:120]
    rep["candidate_error_names"] = idents[:120]

    # 3) Project source-file paths baked in by panic locations. Isolate the
    #    program's OWN modules (programs/<x>/src/...) — the layout you must
    #    recreate — and skip the std/library noise the binary also carries.
    project = sorted(set(re.findall(r"programs/[a-z0-9_-]+/src/[a-zA-Z0-9_/]+\.rs", joined)))
    other_src = sorted(set(re.findall(r"(?<![a-zA-Z0-9_/])src/[a-zA-Z0-9_/]+\.rs", joined)))
    rep["project_source_paths"] = project
    rep["other_src_paths"] = [s for s in other_src if s not in project][:60]

    # 4) Programs it calls into. Real pubkeys live in the binary as RAW 32-byte
    #    arrays, not base58 text, so we search for the raw form of each known
    #    program ID. (Scanning for base58 *text* only finds coincidental word
    #    runs — the wrong method.) Unknown raw pubkeys can't be told apart from
    #    arbitrary 32-byte data, so we only positively identify known ones.
    recognised = {}
    for pid, name in KNOWN.items():
        needle = _b58_to_bytes(pid)
        if needle and needle in b:
            recognised[pid] = name
    rep["calls_into"] = recognised
    # Optional: base58 *text* addresses (noisy; mostly false positives). Kept
    # behind a strict filter and clearly labelled for manual triage only.
    text_cands = sorted({
        m.decode() for m in set(_B58.findall(b))
        if b58_ok(m) and b58_is_pubkey(m.decode()) and m.decode() not in KNOWN
    })
    rep["base58_text_candidates_noisy"] = text_cands[:40]

    # 5) Toolchain / framework fingerprints
    fw = {}
    m = re.search(r"anchor[-_ ]?lang[ -]?v?(\d+\.\d+\.\d+)", joined, re.I) or re.search(r"anchor.*?(\d+\.\d+\.\d+)", joined, re.I)
    if "anchor" in joined.lower():
        fw["anchor"] = (m.group(1) if m else "present (version not stamped)")
    mr = re.search(r"rustc[ -]?(\d+\.\d+\.\d+)", joined)
    if mr:
        fw["rustc"] = mr.group(1)
    ms = re.search(r"solana[-_ ]?program[ -]?v?(\d+\.\d+\.\d+)", joined, re.I)
    if ms:
        fw["solana_program"] = ms.group(1)
    rep["toolchain_fingerprints"] = fw

    # 6) If an IDL is supplied or present, that is ground truth — fold it in.
    if idl_path and os.path.exists(idl_path):
        idl = json.load(open(idl_path))
        rep["idl"] = {
            "name": idl.get("metadata", {}).get("name") or idl.get("name"),
            "version": idl.get("metadata", {}).get("version") or idl.get("version"),
            "instructions": [i["name"] for i in idl.get("instructions", [])],
            "accounts": [a["name"] for a in idl.get("accounts", [])],
            "errors": [(e.get("code"), e.get("name"), e.get("msg", "")) for e in idl.get("errors", [])],
        }
    return rep


def print_report(rep):
    p = print
    p(f"== {rep['file']}  ({rep['bytes']:,} bytes)")
    p(f"   sha256 {rep['sha256']}")
    if rep.get("toolchain_fingerprints"):
        p("\n-- toolchain fingerprints (your rebuild must match these)")
        for k, v in rep["toolchain_fingerprints"].items():
            p(f"   {k}: {v}")
    if rep.get("idl"):
        idl = rep["idl"]
        p(f"\n-- on-chain IDL: {idl['name']} v{idl.get('version')}")
        p(f"   instructions ({len(idl['instructions'])}): {', '.join(idl['instructions'])}")
        p(f"   accounts ({len(idl['accounts'])}): {', '.join(idl['accounts'])}")
        p(f"   errors: {len(idl['errors'])}")
    else:
        p(f"\n-- instructions (from 'Instruction:' log strings): {len(rep['instruction_log_strings'])}")
        p("   " + ", ".join(rep["instruction_log_strings"]) if rep["instruction_log_strings"]
          else "   none found (native program, or names stripped — read the dispatcher)")
    if rep.get("calls_into"):
        p("\n-- programs it calls into (raw pubkey found in the binary):")
        for k, v in sorted(rep["calls_into"].items(), key=lambda x: x[1]):
            p(f"   {v:34s} {k}")
    if rep.get("project_source_paths"):
        p(f"\n-- the program's own module layout ({len(rep['project_source_paths'])} files, from panic locations):")
        for s in rep["project_source_paths"]:
            p(f"   {s}")
    if rep.get("candidate_error_names"):
        p(f"\n-- candidate error names ({len(rep['candidate_error_names'])}):")
        p("   " + ", ".join(rep["candidate_error_names"][:60]))
    if rep.get("candidate_error_messages"):
        p(f"\n-- candidate error messages ({len(rep['candidate_error_messages'])}):")
        for s in rep["candidate_error_messages"][:40]:
            p(f"   {s}")


def main():
    ap = argparse.ArgumentParser(description="Report what a Solana program does from its executable.")
    ap.add_argument("so")
    ap.add_argument("--idl", default=None)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    idl = a.idl
    if idl is None:
        guess = os.path.join(os.path.dirname(a.so), "idl.json")
        if os.path.exists(guess):
            idl = guess
    rep = inspect(a.so, idl)
    print_report(rep)
    if a.json:
        os.makedirs(os.path.dirname(a.json) or ".", exist_ok=True)
        with open(a.json, "w") as f:
            json.dump(rep, f, indent=2)
        # Full raw strings alongside, so concatenated blobs this report trims
        # are never lost — grep them by hand when a binary stores errors densely.
        sdir = os.path.dirname(a.json) or "."
        with open(os.path.join(sdir, "strings.txt"), "w") as f:
            f.write("\n".join(strings(open(a.so, "rb").read())))
        print(f"\n[json written to {a.json}; full strings in {sdir}/strings.txt]")


if __name__ == "__main__":
    main()
