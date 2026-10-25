#!/usr/bin/env python3
"""
difftest.py — does the candidate BEHAVE like the original?

  python3 solopen.py difftest --id <ID> --run runs/<attempt>        # or --candidate some.so
      (needs `python3 -m pip install solders==0.29.0` — LiteSVM, a local
       Solana runtime; everything else in solopen stays stdlib-only)

Replays every transaction collected by `solopen.py cases` twice in LiteSVM —
once with the ORIGINAL program, once with your CANDIDATE at the same address —
from the same account snapshot, and compares what happened:

  status       success, or the exact error (which instruction, which code)
  logs         every program log line (compute-unit counts are masked: they
               differ whenever the code isn't byte-identical)
  return data  what the transaction returned
  accounts     lamports, owner and data of every account afterwards

Each case starts from the snapshot with that transaction's own lamport and
token balances from just before it ran restored. Signatures and blockhashes
aren't checked (the replays are simulations that change nothing), the Clock
is the one captured with the snapshot, other
programs run their real mainnet executables, and the fee payer is topped up
so the replay reaches the program instead of failing on fees. A case only
says something about your code if the original actually ran on it, so the
report counts those ("reached") separately.

Identical behaviour on every case is NOT proof of equivalence — only byte
equality is — but a difference is always a real bug in the reconstruction,
and the list says which instruction and which log line to look at.
"""
import argparse, base64, json, re, struct, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fetch

CLOCK = "SysvarC1ock11111111111111111111111111111111"
FUND = 10 * 10 ** 9                     # lamports added to a fee payer below 1 SOL
TOKEN_PROGRAMS = {"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}



def need_solders():
    try:
        import solders.litesvm  # noqa: F401  (probe only)
    except ImportError:
        raise SystemExit("difftest needs LiteSVM from the `solders` package:\n"
                         "  python3 -m pip install solders==0.29.0\n"
                         "(only difftest uses it; the rest of solopen stays stdlib-only)")


def mask_cu(line):
    """Compute-unit counts differ whenever the code isn't byte-identical."""
    line = re.sub(r"consumed \d+ of \d+ compute units", "consumed _ of _ compute units", line)
    return re.sub(r"consumption: \d+ units remaining", "consumption: _ units remaining", line)


def program_data_address(pid):
    from solders.pubkey import Pubkey
    return Pubkey.find_program_address([bytes(Pubkey.from_string(pid))],
                                       Pubkey.from_string(fetch.UPGRADEABLE_LOADER))[0]


class Runtime:
    """One LiteSVM with every invoked program loaded, plus `target` at its id."""

    def __init__(self, target_id, target_elf, target_loader, cases_dir, index, accounts, restore=True):
        self.restore = restore
        from solders.litesvm import LiteSVM
        from solders.pubkey import Pubkey
        svm = LiteSVM()
        for setting in (lambda s: s.with_sigverify(False), lambda s: s.with_blockhash_check(False),
                        lambda s: s.with_log_bytes_limit(None)):
            svm = setting(svm) or svm
        def loader_for(name):
            # LiteSVM can't host loader-v4 programs; the upgradeable loader runs
            # the same executable (SBPF v0-v3) at the same address.
            return Pubkey.from_string(fetch.UPGRADEABLE_LOADER if name == fetch.LOADER_V4 else name)

        for pid, info in index.get("programs", {}).items():
            elf = (Path(cases_dir) / "programs" / f"{pid}.so").read_bytes()
            svm.add_program_with_loader(Pubkey.from_string(pid), elf, loader_for(info["loader"]))
        svm.add_program_with_loader(Pubkey.from_string(target_id), target_elf, loader_for(target_loader))
        clock = accounts.get(CLOCK)
        if clock:
            from solders.clock import Clock
            slot, start_ts, epoch, leader_epoch, unix_ts = struct.unpack_from("<QqQQq", base64.b64decode(clock["data"]))
            svm.set_clock(Clock(slot, start_ts, epoch, leader_epoch, unix_ts))
        self.svm = svm
        # Program and ProgramData accounts are owned by add_program_*: setting the
        # snapshot's copies would put the ORIGINAL bytes back under the candidate.
        self.skip = {pid for pid, a in accounts.items() if a and a["executable"]}
        self.skip |= {str(program_data_address(p)) for p in list(index.get("programs", {})) + [target_id]}

    def run(self, case, accounts):
        from solders.account import Account
        from solders.pubkey import Pubkey
        from solders.transaction import VersionedTransaction
        tx = VersionedTransaction.from_bytes(base64.b64decode(case["tx"]))
        payer = str(tx.message.account_keys[0])
        funded = False
        pre_lamports = case.get("pre_lamports", {}) if self.restore else {}
        pre_tokens = case.get("pre_token_amounts", {}) if self.restore else {}
        for k in set(case["accounts"]) | set(case.get("tables", [])):
            a = accounts.get(k)
            if k in self.skip or a is None:
                continue
            lamports = pre_lamports.get(k, a["lamports"])
            data = base64.b64decode(a["data"])
            if k in pre_tokens and a["owner"] in TOKEN_PROGRAMS and len(data) >= 72:
                data = data[:64] + struct.pack("<Q", int(pre_tokens[k])) + data[72:]
            if k == payer and lamports < 10 ** 9:
                lamports, funded = lamports + FUND, True
            self.svm.set_account(Pubkey.from_string(k), Account(
                lamports, data, Pubkey.from_string(a["owner"]), a["executable"], a["rent_epoch"]))
        if payer not in accounts or accounts[payer] is None:
            self.svm.set_account(Pubkey.from_string(payer), Account(FUND, b"", Pubkey.from_string(fetch.SYSTEM_PROGRAM),
                                                                    False, 0))
            funded = True
        res = self.svm.simulate_transaction(tx)
        meta = val(res, "meta")
        err = val(res, "err")
        ret = val(meta, "return_data")
        ret_data = bytes(val(ret, "data") or b"") if ret is not None else b""
        out = dict(status="ok" if err is None else str(err), logs=[mask_cu(x) for x in val(meta, "logs")],
                   compute_units=val(meta, "compute_units_consumed"),
                   return_data=[str(val(ret, "program_id")), ret_data.hex()] if ret_data else None,
                   funded_payer=funded, post={})
        for key, acct in (val(res, "post_accounts") or []):
            out["post"][str(key)] = [acct.lamports, str(acct.owner), hashlib_hex(bytes(acct.data))]
        return out


def val(obj, name):
    """solders exposes some fields as properties and others as methods."""
    x = getattr(obj, name, None)
    return x() if callable(x) else x


def hashlib_hex(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()[:16] + f"/{len(b)}"


def compare(a, b):
    """First difference between two outcomes, or None."""
    if a["status"] != b["status"]:
        return dict(kind="status", original=a["status"], candidate=b["status"])
    for n, (x, y) in enumerate(zip(a["logs"], b["logs"])):
        if x != y:
            return dict(kind="log", line=n, original=x, candidate=y)
    if len(a["logs"]) != len(b["logs"]):
        n = min(len(a["logs"]), len(b["logs"]))
        return dict(kind="log", line=n, original=(a["logs"][n:] or ["<end>"])[0],
                    candidate=(b["logs"][n:] or ["<end>"])[0])
    if a["return_data"] != b["return_data"]:
        return dict(kind="return data", original=a["return_data"], candidate=b["return_data"])
    keys = sorted(set(a["post"]) | set(b["post"]))
    changed = [k for k in keys if a["post"].get(k) != b["post"].get(k)]
    if changed:
        k = changed[0]
        return dict(kind="account", account=k, accounts_differing=len(changed),
                    original=a["post"].get(k), candidate=b["post"].get(k))
    return None


def instruction_name(logs, pid):
    """The Anchor instruction the target ran, from its own logs ('Instruction: Buy')."""
    inside = False
    for line in logs:
        if line.startswith(f"Program {pid} invoke"):
            inside = True
        elif inside and line.startswith("Program log: Instruction: "):
            return line[len("Program log: Instruction: "):]
    return None


def difftest(program_id, original, candidate, cases_dir, loader=None, limit=None, restore=True, log=print):
    need_solders()
    cases_dir = Path(cases_dir)
    index = json.loads((cases_dir / "index.json").read_text())
    accounts = json.loads((cases_dir / "accounts.json").read_text())
    loader = loader or fetch.UPGRADEABLE_LOADER

    def elf(path):
        b = Path(path).read_bytes()
        end = fetch.elf_end_from_header(b)
        return b[:end] if end else b

    orig_rt = Runtime(program_id, elf(original), loader, cases_dir, index, accounts, restore)
    cand_rt = Runtime(program_id, elf(candidate), loader, cases_dir, index, accounts, restore)
    cases = index["cases"][:limit] if limit else index["cases"]
    rows, reached, same, by_ix = [], 0, 0, {}
    for case in cases:
        a = orig_rt.run(case, accounts)
        b = cand_rt.run(case, accounts)
        ran = any(x.startswith(f"Program {program_id} invoke") for x in a["logs"])
        diff = compare(a, b)
        name = instruction_name(a["logs"], program_id) or instruction_name(b["logs"], program_id) or "?"
        reached += ran
        same += diff is None
        stat = by_ix.setdefault(name, [0, 0, 0])
        stat[0] += 1
        stat[1] += diff is None
        stat[2] += a["status"] == "ok"
        rows.append(dict(signature=case["signature"], instruction=name, reached=ran,
                         original_status=a["status"], candidate_status=b["status"], identical=diff is None,
                         difference=diff, compute_units=[a["compute_units"], b["compute_units"]],
                         mainnet_err=case.get("mainnet_err"), funded_payer=a["funded_payer"]))
    report = dict(program_id=program_id, original=str(original), candidate=str(candidate),
                  cases=len(rows), reached=reached, identical=same,
                  original_succeeded=sum(r["original_status"] == "ok" for r in rows),
                  by_instruction={k: dict(cases=v[0], identical=v[1], original_ok=v[2]) for k, v in sorted(by_ix.items())},
                  differences=[r for r in rows if not r["identical"]], results=rows)
    return report


def print_report(rep, out=None):
    print(f"behaviour: {rep['identical']}/{rep['cases']} cases identical "
          f"({rep['reached']} reached the program, {rep['original_succeeded']} succeeded with the original)")
    if len(rep["by_instruction"]) > 1 or rep["differences"]:
        for name, s in rep["by_instruction"].items():
            mark = "" if s["identical"] == s["cases"] else "   <-- differs"
            print(f"  {name:32} {s['identical']:>4}/{s['cases']:<4} identical  ({s['original_ok']} ok){mark}")
    for r in rep["differences"][:8]:
        d = r["difference"]
        print(f"  ✗ {r['signature'][:20]}… {r['instruction']}: {d['kind']}"
              + (f" line {d['line']}" if d["kind"] == "log" else "")
              + (f" {d['account']}" if d["kind"] == "account" else ""))
        print(f"      original : {str(d['original'])[:150]}")
        print(f"      candidate: {str(d['candidate'])[:150]}")
    if len(rep["differences"]) > 8:
        print(f"  … {len(rep['differences']) - 8} more")
    if out:
        print(f"details: {out}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True, help="program id")
    ap.add_argument("--capture-root", type=Path, default=Path("capture"))
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--run", type=Path, help="a `try` run directory (uses relinked/program.so)")
    g.add_argument("--candidate", type=Path, help="any candidate program .so")
    ap.add_argument("--cases", type=Path, default=None, help="default: capture/<ID>/cases")
    ap.add_argument("--limit", type=int, default=None, help="only the first N cases")
    ap.add_argument("--current-balances", action="store_true",
                    help="don't restore each transaction's own pre-transaction lamports and token amounts")
    ap.add_argument("--out", type=Path, default=None, help="default: <run>/difftest.json, else print only")
    a = ap.parse_args(argv)
    cases = a.cases or a.capture_root / a.id / "cases"
    if not (cases / "index.json").exists():
        raise SystemExit(f"no cases in {cases} — collect them first: solopen.py cases --id {a.id}")
    candidate = a.candidate or a.run / "relinked" / "program.so"
    if not candidate.exists():
        raise SystemExit(f"{candidate} missing")
    original = a.capture_root / a.id / "program.so"
    loader = None
    try:
        loader = {"upgradeable": fetch.UPGRADEABLE_LOADER, "loader-v4": fetch.LOADER_V4}.get(
            json.loads((a.capture_root / a.id / "report.json").read_text()).get("loader"))
    except (OSError, ValueError):
        pass
    rep = difftest(a.id, original, candidate, cases, loader=loader, limit=a.limit, restore=not a.current_balances)
    out = a.out or (a.run / "difftest.json" if a.run else None)
    if out:
        out.write_text(json.dumps(rep, indent=1) + "\n")
    print_report(rep, out)
    return 0 if not rep["differences"] else 1


if __name__ == "__main__":
    sys.exit(main())
