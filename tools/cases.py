#!/usr/bin/env python3
"""
cases.py — collect real transactions to test a reconstruction's BEHAVIOUR.

  python3 solopen.py cases --id <PROGRAM_ID> [--limit 200] [--rpc URL]
      -> capture/<ID>/cases/  (transactions, account snapshot, invoked programs)

Byte equality is the finish line, but most of a reconstruction is spent far
from it. `difftest` fills that gap: it runs the ORIGINAL program and your
CANDIDATE on the same inputs in a local Solana runtime and compares what they
do. This collects those inputs, read-only:

  - the program's most recent transactions (raw, exactly as sent),
  - one snapshot of every account they touch, taken now, plus the Clock,
  - the executable of every other on-chain program they invoke, so CPIs run
    against the real code.

The snapshot is of the CURRENT state. Each transaction's own lamport and
token balances from just before it ran are kept too and restored on replay,
but program-owned state (a curve, a config) is today's, so some replays fail
where they once succeeded. That doesn't matter for a differential test — both
programs see exactly the same inputs — and `difftest` reports how many cases
reached your program and how many succeeded. Everything is saved, so later runs are offline
and repeatable. No wallet, no keys, nothing is sent to the chain. stdlib only.
"""
import argparse, base64, json, os, struct, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fetch

NATIVE_LOADER = "NativeLoader1111111111111111111111111111111"
CLOCK = "SysvarC1ock11111111111111111111111111111111"


# ---------------------------------------------------- transaction parsing
def compact_u16(b, i):
    n = s = 0
    while True:
        x = b[i]
        i += 1
        n |= (x & 0x7F) << s
        if not x & 0x80:
            return n, i
        s += 7


def parse_transaction(raw):
    """Static account keys, address-lookup-table keys and instructions of a
    serialized (legacy or v0) transaction."""
    nsig, i = compact_u16(raw, 0)
    i += 64 * nsig
    version = None
    if raw[i] & 0x80:
        version = raw[i] & 0x7F
        i += 1
    header = tuple(raw[i:i + 3])
    i += 3
    nkeys, i = compact_u16(raw, i)
    keys = [fetch.base58_encode(raw[i + 32 * k:i + 32 * k + 32]) for k in range(nkeys)]
    i += 32 * nkeys + 32                       # keys, recent blockhash
    ninstr, i = compact_u16(raw, i)
    instructions = []
    for _ in range(ninstr):
        prog = raw[i]
        i += 1
        nacc, i = compact_u16(raw, i)
        accs = list(raw[i:i + nacc])
        i += nacc
        ndata, i = compact_u16(raw, i)
        instructions.append(dict(program_index=prog, accounts=accs, data=raw[i:i + ndata]))
        i += ndata
    tables = []
    if version is not None:
        nlook, i = compact_u16(raw, i)
        for _ in range(nlook):
            key = fetch.base58_encode(raw[i:i + 32])
            i += 32
            nw, i = compact_u16(raw, i)
            i += nw
            nr, i = compact_u16(raw, i)
            i += nr
            tables.append(key)
    return dict(version=version, header=header, keys=keys, tables=tables, instructions=instructions)


# ------------------------------------------------------------- collection
def chunks(seq, n):
    for k in range(0, len(seq), n):
        yield seq[k:k + n]


def snapshot(url, keys, log):
    """{pubkey: account dict or None} for every key, 100 per request."""
    out, slot = {}, None
    keys = sorted(set(keys))
    for part in chunks(keys, 100):
        r = fetch.rpc(url, "getMultipleAccounts", [part, {"encoding": "base64", "commitment": "confirmed"}])
        slot = (r.get("context") or {}).get("slot", slot)
        for k, v in zip(part, r["value"]):
            out[k] = None if v is None else dict(
                lamports=v["lamports"], owner=v["owner"], executable=v["executable"],
                rent_epoch=min(int(v.get("rentEpoch", 0)), 2 ** 64 - 1), data=v["data"][0])
        log(f"  snapshot {len(out)}/{len(keys)} accounts")
    return out, slot


def program_elf(url, pid, acct):
    """(loader, ELF bytes) for an executable account, fetching its ProgramData."""
    raw = base64.b64decode(acct["data"])
    if acct["owner"] == fetch.UPGRADEABLE_LOADER:
        if len(raw) < 36 or struct.unpack_from("<I", raw, 0)[0] != 2:
            return None
        pd = fetch.get_account(url, fetch.base58_encode(raw[4:36]))
        if pd is None:
            return None
        body = base64.b64decode(pd["data"][0])[45:]
    elif acct["owner"] == fetch.LOADER_V4:
        if len(raw) < 48 or struct.unpack_from("<Q", raw, 40)[0] == 0:      # retracted
            return None
        body = raw[48:]
    elif acct["owner"] in fetch.LOADERS:
        body = raw
    else:
        return None
    end = fetch.elf_end_from_header(body)
    return acct["owner"], body[:end] if end else body


def collect(program_id, out, url=fetch.MAINNET, limit=200, before=None, log=print):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    log(f"collecting up to {limit} recent transactions of {program_id}")
    sigs, cursor = [], before
    while len(sigs) < limit:
        opts = {"limit": min(1000, limit - len(sigs)), "commitment": "confirmed"}
        if cursor:
            opts["before"] = cursor
        batch = fetch.rpc(url, "getSignaturesForAddress", [program_id, opts])
        if not batch:
            break
        sigs += batch
        cursor = batch[-1]["signature"]
    cases, keys = [], set()
    for n, s in enumerate(sigs, 1):
        try:
            tx = fetch.rpc(url, "getTransaction", [s["signature"], {
                "encoding": "base64", "maxSupportedTransactionVersion": 0, "commitment": "confirmed"}])
        except RuntimeError as exc:
            log(f"  skip {s['signature'][:16]}…: {exc}")
            continue
        if not tx:
            continue
        raw = base64.b64decode(tx["transaction"][0])
        try:
            parsed = parse_transaction(raw)
        except (IndexError, ValueError) as exc:
            log(f"  skip {s['signature'][:16]}…: unparsable ({exc})")
            continue
        meta = tx.get("meta") or {}
        loaded = meta.get("loadedAddresses") or {}
        accounts = parsed["keys"] + loaded.get("writable", []) + loaded.get("readonly", [])
        keys.update(accounts)
        keys.update(parsed["tables"])
        # Lamports and token amounts BEFORE this transaction ran (the RPC keeps
        # those per transaction), so a replay can restore the user's balances.
        pre_tokens = {accounts[t["accountIndex"]]: t["uiTokenAmount"]["amount"]
                      for t in meta.get("preTokenBalances") or [] if t.get("accountIndex", 1 << 30) < len(accounts)}
        cases.append(dict(signature=s["signature"], slot=tx.get("slot"), block_time=tx.get("blockTime"),
                          mainnet_err=meta.get("err"), tx=tx["transaction"][0],
                          accounts=accounts, tables=parsed["tables"],
                          pre_lamports=dict(zip(accounts, meta.get("preBalances") or [])),
                          pre_token_amounts=pre_tokens))
        if n % 25 == 0:
            log(f"  {n}/{len(sigs)} transactions")
    keys.add(CLOCK)
    keys.discard(program_id)                       # the program under test comes from the capture / candidate
    accounts, slot = snapshot(url, keys, log)
    programs = {}
    (out / "programs").mkdir(exist_ok=True)
    for k, a in sorted(accounts.items()):
        if a and a["executable"] and a["owner"] != NATIVE_LOADER:
            got = program_elf(url, k, a)
            if got:
                loader, elf = got
                (out / "programs" / f"{k}.so").write_bytes(elf)
                programs[k] = dict(loader=loader, bytes=len(elf))
    log(f"  {len(programs)} other on-chain program(s) invoked: saved their executables")
    (out / "accounts.json").write_text(json.dumps(accounts) + "\n")
    index = dict(program_id=program_id, rpc_host=url.split("/")[2] if "//" in url else url,
                 collected_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), snapshot_slot=slot,
                 programs=programs, cases=cases)
    (out / "index.json").write_text(json.dumps(index, indent=1) + "\n")
    ok = sum(c["mainnet_err"] is None for c in cases)
    log(f"saved {len(cases)} transactions ({ok} succeeded on mainnet) and {len(accounts)} accounts to {out}")
    return index


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True, help="program id")
    ap.add_argument("--capture-root", type=Path, default=Path("capture"))
    ap.add_argument("--out", type=Path, default=None, help="default: capture/<ID>/cases")
    ap.add_argument("--limit", type=int, default=200, help="most recent transactions to collect (default 200)")
    ap.add_argument("--before", default=None, help="start below this signature (page further back)")
    ap.add_argument("--rpc", default=os.environ.get("SOLANA_RPC_URL", fetch.MAINNET))
    a = ap.parse_args(argv)
    out = a.out or a.capture_root / a.id / "cases"
    if (out / "index.json").exists():
        raise SystemExit(f"{out} already has cases; use a fresh --out (cases are a fixed test set)")
    collect(a.id, out, a.rpc, a.limit, a.before)


if __name__ == "__main__":
    main()
