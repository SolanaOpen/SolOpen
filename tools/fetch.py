#!/usr/bin/env python3
"""
fetch.py — pull a Solana program's on-chain executable and its control surface.

Works on ANY deployed program. Downloads the exact bytes that run on-chain,
computes the hashes you compare a rebuild against, and reports who can replace
the program (the thing that actually matters for users).

Read-only. No wallet, no keys, no transactions. stdlib only.

  python3 fetch.py <PROGRAM_ID> [--rpc URL] [--out DIR]

Outputs into --out (default ./capture/<program_id>/):
  program.so            the deployed executable (ProgramData body, incl. padding)
  program.elf.so        the same with trailing zero allocation-padding removed
  report.json          hashes, loader, upgrade authority, IDL, verify status
"""
import sys, os, json, hashlib, base64, struct, argparse, urllib.request, time

MAINNET = "https://api.mainnet-beta.solana.com"
# The upgradeable loader's id is 43 characters. An earlier version of this file
# had 9 extra '1's, so no real upgradeable program ever matched: fetch saved the
# 36-byte program account as program.so and reported "no upgrade authority".
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
LOADER_V4 = "LoaderV411111111111111111111111111111111111"
LOADERS = {
    UPGRADEABLE_LOADER: "upgradeable",
    LOADER_V4: "loader-v4",
    "BPFLoader2111111111111111111111111111111111": "immutable (BPFLoader2)",
    "BPFLoader1111111111111111111111111111111111": "immutable (BPFLoader1)",
}
SYSTEM_PROGRAM = "11111111111111111111111111111111"


class RPCError(RuntimeError):
    """The node answered with a JSON-RPC error. Retrying won't change the
    answer (e.g. "Block … cleaned up, does not exist on node"), except for
    rate limiting, which is retried."""


def rpc(url, method, params, tries=5):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(
                url, body, {"content-type": "application/json", "User-Agent": "Mozilla/5.0 solopen"})
            response = json.load(urllib.request.urlopen(req, timeout=40))
            if response.get("error"):
                err = response["error"]
                if not (isinstance(err, dict) and (err.get("code") == 429 or "rate" in str(err.get("message", "")).lower())):
                    raise RPCError(f"RPC {method} returned an error: {err}")
                raise RuntimeError(f"RPC {method} rate-limited: {err}")
            return response["result"]
        except RPCError:
            raise
        except Exception as e:
            last = e
            time.sleep(1.5 + 2 * i)
    raise RuntimeError(f"RPC {method} failed after {tries} tries: {last}")


def get_account(url, pubkey, encoding="base64", with_context=False):
    r = rpc(url, "getAccountInfo", [pubkey, {"encoding": encoding}])
    if with_context:
        return r
    return r["value"] if r else None


def classify_authority(url, pubkey):
    """Classify an authority account WITHOUT reading its transaction history."""
    if pubkey is None:
        return {"address": None, "kind": "none (immutable — no upgrade authority)"}
    acc = get_account(url, pubkey)
    if acc is None:
        return {"address": pubkey, "kind": "unknown (account not found)"}
    owner = acc["owner"]
    data_len = len(base64.b64decode(acc["data"][0])) if acc["data"][0] else 0
    on_curve = _on_curve(base58_decode(pubkey))
    if owner == SYSTEM_PROGRAM and data_len == 0 and on_curve:
        kind = "plain wallet (one keypair holds it — a single person can upgrade)"
    elif owner == SYSTEM_PROGRAM and data_len == 0 and not on_curve:
        kind = ("off-curve address with no data — a program-derived address, "
                "almost always a multisig vault (e.g. Squads). Find the controlling "
                "multisig and its signer threshold before trusting it.")
    elif owner == SYSTEM_PROGRAM:
        kind = f"system-owned with {data_len} bytes of data (unusual)"
    else:
        kind = f"program-owned ({owner[:8]}… — likely a multisig/PDA; inspect that program)"
    return {"address": pubkey, "kind": kind, "owner": owner, "data_len": data_len, "on_curve": on_curve}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def strip_trailing_zeros(b):
    i = len(b)
    while i > 0 and b[i - 1] == 0:
        i -= 1
    return b[:i]


def elf_end_from_header(b):
    """Compute the real ELF end (e_shoff + e_shnum*e_shentsize) from the header.
    This is the padding-free boundary the daosfun repo uses. Falls back to
    trailing-zero stripping if the header does not parse as 64-bit ELF."""
    if len(b) < 64 or b[:4] != b"\x7fELF" or b[4] != 2:
        return None
    e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", b, 0x3C)[0]
    end = e_shoff + e_shentsize * e_shnum
    return end if 0 < end <= len(b) else None


def fetch_program(url, program_id, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rep = {"program_id": program_id, "rpc": url, "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    prog_response = get_account(url, program_id, with_context=True)
    prog = prog_response.get("value") if prog_response else None
    if prog is None:
        raise SystemExit(f"No account at {program_id} — not a deployed program on this cluster.")
    if not prog.get("executable"):
        raise SystemExit("account is not executable; refusing to save it as a Solana program")
    if prog.get("owner") not in LOADERS:
        raise SystemExit(f"account owner is not a recognized Solana BPF loader: {prog.get('owner')}")
    rep["executable"] = prog["executable"]
    rep["loader"] = LOADERS[prog["owner"]]
    rep["slot"] = (prog_response.get("context") or {}).get("slot")

    programdata = None
    if prog["owner"] == UPGRADEABLE_LOADER:
        # Program account: 4-byte tag + 32-byte ProgramData pubkey
        raw = base64.b64decode(prog["data"][0])
        if len(raw) >= 36 and struct.unpack_from("<I", raw, 0)[0] == 2:
            programdata = base58_encode(raw[4:36])
        rep["programdata_address"] = programdata
        if programdata is None:
            raise SystemExit("Upgradeable program account does not name a ProgramData account.")
        # Read both accounts in ONE call so they come from the same slot: two
        # separate reads could pair the Program account with a ProgramData
        # written by an upgrade that landed in between.
        snap = rpc(url, "getMultipleAccounts", [[program_id, programdata], {"encoding": "base64"}]) or {}
        prog_now, pd = (list(snap.get("value") or []) + [None, None])[:2]
        if prog_now is None or base64.b64decode(prog_now["data"][0]) != raw:
            raise SystemExit("the program account changed while fetching (upgrade or close in progress?) — fetch again")
        if pd is None:
            raise SystemExit("Upgradeable program but ProgramData account missing.")
        rep["slot"] = (snap.get("context") or {}).get("slot", rep["slot"])
        pd_raw = base64.b64decode(pd["data"][0])
        # ProgramData layout: tag(4) + slot(8) + option(1) + authority(32), then the
        # ELF. The 32 authority bytes are reserved even when the authority has been
        # removed (the loader always reads the program from byte 45), so the
        # header is 45 bytes either way. Using 13 for "no authority" put 32 zero
        # bytes in front of every renounced program's capture.
        deploy_slot = struct.unpack_from("<Q", pd_raw, 4)[0]
        has_auth = pd_raw[12]
        authority = base58_encode(pd_raw[13:45]) if has_auth else None
        header_len = 45
        rep["last_deploy_slot"] = deploy_slot
        try:
            bt = rpc(url, "getBlockTime", [deploy_slot])
        except RuntimeError as exc:
            # Some RPCs prune old blocks. Block time is metadata, not a reason
            # to lose the deployed executable and its authority evidence.
            bt = None
            rep["block_time_error"] = str(exc)
        rep["last_deploy_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(bt)) if bt else None
        rep["upgrade_authority"] = classify_authority(url, authority)
        body = pd_raw[header_len:]
    elif prog["owner"] == LOADER_V4:
        # Loader-v4 keeps the executable in the program account itself, after
        # a 48-byte state: slot u64, authority-or-next-version (32), status u64
        # (0 retracted, 1 deployed, 2 finalized — no authority any more).
        raw = base64.b64decode(prog["data"][0])
        if len(raw) < 48:
            raise SystemExit("loader-v4 account shorter than its 48-byte header")
        slot, status = struct.unpack_from("<Q", raw, 0)[0], struct.unpack_from("<Q", raw, 40)[0]
        rep["last_deploy_slot"] = slot
        rep["loader_v4_status"] = {0: "retracted", 1: "deployed", 2: "finalized"}.get(status, f"unknown ({status})")
        if status == 0:
            raise SystemExit("this loader-v4 program is retracted (not executable right now); nothing to capture")
        try:
            bt = rpc(url, "getBlockTime", [slot])
        except RuntimeError as exc:
            bt = None
            rep["block_time_error"] = str(exc)
        rep["last_deploy_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(bt)) if bt else None
        if status == 2:
            rep["upgrade_authority"] = {"address": None, "kind": "none (finalized loader-v4 program)"}
        else:
            rep["upgrade_authority"] = classify_authority(url, base58_encode(raw[8:40]))
        body = raw[48:]
    else:
        # Non-upgradeable: the program account data IS the executable.
        rep["upgrade_authority"] = {"address": None, "kind": "none (immutable loader)"}
        body = base64.b64decode(prog["data"][0])

    # Save the full body (this is what matches a full account-padded capture)
    with open(os.path.join(out_dir, "program.so"), "wb") as f:
        f.write(body)
    rep["program_so_bytes"] = len(body)
    rep["program_so_sha256"] = sha256(body)

    end = elf_end_from_header(body)
    if end is not None:
        elf = body[:end]
        rep["elf_boundary"] = "section-header-table end (from ELF header)"
    else:
        elf = strip_trailing_zeros(body)
        rep["elf_boundary"] = "trailing zeros stripped (ELF header did not parse)"
    with open(os.path.join(out_dir, "program.elf.so"), "wb") as f:
        f.write(elf)
    rep["elf_bytes"] = len(elf)
    rep["elf_sha256"] = sha256(elf)
    rep["zero_padding_bytes"] = len(body) - len(elf)

    # On-chain Anchor IDL account (optional; present for many Anchor programs)
    rep["anchor_idl"] = fetch_idl(url, program_id, out_dir)

    # OtterSec verified-build registry (a claim; records repo + match)
    rep["ottersec_verify"] = ottersec_status(program_id)

    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(rep, f, indent=2)
    return rep


# --- base58 (no deps) ---
_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = _ALPH[r] + s
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + s


def base58_decode(s):
    n = 0
    for c in s:
        n = n * 58 + _ALPH.index(c)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def anchor_idl_address(program_id):
    """IDL PDA: createWithSeed(base=findPDA([], program)[0], "anchor:idl", program)."""
    import hashlib as _h
    pid = base58_decode(program_id)
    # The documented account is createWithSeed(basePda, "anchor:idl", program)
    # base PDA = find_program_address([], program)
    base = _find_pda([], pid)
    # createWithSeed(base, "anchor:idl", owner=program)
    h = _h.sha256()
    h.update(base)
    h.update(b"anchor:idl")
    h.update(pid)
    return base58_encode(h.digest())


def _find_pda(seeds, program_bytes):
    import hashlib as _h
    for bump in range(255, -1, -1):
        h = _h.sha256()
        for s in seeds:
            h.update(s)
        h.update(bytes([bump]))
        h.update(program_bytes)
        h.update(b"ProgramDerivedAddress")
        cand = h.digest()
        if not _on_curve(cand):
            return cand
    raise RuntimeError("no PDA bump found")


def _on_curve(b):
    # ed25519 on-curve check (point decompression). PDAs must be OFF curve.
    try:
        return _ed25519_on_curve(b)
    except Exception:
        return False


# minimal ed25519 decompression to test on-curve-ness
_p = 2 ** 255 - 19
_d = (-121665 * pow(121666, _p - 2, _p)) % _p


def _ed25519_on_curve(b):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _p:
        return False
    u = (y * y - 1) % _p
    v = (_d * y * y + 1) % _p
    xx = (u * pow(v, _p - 2, _p)) % _p
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * pow(2, (_p - 1) // 4, _p)) % _p
    return (x * x - xx) % _p == 0


def fetch_idl(url, program_id, out_dir):
    try:
        idl_addr = anchor_idl_address(program_id)
    except Exception as e:
        return {"present": False, "note": f"could not derive IDL address: {e}"}
    acc = get_account(url, idl_addr)
    if acc is None:
        return {"present": False, "idl_address": idl_addr}
    try:
        import zlib
        raw = base64.b64decode(acc["data"][0])
        # IdlAccount: 8-byte discriminator + 32-byte authority + 4-byte len + zlib(json)
        ln = struct.unpack_from("<I", raw, 40)[0]
        js = zlib.decompress(raw[44:44 + ln]).decode("utf-8", "replace")
        idl = json.loads(js)
        with open(os.path.join(out_dir, "idl.json"), "w") as f:
            f.write(js)
        return {
            "present": True, "idl_address": idl_addr,
            "name": idl.get("metadata", {}).get("name") or idl.get("name"),
            "instructions": [i["name"] for i in idl.get("instructions", [])],
            "accounts": [a["name"] for a in idl.get("accounts", [])],
            "errors": len(idl.get("errors", [])),
            "saved": "idl.json",
        }
    except Exception as e:
        return {"present": True, "idl_address": idl_addr, "note": f"account exists but decode failed: {e}"}


def ottersec_status(program_id):
    try:
        req = urllib.request.Request(
            f"https://verify.osec.io/status/{program_id}",
            headers={"User-Agent": "Mozilla/5.0 solopen"})
        d = json.load(urllib.request.urlopen(req, timeout=20))
        return d if isinstance(d, dict) else {"raw": d}
    except Exception as e:
        return {"note": f"verify registry unreachable: {e}"}


def main():
    ap = argparse.ArgumentParser(description="Fetch a Solana program's on-chain bytes and control surface.")
    ap.add_argument("program_id")
    ap.add_argument("--rpc", default=MAINNET)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = a.out or os.path.join("capture", a.program_id)
    rep = fetch_program(a.rpc, a.program_id, out)
    print(json.dumps(rep, indent=2))
    print(f"\nSaved to {out}/ — program.so ({rep['program_so_bytes']} bytes), program.elf.so ({rep['elf_bytes']} bytes)")


if __name__ == "__main__":
    main()
