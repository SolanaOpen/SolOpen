#!/usr/bin/env python3
"""Best-effort reconstruction-integrity checks against deployed-byte smuggling.

These checks deliberately reject flexible build channels. They are not a formal
proof that every possible encoding of the original is absent; independent clean
rebuilds and source review remain necessary.
"""
import hashlib
from pathlib import Path
import re
import evidence

# `#![feature(x)]` / `#![cfg_attr(.., feature(x))]` turn on unstable compiler
# features and are refused. `feature = "x"` inside cfg(...) is an ordinary Cargo
# feature check — SPL programs gate their entrypoint with
# #![cfg(all(target_os = "solana", not(feature = "no-entrypoint")))] — and is fine.
FORBIDDEN = re.compile(
    r"(?m)\b(?:include_bytes|include_str|include)\s*!|\binclude_bytes\b|\binclude_str\b|"
    r"\b(?:global_asm|naked_asm|asm)\s*!|\b(?:global_asm|naked_asm)\b|"
    r"\b(?:core|std)\s*::\s*arch\b|\.incbin\b|\blink_section\b|"
    r"#\s*!\s*\[[^\]]*\bfeature\s*\(|^\s*\[build-dependencies\]|^\s*build\s*=|"
    r"^\s*\[patch|^\s*\[replace\]|git\s*=\s*\"")
PATH_REFERENCE = re.compile(r"(?:capture/|program\.so|mainnet\.so|evidence/)", re.I)
LONG_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{512,}(?![0-9a-fA-F])")
LONG_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{2048,}={0,2}(?![A-Za-z0-9+/])")
TEXT_SUFFIXES = {".rs", ".py", ".sh", ".toml", ".c", ".h", ".cc", ".cpp", ".s"}


def violations(workspace, original=None):
    workspace = Path(workspace).resolve()
    original = Path(original) if original else None
    original_bytes = original.read_bytes() if original and original.exists() else None
    original_sha = hashlib.sha256(original_bytes).hexdigest() if original_bytes else None
    needles = sample_chunks(original_bytes) if original_bytes else []
    out = []
    for rel, path in evidence.source_files(workspace):
        if path.name == "build.rs":
            out.append(f"{rel}: custom build.rs is not allowed in a measured reconstruction")
        raw = path.read_bytes()
        if original_sha and hashlib.sha256(raw).hexdigest() == original_sha:
            out.append(f"{rel}: file is byte-identical to the deployed original")
        if any(chunk in raw for chunk in needles):
            out.append(f"{rel}: contains a raw 32-byte chunk of the deployed original")
        if path.suffix not in TEXT_SUFFIXES:
            continue
        text = raw.decode("utf-8", "replace")
        match = FORBIDDEN.search(text)
        if match:
            out.append(f"{rel}: forbidden embedded-source/byte channel {match.group(0)}")
        if path.suffix == ".rs":
            match = PATH_REFERENCE.search(text)
            if match:
                out.append(f"{rel}: references deployed-binary path {match.group(0)}")
            if LONG_HEX.search(text):
                out.append(f"{rel}: suspicious long hex blob (possible encoded deployed bytes)")
            if LONG_B64.search(text):
                out.append(f"{rel}: suspicious long base64 blob (possible encoded deployed bytes)")
    return out


def require_clean(workspace, original=None):
    problems = violations(workspace, original)
    if problems:
        raise SystemExit("reconstruction integrity check failed:\n  " + "\n  ".join(problems[:40]))
    return True


def sample_chunks(original_bytes, count=6, size=32):
    """32-byte pieces of the deployed CODE with many distinct byte values. Fixed
    offsets can land in zero padding or an ELF header, and 32 zero bytes match
    almost any binary file (a capture with leading zeros flagged 343 innocent
    test fixtures in solana-program/token)."""
    import struct
    text = original_bytes
    if original_bytes[:4] == b"\x7fELF" and len(original_bytes) >= 64:
        shoff = struct.unpack_from("<Q", original_bytes, 0x28)[0]
        shnum, shstrndx = struct.unpack_from("<HH", original_bytes, 0x3C)
        try:
            heads = [struct.unpack_from("<IIQQQQ", original_bytes, shoff + 64 * i) for i in range(shnum)]
            strtab = heads[shstrndx][4]
            for name_off, _typ, _flags, _addr, off, sz in heads:
                end = original_bytes.index(b"\0", strtab + name_off)
                if original_bytes[strtab + name_off:end] == b".text":
                    text = original_bytes[off:off + sz]
        except (struct.error, IndexError, ValueError):
            pass
    out = []
    step = max(size, len(text) // (count + 1))
    for at in range(step, len(text) - size, step):
        for nudge in range(0, min(step, 4096), 8):
            chunk = text[at + nudge:at + nudge + size]
            if len(chunk) == size and len(set(chunk)) >= 12 and chunk not in out:
                out.append(chunk)
                break
        if len(out) >= count:
            break
    return out
