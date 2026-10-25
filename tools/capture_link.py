#!/usr/bin/env python3
"""
capture_link.py — linker wrapper that records a build's final link.

Cargo calls this instead of rust-lld (via CARGO_TARGET_<TRIPLE>_LINKER).
For every link except your program's it just runs the real linker. For your
program's .so it also saves:

  link-inputs/          copies of every object/archive the linker read
  link-args.json        the exact argument list, re-pointed at those copies
  link.map              lld's map: which input section landed at which address
  baseline.unstripped.so  the linked program WITH symbols (linkorder needs them)

so relink.py can replay the same link with a recovered section order, without
recompiling. Nothing here reads the original program.

Environment (set by build.py):
  SOLOPEN_REAL_LINKER   path to rust-lld
  SOLOPEN_CAPTURE_DIR   where to write the capture
  SOLOPEN_PROGRAM       the crate's lib name, e.g. dao_v1 (matches <name>.so)
  SOLOPEN_OBJCOPY       path to llvm-objcopy (recorded for relink.py)
"""
import hashlib, json, os, shutil, subprocess, sys
from pathlib import Path

real = os.environ["SOLOPEN_REAL_LINKER"]
args = sys.argv[1:]
out = args[args.index("-o") + 1] if "-o" in args else ""
prog = os.environ.get("SOLOPEN_PROGRAM", "")
if not prog or Path(out).name not in (prog + ".so", "lib" + prog + ".so"):
    raise SystemExit(subprocess.call([real] + args))

root = Path(os.environ["SOLOPEN_CAPTURE_DIR"])
if root.exists():
    shutil.rmtree(root)
inputs = root / "link-inputs"
inputs.mkdir(parents=True)
records, replay = [], []
for i, arg in enumerate(args):
    if i and args[i - 1] == "-o":
        replay.append("@OUTPUT@")
        continue
    prefix, cand = "", arg
    for p in ("--version-script=", "--script=", "-T"):
        if arg.startswith(p) and len(arg) > len(p):
            prefix, cand = p, arg[len(p):]
            break
    path = Path(cand)
    if path.is_file():
        dest = inputs / f"{i}-{path.name}"
        shutil.copy2(path, dest)
        records.append(dict(argument=i, original=str(path), saved=str(dest),
                            sha256=hashlib.sha256(dest.read_bytes()).hexdigest()))
        replay.append(prefix + str(dest))
    else:
        replay.append(arg)
(root / "link-inputs.json").write_text(json.dumps(records, indent=2) + "\n")
(root / "link-args.json").write_text(json.dumps(dict(linker=real, objcopy=os.environ.get("SOLOPEN_OBJCOPY", ""),
                                                   args=replay, original_args=args), indent=2) + "\n")
rc = subprocess.call([real] + args + ["-Map=" + str(root / "link.map")])
if rc == 0 and Path(out).is_file():
    shutil.copy2(out, root / "baseline.unstripped.so")
raise SystemExit(rc)
