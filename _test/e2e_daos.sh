#!/bin/sh
# End-to-end proof on a real program: rebuild the live daos.fun program from
# the daosfun-source code, with the link order and constant order recovered
# by solopen from bytes alone (the repo's hand-made order-mapping.json and
# constant-order.json are NOT used). Expected: MATCH, full on-chain sha256
# 5020271255ea678fc110fed4671a86b1b7268acad04f990c590decd92091143d.
# Linux x86-64, ~1 GB of downloads, ~5-10 minutes of compiling.
set -e
ID=4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM
S="$(cd "$(dirname "$0")/.." && pwd)/solopen.py"
WORK=${WORK:-./e2e-daos}
mkdir -p "$WORK" && cd "$WORK"

python3 "$S" fetch "$ID"                                   # live bytes -> capture/$ID/
[ -d daosfun-source ] || git clone https://github.com/lalalune/daosfun-source
python3 "$S" toolchain auto --original "capture/$ID/program.so"   # detect + install the compiler
python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["release"]; print("detected v"+r); sys.exit(r!="1.41")' \
    "capture/$ID/toolchain.json"                           # daosfun-source documents v1.41
# the repo pins its crates through a vendor dir; fetch them from
# static.crates.io, checking every archive against Cargo.lock
python3 "$S" vendor --lock daosfun-source/Cargo.lock --out daosfun-source/vendor

python3 "$S" try --id "$ID" --workspace daosfun-source \
    --program dao_v1 --vendor daosfun-source/vendor        # toolchain from capture/$ID/toolchain.json

# ground-truth unit tests (fast)
DAOS_SO="capture/$ID/program.so" DAOS_MAP=daosfun-source/repro/order-mapping.json \
    python3 "$(dirname "$S")/_test/test_order.py"
DAOS_SO="capture/$ID/program.so" DAOS_MAP=daosfun-source/repro/order-mapping.json \
    python3 "$(dirname "$S")/_test/test_faults.py"
DAOS_SO="capture/$ID/program.so" DAOS_MAP=daosfun-source/repro/order-mapping.json \
    python3 "$(dirname "$S")/_test/test_twins.py"

# harness check of the per-function AI loop on the same program (oracle model,
# no API key needed; most time is the final clean build)
python3 "$(dirname "$S")/bench/bench.py" run blank-liquidity-b --pristine daosfun-source \
    --id "$ID" --capture-root capture \
    --program dao_v1 --vendor daosfun-source/vendor --target-cache bench-cache --oracle decoy
