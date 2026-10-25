# Final-version fixes and live verification

Test date: 2026-10-24

## Result

The final-version pipeline passed end to end on the live daos.fun program:

- Live RPC fetch returned 1,120,784 bytes with SHA-256 `5020271255ea678fc110fed4671a86b1b7268acad04f990c590decd92091143d` and ELF SHA-256 `145716b96a30edc81413a77caea1c06c8aaf6adf3ad65b1576d6b9469f226e07`.
- Upgrade authority was correctly classified as an off-curve, multisig-style vault.
- The uncached clean build matched all 672 functions and 100% of `.text`.
- Finalization's second clean build from the packaged source also matched.
- `verify_release.py` verified binary equality, all 110 source files, and the deterministic source archive. No partial release directory remained.
- All 30 offline tests, all 8 real-binary order layouts, the fault test, and all 20 missing-twin trials passed.
- The decoy ablation rejected non-compiling, no-op, and panic-shifting edits before accepting the real repair and confirming with a clean build.

## Fixes validated

- Loader identifiers use the correct 43-character upgradeable loader ID. Loader-v4 is explicitly rejected as undecoded.
- Pruned block-time lookup is non-fatal: deploy slot and binary evidence are retained, with the error recorded in `block_time_error`.
- Release packaging stages in a `.partial-<pid>` directory and moves into place only after every check passes.
- Ordinary `cfg(feature = "...")` predicates are allowed; only genuine unstable `feature(...)` activation is rejected.
- The full toolchain lock covers 2,038 files, including compiler drivers and target libraries. The migrated cache passes verification.
- One shared Cargo home is used and rejected if it contains Cargo configuration or credentials. Proxy and CA settings remain available for downloads.
- AI-editable paths and source-manifest paths follow the same rule, so skipped files cannot be edited invisibly.
- Vendor copies are staged and renamed atomically.
- Restored regression, byte-smuggling, exact-replacement, full-symbol, and target-status tests, including environment-independent API-key assertions.

## Live capture provenance

RPC endpoint: `https://solana-rpc.publicnode.com`. This was a live account capture, not a reuse of the earlier published capture. The deploy block was pruned on the endpoint, so its timestamp is unavailable and recorded as `last_deploy_utc: null`; this did not affect binary or authority evidence.

## Decoy result

`blank-liquidity-b` used the decoy sequence. The first target was `dao_v1::math::migration_math::liquidity_from_b`, and the damaged file appeared in the first prompt. The run restored the source exactly and finished with `solved=true` after 1,096 seconds. As before, the oracle tests the harness, not real-model code quality.
