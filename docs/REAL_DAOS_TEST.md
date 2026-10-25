# daos.fun reconstruction workflow test report

Test date: 2026-10-24

## Result

The complete reconstruction and verification workflow passed twice: once from the pinned daosfun-source workspace and again from the finalized package’s own `source/` directory.

| Check | Result |
|---|---|
| Original/rebuilt full payload | **1,120,784 bytes, byte-identical** |
| Full payload SHA-256 | `5020271255ea678fc110fed4671a86b1b7268acad04f990c590decd92091143d` |
| Rebuilt ELF | 1,041,728 bytes |
| ELF SHA-256 | `145716b96a30edc81413a77caea1c06c8aaf6adf3ad65b1576d6b9469f226e07` |
| Generated zero allocation padding | 79,056 bytes |
| Functions matched | 672/672 |
| Original `.text` coverage | 951,456/951,456 bytes (100%) |
| Hand-made order files used | **No** |
| Packaged-source second rebuild | **Byte-identical** |
| Source files in measured package | 110 |
| Source tree SHA-256 | `20e3cba4c543b45358c9aab6be7d18aaa2cbc97366a391326aee4d5cbda381f2` |
| Security reproductions | **6/6 passed** |
| Differential behavior cases | **410/410 passed across 15 suites** |
| Offline unit tests | **16/16 passed** |
| Source-integrity violations | 0 |

`verify_release.py` independently verified whole-file equality, all published source-file hashes, the deterministic source archive, and the recorded hashes.

## Inputs and provenance

- Program: `4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM`
- Original capture: `lalalune/daosfun-source` `evidence/mainnet.so`, commit `5837c6b34575841590d694f7d539918d193b6ba0`. This was not a fresh RPC fetch.
- Recovered source: the same reference repository. This was a baseline reconstruction test, **not an AI reconstruction from scratch**.
- `repro/order-mapping.json` and `repro/constant-order.json` were moved out of the build workspace. solopen recovered ordering from the original and candidate bytes.
- Compiler: official Anza platform-tools v1.41, uploaded in four parts. Reassembled archive: 368,670,614 bytes, SHA-256 `d464229ce31fa36aaf1184505701a2da5c7bb48e29d34004f5b2055dfd9fb0b8`.
- Compiler verification: Rust 1.75.0-dev, Cargo 1.75.0; all 47 component hashes in daosfun-source matched.
- Dependencies: all 264 registry packages installed and verified against Cargo.lock.

## Real decompilation results

| Measurement | Result |
|---|---:|
| `.text` bytes | 951,456 |
| SBPF instructions | 115,478 |
| Heuristic analysis chunks | 662 |
| Named syscall instructions | 742 |
| Indirect-call instructions | 113 |
| Data references | 2,134 |
| Instruction log names | 25 |
| Recovered project source paths | 19 |
| Anchor discriminator annotations | 1 direct `lddw` annotation (`initialize`) |

The 662 chunks are heuristic analysis units, not a claim about the original function count or exact boundaries. Anchor discriminator annotation currently covers only directly loaded constants; other dispatcher encodings require additional analysis. Full disassembly and a machine summary are included under `repro/`.

## Ground-truth tests

- Eight shuffled real-binary layouts reproduced identical `.text` and `.data.rel.ro` after recovery.
- The strengthened fault test passed: three broken functions, one missing function, and one extra function were correctly identified, with assertions for off-boundary and unique-body placement.
- Twenty missing-twin trials completed without crashes; 19 produced one exact-size gap and one split the missing region into two gaps.
- The supplied verified patch was applied, including syscall relocation decoding, `callx` and byte-swap decoding, exit-boundary handling, twin fallback, and the Anchor LTO template correction.

## Reproducibility and integrity

Every measured build used a fresh target directory and an isolated Cargo home. The source manifest covers all selected source/configuration files rather than relying on extensions. Vendor content is manifested separately.

The integrity scan rejects custom `build.rs`, `include_bytes!`, `include_str!`, `global_asm!`, `asm!`, `include!`, deployed-binary path references, raw original chunks, and suspicious long encoded blobs. These are useful checks, not a formal proof against every possible encoding trick. The original binary was used for comparison and evidence, not injected into compilation or linking.

The finalizer independently required all of the following:

1. A byte-identical initial measured build.
2. An unchanged source tree and a valid capture hash in `report.json`.
3. A second clean build from the packaged `source/` directory.
4. Byte identity of that second build and an unchanged manifest.

## Security results

The six original-binary security reproductions passed:

- `poc_finalize_cross_pool.py`
- `poc_second_redemption.py`
- `poc_tr1_expiry.py`
- `poc_tr2_cosigner_signer.py`
- `poc_tr3_delegate_snapshot.py`
- `poc_tr4_token2022_lock.py`

The additional differential suite passed 410/410 cases across 15 suites. The finalized package contains the supplied audit and scope, plus automated review leads and test summaries. The finalizer labels the supplied audit `SUPPLIED_AUDIT_UNVALIDATED_BY_FINALIZER`; the separate 6/6 and 410/410 runs reported here are independent test results.

Passing these reproductions confirms documented behavior, including known vulnerabilities. It does not mean the program is secure or remediated.

## Limitations

- No fresh Solana RPC capture or current mainnet-state assessment was performed.
- The source came from daosfun-source; this test did not demonstrate AI recovering it from scratch.
- Byte identity proves that this source builds these bytes, not unique historical variable names, comments, lockfile, or build configuration.
- No v1.58 toolchain compatibility result is claimed; v1.41 was required for this reproduction.
- No mainnet transaction, deployment, exploit broadcast, or real-wallet operation was performed.

## Follow-up: pointer correction and per-function ablations

A subsequent review identified the high-half encoding of relocated addresses in `.data.rel.ro`. After correcting it, decompilation recovers 672 heuristic chunks and order recovery places every function by evidence with no unresolved-twin fallback. All 8 shuffled layouts, the fault test, and all 20 missing-twin trials pass again.

Seven oracle ablation cases also passed with exact clean builds. The decoy sequence rejected non-compiling, no-op, and panic-shifting edits before accepting the exact repair. See `ABLATION_TEST.md` for the per-case results and the important limitation that an oracle is not a real model.
