# Per-function ablation benchmark and pointer-correction report

Test date: 2026-10-24

## Result

All seven built-in daos.fun ablation cases passed with an oracle model, ending in byte-identical clean builds. Every damaged file appeared in the first prompt. This validates targeting, prompting, cached builds, scoring, rollback, and final confirmation. It is not a measurement of real-model code quality.

| Case | Model calls | Seconds | First target |
|---|---:|---:|---|
| `perturb-redeem-compare` | 1 | 574 | `dao_v1::instructions::redeem_sol::handle_redeem_sol` |
| `perturb-liquidity-shift` | 1 | 564 | `dao_v1::math::migration_math::liquidity_from_b` |
| `perturb-unwrap-column` | 1 | 568 | `dao_v1::math::migration_math::liquidity_from_a` |
| `blank-liquidity-b` | 4 | 1350 | `dao_v1::math::migration_math::liquidity_from_b` |
| `blank-redeem-sol` | 1 | 571 | `dao_v1::__private::__global::redeem_sol` |
| `blank-start-raise` | 1 | 598 | `dao_v1::__private::__global::start_raise` |
| `blank-init-curve` | 1 | 557 | `dao_v1::instructions::init_curve::initialize` |

All seven reports have `solved=true`, `source_restored_exactly=true`, and `damaged_file_in_first_prompt=true`.

## Decoy rejection test

The `blank-liquidity-b` run used the decoy sequence and behaved as required:

1. A non-compiling edit was rejected.
2. A no-op edit was rejected with no distance improvement.
3. An edit that restored the function but added a line above other functions was rejected because two previously matching functions loaded different panic constants. This happened even though code coverage was 100%.
4. The exact repair was accepted, and a final uncached build was byte-identical.

## Constant-level and inline targeting

The `perturb-unwrap-column` case also had 100% code coverage before editing. The new data targets still identified two wrong constant locations and repaired them. The whole-handler ablations selected either the removed function itself or the Anchor dispatcher into which it had been inlined, as appropriate.

## High-half pointer correction

The `.data.rel.ro` encoding stores relocated addresses in the high 32 bits on this SBPFv1 binary. Decoding and re-pointing those words had these measured effects:

- Eight shuffled layouts reproduced identical `.text` and `.data.rel.ro`.
- Every function was placed by evidence: `call-forced`, `callee-forced`, or `unique`; no `unresolved-twin` fallback remained.
- The fault test and all 20 missing-twin trials still passed.
- Real decompilation now recovers 672 heuristic chunks, 742 named syscall instructions, and 113 indirect calls.
- Final order recovery on the clean daos build likewise required no unresolved-twin guesses.

## Build and integrity checks

- The generated linker launcher is executable even when source archives lose executable bits.
- Search builds reuse dependency caches but always recompile the program crate.
- Finalization refuses cached search runs and requires a clean build.
- Alias-based smuggling checks now reject `use core::arch::global_asm as g`, `.incbin`, inline/global assembly, unstable features, custom build scripts, and dependency patching.
- Final packaged-source verification succeeded: 110 source files, source tree `20e3cba4c543b45358c9aab6be7d18aaa2cbc97366a391326aee4d5cbda381f2`, full hash `5020271255ea678fc110fed4671a86b1b7268acad04f990c590decd92091143d`.
- The new vendor command verified all 264 already-present packages.

## Scope

No real model was used. The oracle returns the removed or original code, so these results do not estimate how often an AI model can reconstruct unknown Rust. The pinned capture and reference source are used as ground truth, not as evidence that source recovery from an unpublished program has succeeded.
