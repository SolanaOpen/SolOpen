# solopen: rebuild a deployed Solana program byte-for-byte

A Solana program on-chain is only a compiled executable. "Open-sourcing" one
means publishing source code that **compiles back to exactly the same bytes**.
Then anyone can check the source is what actually runs, not a look-alike.

Inspired by [**lalalune/daosfun-source**](https://github.com/lalalune/daosfun-source):
that project recovered the source, compiler, dependency versions and linker
layout, then proved a byte-identical rebuild and published security evidence.
solopen turns that workflow into a reusable toolkit and automates the mechanical
link-order step plus the measured reconstruction loop.

## The loop

```sh
python3 solopen.py fetch <PROGRAM_ID>          # capture/<ID>/: exact on-chain bytes, hashes,
                                               # who can upgrade it, on-chain IDL, verify status
python3 solopen.py inspect capture/<ID>        # instruction names, source-file layout,
                                               # programs it calls, error strings
python3 solopen.py decompile capture/<ID> --out reverse/<ID> --workspace my-rebuild
                                               # SBPF assembly + CFG + unimplemented Anchor stubs
python3 solopen.py toolchain auto --original capture/<ID>/program.so
                                               # which platform-tools release built it; installs that
                                               # one and records it in capture/<ID>/toolchain.json
cd my-rebuild && ~/.cache/solopen/platform-tools-v<X>/rust/bin/cargo generate-lockfile && cd ..
                                               # use that release's cargo; newer lockfile formats can break old builds
python3 solopen.py lockfit --id <ID> --workspace my-rebuild [--apply]
                                               # dependency versions the binary proves vs your Cargo.lock
python3 solopen.py vendor --lock my-rebuild/Cargo.lock --out vendor   # optional: offline, hash-checked crates
python3 solopen.py cases --id <ID>             # optional: 200 recent real transactions + account snapshot,
                                               # so try also compares behaviour (pip install solders==0.29.0)
python3 solopen.py try --id <ID> --workspace my-rebuild --program my_program [--vendor vendor]
                                               # uses capture/<ID>/toolchain.json (detects it first if
                                               # missing); --toolchain 1.44 or a directory overrides
python3 solopen.py target --run runs/<that run> --original capture/<ID>/program.so
                                               # per-function targets, assembly diffs and panic sites
```

Each `try` does a clean build, then:

1. **Recovers the link order** (`tools/linkorder.py`). Your build puts
   functions in a different order than the original, so the bytes can't match
   even when every function is right. linkorder tiles the original's code with
   your compiled functions (ignoring only the address fields that moving a
   function changes), works out which of several identical-looking functions
   sits where from the call graph and from what constants each one loads, and
   derives where each constant must go too. This was the hand-made
   `order-mapping.json` + `constant-order.json` in the daosfun repo.
2. **Relinks your same objects in that order** (`tools/relink.py`), with no
   recompiling and no bytes copied from the original, strips, and byte-compares.
3. **Scores the attempt**: what % of the original's code your functions
   reproduce, and a list of *your* functions that don't match yet, biggest
   first. That list is the to-do list.
4. **Compares behaviour** when `capture/<ID>/cases` exists (below): how many
   recorded transactions behave identically, per instruction.

### Which compiler

Nothing is hard-coded: `toolchain auto` (and `try`/`rebuild` when you leave
out `--toolchain`) works out the platform-tools release before you write any
source, cheapest evidence first:

1. **Release dates.** It lists every platform-tools release (GitHub API, or
   the git tags if the API is unreachable) and drops those published after
   the program's last deploy (from `fetch`'s report).
2. **Standard-library source.** Each release's `build.sh` names the
   anza-xyz/rust tag it was built from. The Rust panic locations the original
   carries for core/alloc/std (file, line, column) are checked against that
   tag's source with git. A wrong release points at missing files, past the
   end of a file, or at blank and comment lines. No toolchain is downloaded
   for this; it narrows ~60 releases to the few that share a Rust version.
3. **Canary.** Only those few are downloaded. Each compiles a small bundled
   canary program (`calibrate.py`), and the release whose ELF header,
   precompiled std coordinates and helper bodies (`core::fmt::write`, integer
   formatting, `__multi3`, Vec growth…) best match the original wins. The
   others are deleted again (`--keep` keeps them); their fingerprints stay in
   `~/.cache/solopen/fingerprints`, so the next program doesn't need them.

The choice goes to `capture/<ID>/toolchain.json` with the evidence and a
confidence. `calibrate.py` also works directly on releases you pick yourself
(`--toolchain 1.44 --toolchain 1.45`, or `--cached`). Results so far:

| Program | Release picked | How it got there |
|---|---|---|
| Pump, PumpSwap, Fees (pump.fun) | v1.44, high | source check: 61 releases → v1.43–v1.46.1 (one Rust version); canary: 52/60 helpers vs 17/71 for the next best |
| Mayhem (pump.fun) | v1.54, **low** | source check → v1.52–v1.56; v1.55/v1.56 match every helper but one (`u128_div_rem`), so it is flagged as a close call |
| SPL Token | v1.54, high | deploy date rules out v1.55+; the release its verified build used |
| daos.fun | v1.41, **low** | source check → v1.40–v1.42.1; v1.40 and v1.41 compile every canary helper identically, so it reports a tie (daosfun-source documents v1.41); v1.42.1 ships no SBPF v0 target |

These agree with lalalune/pumpfun-source's controlled builds (v1.44 for the
three older programs, v1.52–v1.56 for Mayhem) and add v1.46.1, which they had
not measured: it fits the Fees binary no better than v1.46.

It assumes a stock platform-tools build and ordinary settings: a custom
toolchain, or a program with almost no standard-library code, can come out
ambiguous (the result says so). Treat it as the release to start with, not a
proof; `--toolchain` always overrides it.

### Which dependency versions

A wrong library version changes code everywhere that crate is used, and
nothing in your source shows it. `lockfit` reads the evidence the binary
carries and checks `Cargo.lock` against it, without building anything:

- **Exact.** Some releases leave a crate's registry path in panic messages
  (`…/borsh-1.5.7/src/ser/mod.rs`): that is the crate and version. The
  standard library has crates.io dependencies of its own (`hashbrown` is
  std's `HashMap`); a path the toolchain's sysroot carries is reported as
  std's copy and never proposed as a `Cargo.lock` change.
- **Coordinates.** Every other dependency panic location is `src/<file>.rs`
  with a line and column. For each locked crate it reads the published source
  (static.crates.io, checksum-verified, cached) and checks the code is there.
  A crate whose own files don't fit is checked at its other published
  versions, and the best fit is proposed; `--apply` runs
  `cargo update --precise` with the program's toolchain.
- **Builds.** When several versions fit equally, `--resolve-ties` builds
  each and keeps the best coverage; `--try-lock other.lock` (repeatable) ranks
  whole candidate lockfiles, such as an official release's, the same way.

On daos.fun, with `num-bigint` set back to 0.4.3 and `rust_decimal` to
1.33.1, it proposed `num-bigint` 0.4.6 (46/46 locations fit vs 17/46) and
`rust_decimal` 1.34.0–1.36.0 (a tie, 62/62); `--apply` gave back a
Cargo.lock identical to daosfun-source's. On pumpfun-source's Mayhem it
lists the original's nine source files (`programs/mayhem-program/src/…`)
that sit at other paths there, recognises the binary's `hashbrown` 0.15.4 as
the standard library's copy (so the original uses a std `HashMap` or
`HashSet` somewhere), and finds two panic locations in a `src/account_wrapper.rs`
that no locked crate has.

### SBPF versions

A program's SBPF version is its ELF `e_flags`, and solopen handles v0–v3:
`try` builds for the original's version (`--target sbpfv1/v2/v3-solana-solana`),
and decoding, link-order recovery, relinking, per-function targets, compiler
detection and difftest all follow its rules:

| | encoding | syscalls | layout |
|---|---|---|---|
| v0 | original | `call -1` + a named relocation | relocated; pointers in `.data.rel.ro` |
| v1 | as v0 (adds `add64 r10, imm` stack frames) | as v0 | as v0 |
| v2 | no `lddw` (addresses are `mov32` + `hor64`), loads/stores moved into the ALU classes, mul/div/rem in a new class | as v0 | as v0 |
| v3 | as v0, plus `jmp32` | `call` with the murmur3 hash of the name | fixed: `.rodata` at 0, `.text` at 1<<32, no relocations |

The rules come from anza-xyz/sbpf. The decoder agrees with `llvm-objdump`
from platform-tools v1.54 and v1.58 (the newest) on every instruction,
`callx` register and call target of a ~5,500-instruction program built for
each version. `_test/e2e_versions.py`, which builds a program for each
version, shuffles its functions, and checks that `try` rebuilds it
byte-for-byte, passes with both releases. v3 programs name
no syscall in the file, so `decompile` recovers the names from a table of
every SDK syscall's hash. With no relocations, v3 data pointers are found as
code addresses or (address, length) pairs pointing at text; other v3 data
pointers can't be told from numbers.

`fetch` also reads loader-v4 programs (the executable after a 48-byte state:
slot, authority, status); difftest runs them under the upgradeable loader,
which LiteSVM supports.

platform-tools v1.44 added the target name `sbpf-solana-solana`, and later
releases ship only that name; where a release has both, they compile the
same code. From v1.44 on v0–v2 programs carry ELF machine 263 (EM_SBF)
instead of 247; v3 is 247 again. `build.py` picks the target the toolchain
ships for v0; `try` passes the original's version; `--target` overrides.

## Behaviour: does it act like the original?

Byte equality is the finish line, but most of a reconstruction is spent far
from it. `cases` saves the program's recent real transactions, a snapshot of
every account they touch, the Clock and the executables of every program they
call (read-only; nothing is sent). `difftest` then replays each one twice in
LiteSVM (once with the original, once with your build at the same address) and
compares status and error code, every log line (compute-unit counts masked),
return data and every account afterwards. Each transaction's own
pre-transaction lamport and token balances are restored, so most replays
reach real logic; program-owned state is the snapshot's.

```sh
python3 -m pip install solders==0.29.0            # LiteSVM; only difftest needs it
python3 solopen.py cases --id <ID> --limit 300
python3 solopen.py difftest --id <ID> --run runs/<attempt>   # try runs it too
```

```
behaviour: 260/300 cases identical (299 reached the program, 191 succeeded with the original)
  BurnDaoTokens                      15/55   identical  (40 ok)   <-- differs
  ✗ Cr1BqKRq7fhKpsEWSZtC… BurnDaoTokens: status
      original : ok
      candidate: TransactionErrorInstructionError((5, Tagged(InstructionErrorCustom(6006))))
```

On daos.fun's last 300 transactions, the ablation benchmark's damaged builds
split cleanly: the two with broken redeem logic differ on 40 cases each; the
builds damaged in instructions nobody called recently (`init_curve`,
`start_raise`, liquidity) or only in a panic column behave identically, because
recent traffic can't exercise them. Identical behaviour is not proof of
equivalence; a difference is always a real bug, and it says where.

## Decompile

`decompile` decodes SBPF v0–v3 (ELF e_flags 0–3; v0 is called SBFv1 in older Solana docs) into per-function assembly and basic-block CFGs. It
uses ELF symbols when available; on stripped programs it infers function starts
from internal calls, code pointers (vtables) and exits that no branch crosses,
and labels those boundaries as heuristic (on daos.fun: 672 chunks). Syscalls are
named from the ELF's relocations, indirect calls show as `callx rN`, and
data/string references and Anchor instruction discriminators are annotated.
With `--workspace`, it generates an Anchor crate with recovered program id and
instruction names, but every handler returns `NotImplemented`: names and empty
contexts are starting hypotheses, not recovered behavior.

## Per-function targets

`target` turns a `try` run's to-do list into one target per function of yours
that doesn't match yet: the range of the original it should become, found from
the call graph (a function that already matches calls it, takes its address,
or loads a vtable pointing at it), the functions both call, and its neighbours.
Each target gets the two sides as assembly with the same names for calls,
syscalls, strings, panic locations and in-function branch offsets, a diff, and a
distance (differing instructions; 0 = matches). It also lists the panic
`file:line:col` sites each side has, which tell you exactly which line and
column every overflow check, `unwrap` and index must sit on, and guesses the
source file. Targets are ordered bottom-up: functions whose callees already
match come first, because callers inline them. Constant-only differences are
targets too, even when code coverage is already 100%.

## The AI rebuild loop

`rebuild` drives an OpenAI-compatible chat model one function at a time:

```sh
export SOLOPEN_AI_API_KEY=...   # provider-specific variables only for matching hosts
export SOLOPEN_AI_MODEL=<model-name>
python3 solopen.py rebuild --id <ID> --workspace my-rebuild --program my_program \
  --out runs/ai-01 --max-iters 40 [--vendor vendor] [--focus some_module]
# toolchain: capture/<ID>/toolchain.json (detected if missing); --toolchain overrides
# --base-url http://localhost:8000/v1 for a local compatible server
```

Each round takes the first open target and sends the model its assembly diff,
both panic-site lists, the source file(s) with line numbers, and its earlier
rejected attempts on that function with their compiler errors. The model
returns exact search/replace edits (or whole files) to `.rs` files only by
default; `include_bytes!`/`include_str!`, inline/global assembly (including
aliases), `#![feature]`, build scripts, dependency changes and anything under
`vendor/`, `.cargo/` or `target/` are refused. Every proposal is built with
shared dependency caching, re-ordered, relinked and re-targeted. It is kept only
if that function got closer or now matches **and** nothing that matched before
stopped matching, including functions whose code still matches but whose panic
locations moved. After `--max-per-target` failed tries the loop moves on.
Endpoint errors are retried with backoff; a malformed answer costs one attempt,
not the run. Ctrl-C never leaves an unscored edit behind. When everything
matches, a clean uncached build confirms it. Prompts, responses, every attempt
and `history.json` are saved under `--out`; `--baseline-only` builds and targets
once without AI.

This is a bounded search aid, **not** a guarantee of convergence or a universal
decompiler. Review accepted source before using or publishing it. Builds execute
model-written Rust and dependencies' build scripts: use a disposable Linux
VM/container with no wallet keys or other secrets. The configured AI provider
receives the source and evidence in each prompt.

## Measuring the loop: the ablation benchmark

`bench/bench.py` measures the loop where the answer is known. It copies a
workspace that already rebuilds byte-for-byte (daosfun-source), removes or
perturbs one function while keeping every line number, runs `rebuild` on the
copy, and records whether it gets back to an exact, clean-build match:

```sh
python3 bench/bench.py list
python3 bench/bench.py run blank-liquidity-b --pristine daosfun-source \
  --id 4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM --capture-root capture \
  --program dao_v1 --vendor vendor --target-cache bench-cache --model <model>
# --oracle answers with the removed code instead of a model: a harness check only
```

Cases range from one wrong operator or a wrong panic column to a whole
100-line instruction handler removed. Run them with your model before trusting
the loop on a program nobody has published.

## Finalize a recovery: source + exact binary + proof + security review

Every measured build now writes `source-manifest.json`: deterministic hashes of
the source/configuration files and their paths. After an exact match, `finalize`
checks the complete binaries again and refuses to continue if the workspace has
changed since that measured build. It then performs a **second clean build from
the packaged `source/` tree itself** and requires that build to match too. A
copied original cannot satisfy this check. Cached search runs are not accepted:
use the clean confirmation build. Capture hashes are mandatory, and source
integrity rules reject `include_bytes!`/`include_str!`, inline/global assembly
(including aliases), `.incbin`, custom build scripts, unstable features and
dependency patching, plus raw original chunks and suspicious encoded blobs.
These are strong integrity checks, not a formal proof against every possible encoding:

```sh
python3 solopen.py finalize --id <ID> --workspace my-rebuild \
  --run runs/ai-01/attempt-008 --decompile reverse/<ID> --out release/<ID>
# Use the actual successful try/attempt directory, not necessarily attempt-008.
# A completed human audit can be packaged with: --audit AUDIT.md --scope SECURITY_SCOPE.md
```

The fresh release directory follows the daosfun-source delivery model:

| Path | Delivered evidence |
|---|---|
| `source/`, `source-reconstruction.zip` | recovered Anchor/Rust workspace and deterministic source archive |
| `binaries/rebuilt.elf.so` | rebuilt ELF before account-allocation padding |
| `binaries/rebuilt.so` | rebuilt, zero-padded payload, exactly equal to the capture |
| `evidence/original.so` | original bytes for comparison only, never a build input |
| `repro/final-proof.json` | hashes, equality, ELF/padding lengths, source binding and capture authority |
| `repro/source-manifest.json` | path, size and SHA-256 for every measured source/configuration file |
| `repro/` other records | build command/log, order mapping, relink report, packaged-source rebuild receipts, toolchain/vendor manifests |
| `audit/AUDIT.md` | supplied audit, or an explicitly incomplete automated pre-review |
| `audit/automated-security-review.json` | static leads marked `UNCONFIRMED_REVIEW_LEAD`, never confirmed vulnerabilities |
| `docs/` | build, delivery and security-scope records |
| `verify_release.py` | stdlib-only independent check of binaries, hashes, source files and archive |

Run `python3 verify_release.py` inside the release. This validates the published
receipts; it does not replace another clean rebuild. Without `--audit`, security
status remains **MANUAL_SECURITY_REVIEW_REQUIRED**. A supplied audit is packaged
but not independently validated by the finalizer. Static patterns are leads, not
proof of vulnerabilities; confirmed findings need code reasoning and preferably
original-binary runtime reproductions, as in daosfun-source. Exact reconstruction
preserves vulnerabilities rather than remediating them.

## Reconstructing the source

This remains the real work. A human or AI must write Rust that does what the
binary does, guided by `inspect`, `decompile`, the on-chain IDL if there is one,
and measured mismatches. Then iterate until the to-do list is empty and the
final bytes match. Panic locations (file:line:column) are compiled in, so file
layout and even blank lines matter: never reformat a file once it matches.

## What has been verified

- `fetch` / `inspect` / `compare` against the live daos.fun program
  (`4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM`): hashes match the repo's
  published ones; its upgrade authority is correctly classified as a
  multisig-style vault, not a single wallet.
- `linkorder` on the real daos.fun binary, scrambled the way a fresh build
  scrambles it, 8 different ways: the recovered order reproduces `.text`
  and `.data.rel.ro` byte-for-byte every time, from bytes alone
  (`_test/test_order.py`). With 3 broken functions, 1 missing and 1 extra, it
  names exactly those and still places everything else
  (`_test/test_faults.py`).
- **End to end on the live program** (`_test/e2e_daos.sh`): a clean build of
  the daosfun-source code with platform-tools v1.41, then solopen's own
  order recovery, relink and strip (without the repo's hand-made
  `order-mapping.json` or `constant-order.json`) reproduced the on-chain
  account body exactly: 1,120,784 bytes, sha256
  `5020271255ea678fc110fed4671a86b1b7268acad04f990c590decd92091143d`. All
  672 functions placed, 100% of the code covered, constants reordered in
  `.rodata` and `.data.rel.ro` from the recovered map.

That last one is the claim that matters: the part the repo did as a one-off
(order + constants) is now automatic. What it does not show is the hard
part, writing the source, because the source came from the repo.

An independent real-workflow run on 2026-10-24 additionally passed with the
pinned daosfun capture and no hand-made order files: 662 heuristic decompiler
chunks (672 after the pointer fix below), 742 named syscalls, two clean byte-identical builds (the second from the
finalized `source/` package), 110 measured source files, all 264 verified crates,
6/6 security reproductions and 410/410 differential cases. The uploaded v1.41
archive matched all 47 reference component hashes. See
[`docs/REAL_DAOS_TEST.md`](docs/REAL_DAOS_TEST.md) for provenance and limits.

Follow-up pointer and per-function tests measured on the same binary: all 8
shuffled layouts now re-point calls, function-address loads and the 154
vtable/fn-table pointers in `.data.rel.ro`, and every function is named by
evidence with no unresolved-twin fallback. Real decompilation recovers 672
chunks with named syscalls. All 7 oracle ablation cases (wrong operator,
constant, panic column and removed handlers up to `init_curve`) ended in exact
clean builds; the decoy sequence rejected non-compiling, no-op and
panic-shifting edits before accepting the real fix. Every damaged file was in
the first prompt. These are harness results, not a real-model success rate;
see [`docs/ABLATION_TEST.md`](docs/ABLATION_TEST.md).

The newer decompiler, AI-loop and finalization tests are separate and much
narrower: `_test/test_decompile.py` uses synthetic SBPF ELF inputs;
`_test/test_rebuild.py` checks AI validation, confinement, rollback and scoring;
`_test/test_finalize.py` checks deterministic source binding, exact-match gates,
static-review labels and the self-contained release verifier. `_test/test_bench.py`
checks the ablation Rust parser. `_test/test_calibrate.py` checks panic-location parsing (with and without Rust 1.89's trailing NUL), stdlib lookups and aligned body search. `_test/test_pick_toolchain.py` checks release-date filtering, the source-coordinate check, the shortlist and that the canary stage only downloads the leader's neighbours. `_test/test_behaviour.py` checks transaction parsing, the behaviour comparison and lockfit's classification and version fitting. `_test/test_versions.py` pins the v2/v3 encodings, masking, static-syscall names, v3 pointer detection and loader-v4 capture. All 56 offline tests pass (one LiteSVM test runs only with `solders`); `_test/e2e_versions.py` is the per-version rebuild check above (needs platform-tools). **No end-to-end AI reconstruction of daos.fun or another real
program has been measured yet**, so no success rate or claim that the AI loop
finishes a real reconstruction is made.

## Files

| | |
|---|---|
| `solopen.py` | the CLI (`fetch`, `inspect`, `decompile`, `toolchain`, `calibrate`, `try`, `rebuild`, `finalize`, plus each step) |
| `tools/fetch.py` | capture executable, hashes, upgrade authority, IDL, verified-build status |
| `tools/inspect_program.py` | what the binary does, from its own strings and references |
| `tools/sbf.py` | dependency-free SBPF v0–v3 instruction and basic-block decoder, syscall hash table |
| `tools/decompile.py` | disassembly, CFGs, reference annotations and explicit unimplemented Rust scaffolds |
| `tools/target.py` | per-function targets: original placement, assembly diff, distance, panic sites |
| `tools/rebuild.py` | per-function AI edit loop with cached builds, scoring and regression rollback |
| `tools/vendor.py` | fetch lockfile crates from static.crates.io, hash-checked, for offline builds |
| `bench/bench.py` | ablation benchmark: damage known-good source and measure repair |
| `tools/evidence.py` | all-file deterministic build-input manifests shared by build and finalization |
| `tools/integrity.py` | reject deployed-byte smuggling channels before builds and finalization |
| `tools/security_review.py` | explicit-scope Anchor static pre-review, never a security certification |
| `tools/finalize.py` | exact-gated source, binary, proof and security release packaging |
| `tools/toolchain.py` | download an official platform-tools release, hash-locked |
| `tools/calibrate.py` | rank platform-tools releases by header, stdlib coordinates and helper bodies (cached fingerprints) |
| `tools/pick_toolchain.py` | `toolchain auto`: detect the release from release dates, Rust std source and the canary; install it |
| `tools/lockfit.py` | dependency versions from the binary (exact paths, source coordinates) vs Cargo.lock; `--apply`, `--try-lock` |
| `tools/cases.py` | recent real transactions + account snapshot + invoked programs, for difftest |
| `tools/difftest.py` | replay cases on the original and a candidate in LiteSVM; compare behaviour (needs `solders`) |
| `tools/build.py` | clean, isolated `cargo build` for SBF that captures the link (`--target-cache` for search loops) |
| `tools/capture_link.py` | linker wrapper used by build.py |
| `tools/linkorder.py` | recover function order + constant order from bytes |
| `tools/relink.py` | replay the link in that order, strip, compare |
| `tools/compare.py` | byte check with first-difference location and fix hints |
| `workspace_template/` | a starting Cargo workspace with the settings that matter |
| `_test/` | the ground-truth tests above, `e2e_daos.sh` for the full daos.fun rebuild, `e2e_versions.py` for v0–v3 |

Everything is Python 3.11.4+ standard library, except `difftest`, which needs
`solders` (LiteSVM). Normal reconstruction downloads
only the compiler (and crates, by Cargo); `rebuild` additionally contacts the
AI endpoint you configure and sends it the prompt artifacts described above.
