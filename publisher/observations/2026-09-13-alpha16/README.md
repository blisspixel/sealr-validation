# Local Alpha.16 publisher observation

This Linux execution passed both retention choices and all ten structured
refusals using the immutable published Alpha.16 source and authenticated native
release. It is a local observation, not a remote CI run or a production publisher
deployment. The owner-maintained consumer follows the
[integration contract](../../README.md).

The [complete report](publisher-report.json) records the release and adapted
consumer hashes, decisions, canonical evidence digests, retention outcomes,
observed phase times, and summaries of the three retained
[source-open traces](publisher-traces/).

| Traced case | Processes with terminal evidence | Trace bytes | Observed wheel opens after private deletion |
|---|---:|---:|---:|
| No retention | 8 | 21,743 | 0 |
| Four semantic members retained | 4 | 13,536 | 0 |
| Late wheel-filename refusal | 4 | 13,561 | 0 |

The caller's wheel bytes remained identical in every case. The accepted cases
agreed on all four semantic identities. The late refusal followed successful
independent evidence verification and private source deletion. No installation
output was created.

## Environment and provenance

- Ubuntu 24.04.4 LTS under WSL2, x86_64 Linux
  `6.18.33.2-microsoft-standard-WSL2`.
- Rust `1.98.0 (88d9e12ae 2026-08-18)`, Python 3.12.3, strace 6.8.
- Native acquisition on Windows used Python 3.12.10 and GitHub CLI 2.97.0.
- Published source and typed publisher input:
  `711955645bcca4f0e50838e0ba7f7d4825abb81e`, tag `v0.1.0-alpha.16`.
- Immutable GitHub release ID `387952440`, published on 2026-09-13.
- Published GNU native archive: 3,022,592 bytes, SHA-256
  `86e877f52cf83da62d28b128764ed3defa2687919f24678be46fa1397a1e7d4a`.

The publisher's typed checks and structured failures come from the released
Alpha.16 example. The downstream executable adjusts the stage include and omits
repository-only tests; its smoke adds source provenance and bounded tracing.
The report preserves separate baseline and adapted file hashes. The exact
copied handoff and released publisher baseline match the actual Cargo-resolved
Git checkout, with an empty Sealr feature set and no path patch. This is immutable
Git acquisition, not registry distribution evidence.

Acquisition verified release immutability, the exact tag commit, native archive
hash and size, and build provenance constrained to the release workflow,
source digest, tag, signer digest, and hosted runner before extraction.

## Commands and validation

From the Windows downstream checkout:

```powershell
python scripts/acquire_release.py --destination target/alpha16-native
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --nocapture
```

Formatting, Clippy, three copied handoff outcome tests, and the public real-wheel
test passed. The latter rechecked the cached wheel bytes, deleted private source
copies, and read all 1,576 members. Source metadata and all thirteen negative
source/provenance cases passed on Windows and Linux. The experimental staging
copy reproduced exactly, and all three public retention inventories were
unchanged. Nine Linux trace/resource tests and nine repeated-read harness tests
passed; the Windows harness skipped its four Linux-only process tests.
The unchanged workflow passed actionlint 1.7.12 with ShellCheck disabled.

From `/mnt/c/GitHub/sealr-validation` in the `numinous-linux` WSL distribution:

```sh
export CARGO_TARGET_DIR=/root/sealr-validation-target
cargo build --locked --release --bins
cargo metadata --locked --format-version 1 > target/publisher-metadata-linux-alpha16.json
python3 scripts/verify_source.py target/publisher-metadata-linux-alpha16.json
python3 scripts/test_source_contract.py target/publisher-metadata-linux-alpha16.json
python3 scripts/test_publisher_trace.py
python3 -m unittest discover -s experiments/repeated-reads -p 'test_*.py'
python3 scripts/validate_publisher.py \
  --example /root/sealr-validation-target/release/publisher-content-gate \
  --native /mnt/c/GitHub/sealr-validation/target/alpha16-native/sealr-0.1.0-alpha.16-x86_64-unknown-linux-gnu \
  --metadata target/publisher-metadata-linux-alpha16.json \
  --report results/publisher-alpha16/publisher-report.json
```

The complete report and three raw traces were copied here without modification.
Report SHA-256:
`4bef8ae9e7ff0426a0e508b443078abee0e0c776461060b156978c82f8c4611f`.

Each traced session had a 60-second deadline, live one MiB combined output limit,
and inherited hard four MiB file-write limit. Analysis required complete process
and split-syscall evidence and rejected wheel opens overlapping or following
private deletion. This establishes no observed wheel-pathname or
wheel-FD-annotation opens after private deletion in these recorded process trees.
It does not cover unobserved processes or aliases absent from those annotations.
Verified snapshot FD reads remain allowed; pathname deletion does not erase all
bytes. Phase times include tracing overhead and are single-run observations,
not performance claims. Historical Alpha.14 and Alpha.15 observations remain
unchanged, and no controlled measurement was rerun for this release refresh.
