# Local Alpha.15 publisher observation

This Linux execution passed two acceptance cases and all ten structured refusal
cases using the immutable published Alpha.15 library and authenticated native
release. It is a local observation, not a remote CI run or a production publisher
deployment. The publisher is the explicitly adapted, owner-maintained consumer
described in [the integration contract](../../README.md).

The [complete report](publisher-report.json) preserves the exact release pin,
adaptation lineage and source hashes, all decisions, canonical evidence digests,
retention outcomes, observed phase times, and source-open trace summaries.
The three raw traces are retained in [publisher-traces/](publisher-traces/).

| Traced case | Processes with terminal evidence | Trace bytes | Observed wheel opens after private deletion |
|---|---:|---:|---:|
| No retention | 8 | 21,707 | 0 |
| Four semantic members retained | 4 | 13,601 | 0 |
| Late wheel-filename refusal | 4 | 13,548 | 0 |

The caller's wheel bytes remained identical in every case. The two accepted
decisions agreed on all four semantic identities. The late refusal occurred
after successful independent evidence verification and private source deletion.
No installation output was created.

## Environment and provenance

- Ubuntu 24.04.4 LTS under WSL2, x86_64 Linux
  `6.18.33.2-microsoft-standard-WSL2`.
- Rust `1.98.0 (88d9e12ae 2026-08-18)`, Python 3.12.3, strace 6.8.
- Native acquisition ran on Windows with Python 3.12.10 and GitHub CLI 2.97.0.
- Published library source:
  `8090a6bb6b0a6cc51461d2bce18966eb1a323434`, tag `v0.1.0-alpha.15`.
- Published GNU native archive: 3,020,812 bytes, SHA-256
  `c3f761fd52804485afed636ab5bec7c54098481b851df8bb80dc28deb2a2f6f4`.
- Typed-report adaptation input:
  `bc364da763f1933ee0bd3b384b3e7a63c465e1f9`, explicitly local and unpublished.
  This is consumer lineage; the dependency is still the published Alpha.15 Git
  commit. The report records all separate baseline and adapted file hashes.

Acquisition verified the release's immutable attestation, exact tag commit,
archive hash and size, and build provenance constrained to the release workflow,
source digest, tag, signer digest, and hosted runner before extraction. Source
checks compared exact handoff and baseline files against the Cargo-resolved
immutable Git checkout. The resolved Sealr feature set was empty.

## Commands

From the Windows downstream checkout:

```powershell
python scripts/acquire_release.py --destination target/alpha15-native
cargo test --locked --test real_wheels -- --nocapture
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

The three wheel artifacts were already present in the digest-checked download
cache. The portable test rechecked their bytes, deleted private source copies,
and read all 1,576 members through the public API.

From `/mnt/c/GitHub/sealr-validation` in the `numinous-linux` WSL distribution:

```sh
CARGO_TARGET_DIR=/root/sealr-validation-target \
  cargo build --locked --release --bin publisher-content-gate
CARGO_TARGET_DIR=/root/sealr-validation-target \
  cargo metadata --locked --format-version 1 > target/publisher-metadata-linux.json
python3 scripts/verify_source.py target/publisher-metadata-linux.json
python3 scripts/test_source_contract.py target/publisher-metadata-linux.json
python3 scripts/test_publisher_trace.py
python3 scripts/validate_publisher.py \
  --example /root/sealr-validation-target/release/publisher-content-gate \
  --native /mnt/c/GitHub/sealr-validation/target/alpha15-native/sealr-0.1.0-alpha.15-x86_64-unknown-linux-gnu \
  --metadata /mnt/c/GitHub/sealr-validation/target/publisher-metadata-linux.json \
  --report /mnt/c/GitHub/sealr-validation/results/publisher-report.json
```

Nine offline source/provenance mutations and nine Linux trace/resource tests
passed. The final exact-empty-feature negative checks ran after the smoke; the
smoke itself had already consumed the same observed empty feature list.
The workflow also passed actionlint 1.7.12 with external ShellCheck disabled.

Each observed session had a 60-second deadline, live one MiB combined output
limit, and inherited hard four MiB file-write limit. Trace analysis required
complete process and split-syscall evidence and rejected wheel opens overlapping
or following private deletion. Failed literal-null pathname sandbox probes have
no pathname; unknown pointers and successful null probes were not accepted.

This establishes no observed wheel-pathname or wheel-FD-annotation opens after
private deletion in the recorded process trees. It does not cover unobserved
processes or aliases absent from pathname and FD annotations. Verified snapshot
FD reads remain permitted, and deleting a pathname does not erase all bytes.
Phase times are single-run observations with tracing overhead, not performance
claims. The historical Alpha.14 retention reports remain unchanged.
