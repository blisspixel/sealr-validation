# Local Alpha.17 publisher observation

This Linux execution passed both retention choices and all ten structured
refusals using published Alpha.17 source and its authenticated native release.
It is a local observation, not a remote CI result or a production publisher
deployment. The consumer follows the [integration contract](../../README.md).

The [complete report](publisher-report.json) records exact release and consumer
hashes, decisions, canonical evidence digests, retention outcomes, observed
phase times, and summaries of the three retained
[source-open traces](publisher-traces/).

| Traced case | Processes with terminal evidence | Trace bytes | Observed wheel opens after private deletion |
|---|---:|---:|---:|
| No retention | 8 | 21,705 | 0 |
| Four semantic members retained | 4 | 13,635 | 0 |
| Late wheel-filename refusal | 4 | 13,586 | 0 |

The caller's wheel bytes remained identical in every case. Both acceptance
cases agreed on all four semantic identities. The late refusal followed
successful independent evidence verification and private source deletion.
No installation output was created.

## Environment and provenance

- Ubuntu 24.04.4 LTS under WSL2, x86_64 Linux
  `6.18.33.2-microsoft-standard-WSL2`.
- Rust `1.98.0 (88d9e12ae 2026-08-18)`, Python 3.12.3, strace 6.8.
- Native acquisition on Windows used Python 3.12.10 and GitHub CLI 2.97.0.
- Published source and typed publisher input:
  `fd158e06bb25287adf93977f4a9b86c48b3723aa`, tag `v0.1.0-alpha.17`.
- Public repository ID `1368698020`; immutable release ID `387987318`,
  published by `blisspixel` on 2026-09-13.
- Published GNU native archive: 3,023,161 bytes, SHA-256
  `c4c5cc996b2ea40ebfe732aa6d8e4fccd8693c46f9d92e2175a9feb64118bd01`.

Acquisition verified the exact tag commit, release immutability, native archive
hash and size, and build provenance constrained to the release workflow,
source digest, tag, signer digest, and hosted runner before extraction. The
verifier uses the current repository namespace without a fixed repository ID
or release-author assumption in place of those checks.

The handoff files match the actual Cargo-resolved source byte for byte. The
publisher uses the released example with only the documented stage include and
test-module adjustments; its smoke adds provenance checks and bounded tracing.
These consumer bytes are unchanged from the Alpha.16 integration, while the
source and native identity pins now identify Alpha.17. Sealr resolves with an
empty feature set and no path patch. This is immutable Git acquisition, not
registry distribution evidence.

## Commands and validation

From the Windows downstream checkout after updating the exact source and native
pins from the published release:

```powershell
python scripts/acquire_release.py --destination target/alpha17-native
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python -m unittest discover -s tests/attribution -p 'test_*.py'
python scripts/verify_attribution.py --ci
python scripts/verify_source.py target/source-metadata-alpha17.json
python scripts/test_source_contract.py target/source-metadata-alpha17.json
python scripts/prepare_experiment_stage.py
```

The complete metadata file came from `cargo metadata --format-version 1` during
the exact dependency refresh. The lockfile changed only the Sealr version and
Git source. Formatting, Clippy, thirteen source/provenance refusals, exact staging
reproduction, and the actual-history metadata guard passed. The guard's thirteen
offline tests passed on Windows and Linux. The required workflow also passed
actionlint 1.7.12 with ShellCheck disabled.

From `/mnt/c/GitHub/sealr-validation` in `numinous-linux`:

```sh
export CARGO_TARGET_DIR=/root/sealr-validation-target
cargo build --locked --release --bin publisher-content-gate
cargo metadata --locked --format-version 1 > target/publisher-metadata-linux-alpha17.json
python3 scripts/verify_source.py target/publisher-metadata-linux-alpha17.json
python3 scripts/verify_attribution.py --ci
python3 scripts/validate_publisher.py \
  --example /root/sealr-validation-target/release/publisher-content-gate \
  --native /mnt/c/GitHub/sealr-validation/target/alpha17-native/sealr-0.1.0-alpha.17-x86_64-unknown-linux-gnu \
  --metadata target/publisher-metadata-linux-alpha17.json \
  --report results/publisher-alpha17/publisher-report.json
```

The report and all three traces were copied here without modification. Report
SHA-256:
`0910171511eab37f88c2a0712c665442dcca78ef3fd619264f8cce54ce4ae320`.

Each traced session had a 60-second deadline, live one MiB combined output cap,
and inherited hard four MiB file-write limit. Analysis required complete process
and split-syscall evidence and rejected wheel opens overlapping or following
private deletion. The claim is limited to observed wheel pathnames and FD
annotations in these process trees. It does not cover unobserved processes or
aliases absent from those annotations. Verified snapshot FD reads remain
allowed; pathname deletion does not erase all bytes. Phase times include tracing
overhead and are single-run observations, not performance claims.

All 17 files in the earlier Alpha.14, Alpha.15, and Alpha.16 observation folders
retain their exact bytes. Their original hashes and URLs remain historical
records even when retired upstream URLs no longer provide those inputs. No
optional retention or controlled repeated-read measurement was rerun.
