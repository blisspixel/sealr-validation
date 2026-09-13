# Sealr downstream validation

[![Downstream validation](https://github.com/blisspixel/sealr-validation/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/sealr-validation/actions/workflows/ci.yml)

This project tests whether an ordinary downstream checkout can obtain an exact
Sealr source revision and authenticated native release, then make publisher
decisions and install real wheels through the admitted capability.

It is a validation project maintained by Sealr's owner. It does not establish
independent external adoption, an independent security review, a stable API,
general package-manager support, or application runtime compatibility.

## What is tested

The [publisher content gate](publisher/README.md) makes Deepr's concrete dashboard
and runtime-content decision with no installation. Required Linux CI exercises
both retention choices and ten machine-readable refusals. A bounded merged
`strace` observes both successful cases and the late wheel-semantic refusal:
the publisher deletes its private wheel copy after independent evidence
verification, and no process in the observed tree opens a wheel pathname after
that boundary. The caller's original is preserved byte for byte.
The [first local Alpha.15 observation](publisher/observations/2026-09-13/README.md)
includes the complete report and three raw traces; it is not a remote CI result.

| Released wheel | Source | Members | Planned entries |
|---|---|---:|---:|
| Deepr Research 2.50.11 | GitHub release | 832 | 833 |
| Primr 1.39.13 | PyPI | 546 | 548 |
| Recon Tool 2.18.4 | PyPI | 198 | 198 |

[`artifacts.json`](artifacts.json) pins each download URL, byte length, SHA-256,
provenance URL, member count, plan count, and measured semantic artifact identity.
Wheel bytes are acquired during validation and are not redistributed here.

On Linux, macOS, and Windows, a public-API regression admits all three wheels,
deletes its private source copy, evaluates the wheel plan, and reads every one
of the 1,576 members through `VerifiedArchive`.

On Ubuntu 24.04 x86_64, each wheel also completes installation twice through the
authenticated Linux worker, from inspect and native materialization. The copied
public handoff independently verifies canonical evidence before source deletion.
Rust keeps the exact plan, supplies verified member blobs to installer 1.0.1,
and audits installed paths, content, executable modes, and realization identity.
The Python bridge denies wheel opens after admission. Both origins must produce
the same source, archive, artifact, plan, and realization identities.

For each project, three additional runs mutate the worker release version,
target, and bootstrap ABI. Each must be refused without consuming the input or
creating an installer destination.

Each project has its own Linux job, with a ten-minute deadline per complete
handoff and a thirty-second deadline per manifest refusal. Reports preserve the
elapsed time. A locally measured Deepr inspect handoff took 217 seconds for 834
audited output files, so the original three-minute harness deadline was too short.
Each unretained member read uses a fresh restricted worker. This validates the
boundary; its per-member overhead remains integration feedback to address.

These installations do not execute application code, install runtime dependencies,
or establish that the applications run in the test environment.

## Release and source boundary

[`sealr-release.json`](sealr-release.json) pins the release tag, full commit, and
native archive digest and length. Acquisition verifies GitHub release immutability,
the tag commit, the downloaded archive, and GitHub build provenance constrained
to the release workflow, source commit, tag, and hosted runner before extraction.

The Rust dependency uses an exact Git revision and a committed Cargo lockfile.
There is no local path patch, mutable branch dependency, private Sealr feature,
or dependency on a workspace-only Sealr tool. Alpha.15 is a GitHub-only release,
so this deliberately tests immutable Git source acquisition. It is not evidence
of a crates.io publication or completion of the registry pilot gate.

The four files in `handoff/` are the public copyable handoff from the same Sealr
release. [`handoff-origin.json`](handoff-origin.json) pins their exact hashes and
source commit. CI rejects copied-source drift, a source/native version mismatch,
path patches, or private features before transferring an input to the worker.
The copy check compares the files with the actual Cargo-resolved immutable Git
checkout, in addition to the recorded hashes.

[`publisher-origin.json`](publisher-origin.json) separately pins the released
publisher baseline and the local adapted consumer. Its structured failures came
from an explicitly unpublished source revision, then received downstream path,
source-contract, and observation integration. They are not represented as
released Alpha.15 example behavior. The library and native dependency remain the
published Alpha.15 pair.

## Reproduce

Rust 1.98.0 is pinned by `rust-toolchain.toml`. Portable checks need Python 3:

```sh
python3 scripts/acquire.py
cargo test --locked -- --nocapture
```

For complete installation, use Ubuntu 24.04 x86_64 with Linux 6.8 or later,
Landlock ABI 3, and the supported seccomp setup. An authenticated `gh` session
must be able to read public release attestations.

```sh
python3 scripts/acquire_release.py --destination /tmp/sealr-validation-native
cargo build --locked --release
cargo metadata --locked --format-version 1 > /tmp/sealr-validation-metadata.json
python3 scripts/verify_source.py /tmp/sealr-validation-metadata.json
```

The [CI workflow](.github/workflows/ci.yml) contains the exact installer acquisition
and complete handoff commands. It saves `results/report.json` as a commit-bound
artifact per project for 30 days. Input copies and installed trees are temporary; the original
download cache remains available for deliberate reruns.

## What comes next

The publisher job now provides unattended, commit-bound decision and source-open
evidence. The next work is to use those checked decisions in an actual publishing
workflow and measure acquisition or capability-use costs exposed by that path.
This validation repository remains maintained by Sealr's owner and does not
establish independently maintained adoption or production publisher deployment.

The [bounded retention experiment](experiments/retention/README.md) compares
nine full installations with no retention, a semantic working set, and up to
64 explicitly selected members. It keeps the copied handoff unchanged and
requires exact evidence and installed-output parity. Its phase times are
single-run integration observations, not controlled benchmark results.
The [observed Linux run](experiments/retention/observed-linux-wsl/README.md)
passed all nine installations and three native-manifest refusals.

The committed observed retention reports remain historical Alpha.14 evidence.
New executions use the active Alpha.15 pins and must produce new reports; existing
observations are not relabeled as results from the newer release.

[Apache-2.0](LICENSE).
