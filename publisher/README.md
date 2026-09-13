# Unattended publisher content decisions

`publisher-content-gate` verifies a complete Deepr wheel, independently checks
canonical evidence, deletes its private source copy, evaluates wheel semantics,
and decides whether the admitted files satisfy the dashboard and runtime rules.
It preserves the caller's original and creates no installation output.

This is an owner-maintained downstream validation integration. It uses the
published Alpha.17 Rust API through one exact Git revision and the matching
authenticated native release. It is not installed in Deepr's production release
workflow and does not establish independent adoption or crates.io distribution.

## Reproduce on Linux

Use the supported x86_64 Linux worker environment with Landlock ABI 3, Rust
1.98.0, Python 3, GitHub CLI authentication for public attestations, and `strace`.
The acquisition command verifies the immutable release, tag commit, native
archive length and SHA-256, and constrained build provenance before extraction.

```sh
python3 scripts/acquire.py
python3 scripts/acquire_release.py --destination /tmp/sealr-publisher-native
cargo build --locked --release --bin publisher-content-gate
cargo metadata --locked --format-version 1 > target/publisher-metadata.json
python3 scripts/verify_source.py target/publisher-metadata.json
python3 scripts/test_source_contract.py target/publisher-metadata.json
python3 scripts/test_publisher_trace.py
python3 scripts/validate_publisher.py \
  --metadata target/publisher-metadata.json \
  --native /tmp/sealr-publisher-native/sealr-0.1.0-alpha.17-x86_64-unknown-linux-gnu \
  --report results/publisher-report.json
```

The required CI publisher job runs these checks on pushes and pull requests.
Its report and raw traces are preserved as commit-bound artifacts for 30 days.
There is no manual approval step. The complete installer and retention
experiment paths continue to use their existing checked handoff.

## Decision and failure contract

Both no-retention and four-metadata-member retention runs must accept the exact
released Deepr Research 2.50.11 wheel with the same source, tree, artifact, and
plan identities. The decision requires five runtime files, at least one frontend
JavaScript and CSS asset, and absence of the named build debris. The business
function receives only `&VerifiedArchive`.

The executable preserves successful `sealr.deepr-content-gate.v1` JSON and exit
0. Handled failures emit `sealr.deepr-content-gate-failure.v1` JSON and exit 1.
Automation uses `stage`, `code`, and sorted unique `finding_codes`; `detail`
remains diagnostic text. The report records whether the private source was
deleted before evaluation and always reports zero installed files. Missing or
invalid JSON, missing tracing, process failures, or deadline failures fail the
smoke and never imply acceptance.

Ten executable refusals cover worker version, target, and ABI mismatch; verifier
exit 1, unexpected exit 23, and SIGTERM; duplicate arguments; missing source;
malformed archive; and a renamed otherwise valid wheel after verified evidence
and private source deletion. Verifier exit 1 means `verifier-refusal`, which may
include verifier I/O failure. A signal or other nonzero exit means `verifier-exit`.
Neither is silently treated as a content-policy decision.

## Observed source-open boundary

The smoke requires one merged `strace -f` process-tree trace for each accepted
retention choice and the late wheel-semantic refusal. It observes open, openat,
openat2, unlink, unlinkat, process, and directory-change syscalls with FD-path
annotations and a 4,096-byte string limit. No successful-only filter is used.

The analyzer requires source acquisition, exactly one successful canonical
private wheel unlink by the publisher, complete split syscall records, and
normal terminal evidence for every process announced by child creation. Any
wheel-path open attempt after or overlapping deletion fails, including failed,
relative, hidden, escaped, trailing-component, child-process, and observed
proc-fd-alias attempts. Abbreviated paths, ambiguous FD annotations, unknown
relevant records, missing termination, and incomplete traces fail closed.

Each process session has a 60-second deadline, a combined live one MiB stdout
and stderr cap, and an inherited hard four MiB file-write ceiling. The pinned
4,126,292-byte wheel fits within that file limit. This ceiling also bounds the
trace while it is written. Deadline or output failures kill the session's process
groups and wait at most five seconds for the direct child to be reaped. CI adds
a 15-minute outer job deadline. These limits describe this fixed validation
workload and make no durability or general resource guarantee for the library.

`results/publisher-report.json` records the tracer version, release and consumer
pins, phase observations, trace hashes, and refusal results. Raw traces live in
`results/publisher-traces/`. The claim is limited to the observed process tree
and recognizable wheel pathnames or FD annotations. It does not cover unobserved
processes or aliases absent from those observations. Verified snapshot storage
survives private pathname deletion; FD reads from that storage remain allowed.

## Copy and adaptation boundary

`handoff/` stays an exact copy of the four public Alpha.17 handoff files. Source
verification compares each copy and its recorded hash with the actual
Cargo-resolved Git source. It also requires exactly one resolved Sealr feature
node with the release's exact empty feature set, an exact release/source match,
and no local path patch.

`publisher-origin.json` pins the released Alpha.17 example and smoke baselines.
The typed outcome checks and structured reports now use that published input;
source verification requires its commit and hashes to match the resolved release.
The downstream executable changes the stage include path and omits
repository-only tests; its validation adds provenance checks and bounded
source-open observation.
The executable, smoke, and trace analyzer each have an exact checked local hash.
CI verifies this boundary without reading a sibling Sealr checkout.

Offline mutation checks reject missing or duplicate resolve evidence, private,
unknown, or malformed features, source replacement, forged exact-copy provenance, unrecorded publisher
edits, incorrect release baselines, and inconsistent adaptation publication
claims. Trace counterexamples separately exercise
the source-open analyzer and live resource limits.

Historical Alpha.14 installation and retention reports and Alpha.15 publisher
reports remain unchanged. Each new report identifies its exact release and
adapted consumer; phase timings are observations, not controlled performance
comparisons.
The [2026-09-13 local observation](observations/2026-09-13/README.md) preserves
the first complete report and all three source-open traces from this integration.
The [Alpha.16 local observation](observations/2026-09-13-alpha16/README.md) repeats
the complete smoke with the published Alpha.16 source and native pair.
The [Alpha.17 local observation](observations/2026-09-13-alpha17/README.md) records
the same bounded cases with the current published source and native pair.
Earlier observations retain their original inputs and hashes even when retired
upstream release URLs no longer serve those inputs.
