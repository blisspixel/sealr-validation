# Controlled repeated reads

This Deepr-only experiment measures end-to-end `VerifiedArchive::read_member`
calls through the immutable Alpha.15 Linux helper. It uses cached artifacts and
the existing public API. It does not install files or change retention limits,
source validation, the worker protocol, or the supported copied handoff.

The verified inventory selects exactly eight nonempty members: the four semantic
wheel members, two smallest ordinary members, and two largest ordinary members
that individually fit 256 KiB. The complete selected set must fit one MiB. Exact
paths, sizes, content hashes, and the complete inventory digest enter the report.

There is one discarded warmup pair followed by six measured pairs. Each pair
compares no retention with retention of those same eight paths. Measured pairs
alternate which strategy runs first, with three pairs in each order. A fixed
seed varies member order between pairs; both strategies use the same order.
Each case reads the eight members twice from one admitted capability.

Every case verifies canonical evidence independently before deleting its private
source pathname. Wheel evaluation and both read passes then use the capability.
The private source pathname remains the same between completed cases, so exact
canonical evidence digests can be compared. Source, archive-tree, artifact,
installation-plan, and canonical evidence identities must match every case.
Every returned member must match the pinned size and SHA-256. The caller's cached
original remains unchanged. No installation or realization identity is claimed.

Per-read times exclude the separate returned-byte digest check. They include the
actual public read path, with its existing validation, worker setup, streaming,
exit, and reap where applicable. Retention avoids multiple costs. Differences
cannot be attributed specifically to source hashing or codec execution. Six
paired observations support a local comparison, not a significance claim or
latency guarantee. Initial admission, wheel evaluation, and explicit warmup
already exercise the source, so this is a warm-cache experiment.

## Reproduce using cached Linux artifacts

Build outside the measurement window, then leave other builds and tests idle.
Use the native Linux filesystem for the private temporary source; the runner
uses `/tmp`. The source and native archive caches must already be populated by
the repository's authenticated acquisition workflow. The runner makes no network
requests and checks the extracted helper, verifier, and manifest against the
exact cached native archive bytes before executing them.

```sh
cargo build --offline --locked --release --bin repeated-read-probe
python3 -m unittest discover -s experiments/repeated-reads -p 'test_*.py'
python3 experiments/repeated-reads/run.py \
  --binary target/release/repeated-read-probe \
  --native target/alpha15-native/sealr-0.1.0-alpha.15-x86_64-unknown-linux-gnu \
  --output results/repeated-reads-new
```

The output directory must be new. Each child has a 60-second case ceiling within
one 300-second overall budget, with five seconds reserved for descendant cleanup.
The existing five-second Sealr member deadline remains unchanged. Captured child
output is capped at one MiB, child file writes at four MiB, and the checkpointed
report at four MiB. A subreaper rejects surviving descendants and cleans up after
failure. Partial or failed observations remain marked incomplete.

The report preserves the raw two-pass observations for every case, fixed order,
native and consumer hashes, kernel, identity comparisons, and paired summaries.
Historical retention-installation measurements remain in their original folder.

The [first controlled Deepr observation](observed-linux-wsl-2026-09-13/README.md)
completed all 14 cases and records the resulting next measurement question.
