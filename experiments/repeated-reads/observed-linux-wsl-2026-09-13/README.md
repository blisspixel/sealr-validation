# Deepr repeated-read observation, 2026-09-13

The [complete raw report](report.json) records one controlled local run against
immutable Sealr Alpha.15, commit
`8090a6bb6b0a6cc51461d2bce18966eb1a323434`, and the exact Deepr Research 2.50.11
wheel. The experiment completed in 37.846 seconds within its 300-second budget.
All 14 cases and 224 returned member reads passed their checks.

The eight selected members total 363,559 bytes. They include the four semantic
members, two smallest other members, and two largest eligible members. Each case
read this identical set twice from one admitted capability. Exact paths, sizes,
digests, seeded orders, and every per-read duration remain in the report.

One warmup pair was discarded. Six measured pairs alternated strategy order,
with three baseline-first and three retained-first pairs. Other project builds
and tests were paused for this measurement window. The run used native Linux
temporary storage under `/tmp`, a Linux-built consumer, and the cached,
authenticated released helper. The kernel was
`6.18.33.2-microsoft-standard-WSL2` on x86_64, with Python 3.12.3 and Rust
`1.98.0 (88d9e12ae 2026-08-18)`. OS scheduling and unrelated system activity
were not controlled.

## Observed times

These are medians across the six measured cases for each strategy. Read totals
cover 16 calls and exclude their separately recorded returned-byte digest checks.
Whole-case elapsed time also includes admission, evidence verification,
evaluation, input checks, and bookkeeping.

| Measurement | No retention | Retain selected eight |
|---|---:|---:|
| Six-case median, 16 read calls | 3.685663 s | 0.000056 s |
| Range, 16 read calls | 3.573640 to 4.054945 s | 0.000032 to 0.000077 s |
| Whole-case elapsed median | 4.953719 s | 0.321272 s |
| Admission median | 0.244178 s | 0.243477 s |
| Wheel evaluation median | 0.949688 s | 0.011485 s |
| Separate output-digest checks, median sum | 0.000536 s | 0.000355 s |

All cases independently verified canonical evidence before deleting their
private source pathname. Source, archive-tree, artifact, installation-plan,
canonical-view, and canonical-receipt identities matched across the complete
run. Every selected member had the same output size and SHA-256 on both passes.
Retention was fulfilled exactly, the caller's cached wheel remained unchanged,
and no case left surviving child processes. This experiment did not install
files or measure a realization identity.

The six-byte `top_level.txt` member had a 0.228400-second median unretained read,
while the 138,704-byte `deepr/web/app.py` member had a 0.231793-second median
across their twelve measured reads each. This makes the repeated per-call work
worth measuring directly. It does not establish which part dominates.

## What follows from this result

Use the existing bounded retention API for a consumer that repeatedly needs
this small known working set. The experiment required no larger limit, worker
pool, or weaker source check. These measurements do not describe full-wheel
installation or a cold-cache workload, and the small retained-read times exclude
the initial verification that populated retention.

The next implementation increment should separately measure source hashing,
plan validation, worker setup, and payload verification on the unretained path.
Retention bypasses several of these costs together, so attributing the observed
difference entirely to hashing or decompression would be unsupported. Keep that
diagnostic work separate from this released-helper observation and preserve all
verification and cleanup behavior.

## Reproduction and integrity

See the [fixed protocol and bounded reproduction commands](../README.md).
Build and validate before opening a measurement window, use the exact cached
release, and select a new output directory. The report contains the source and
native archive pins, extracted helper/verifier/manifest hashes, consumer source
hashes, and consumer binary hash. No network acquisition, paid service, or
workflow dispatch was used during this run.

Report SHA-256:
`3b823bbc6e2a1d60f4fc3f97647b53951ed03a21e91573fb6494380a49a5b70f`.

Validation before measurement passed the release build, release Clippy with
warnings denied, formatting, and nine offline/Linux contract and process-bound
tests. The tests include output exhaustion, deadline cleanup of descendants,
identity changes, read-order changes, and invalid timing values.
