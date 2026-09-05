# Bounded retention experiment

This is a separately instrumented public-API consumer of immutable Sealr
Alpha.14. It compares three working sets on the pinned Deepr, Primr, and Recon
wheels. The four provenance-pinned files in `handoff/` remain unchanged.

The question is whether retaining a small known set during initial verification
avoids enough later member-read work to help a real consumer. An unretained
supervised read authenticates a fresh worker and repeats source and plan
validation. This experiment avoids both costs for selected members, so its times
cannot identify which cost dominates.

## Fixed experiment

| Strategy | Exact requested working set |
|---|---|
| Baseline | No retention request |
| Semantic | Required `METADATA`, `WHEEL`, `RECORD`, and existing `entry_points.txt` |
| Bounded | Semantic paths plus eligible regular members in canonical path order |

Every strategy uses the same wheel bytes, interpretation profile, policy,
authenticated helper, installer, and installation target model. Retention stays
within the existing public 64-path limit, 256 KiB per member, and 1 MiB total.
It is an operation capability and does not broaden archive admission.

The three strategies reuse one private input pathname per wheel, recreating the
input only between completed cases. Canonical views intentionally record that
pathname, and receipts bind the view. Keeping it fixed makes exact evidence
digest comparison meaningful as well as comparing the semantic identities.

[`path-pins.json`](path-pins.json) records exact selected paths, verified sizes
and content hashes, each wheel's source digest, and a digest of its complete
verified regular-member inventory. The inventory command obtains those facts
through `VerifiedArchive`. It does not introduce another ZIP parser. Semantic
members are reserved first; the bounded set then adds fitting regular members
in canonical path order until the path limit or available inventory is reached.
The total byte cap can leave capacity too small for a later large member.

Each of the nine cases:

1. Authenticates the helper and admits the private input through the public
   `apply_supervised` API with the selected `RetentionPlan`.
2. Independently verifies canonical evidence against the source bytes.
3. Deletes the private source pathname before wheel evaluation or member access.
4. Evaluates and stages solely through `VerifiedArchive`, installs using the
   unchanged Python bridge and PyPA installer 1.0.1, and audits all outputs.
5. Compares source, archive-tree, artifact, plan, and realization identities;
   canonical view and receipt digests; and every installed path, content hash,
   size, and executable disposition with that wheel's baseline.

The harness records each requested retention status and byte count. These pins
are expected to fit completely, so an unsuccessful retention request fails the
experiment and remains visible in the consumer's report. Three additional
version, target, and ABI mismatch cases must refuse before source consumption
or installer destination creation.

## Timing and source provenance

[`main.rs`](main.rs) is experimental integration code. It uses the same staging
checks as the copied handoff, with an explicitly derived
[`stage.rs`](stage.rs). The derived module only adds two timing observations and
result fields, and adjusts the relative path to the unchanged Python bridge.
[`prepare_experiment_stage.py`](../../scripts/prepare_experiment_stage.py)
reconstructs the exact derived bytes from the SHA-256-pinned original and rejects
any additional change. The supported copied handoff remains the separate
`sealr-validation` executable.

The report separates admission, canonical evidence verification, wheel
evaluation, member staging, installation, and output auditing. Installation
includes invocation validation, bridge setup, the Python subprocess, and its
clean exit. Output auditing begins afterward and includes report validation,
independent filesystem enumeration, plan checks, and realization derivation.
Total elapsed time also includes input checking and bookkeeping.

One sequential run per case is integration evidence, not a controlled benchmark.
Case order is recorded. Cache warming, scheduler load, storage, kernel, and CPU
can affect comparisons. There is no throughput claim, statistical significance
claim, performance pass threshold, or process-startup attribution.

## Reproduce on supported Linux

Acquire the exact native release and installer using the repository's existing
authenticated acquisition steps. Use trusted native Linux directories for the
installer and temporary input/output roots.

```sh
cargo build --locked --release --bin retention-experiment
python3 scripts/prepare_experiment_stage.py
python3 scripts/verify_retention_pins.py \
  --binary target/release/retention-experiment
python3 scripts/retention_experiment.py \
  --native /tmp/sealr-validation-native/sealr-0.1.0-alpha.14-x86_64-unknown-linux-gnu \
  --installer-root /tmp/sealr-validation-installer
```

The output directory must be new. Each installation has a 600-second deadline;
each refusal has 30 seconds. The harness establishes a Linux child subreaper,
checks that no child survives a case, and terminates/reaps its own descendants
after timeout before temporary-tree cleanup. Internal worker and bridge
deadlines and fail-closed checks remain unchanged.

The manual [Retention experiment workflow](../../.github/workflows/retention-experiment.yml)
runs all nine cases and retains the report and exact baseline output inventories
for 30 days. Ordinary three-platform CI verifies the timing-only derivation and
reproduces the public inventory pins without running the full timing experiment.

## Decision boundary

Use bounded retention when the consumer knows a small set it will read. Do not
increase the public path limit to retain a whole installation. A complete wheel
install still needs hundreds of unretained member reads. A future optimization
of repeated supervisor binding requires a source-owning validated authority and
separate review of mutation, lifetime, clone, cancellation, and failure behavior.
This experiment changes none of those security internals or protocols.

The [observed Linux run](observed-linux-wsl/README.md) completed all nine
installations with exact evidence and output parity, plus the three native
manifest refusals. It preserves the raw phase times and bound output inventories.
