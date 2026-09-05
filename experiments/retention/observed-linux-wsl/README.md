# Observed Linux retention run

All nine complete installations passed on 2026-09-05 with the immutable
Alpha.14 source and authenticated native release pinned in the report. Every
strategy independently verified canonical evidence, deleted its private source
before evaluation and member consumption, and matched its wheel's baseline
source, tree, artifact, plan, realization, and canonical evidence identities.
Every installed path, byte length, content hash, and executable disposition
matched: 834 Deepr outputs, 549 Primr outputs, and 199 Recon outputs per strategy.
The three worker version, target, and ABI mismatches refused without consuming
the input or creating an installer destination. No case left a child process.

These are individual sequential observations from Linux x86_64 under WSL2,
kernel `6.18.33.2-microsoft-standard-WSL2`, Python 3.12.3, and trusted native
Linux storage. They are not controlled benchmark results. The strategy order
was baseline, semantic, then bounded for each wheel. Other validation work was
active on the machine, so cache and scheduler effects are not controlled.

| Wheel | Strategy | Retained files | Retained bytes | Evaluation seconds | Staging seconds | Total seconds |
|---|---|---:|---:|---:|---:|---:|
| Deepr | baseline | 0 | 0 | 1.028 | 209.286 | 225.607 |
| Deepr | semantic | 4 | 91,892 | 0.015 | 209.261 | 224.128 |
| Deepr | bounded | 64 | 647,049 | 0.011 | 198.188 | 215.493 |
| Primr | baseline | 0 | 0 | 0.621 | 79.239 | 86.891 |
| Primr | semantic | 4 | 61,379 | 0.006 | 75.402 | 81.820 |
| Primr | bounded | 64 | 830,387 | 0.007 | 63.774 | 70.096 |
| Recon | baseline | 0 | 0 | 0.142 | 7.129 | 8.246 |
| Recon | semantic | 4 | 39,279 | 0.002 | 7.111 | 8.124 |
| Recon | bounded | 64 | 704,453 | 0.002 | 5.061 | 6.097 |

The [complete report](report.json) also records admission, evidence verification,
installation, and output-audit times, every retention outcome, and the exact
source/native release and working-set pins. The [Deepr](deepr-installed-files.json),
[Primr](primr-installed-files.json), and [Recon](recon-installed-files.json)
output inventories are bound by SHA-256 in every corresponding strategy report.

The useful implementation result is to retain a known semantic working set for
metadata consumers and make content decisions directly from the admitted
capability. Four retained metadata members avoid their later supervised reads.
A complete installation still stages hundreds of other members; increasing a
small retained set to 64 does not remove that work. Preserve the current public
limits and use the complete-install phase data to scope any future private
validated-authority experiment. These observations do not distinguish process
startup from repeated full-source and plan validation within unretained reads.

Reproduce the mechanism with the [experimental consumer and harness](../README.md).
The manual workflow publishes its own fresh report rather than treating these
local elapsed times as a performance threshold.
