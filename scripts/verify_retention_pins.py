"""Reproduce working-set pins through only the public verified member inventory."""

import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    suffix = ".exe" if os.name == "nt" else ""
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug" / f"retention-experiment{suffix}")
    args = parser.parse_args()
    actual = json.loads(subprocess.check_output([str(args.binary), "inventory", str(ROOT)], timeout=120))
    expected = json.loads((ROOT / "experiments/retention/path-pins.json").read_bytes())
    if actual != expected:
        raise RuntimeError("Public verified inventory no longer reproduces the pinned working sets")
    print("Verified all three exact source-bound retention working sets without a second ZIP parser")


if __name__ == "__main__":
    main()
