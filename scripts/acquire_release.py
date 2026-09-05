"""Authenticate a pinned native Sealr release before extraction or execution."""

import argparse
from pathlib import Path
import subprocess
import tarfile

from acquire import acquire
from release_pin import load_release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    release = load_release()
    args.destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    tag = release["tag"]
    commit = release["commit"]
    observed = subprocess.check_output(["gh", "api", f"repos/blisspixel/sealr/commits/{tag}", "--jq", ".sha"], text=True).strip()
    if len(commit) != 40 or observed != commit:
        raise RuntimeError("Release tag commit does not match the source dependency")
    subprocess.run(["gh", "release", "verify", tag, "--repo", "blisspixel/sealr"], check=True)
    archive = args.destination / release["native"]["filename"]
    acquire(release["native"], archive)
    subprocess.run(["gh", "attestation", "verify", str(archive),
                    "--repo", "blisspixel/sealr",
                    "--signer-workflow", "github.com/blisspixel/sealr/.github/workflows/release.yml",
                    "--source-digest", commit, "--source-ref", f"refs/tags/{tag}",
                    "--signer-digest", commit, "--deny-self-hosted-runners"], check=True)
    with tarfile.open(archive, "r:gz") as package:
        package.extractall(args.destination, filter="data")
    print(args.destination / release["native"]["filename"].removesuffix(".tar.gz"))


if __name__ == "__main__":
    main()
