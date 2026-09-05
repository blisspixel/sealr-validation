"""Acquire only the exact, bounded, digest-pinned validation artifacts."""

import hashlib
import json
from pathlib import Path
import re
import urllib.request
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]


def acquire(artifact, destination):
    size = artifact["bytes"]
    url = urlparse(artifact["url"])
    if type(size) is not int or not 0 < size <= 128 * 1024 * 1024:
        raise RuntimeError("Artifact byte cap must be positive and at most 128 MiB")
    if not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]):
        raise RuntimeError("Artifact digest must be an exact lowercase SHA-256")
    if url.scheme != "https" or url.netloc not in {"github.com", "files.pythonhosted.org"}:
        raise RuntimeError("Artifact origin must be an allowlisted HTTPS release host")
    if destination.exists():
        with destination.open("rb") as cached:
            content = cached.read(size + 1)
    else:
        with urllib.request.urlopen(artifact["url"], timeout=60) as response:
            content = response.read(size + 1)
    if len(content) != artifact["bytes"] or hashlib.sha256(content).hexdigest() != artifact["sha256"]:
        raise RuntimeError(f"Artifact integrity mismatch: {artifact['filename']}")
    if not destination.exists():
        with destination.open("xb") as output:
            output.write(content)
    print(f"Verified {artifact['filename']}", flush=True)


def main():
    manifest = json.loads((ROOT / "artifacts.json").read_bytes())
    if manifest["schema"] != "sealr.downstream-artifacts.v1":
        raise RuntimeError("Unknown acquisition manifest")
    destination = ROOT / "artifacts"
    destination.mkdir(exist_ok=True)
    for artifact in manifest["artifacts"]:
        if Path(artifact["filename"]).name != artifact["filename"]:
            raise RuntimeError("Artifact name must be a single path component")
        acquire(artifact, destination / artifact["filename"])


if __name__ == "__main__":
    main()
