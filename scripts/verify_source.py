"""Reject workspace patches, source drift, and private Sealr features."""

import hashlib
import json
from pathlib import Path
import sys
import tomllib

from release_pin import load_release


ROOT = Path(__file__).resolve().parents[1]
metadata = json.loads(Path(sys.argv[1]).read_bytes())
release = load_release()
manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
dependency = manifest["dependencies"]["sealr"]
if manifest.get("patch") or manifest.get("replace") or "path" in dependency:
    raise RuntimeError("Repository path patches are forbidden")
if dependency != {"git": "https://github.com/blisspixel/sealr", "rev": release["commit"], "version": "=" + release["version"]}:
    raise RuntimeError("Source dependency does not match the immutable release")
packages = [p for p in metadata["packages"] if p["name"] == "sealr"]
if len(packages) != 1 or packages[0]["version"] != release["version"]:
    raise RuntimeError("Expected exactly one release-matched public Sealr crate")
package = packages[0]
if package["source"] != f"git+https://github.com/blisspixel/sealr?rev={release['commit']}#{release['commit']}":
    raise RuntimeError("Resolved source does not match the immutable release")
for node in metadata["resolve"]["nodes"]:
    if node["id"] == package["id"] and any(f.startswith("__internal-") for f in node["features"]):
        raise RuntimeError("Private Sealr features are forbidden")
origin = json.loads((ROOT / "handoff-origin.json").read_bytes())
if set(origin) != {"schema", "repository", "commit", "path", "files"} or origin["schema"] != "sealr.copied-public-handoff.v1":
    raise RuntimeError("Unknown copied handoff provenance schema")
if origin["repository"] != "https://github.com/blisspixel/sealr" or origin["path"] != "crates/sealr/examples/pypa_installer_handoff":
    raise RuntimeError("Unexpected copied handoff origin")
if set(origin["files"]) != {"main.rs", "stage.rs", "wheel_source.py", "requirements.txt"}:
    raise RuntimeError("Copied handoff file set changed")
if origin["commit"] != release["commit"]:
    raise RuntimeError("Handoff source is not bound to the release")
for name, digest in origin["files"].items():
    if hashlib.sha256((ROOT / "handoff" / name).read_bytes()).hexdigest() != digest:
        raise RuntimeError(f"Copied public handoff source changed: {name}")
print("Verified immutable public source, copied handoff, and absence of internal features or path patches")
