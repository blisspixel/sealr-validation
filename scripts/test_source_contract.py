"""Reject missing feature evidence and falsified consumer provenance offline."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    metadata = json.loads(Path(sys.argv[1]).read_bytes())
    package = next(package for package in metadata["packages"] if package["name"] == "sealr")
    with tempfile.TemporaryDirectory(prefix="sealr-source-contract-") as temporary:
        root = Path(temporary)
        for filename in ["Cargo.toml", "sealr-release.json", "handoff-origin.json", "publisher-origin.json"]:
            shutil.copyfile(ROOT / filename, root / filename)
        for directory in ["handoff", "publisher", "scripts"]:
            shutil.copytree(ROOT / directory, root / directory, ignore=shutil.ignore_patterns("__pycache__"))

        def run(candidate, expected=None):
            path = root / "metadata.json"
            path.write_text(json.dumps(candidate), encoding="utf-8")
            result = subprocess.run([sys.executable, str(root / "scripts/verify_source.py"), str(path)],
                                    capture_output=True, text=True, timeout=15)
            if expected is None:
                if result.returncode != 0:
                    raise RuntimeError(f"Valid source contract failed: {result.stderr}")
            elif result.returncode == 0 or expected not in result.stderr:
                raise RuntimeError(f"Missing contract refusal {expected}: {result.stdout}\n{result.stderr}")

        run(metadata)
        for mode in ["missing", "duplicate", "private-feature", "unknown-feature", "malformed-feature-list"]:
            candidate = copy.deepcopy(metadata)
            nodes = candidate["resolve"]["nodes"]
            node = next(node for node in nodes if node["id"] == package["id"])
            if mode == "missing":
                nodes.remove(node)
            elif mode == "duplicate":
                nodes.append(copy.deepcopy(node))
            elif mode == "private-feature":
                node["features"].append("__internal-worker-lab")
            elif mode == "unknown-feature":
                node["features"].append("unrecognized-public-feature")
            else:
                node["features"] = {}
            run(candidate, "exactly one resolved Sealr feature node" if mode in {"missing", "duplicate"} else "exact empty feature set")
        candidate = copy.deepcopy(metadata)
        next(item for item in candidate["packages"] if item["name"] == "sealr")["source"] = None
        run(candidate, "Resolved source does not match")

        handoff = root / "handoff/main.rs"
        original = handoff.read_bytes()
        handoff.write_bytes(original + b"\n// changed copy\n")
        origin = json.loads((root / "handoff-origin.json").read_bytes())
        origin["files"]["main.rs"] = hashlib.sha256(handoff.read_bytes()).hexdigest()
        (root / "handoff-origin.json").write_text(json.dumps(origin), encoding="utf-8")
        run(metadata, "Handoff origin differs from the resolved release")
        handoff.write_bytes(original)
        shutil.copyfile(ROOT / "handoff-origin.json", root / "handoff-origin.json")

        publisher = root / "publisher/main.rs"
        original = publisher.read_bytes()
        publisher.write_bytes(original + b"\n// unrecorded adaptation\n")
        run(metadata, "Adapted publisher source changed")
        publisher.write_bytes(original)
        origin = json.loads((root / "publisher-origin.json").read_bytes())
        origin["released_baseline"]["crates/sealr/examples/deepr_content_gate/main.rs"] = "0" * 64
        (root / "publisher-origin.json").write_text(json.dumps(origin), encoding="utf-8")
        run(metadata, "Publisher baseline differs from the resolved release")
    print("Verified valid source contract and nine missing, forged, or drifted evidence refusals")


if __name__ == "__main__":
    main()
