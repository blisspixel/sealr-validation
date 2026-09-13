"""Bind released publisher baselines and explicitly adapted downstream files."""

import hashlib
import json
import re


BASELINES = {"crates/sealr/examples/deepr_content_gate/main.rs", "scripts/verify_deepr_content_gate.py"}
ADAPTED = {"publisher/main.rs", "scripts/validate_publisher.py", "scripts/publisher_trace.py"}


def verify_publisher(root, upstream, release):
    publisher = json.loads((root / "publisher-origin.json").read_bytes())
    fields = {"schema", "repository", "release_commit", "released_baseline", "adaptation_input", "changes", "adapted_files"}
    if set(publisher) != fields or publisher["schema"] != "sealr.adapted-public-publisher.v1":
        raise RuntimeError("Unknown adapted publisher provenance schema")
    if publisher["repository"] != "https://github.com/blisspixel/sealr" or publisher["release_commit"] != release["commit"]:
        raise RuntimeError("Publisher baseline does not match the resolved release")
    if set(publisher["released_baseline"]) != BASELINES or set(publisher["adapted_files"]) != ADAPTED:
        raise RuntimeError("Publisher provenance file set changed")
    for name, expected in publisher["released_baseline"].items():
        if hashlib.sha256((upstream / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Publisher baseline differs from the resolved release: {name}")
    adaptation = publisher["adaptation_input"]
    if set(adaptation) != {"commit", "publication", "files"} or adaptation["publication"] != "unreleased" or not re.fullmatch(r"[0-9a-f]{40}", adaptation["commit"]) or set(adaptation["files"]) != BASELINES:
        raise RuntimeError("Publisher adaptation must name its unreleased input separately")
    for expected in adaptation["files"].values():
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RuntimeError("Publisher adaptation input hashes must be exact")
    if not publisher["changes"] or not all(isinstance(change, str) and change for change in publisher["changes"]):
        raise RuntimeError("Publisher adaptation changes must be explicit")
    for name, expected in publisher["adapted_files"].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Adapted publisher source changed: {name}")
    if '#[path = "../handoff/stage.rs"]' not in (root / "publisher/main.rs").read_text(encoding="utf-8"):
        raise RuntimeError("Publisher must use the provenance-checked public handoff helpers")
