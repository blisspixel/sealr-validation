"""Closed source and native release identity shared by acquisition and builds."""

import json
from pathlib import Path
import re


def load_release():
    release = json.loads((Path(__file__).resolve().parents[1] / "sealr-release.json").read_bytes())
    if set(release) != {"schema", "version", "tag", "commit", "native"} or release["schema"] != "sealr.immutable-release-pin.v1":
        raise RuntimeError("Unknown Sealr release pin schema")
    version = re.fullmatch(r"0\.1\.0-alpha\.([1-9][0-9]*)", release["version"])
    if version is None or int(version[1]) < 14:
        raise RuntimeError("This validation contract requires Alpha.14 or a later alpha preview")
    if not re.fullmatch(r"[0-9a-f]{40}", release["commit"]) or release["tag"] != "v" + release["version"]:
        raise RuntimeError("Release tag and full source commit must be explicit")
    native = release["native"]
    if set(native) != {"filename", "url", "bytes", "sha256"}:
        raise RuntimeError("Unknown native artifact fields")
    expected = f"sealr-{release['version']}-x86_64-unknown-linux-gnu.tar.gz"
    if native["filename"] != expected or native["url"] != f"https://github.com/blisspixel/sealr/releases/download/{release['tag']}/{expected}":
        raise RuntimeError("Native artifact is not the matching supported Linux release")
    return release
