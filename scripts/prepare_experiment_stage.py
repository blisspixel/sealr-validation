"""Verify or reproduce the explicitly instrumented experimental staging module."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "experiments/retention/stage.rs"


def render():
    origin = json.loads((ROOT / "handoff-origin.json").read_bytes())
    original = (ROOT / "handoff/stage.rs").read_bytes()
    if hashlib.sha256(original).hexdigest() != origin["files"]["stage.rs"]:
        raise RuntimeError("The provenance-pinned staging source changed")
    source = original.decode("utf-8")
    replacements = [
        ('include_bytes!("wheel_source.py")', 'include_bytes!("../../handoff/wheel_source.py")'),
        ("pub struct InstallationResult {\n", "pub struct InstallationResult {\n    pub installation_seconds: f64,\n    pub output_audit_seconds: f64,\n"),
        ('        self.validate_invocation(python, installer_root, output_root)?;\n        let bridge_path = self.ensure_bridge()?;\n        let report_path = self.root.path().join("report.json");', '        let installation_started = Instant::now();\n        self.validate_invocation(python, installer_root, output_root)?;\n        let bridge_path = self.ensure_bridge()?;\n        let report_path = self.root.path().join("report.json");'),
        ("        let report_metadata = fs::symlink_metadata(&report_path)?;", "        let installation_seconds = installation_started.elapsed().as_secs_f64();\n        let output_audit_started = Instant::now();\n        let report_metadata = fs::symlink_metadata(&report_path)?;"),
        ("        Ok(InstallationResult {\n", "        Ok(InstallationResult {\n            installation_seconds,\n            output_audit_seconds: output_audit_started.elapsed().as_secs_f64(),\n"),
    ]
    for old, new in replacements:
        expected_count = 2 if old.startswith("include_bytes!") else 1
        if source.count(old) != expected_count:
            raise RuntimeError(f"Expected {expected_count} instrumentation locations: {old!r}")
        source = source.replace(old, new)
    return (
        "// Experimental timing copy of the provenance-pinned handoff/stage.rs.\n"
        "// Reproduce and verify with scripts/prepare_experiment_stage.py.\n"
        "// Only timing fields, timing observations, and the bridge include path differ.\n"
        + source
    ).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(expected)
    if not TARGET.exists() or TARGET.read_bytes() != expected:
        raise RuntimeError("Experimental stage differs from the exact documented instrumentation")
    print("Verified experimental stage: original checks unchanged; timing observations and bridge path only")


if __name__ == "__main__":
    main()
