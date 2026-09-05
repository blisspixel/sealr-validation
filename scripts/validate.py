"""Exercise real released wheels through the authenticated Linux handoff."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def run(command, expected_failure=None):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=30 if expected_failure is not None else 600)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise
        if expected_failure is not None:
            if child.returncode == 0 or expected_failure not in stderr:
                raise RuntimeError(f"Expected refusal {expected_failure!r}: {stdout}\n{stderr}")
            return {"refusal": expected_failure}
        if child.returncode:
            raise RuntimeError(f"handoff failed ({child.returncode}):\n{stdout}\n{stderr}")
        return json.loads(stdout.splitlines()[-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--installer-root", required=True, type=Path)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/sealr-validation")
    parser.add_argument("--project", choices=["deepr", "primr", "recon"])
    args = parser.parse_args()
    manifest = json.loads((ROOT / "artifacts.json").read_bytes())
    if args.project:
        manifest["artifacts"] = [item for item in manifest["artifacts"] if item["project"] == args.project]
    reports = []
    negatives = []
    with tempfile.TemporaryDirectory(prefix="sealr-downstream-") as temporary:
        root = Path(temporary)
        for artifact in manifest["artifacts"]:
            original = ROOT / "artifacts" / artifact["filename"]
            content = original.read_bytes()
            if len(content) != artifact["bytes"] or hashlib.sha256(content).hexdigest() != artifact["sha256"]:
                raise RuntimeError(f"Input changed: {artifact['filename']}")
            runs = []
            timings = {}
            for mode in ("inspect", "materialize"):
                case = root / f"{artifact['project']}-{mode}"
                case.mkdir()
                source = case / artifact["filename"]
                shutil.copyfile(original, source)
                command = [str(args.binary), "--consume-wheel", str(source),
                           "--worker-manifest", str(args.native / "libexec/sealr/sealr-worker.manifest"),
                           "--verifier", str(args.native / "sealr-identity-verifier"),
                           "--python", "/usr/bin/python3", "--installer-root", str(args.installer_root),
                           "--output-root", str(case / "installed")]
                if mode == "materialize":
                    command += ["--materialize-raw", str(case / "raw")]
                print(f"Starting {artifact['filename']} via {mode} (600-second deadline)", flush=True)
                started = time.monotonic()
                report = run(command)
                timings[mode] = round(time.monotonic() - started, 3)
                if report["schema"] != "sealr.pypa-wheel-source-example.v1" or report["source_sha256"] != artifact["sha256"]:
                    raise RuntimeError("Report source identity mismatch")
                if source.exists() or report["source_deleted_before_python"] is not True:
                    raise RuntimeError("Source deletion boundary failed")
                if report["raw_materialized"] != (mode == "materialize"):
                    raise RuntimeError("Requested materialization was not honored")
                if report["installed_files"] <= 0:
                    raise RuntimeError("Installation produced no audited files")
                if report["artifact_sha256"] != artifact["expected"]["artifact_sha256"]:
                    raise RuntimeError("Released artifact semantics changed")
                if report["installed_files"] != artifact["expected"]["plan_entries"] + 1:
                    raise RuntimeError("Installed file count differs from the plan plus generated RECORD")
                runs.append(report)
                print(f"Verified {artifact['filename']} via {mode}: {report['installed_files']} audited files", flush=True)
            for field in ["source_sha256", "archive_tree_sha256", "artifact_sha256", "install_plan_sha256", "realization_sha256", "installed_files"]:
                if runs[0][field] != runs[1][field]:
                    raise RuntimeError(f"Inspect/materialize divergence: {artifact['filename']} {field}")
            reports.append({"project": artifact["project"], "filename": artifact["filename"], "inspect": runs[0], "materialize": runs[1], "elapsed_seconds": timings})
        artifact = manifest["artifacts"][0]
        original = ROOT / "artifacts" / artifact["filename"]
        worker_root = args.native / "libexec/sealr"
        for label, field, value, expected in [
            ("worker-version", "release_version", "0.0.0-mismatch", "worker manifest release version does not match"),
            ("worker-target", "target", "aarch64-unknown-linux-musl", "worker manifest does not select the supported x86_64 Linux helper target"),
            ("worker-abi", "bootstrap_abi", 0, "worker manifest bootstrap ABI is unsupported"),
        ]:
            case = root / label
            case.mkdir()
            source = case / artifact["filename"]
            shutil.copyfile(original, source)
            worker_manifest = json.loads((worker_root / "sealr-worker.manifest").read_bytes())
            worker_manifest[field] = value
            mutated = case / "sealr-worker.manifest"
            mutated.write_text(json.dumps(worker_manifest) + "\n", encoding="utf-8")
            command = [str(args.binary), "--consume-wheel", str(source),
                       "--worker-manifest", str(mutated),
                       "--verifier", str(args.native / "sealr-identity-verifier"),
                       "--python", "/usr/bin/python3", "--installer-root", str(args.installer_root),
                       "--output-root", str(case / "installed")]
            run(command, expected_failure=expected)
            if not source.exists() or hashlib.sha256(source.read_bytes()).hexdigest() != artifact["sha256"] or (case / "installed").exists():
                raise RuntimeError(f"Native mismatch affected the source or destination: {label}")
            negatives.append(label)
            print(f"Verified {label} refusal before source consumption or destination effects", flush=True)
    output = ROOT / "results"
    output.mkdir(exist_ok=True)
    (output / "report.json").write_text(json.dumps({"schema": "sealr.downstream-report.v1", "artifacts": reports, "native_mismatch_refusals": negatives}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
