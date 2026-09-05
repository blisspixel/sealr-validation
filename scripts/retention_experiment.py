"""Run nine complete installations through the separately instrumented consumer."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
STRATEGIES = ("baseline", "semantic", "bounded")
IDENTITIES = ("source_sha256", "archive_tree_sha256", "artifact_sha256",
              "install_plan_sha256", "realization_sha256")


def children():
    return [int(pid) for pid in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()]


def reap_residue():
    """Terminate and reap only this experiment's adopted descendant processes."""
    deadline = time.monotonic() + 5
    observed = set()
    while True:
        pending = children()
        if not pending:
            return sorted(observed)
        observed.update(pending)
        for pid in pending:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        if time.monotonic() >= deadline:
            raise RuntimeError("Experiment descendant reap exceeded five seconds")
        time.sleep(0.01)


def run_case(binary, config_path, *, expected_failure=None):
    if children():
        raise RuntimeError("Experiment started with an unexpected child process")
    started = time.monotonic()
    timeout = 30 if expected_failure else 600
    with subprocess.Popen([str(binary), "run", str(config_path)], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, start_new_session=True) as child:
        try:
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(child.args, timeout)
                try:
                    stdout, stderr = child.communicate(timeout=min(30, remaining))
                    break
                except subprocess.TimeoutExpired:
                    print(f"  still running after {time.monotonic() - started:.0f}s", flush=True)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=5)
            reap_residue()
            raise
    if reap_residue():
        raise RuntimeError("Consumer left descendants after its exit")
    if expected_failure:
        if child.returncode == 0 or expected_failure not in stderr:
            raise RuntimeError(f"Expected refusal {expected_failure!r}: {stdout}\n{stderr}")
        return {"refusal": expected_failure}
    if child.returncode:
        raise RuntimeError(f"Experimental consumer failed ({child.returncode}):\n{stdout}\n{stderr}")
    report = json.loads(stdout)
    report["elapsed_seconds"] = time.monotonic() - started
    return report


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--installer-root", required=True, type=Path)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/retention-experiment")
    parser.add_argument("--temporary-parent", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "results/retention-experiment")
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise RuntimeError("The experiment requires the authenticated Linux worker")
    # PR_SET_CHILD_SUBREAPER lets this harness verify and clean its own descendants
    # even if a timed-out consumer had given a bridge a separate process group.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "could not establish experiment child subreaper")
    args.output.mkdir(parents=True, exist_ok=False)
    pins_path = ROOT / "experiments/retention/path-pins.json"
    pins = json.loads(pins_path.read_bytes())
    if pins["schema"] != "sealr.retention-path-pins.v1" or (
        pins["max_paths"], pins["max_member_bytes"], pins["max_total_bytes"]
    ) != (64, 256 * 1024, 1024 * 1024):
        raise RuntimeError("Unexpected retention pin contract")
    artifacts = json.loads((ROOT / "artifacts.json").read_bytes())["artifacts"]
    if [pin["project"] for pin in pins["artifacts"]] != [item["project"] for item in artifacts]:
        raise RuntimeError("The exact three pinned projects must be exercised")
    result = {"schema": "sealr.retention-experiment.v1", "complete": False,
              "evidence_class": "single sequential run, not a controlled benchmark",
              "environment": {"system": platform.system(), "release": platform.release(),
                              "machine": platform.machine(), "python": platform.python_version()},
              "release": json.loads((ROOT / "sealr-release.json").read_bytes()),
              "path_pins_sha256": hashlib.sha256(pins_path.read_bytes()).hexdigest(),
              "strategy_order": list(STRATEGIES), "cases": [], "refusals": []}

    def checkpoint():
        (args.output / "report.json").write_bytes(encoded(result))

    checkpoint()
    with tempfile.TemporaryDirectory(prefix="sealr-retention-", dir=args.temporary_parent) as temporary:
        root = Path(temporary)
        print(f"Private experiment root: {root}", flush=True)
        for artifact, pin in zip(artifacts, pins["artifacts"], strict=True):
            if artifact["filename"] != pin["filename"] or artifact["sha256"] != pin["source_sha256"]:
                raise RuntimeError("Artifact and retention pins disagree")
            original = ROOT / "artifacts" / artifact["filename"]
            content = original.read_bytes()
            if len(content) != artifact["bytes"] or hashlib.sha256(content).hexdigest() != artifact["sha256"]:
                raise RuntimeError("The source wheel bytes changed")
            input_root = root / f"{artifact['project']}-input"
            input_root.mkdir()
            source = input_root / artifact["filename"]
            baseline = None
            for strategy in STRATEGIES:
                case = root / f"{artifact['project']}-{strategy}"
                case.mkdir()
                if source.exists():
                    raise RuntimeError("The previous strategy left its private input accessible")
                shutil.copyfile(original, source)
                config = {"wheel": str(source), "source_sha256": artifact["sha256"],
                          "inventory_sha256": pin["inventory_sha256"], "strategy": strategy,
                          "paths": [] if strategy == "baseline" else pin[strategy],
                          "worker_manifest": str(args.native / "libexec/sealr/sealr-worker.manifest"),
                          "verifier": str(args.native / "sealr-identity-verifier"),
                          "installer_root": str(args.installer_root), "output_root": str(case / "installed")}
                config_path = case / "config.json"
                config_path.write_bytes(encoded(config))
                print(f"Starting {artifact['project']} / {strategy}: {len(config['paths'])} retained paths", flush=True)
                report = run_case(args.binary, config_path)
                (args.output / f"{artifact['project']}-{strategy}-case.json").write_bytes(encoded(report))
                if report["schema"] != "sealr.retention-experiment-case.v1" or report["strategy"] != strategy:
                    raise RuntimeError("Unexpected experimental report")
                if source.exists() or not all(report[field] is True for field in (
                    "source_deleted_before_evaluation", "source_deleted_before_member_consumption", "independent_evidence_verified"
                )):
                    raise RuntimeError("Evidence verification and source deletion boundary failed")
                if report["source_sha256"] != artifact["sha256"] or report["artifact_sha256"] != artifact["expected"]["artifact_sha256"]:
                    raise RuntimeError("Source or artifact semantics changed")
                if len(report["installed_files"]) != artifact["expected"]["plan_entries"] + 1:
                    raise RuntimeError("Installed file count differs from the existing handoff")
                if report["requested_paths"] != len(config["paths"]) or report["retained_members"] != len(config["paths"]):
                    raise RuntimeError("A pinned requested member was not retained")
                if report["retained_bytes"] != sum(member["size"] for member in config["paths"]):
                    raise RuntimeError("Retained byte count differs from the pins")
                if baseline is None:
                    baseline = report
                    (args.output / f"{artifact['project']}-installed-files.json").write_bytes(encoded(report["installed_files"]))
                else:
                    for field in (*IDENTITIES, "installed_files", "canonical_view_sha256", "canonical_receipt_sha256"):
                        if report[field] != baseline[field]:
                            raise RuntimeError(f"Retention changed {artifact['project']} {field}")
                print(f"Verified {artifact['project']} / {strategy}: {len(report['installed_files'])} files, "
                      f"{report['retained_bytes']} retained bytes, {report['elapsed_seconds']:.3f}s", flush=True)
                stored = dict(report)
                files = stored.pop("installed_files")
                stored.update({"project": artifact["project"], "filename": artifact["filename"],
                               "installed_file_count": len(files),
                               "installed_files_sha256": hashlib.sha256(encoded(files)).hexdigest()})
                result["cases"].append(stored)
                checkpoint()

        # Exercise the experimental consumer's loader with the same version,
        # target, and ABI refusals as the unchanged copied handoff.
        artifact, pin = artifacts[0], pins["artifacts"][0]
        for label, field, value, expected in [
            ("worker-version", "release_version", "0.0.0-mismatch", "worker manifest release version does not match"),
            ("worker-target", "target", "aarch64-unknown-linux-musl", "worker manifest does not select the supported x86_64 Linux helper target"),
            ("worker-abi", "bootstrap_abi", 0, "worker manifest bootstrap ABI is unsupported"),
        ]:
            case = root / label
            case.mkdir()
            source = case / artifact["filename"]
            shutil.copyfile(ROOT / "artifacts" / artifact["filename"], source)
            manifest = json.loads((args.native / "libexec/sealr/sealr-worker.manifest").read_bytes())
            manifest[field] = value
            mutated = case / "sealr-worker.manifest"
            mutated.write_bytes(encoded(manifest))
            config = {"wheel": str(source), "source_sha256": artifact["sha256"],
                      "inventory_sha256": pin["inventory_sha256"], "strategy": "bounded", "paths": pin["bounded"],
                      "worker_manifest": str(mutated), "verifier": str(args.native / "sealr-identity-verifier"),
                      "installer_root": str(args.installer_root), "output_root": str(case / "installed")}
            config_path = case / "config.json"
            config_path.write_bytes(encoded(config))
            run_case(args.binary, config_path, expected_failure=expected)
            if not source.exists() or hashlib.sha256(source.read_bytes()).hexdigest() != artifact["sha256"] or (case / "installed").exists():
                raise RuntimeError(f"Refusal changed source or destination: {label}")
            result["refusals"].append(label)
            print(f"Verified {label} refusal before source consumption or destination effects", flush=True)
            checkpoint()
    result["complete"] = len(result["cases"]) == 9 and len(result["refusals"]) == 3
    checkpoint()
    print(f"Verified nine installations, exact semantic/output parity, and three refusals: {args.output}", flush=True)


if __name__ == "__main__":
    main()
