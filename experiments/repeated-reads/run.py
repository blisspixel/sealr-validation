"""Run one cached Deepr repeated-read experiment with fixed paired observations."""

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import selectors
import shutil
import signal
import statistics
import subprocess
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
CASE_SECONDS = 60
TOTAL_SECONDS = 300
OUTPUT_LIMIT = 1024 * 1024
FILE_LIMIT = 4 * 1024 * 1024
SEED = 20260913
IDENTITIES = ("source_sha256", "archive_tree_sha256", "artifact_sha256", "install_plan_sha256",
              "canonical_view_sha256", "canonical_receipt_sha256")


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def checked_bytes(path, maximum):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise RuntimeError("Expected bounded regular non-link file: " + str(path))
    with path.open("rb") as source:
        content = source.read(maximum + 1)
    if len(content) > maximum:
        raise RuntimeError("File exceeded its byte limit")
    return content


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def children():
    return [int(pid) for pid in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()]


def reap(deadline):
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
            raise RuntimeError("Descendant reap exceeded the reserved cleanup deadline")
        time.sleep(0.01)


def child_limits():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))


def run_child(command, global_deadline, case_seconds=CASE_SECONDS):
    if children():
        raise RuntimeError("Unexpected existing child before experiment case")
    started = time.monotonic()
    deadline = min(started + case_seconds, global_deadline - 5)
    if started >= deadline:
        raise RuntimeError("Overall experiment deadline exhausted")
    collected = {"stdout": bytearray(), "stderr": bytearray()}
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, preexec_fn=child_limits)
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Experiment case exceeded its deadline")
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    collected[key.data].extend(chunk)
                    if sum(len(value) for value in collected.values()) > OUTPUT_LIMIT:
                        raise RuntimeError("Experiment child exceeded its output limit")
        status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        residue = reap(min(global_deadline, time.monotonic() + 5))
        if residue:
            raise RuntimeError("Experiment case left surviving descendants")
        if status != 0:
            raise RuntimeError(f"Experiment child exited {status}: " + collected["stderr"].decode(errors="replace")[:2000])
        report = json.loads(collected["stdout"])
        if not isinstance(report, dict):
            raise RuntimeError("Experiment child did not return a JSON object")
        return report, time.monotonic() - started
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        reap(min(global_deadline, time.monotonic() + 5))
        raise
    finally:
        child.stdout.close()
        child.stderr.close()


def verify_native(native, release):
    archive_path = native.parent / release["native"]["filename"]
    archive = checked_bytes(archive_path, 8 * 1024 * 1024)
    if len(archive) != release["native"]["bytes"] or sha256(archive) != release["native"]["sha256"]:
        raise RuntimeError("Cached native archive differs from its immutable release pin")
    files = ("sealr-identity-verifier", "libexec/sealr/sealr-worker", "libexec/sealr/sealr-worker.manifest")
    observed = {}
    with tarfile.open(archive_path, "r:gz") as package:
        for name in files:
            path = native / name
            content = checked_bytes(path, 8 * 1024 * 1024)
            member = package.getmember(native.name + "/" + name)
            if not member.isfile() or member.size != len(content):
                raise RuntimeError("Native member is not the expected bounded regular file")
            archived = package.extractfile(member).read(8 * 1024 * 1024 + 1)
            if archived != content:
                raise RuntimeError("Extracted executable differs from the pinned native archive")
            observed[name] = sha256(content)
    return observed


def verify_pins(pins, artifact, historical_pins):
    if pins.get("schema") != "sealr.repeated-read-pins.v1" or pins.get("source_sha256") != artifact["sha256"]:
        raise RuntimeError("Unexpected source-bound read pins")
    if pins.get("source_bytes") != artifact["bytes"] or pins.get("inventory_sha256") != historical_pins["inventory_sha256"]:
        raise RuntimeError("Verified inventory changed from the existing downstream contract")
    paths = pins.get("paths")
    if not isinstance(paths, list) or len(paths) != 8 or len({pin["path"] for pin in paths}) != 8:
        raise RuntimeError("Exactly eight distinct read paths are required")
    if any(type(pin["size"]) is not int or not 0 < pin["size"] <= 256 * 1024 for pin in paths):
        raise RuntimeError("Selected member exceeds the established retention bound")
    if sum(pin["size"] for pin in paths) > 1024 * 1024:
        raise RuntimeError("Selected working set exceeds one MiB")


def schedule(paths):
    result = []
    generator = random.Random(SEED)
    for block in range(7):
        order = [pin["path"] for pin in paths]
        generator.shuffle(order)
        strategies = ("baseline", "retained") if block % 2 == 0 else ("retained", "baseline")
        for position, strategy in enumerate(strategies):
            result.append({"block": block, "warmup": block == 0, "position": position,
                           "strategy": strategy, "member_order": order})
    return result


def verify_case(report, case, pins, artifact, baseline):
    if report.get("schema") != "sealr.repeated-read-case.v1" or report.get("strategy") != case["strategy"]:
        raise RuntimeError("Unexpected read case report")
    for field in ("source_deleted_before_evaluation", "source_deleted_before_member_consumption", "independent_evidence_verified"):
        if report.get(field) is not True:
            raise RuntimeError("Evidence verification and deletion boundary failed")
    if report.get("source_sha256") != artifact["sha256"] or report.get("artifact_sha256") != artifact["expected"]["artifact_sha256"]:
        raise RuntimeError("Pinned source or artifact identity changed")
    if baseline is not None and any(report.get(field) != baseline.get(field) for field in IDENTITIES):
        raise RuntimeError("Source, semantic, or canonical evidence identity changed between cases")
    expected_retained = sum(pin["size"] for pin in pins["paths"]) if case["strategy"] == "retained" else 0
    if report.get("retained_bytes") != expected_retained:
        raise RuntimeError("Working-set retention was not fulfilled exactly")
    reads = report.get("reads")
    if not isinstance(reads, list) or len(reads) != 16:
        raise RuntimeError("Two complete eight-member read passes are required")
    by_path = {pin["path"]: pin for pin in pins["paths"]}
    for index, row in enumerate(reads):
        path = case["member_order"][index % 8]
        pin = by_path[path]
        if (row.get("pass"), row.get("position"), row.get("path")) != (index // 8, index % 8, path):
            raise RuntimeError("Read observations changed the fixed case order")
        if row.get("output_bytes") != pin["size"] or row.get("output_sha256") != pin["sha256"]:
            raise RuntimeError("Read output changed its bound size or digest")
        if row.get("retention_status") != ("Retained" if case["strategy"] == "retained" else "NotRequested"):
            raise RuntimeError("Read retention status differs from the selected strategy")
        for field in ("read_seconds", "digest_check_seconds"):
            value = row.get(field)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise RuntimeError("Read timing is not finite and nonnegative")


def summarize(cases):
    measured = [case for case in cases if not case["schedule"]["warmup"]]
    paired = []
    for block in range(1, 7):
        pair = {case["schedule"]["strategy"]: case for case in measured if case["schedule"]["block"] == block}
        if set(pair) != {"baseline", "retained"}:
            raise RuntimeError("A measured pair is incomplete")
        sums = {strategy: sum(row["read_seconds"] for row in case["report"]["reads"]) for strategy, case in pair.items()}
        paired.append({"block": block, "baseline_read_seconds": sums["baseline"], "retained_read_seconds": sums["retained"],
                       "paired_difference_seconds": sums["baseline"] - sums["retained"]})
    by_member = []
    for path in measured[0]["schedule"]["member_order"]:
        for read_pass in range(2):
            values = {}
            for strategy in ("baseline", "retained"):
                samples = [row["read_seconds"] for case in measured if case["schedule"]["strategy"] == strategy
                           for row in case["report"]["reads"] if row["path"] == path and row["pass"] == read_pass]
                values[strategy] = {"samples": len(samples), "median_seconds": statistics.median(samples),
                                    "minimum_seconds": min(samples), "maximum_seconds": max(samples)}
            by_member.append({"path": path, "pass": read_pass, **values})
    return {"paired_blocks": paired, "member_passes": by_member,
            "median_paired_difference_seconds": statistics.median(row["paired_difference_seconds"] for row in paired)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise RuntimeError("The controlled experiment requires Linux")
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Could not establish the experiment child subreaper")
    args.native, args.binary = args.native.resolve(), args.binary.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "sealr.repeated-read-experiment.v1", "complete": False,
              "observed_at": datetime.now(timezone.utc).isoformat(), "project": "deepr",
              "bounds": {"case_seconds": CASE_SECONDS, "overall_seconds": TOTAL_SECONDS, "child_output_bytes": OUTPUT_LIMIT,
                         "child_file_bytes": FILE_LIMIT, "cleanup_reserve_seconds": 5},
              "design": {"warmup_pairs": 1, "measured_pairs": 6, "passes": 2, "paths": 8, "order_seed": SEED},
              "environment": {"kernel": platform.release(), "machine": platform.machine(), "python": platform.python_version()},
              "nonclaim": "Direct local warm-cache repeated-read observations. Retention avoids multiple costs; these timings do not isolate source hashing, decoding, process startup, or prove a performance guarantee.",
              "cases": []}

    def checkpoint():
        content = encoded(report)
        if len(content) > FILE_LIMIT:
            raise RuntimeError("Experiment report exceeded its four MiB bound")
        (args.output / "report.json").write_bytes(content)

    try:
        release = json.loads(checked_bytes(ROOT / "sealr-release.json", OUTPUT_LIMIT))
        artifact = next(item for item in json.loads(checked_bytes(ROOT / "artifacts.json", OUTPUT_LIMIT))["artifacts"] if item["project"] == "deepr")
        historical = next(item for item in json.loads(checked_bytes(ROOT / "experiments/retention/path-pins.json", OUTPUT_LIMIT))["artifacts"] if item["project"] == "deepr")
        original = ROOT / "artifacts" / artifact["filename"]
        content = checked_bytes(original, 16 * 1024 * 1024)
        if len(content) != artifact["bytes"] or sha256(content) != artifact["sha256"]:
            raise RuntimeError("Cached Deepr wheel differs from its immutable pin")
        report.update(release=release, native_files=verify_native(args.native, release),
                      binary_sha256=sha256(checked_bytes(args.binary, 32 * 1024 * 1024)))
        sources = ("Cargo.toml", "Cargo.lock", "handoff/stage.rs", "experiments/repeated-reads/main.rs", "experiments/repeated-reads/run.py")
        report["consumer_sources"] = {name: sha256(checked_bytes(ROOT / name, OUTPUT_LIMIT)) for name in sources}
        pins, _ = run_child([str(args.binary), "inventory", str(original)], deadline)
        verify_pins(pins, artifact, historical)
        report["pins"] = pins
        cases = schedule(pins["paths"])
        report["schedule"] = cases
        checkpoint()
        with tempfile.TemporaryDirectory(prefix="sealr-repeated-reads-", dir="/tmp") as temporary:
            source = Path(temporary) / artifact["filename"]
            config_path = Path(temporary) / "case.json"
            baseline = None
            for case in cases:
                if source.exists():
                    raise RuntimeError("Previous case left its private source pathname accessible")
                shutil.copyfile(original, source)
                config = {"wheel": str(source), "source_sha256": artifact["sha256"], "source_bytes": artifact["bytes"],
                          "inventory_sha256": pins["inventory_sha256"], "paths": pins["paths"], "order": case["member_order"],
                          "strategy": case["strategy"], "worker_manifest": str(args.native / "libexec/sealr/sealr-worker.manifest"),
                          "verifier": str(args.native / "sealr-identity-verifier")}
                config_path.write_bytes(encoded(config))
                observed, elapsed = run_child([str(args.binary), "run", str(config_path)], deadline)
                verify_case(observed, case, pins, artifact, baseline)
                if source.exists():
                    raise RuntimeError("Case did not remove its private source")
                baseline = baseline or observed
                report["cases"].append({"schedule": case, "elapsed_seconds": elapsed, "report": observed})
                checkpoint()
                print(f"block {case['block']} {case['strategy']}: {sum(row['read_seconds'] for row in observed['reads']):.6f}s reads", flush=True)
        if sha256(checked_bytes(original, 16 * 1024 * 1024)) != artifact["sha256"]:
            raise RuntimeError("The caller's original source changed")
        report["summary"] = summarize(report["cases"])
        report["elapsed_seconds"] = time.monotonic() - started
        if report["elapsed_seconds"] >= TOTAL_SECONDS:
            raise RuntimeError("Overall experiment deadline exhausted")
        report["complete"] = len(report["cases"]) == 14
        checkpoint()
        print(f"Completed bounded repeated-read observations: {args.output}", flush=True)
    except BaseException as error:
        report["error"] = str(error)
        report["elapsed_seconds"] = time.monotonic() - started
        checkpoint()
        raise


if __name__ == "__main__":
    main()
