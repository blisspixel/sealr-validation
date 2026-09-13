"""Run the adapted downstream publisher through pinned artifacts and source-open traces."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

from publisher_trace import TRACE_LIMIT, analyze_trace
from release_pin import load_release

if sys.platform == "linux":
    import resource


ROOT = Path(__file__).resolve().parents[1]

FILENAME = "deepr_research-2.50.11-py3-none-any.whl"
SOURCE_BYTES = 4_126_292
SOURCE_URL = f"https://github.com/blisspixel/deepr/releases/download/v2.50.11/{FILENAME}"
IDENTITIES = {
    "source_sha256": "149377d4db9fa2a074dd213d155afd5cb1c0e145cbed2c80beff6f25a692f0a1",
    "archive_tree_sha256": "7c201d810c3144d53e9fca7b92c145810ef3f4dd159872569ef22053aad4bc6d",
    "artifact_sha256": "1b7e4dab651e034f53653d09ff3180ce26c13683dfc93c9582f40e91c2a6dc80",
    "install_plan_sha256": "545f556f42408b5497fb9c626231660fea925faa6ab236d858bb1c2743eed671",
}
SEMANTIC_PATHS = sorted(
    f"deepr_research-2.50.11.dist-info/{name}"
    for name in ("METADATA", "WHEEL", "RECORD", "entry_points.txt")
)
PHASES = (
    "admission_seconds",
    "evidence_seconds",
    "evaluation_seconds",
    "content_gate_seconds",
)
DEADLINE_SECONDS = 60
OUTPUT_LIMIT = 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def bounded_read(path, limit):
    require(path.is_file() and not path.is_symlink(), f"Expected regular file: {path}")
    with path.open("rb") as source:
        content = source.read(limit + 1)
    require(len(content) <= limit, f"File exceeds its {limit}-byte bound: {path}")
    return content


def check_wheel_bytes(content):
    require(len(content) == SOURCE_BYTES, "Released wheel byte length changed")
    require(
        hashlib.sha256(content).hexdigest() == IDENTITIES["source_sha256"],
        "Released wheel SHA-256 changed",
    )


def acquire(cache):
    if cache is not None:
        content = bounded_read(cache, SOURCE_BYTES)
    else:
        request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "sealr-content-gate-ci"})
        with urllib.request.urlopen(request, timeout=30) as response:
            resolved = urllib.parse.urlsplit(response.url)
            require(
                resolved.scheme == "https"
                and resolved.hostname in {
                    "github.com",
                    "release-assets.githubusercontent.com",
                    "objects.githubusercontent.com",
                },
                "Wheel download redirected outside the allowed HTTPS release hosts",
            )
            content = response.read(SOURCE_BYTES + 1)
    check_wheel_bytes(content)
    return content


def kill_session_groups(session):
    # The example gives its verifier a separate process group in this same session.
    # Include that group when the outer deadline aborts the example.
    groups = {session}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text(encoding="utf-8", errors="replace").rsplit(")", 1)[1].split()
            if int(fields[3]) == session:
                groups.add(int(fields[2]))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    for group in groups:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass


def child_file_limit():
    # The fixed 4,126,292-byte wheel fits below this ceiling. The same hard
    # limit bounds strace output and files written by every inherited child.
    resource.setrlimit(resource.RLIMIT_FSIZE, (TRACE_LIMIT, TRACE_LIMIT))


def run(command, case, tracer=None):
    if tracer is not None:
        command = [str(tracer), "-f", "-q", "-s", "4096", "-yy", "-e",
                   "trace=open,openat,openat2,unlink,unlinkat,process,chdir,fchdir",
                   "-o", str(case / "source-opens.strace"), "--", *command]
    with subprocess.Popen(
        command,
        cwd=case,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=child_file_limit,
    ) as child:
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + DEADLINE_SECONDS
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, "stdout")
                selector.register(child.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, DEADLINE_SECONDS)
                    for key, _ in selector.select(min(remaining, 0.5)):
                        total = sum(len(value) for value in captured.values())
                        chunk = os.read(key.fd, min(65536, OUTPUT_LIMIT + 1 - total))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        captured[key.data].extend(chunk)
                        require(sum(len(value) for value in captured.values()) <= OUTPUT_LIMIT,
                                "Content-gate output exceeded one MiB during capture")
            child.wait(timeout=max(0.001, deadline - time.monotonic()))
        except (subprocess.TimeoutExpired, KeyboardInterrupt, RuntimeError, OSError):
            kill_session_groups(child.pid)
            child.kill()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("Content-gate deadline cleanup did not complete within five seconds") from error
            raise
    return child.returncode, captured["stdout"].decode("utf-8"), captured["stderr"].decode("utf-8")


def verify_trace(case, label, source, code, trace_directory):
    content = bounded_read(case / "source-opens.strace", TRACE_LIMIT)
    trace_directory.mkdir(parents=True, exist_ok=True)
    filename = f"{label}.strace"
    (trace_directory / filename).write_bytes(content)
    report = analyze_trace(content, source, code)
    report["artifact"] = f"publisher-traces/{filename}"
    return report


def verifier_wrapper(case, verifier, failure=None):
    wrapper = case / "verify-evidence"
    marker = case / "evidence-verified"
    if failure == "refusal":
        script = "#!/bin/sh\nexit 1\n"
    elif failure == "unexpected-exit":
        script = "#!/bin/sh\nexit 23\n"
    elif failure == "signal":
        script = '#!/bin/sh\nkill -TERM "$$"\n'
    else:
        require(failure is None, "Unknown verifier failure fixture")
        script = (
            "#!/bin/sh\nset -eu\n"
            f"{shlex.quote(str(verifier))} \"$@\"\n"
            f"printf 'verified\\n' >> {shlex.quote(str(marker))}\n"
        )
    wrapper.write_text(script, encoding="utf-8", newline="\n")
    wrapper.chmod(0o500)
    return wrapper, marker


def command(example, source, manifest, verifier, retention=()):
    result = [
        str(example), "--wheel", str(source),
        "--worker-manifest", str(manifest), "--verifier", str(verifier),
    ]
    for path in retention:
        result += ["--retain-member", path]
    return result


def check_report(report, retained):
    fields = {
        "schema", "accepted", "private_source_deleted_before_evaluation", "installed_files",
        "canonical_view_sha256", "canonical_receipt_sha256", "content", "retention",
        "retained_bytes", *IDENTITIES, *PHASES,
    }
    require(isinstance(report, dict) and set(report) == fields, "Content-gate report fields changed")
    require(report["schema"] == "sealr.deepr-content-gate.v1", "Content-gate report schema changed")
    require(report["accepted"] is True, "Content decision was not accepted")
    require(
        report["private_source_deleted_before_evaluation"] is True,
        "Private source was not deleted before evaluation",
    )
    require(type(report["installed_files"]) is int and report["installed_files"] == 0,
            "The content gate reported installed files")
    for field, expected in IDENTITIES.items():
        require(report[field] == expected, f"Released wheel identity changed: {field}")
    require(report["content"] == {
        "required_files": 5, "javascript_files": 51, "css_files": 1,
    }, "Released Deepr content decision changed")
    expected_retention = [{"path": path, "status": "Retained"} for path in SEMANTIC_PATHS] if retained else []
    require(report["retention"] == expected_retention, "Requested retention was not fulfilled exactly")
    require(type(report["retained_bytes"]) is int and report["retained_bytes"] == (91_892 if retained else 0),
            "Retained byte count changed")
    for field in ("canonical_view_sha256", "canonical_receipt_sha256"):
        require(isinstance(report[field], str) and re.fullmatch(r"[0-9a-f]{64}", report[field]),
                f"Invalid canonical evidence digest: {field}")
    for field in PHASES:
        value = report[field]
        require(type(value) in (int, float) and math.isfinite(value) and value > 0,
                f"Expected positive finite phase timing: {field}")


def accepted_case(root, label, example, manifest, verifier, content, retained, tracer, trace_directory):
    case = root / label
    case.mkdir()
    source = case / FILENAME
    source.write_bytes(content)
    wrapper, marker = verifier_wrapper(case, verifier)
    code, stdout, stderr = run(
        command(example, source, manifest, wrapper, SEMANTIC_PATHS if retained else ()), case, tracer,
    )
    require(code == 0, f"{label} failed ({code}):\n{stdout}\n{stderr}")
    report = json.loads(stdout)
    check_report(report, retained)
    require(bounded_read(marker, 32) == b"verified\n", "Independent verifier did not succeed exactly once")
    check_wheel_bytes(bounded_read(source, SOURCE_BYTES))
    trace = verify_trace(case, label, source, code, trace_directory)
    require(set(case.iterdir()) == {source, wrapper, marker, case / "source-opens.strace"},
            f"{label} wrote unexpected caller-visible files")
    print(f"Verified {label}: 5 required files, 51 JavaScript, 1 CSS, no installation", flush=True)
    return {
        "example_report": report,
        "independent_verifier_successes": 1,
        "caller_source_preserved": True,
        "source_open_trace": trace,
    }


def check_failure_report(report, stage, code, source_deleted=False):
    fields = {
        "schema", "accepted", "stage", "code", "detail", "finding_codes",
        "private_source_deleted_before_evaluation", "installed_files",
    }
    require(isinstance(report, dict) and set(report) == fields, "Failure report fields changed")
    require(report["schema"] == "sealr.deepr-content-gate-failure.v1", "Failure report schema changed")
    require(report["accepted"] is False, "Refusal reported acceptance")
    require(report["stage"] == stage and report["code"] == code,
            f"Expected {stage}/{code}, received {report['stage']}/{report['code']}")
    require(isinstance(report["detail"], str) and report["detail"], "Failure diagnostic is absent")
    findings = report["finding_codes"]
    require(isinstance(findings, list) and all(isinstance(item, str) and item for item in findings)
            and findings == sorted(set(findings)), "Finding codes must be sorted unique strings")
    require(report["private_source_deleted_before_evaluation"] is source_deleted,
            "Refusal reported an incorrect source-removal boundary")
    require(type(report["installed_files"]) is int and report["installed_files"] == 0,
            "Refusal reported installation output")


def refused_case(root, label, example, manifest, verifier, content, expected_stage, expected_code,
                 failure_verifier=None, duplicate_wheel=False, missing_source=False,
                 wheel_filename=FILENAME, evidence_verified=False, expected_findings=None,
                 tracer=None, trace_directory=None):
    case = root / label
    case.mkdir()
    source = case / wheel_filename
    source.write_bytes(content)
    wrapper, marker = verifier_wrapper(case, verifier, failure=failure_verifier)
    arguments = command(example, case / "missing.whl" if missing_source else source, manifest, wrapper)
    if duplicate_wheel:
        arguments += ["--wheel", str(source)]
    code, stdout, stderr = run(arguments, case, tracer)
    require(code == 1, f"Expected {label} refusal exit 1, received {code}:\n{stdout}\n{stderr}")
    report = json.loads(stdout)
    check_failure_report(report, expected_stage, expected_code, source_deleted=evidence_verified)
    if expected_findings is not None:
        require(report["finding_codes"] == expected_findings, f"{label} finding codes changed")
    require(bool(stderr.strip()), f"{label} omitted its human-readable diagnostic")
    expected_files = {source, wrapper}
    if evidence_verified:
        require(bounded_read(marker, 32) == b"verified\n", "Independent verifier did not succeed exactly once")
        expected_files.add(marker)
    else:
        require(not marker.exists(), f"{label} unexpectedly verified evidence")
    trace = None
    if tracer is not None:
        trace = verify_trace(case, label, source, code, trace_directory)
        expected_files.add(case / "source-opens.strace")
    require(bounded_read(source, SOURCE_BYTES) == content, f"{label} changed the caller source")
    require(set(case.iterdir()) == expected_files, f"{label} wrote unexpected caller-visible files")
    print(f"Verified {label}: refusal, caller source preserved, no installation", flush=True)
    return {"case": label, "failure_report": report, "caller_source_preserved": True,
            "independent_verifier_successes": int(evidence_verified), "source_open_trace": trace}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", type=Path, default=ROOT / "target/release/publisher-content-gate")
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path, help="Complete cargo metadata --locked output")
    parser.add_argument("--wheel-cache", type=Path, default=ROOT / "artifacts" / FILENAME,
                        help="Existing exact wheel file; never modified")
    parser.add_argument("--report", type=Path, default=ROOT / "results/publisher-report.json")
    parser.add_argument("--strace", type=Path, default=shutil.which("strace"))
    args = parser.parse_args()
    require(sys.platform == "linux", "This smoke test requires the supported Linux worker environment")
    require(args.strace is not None, "strace is required; source-open observation has no fallback")
    tracer = args.strace.resolve(strict=True)
    tracer_version = subprocess.check_output([str(tracer), "--version"], text=True, timeout=10).splitlines()[0]
    subprocess.run([sys.executable, str(ROOT / "scripts/verify_source.py"), str(args.metadata)], check=True)
    release = load_release()
    artifacts = json.loads((ROOT / "artifacts.json").read_bytes())["artifacts"]
    artifacts = [artifact for artifact in artifacts if artifact["filename"] == FILENAME]
    require(len(artifacts) == 1 and artifacts[0]["bytes"] == SOURCE_BYTES
            and artifacts[0]["sha256"] == IDENTITIES["source_sha256"]
            and artifacts[0]["url"] == SOURCE_URL, "Publisher wheel pins differ from downstream acquisition")
    trace_directory = args.report.parent / "publisher-traces"
    example = args.example.resolve(strict=True)
    native = args.native.resolve(strict=True)
    manifest = native / "libexec/sealr/sealr-worker.manifest"
    verifier = native / "sealr-identity-verifier"
    manifest_bytes = bounded_read(manifest, 16 * 1024)
    native_manifest = json.loads(manifest_bytes)
    require(native_manifest["schema"] == "sealr.worker-artifact.v1", "Unexpected native manifest schema")
    require(native_manifest["release_version"] == release["version"], "Native release differs from immutable source pin")
    worker_bytes = bounded_read(manifest.parent / "sealr-worker", 32 * 1024 * 1024)
    require(len(worker_bytes) == native_manifest["byte_len"], "Packaged worker byte length changed")
    require(hashlib.sha256(worker_bytes).hexdigest() == native_manifest["sha256"],
            "Packaged worker SHA-256 changed")
    content = acquire(args.wheel_cache)
    with tempfile.TemporaryDirectory(prefix="sealr-deepr-content-gate-") as temporary:
        root = Path(temporary)
        accepted = {
            "baseline": accepted_case(root, "baseline", example, manifest, verifier, content, False, tracer, trace_directory),
            "semantic-retention": accepted_case(root, "semantic-retention", example, manifest, verifier, content, True, tracer, trace_directory),
        }
        # Canonical evidence includes distinct private paths. Each pair is independently
        # verified above; equality is required only for the four semantic identities.
        for field in IDENTITIES:
            require(accepted["baseline"]["example_report"][field]
                    == accepted["semantic-retention"]["example_report"][field],
                    f"Retention changed {field}")
        refused = []
        for label, field, value in [
            ("worker-version", "release_version", "0.0.0-mismatch"),
            ("worker-target", "target", "aarch64-unknown-linux-musl"),
            ("worker-abi", "bootstrap_abi", 0),
        ]:
            worker_root = root / f"{label}-native"
            worker_root.mkdir()
            copied_worker = worker_root / "sealr-worker"
            copied_worker.write_bytes(worker_bytes)
            copied_worker.chmod(0o500)
            mutated = dict(native_manifest)
            mutated[field] = value
            mutated_manifest = worker_root / "sealr-worker.manifest"
            mutated_manifest.write_text(json.dumps(mutated) + "\n", encoding="utf-8")
            refused.append(refused_case(root, label, example, mutated_manifest, verifier, content,
                                        "setup", "worker-artifact"))
        for failure, expected in [("refusal", "verifier-refusal"),
                                  ("unexpected-exit", "verifier-exit"),
                                  ("signal", "verifier-exit")]:
            refused.append(refused_case(
                root, f"verifier-{failure}", example, manifest, verifier, content,
                "evidence", expected, failure_verifier=failure,
            ))
        refused.append(refused_case(
            root, "duplicate-argument", example, manifest, verifier, content,
            "setup", "invalid-arguments", duplicate_wheel=True,
        ))
        refused.append(refused_case(
            root, "missing-source", example, manifest, verifier, content,
            "acquisition", "source-copy", missing_source=True,
        ))
        refused.append(refused_case(
            root, "malformed-archive", example, manifest, verifier, content[:64],
            "admission", "archive-not-admitted",
        ))
        refused.append(refused_case(
            root, "wheel-filename-disagreement", example, manifest, verifier, content,
            "wheel-evaluation", "wheel-denied", wheel_filename="other-2.50.11-py3-none-any.whl",
            evidence_verified=True, expected_findings=["wheel.artifact-root-disagreement"],
            tracer=tracer, trace_directory=trace_directory,
        ))
    require(bounded_read(manifest, 16 * 1024) == manifest_bytes, "Native package manifest was modified")
    if args.wheel_cache is not None:
        check_wheel_bytes(bounded_read(args.wheel_cache, SOURCE_BYTES))
    report = {
        "schema": "sealr.downstream-publisher-report.v1",
        "release": release,
        "publisher_origin": json.loads((ROOT / "publisher-origin.json").read_bytes()),
        "tracer_version": tracer_version,
        "source": {"filename": FILENAME, "url": SOURCE_URL, "bytes": SOURCE_BYTES, **IDENTITIES},
        "native_release_version": native_manifest["release_version"],
        "accepted": accepted,
        "refused": refused,
        "timing_claim": "Observed phase timings only; no performance threshold or speedup claim.",
    }
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Verified two capability-only acceptance runs and {len(refused)} structured fail-closed refusals",
          flush=True)


if __name__ == "__main__":
    main()
