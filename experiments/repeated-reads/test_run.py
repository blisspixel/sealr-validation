"""Offline contract and Linux process-bound tests for repeated-read observations."""

import copy
import ctypes
import importlib.util
import math
from pathlib import Path
import platform
import sys
import time
import unittest


SPEC = importlib.util.spec_from_file_location("read_probe_run", Path(__file__).with_name("run.py"))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


def fixture():
    pins = {"paths": [{"path": f"member-{index}.txt", "size": index + 1, "sha256": "a" * 64} for index in range(8)]}
    artifact = {"sha256": "b" * 64, "expected": {"artifact_sha256": "c" * 64}}
    case = RUN.schedule(pins["paths"])[0]
    by_path = {pin["path"]: pin for pin in pins["paths"]}
    report = {field: "d" * 64 for field in RUN.IDENTITIES}
    report.update(schema="sealr.repeated-read-case.v1", strategy="baseline", retained_bytes=0,
                  source_sha256=artifact["sha256"], artifact_sha256=artifact["expected"]["artifact_sha256"],
                  source_deleted_before_evaluation=True, source_deleted_before_member_consumption=True,
                  independent_evidence_verified=True)
    report["reads"] = [{"pass": index // 8, "position": index % 8, "path": path,
                        "output_bytes": by_path[path]["size"], "output_sha256": by_path[path]["sha256"],
                        "retention_status": "NotRequested", "read_seconds": 0.1, "digest_check_seconds": 0.01}
                       for index, path in enumerate(case["member_order"] * 2)]
    return pins, artifact, case, report


class ContractTests(unittest.TestCase):
    def test_schedule_has_discarded_warmup_and_six_balanced_pairs(self):
        pins, _, _, _ = fixture()
        scheduled = RUN.schedule(pins["paths"])
        self.assertEqual(scheduled, RUN.schedule(pins["paths"]))
        self.assertEqual(len(scheduled), 14)
        self.assertEqual(sum(case["warmup"] for case in scheduled), 2)
        firsts = [case["strategy"] for case in scheduled if not case["warmup"] and case["position"] == 0]
        self.assertEqual(firsts.count("baseline"), 3)
        self.assertEqual(firsts.count("retained"), 3)
        for index in range(0, 14, 2):
            self.assertEqual(scheduled[index]["member_order"], scheduled[index + 1]["member_order"])

    def test_valid_case_preserves_bound_outputs(self):
        pins, artifact, case, report = fixture()
        RUN.verify_case(report, case, pins, artifact, None)

    def test_identity_output_order_and_retention_drift_are_rejected(self):
        mutations = (lambda report: report.update(archive_tree_sha256="e" * 64),
                     lambda report: report["reads"][0].update(output_sha256="e" * 64),
                     lambda report: report["reads"][0].update(output_bytes=999),
                     lambda report: report["reads"][0].update(position=7),
                     lambda report: report["reads"][0].update(retention_status="Retained"),
                     lambda report: report.update(independent_evidence_verified=False),
                     lambda report: report["reads"].pop())
        for mutation in mutations:
            pins, artifact, case, report = fixture()
            baseline = copy.deepcopy(report)
            mutation(report)
            with self.assertRaises(RuntimeError):
                RUN.verify_case(report, case, pins, artifact, baseline)

    def test_nonfinite_or_negative_timings_are_rejected(self):
        for value in (math.nan, math.inf, -1, True, None):
            pins, artifact, case, report = fixture()
            report["reads"][0]["read_seconds"] = value
            with self.assertRaises(RuntimeError):
                RUN.verify_case(report, case, pins, artifact, None)

    def test_incomplete_pairs_do_not_produce_a_summary(self):
        with self.assertRaises(RuntimeError):
            RUN.summarize([])


@unittest.skipUnless(platform.system() == "Linux", "Linux child supervision")
class ProcessBoundsTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0), 0)

    def run_python(self, code, seconds=3):
        return RUN.run_child([sys.executable, "-c", code], time.monotonic() + 10, case_seconds=seconds)

    def test_valid_child_is_reaped(self):
        report, _ = self.run_python("print('{\"ok\":true}')")
        self.assertEqual(report, {"ok": True})
        self.assertEqual(RUN.children(), [])

    def test_output_limit_terminates_and_reaps(self):
        with self.assertRaisesRegex(RuntimeError, "output limit"):
            self.run_python("import os; os.write(1,b'x'*(2*1024*1024))")
        self.assertEqual(RUN.children(), [])

    def test_deadline_terminates_descendants(self):
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            self.run_python("import os,time; os.fork(); time.sleep(10)", seconds=0.1)
        self.assertEqual(RUN.children(), [])

    def test_global_budget_preserves_cleanup_reserve(self):
        with self.assertRaisesRegex(RuntimeError, "Overall experiment deadline"):
            RUN.run_child([sys.executable, "-c", "print('{}')"], time.monotonic() + 4)
        self.assertEqual(RUN.children(), [])


if __name__ == "__main__":
    unittest.main()
