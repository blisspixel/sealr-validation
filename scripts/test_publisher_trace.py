"""Offline counterexamples for the bounded publisher source-open trace proof."""

import unittest
import sys
import tempfile
from pathlib import Path

from publisher_trace import analyze_trace


CALLER = "/input/demo.whl"
PREFIX = '10 execve("/publisher", ["/publisher"], 0x123 /* 1 var */) = 0\n10 openat(AT_FDCWD, "/input/demo.whl", O_RDONLY) = 3</input/demo.whl>\n10 openat(AT_FDCWD, "/private/demo.whl", O_RDONLY) = 4</private/demo.whl>\n'
DELETE = '10 unlink("/private/demo.whl") = 0\n'
END = '10 exit_group(0) = ?\n10 +++ exited with 0 +++\n'


class TraceTests(unittest.TestCase):
    def accepted(self, text):
        return analyze_trace(text.encode(), CALLER, 0)

    def rejected(self, text):
        with self.assertRaises((RuntimeError, UnicodeError, ValueError)):
            self.accepted(text)

    def test_complete_no_reopen_trace(self):
        report = self.accepted(PREFIX + DELETE + END)
        self.assertEqual(report["wheel_opens_before_deletion"], 2)
        self.assertEqual(report["wheel_open_attempts_after_deletion"], 0)
        self.accepted(PREFIX + '10 unlinkat(-1, NULL, 0) = -1 EPERM (denied)\n' + DELETE + END)
        self.rejected(PREFIX + '10 unlinkat(-1, NULL, 0) = 0\n' + DELETE + END)

    def test_failed_hidden_relative_escaped_and_fd_alias_reopens(self):
        for operation in [
            'open("/private/demo.whl", O_RDONLY) = -1 ENOENT (missing)',
            'openat(5</private>, ".hidden.whl", O_RDONLY) = -1 ENOENT (missing)',
            r'openat2(5</private>, "demo\x2ewhl", {flags=O_RDONLY}, 24) = -1 ENOENT (missing)',
            r'openat(5</private>, "demo\056whl", O_RDONLY) = -1 ENOENT (missing)',
            'open("/proc/self/fd/3", O_RDONLY) = 6</input/demo.whl>',
            'open("/private/demo.whl/.", O_RDONLY) = -1 ENOTDIR (not a directory)',
            'open("/private/demo.whl/", O_RDONLY) = -1 ENOTDIR (not a directory)',
        ]:
            with self.subTest(operation=operation):
                self.rejected(PREFIX + DELETE + f"10 {operation}\n" + END)

    def test_child_reopen_is_not_hidden_by_root_exit(self):
        self.rejected(PREFIX + DELETE + '11 openat(AT_FDCWD, "demo.whl", O_RDONLY) = -1 ENOENT (missing)\n11 +++ exited with 0 +++\n' + END)

    def test_split_open_before_boundary_is_accepted_only_if_completed_before_it(self):
        split = '10 clone(child_stack=NULL, flags=SIGCHLD) = 11\n11 openat(AT_FDCWD, "demo.whl", O_RDONLY <unfinished ...>\n'
        resumed = '11 <... openat resumed>) = 5</private/demo.whl>\n11 +++ exited with 0 +++\n'
        self.accepted(PREFIX + split + resumed + DELETE + END)
        self.rejected(PREFIX + split + DELETE + resumed + END)

    def test_open_overlapping_split_unlink_is_unresolved(self):
        self.rejected(PREFIX + '10 unlink("/private/demo.whl" <unfinished ...>\n11 open("demo.whl", O_RDONLY) = -1 ENOENT (missing)\n10 <... unlink resumed>) = 0\n11 +++ exited with 0 +++\n' + END)

    def test_unmatched_split_and_abbreviated_path_fail(self):
        for event in ['11 openat(AT_FDCWD, "demo.whl", O_RDONLY <unfinished ...>\n',
                      '11 <... openat resumed>) = 3\n',
                      '10 open("/private/demo"..., O_RDONLY) = 3\n',
                      '10 openat(AT_FDCWD, 0x123, O_RDONLY) = -1 EFAULT (bad)\n']:
            self.rejected(PREFIX + DELETE + event + END)

    def test_missing_deletion_or_termination_cannot_pass(self):
        self.rejected(PREFIX + END)
        self.rejected(PREFIX + DELETE)
        self.rejected((PREFIX + DELETE + END).rstrip())
        self.rejected(PREFIX + DELETE + '11 execve("/child", [], 0x1) = 0\n' + END)
        self.rejected(PREFIX + '10 clone(child_stack=NULL, flags=SIGCHLD) = 11\n' + DELETE + END)
        self.rejected(PREFIX + '10 unlink("/input/../input/demo.whl") = 0\n' + END)

    @unittest.skipUnless(sys.platform == "linux", "capture limits apply to the Linux observer")
    def test_live_output_limit_terminates_the_process(self):
        from validate_publisher import run
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "exceeded one MiB during capture"):
                run([sys.executable, "-c", 'import os; os.write(1, b"x" * (2 * 1024 * 1024))'], Path(temporary))

    @unittest.skipUnless(sys.platform == "linux", "file limits apply to the Linux observer")
    def test_inherited_file_limit_prevents_unbounded_trace_growth(self):
        from validate_publisher import run
        from publisher_trace import TRACE_LIMIT
        with tempfile.TemporaryDirectory() as temporary:
            code, _, _ = run([sys.executable, "-c", f'f = open("oversized", "wb"); f.write(b"x" * {TRACE_LIMIT + 1}); f.flush()'], Path(temporary))
            self.assertNotEqual(code, 0)
            self.assertLessEqual((Path(temporary) / "oversized").stat().st_size, TRACE_LIMIT)


if __name__ == "__main__":
    unittest.main()
