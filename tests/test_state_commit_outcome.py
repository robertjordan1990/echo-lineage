"""CLI results agree with the actual published snapshot after injected IO faults."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
import stat
import unittest
from unittest import mock

import test_state_cli as fixtures
from tools.tools import echo_state as cli
from tools.tools import echo_state_store as storage


class StateCommitOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.StateCLITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.initialize()
        self.old = self.fixture.state()
        signed = self.fixture.sign(self.fixture.prepare())
        self.arguments = ["decision", "apply", "--state-dir", str(self.fixture.state_dir),
            "--decision", str(signed), "--expected-state-digest", self.fixture.digest(),
            "--request-id", "request-1"]

    def run_apply(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(self.arguments)
        return code, json.loads(output.getvalue())

    def assert_recovery(self, code, result):
        self.assertEqual(code, 2)
        self.assertTrue(result["commit_uncertain"])
        self.assertEqual(result["next_action"], "inspect_state_and_request_before_any_retry")
        persisted = self.fixture.state()
        self.assertEqual(persisted["generation"], 1)
        self.assertEqual(persisted["records"][0]["request_id"], "request-1")
        status = self.fixture.status()  # Explicit inspection, not an automatic retry.
        self.assertTrue(status["local_chain_valid"])
        self.assertFalse(status["runtime_activation"])
        code, result = self.run_apply()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "already_recorded")
        self.assertTrue(result["idempotent"])
        self.assertEqual(self.fixture.state(), persisted)

    def test_directory_fsync_failure_after_rename_reports_uncertain_and_is_inspectable(self):
        actual_fsync = os.fsync
        directory_info = self.fixture.state_dir.stat()

        def fail_published_directory(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (directory_info.st_dev, directory_info.st_ino):
                raise OSError("synthetic directory fsync failure")
            return actual_fsync(fd)

        with mock.patch.object(storage.os, "fsync", side_effect=fail_published_directory):
            code, result = self.run_apply()
        self.assert_recovery(code, result)

    def test_lock_close_failure_after_durable_write_reports_uncertain_and_is_inspectable(self):
        actual_close = os.close
        lock_info = (self.fixture.state_dir / "state.lock").stat()

        def fail_lock_close(fd):
            info = os.fstat(fd)
            actual_close(fd)
            if (info.st_dev, info.st_ino) == (lock_info.st_dev, lock_info.st_ino):
                raise OSError("synthetic lock close failure")

        with mock.patch.object(storage.os, "close", side_effect=fail_lock_close):
            code, result = self.run_apply()
        self.assert_recovery(code, result)

    def test_file_fsync_failure_before_rename_leaves_old_state_and_reports_refusal(self):
        actual_fsync = os.fsync

        def fail_temporary_fsync(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("synthetic temporary file fsync failure")
            return actual_fsync(fd)

        with mock.patch.object(storage.os, "fsync", side_effect=fail_temporary_fsync):
            code, result = self.run_apply()
        self.assertEqual(code, 2)
        self.assertFalse(result["commit_uncertain"])
        self.assertEqual(result["status"], "refused")
        self.assertEqual(self.fixture.state(), self.old)
        self.assertEqual(sorted(p.name for p in self.fixture.state_dir.iterdir()),
            ["state.json", "state.lock"])


if __name__ == "__main__":
    unittest.main()
