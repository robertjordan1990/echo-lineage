"""2C CLI distinguishes pre-commit refusal, uncertain commit and output."""
from __future__ import annotations
from contextlib import redirect_stdout
import io
import json
import os
import stat
import unittest
from unittest import mock
import test_transfer_cli as fixtures
from transfer_test_helpers import SOURCE_ACTOR, LATER, EXPIRY
from lineage_test_helpers import eid
from tools.tools import echo_transfer as cli
from tools.tools import echo_transfer_model as model
from tools.tools import echo_state_store as storage


class TransferCommitOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TransferCLITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.migrate()
        self.before = self.fixture.state(self.fixture.source)
        self.old_digest = storage.snapshot_digest(self.before)
        self.inputs = {"producer_runtime_session_id": eid("runtime-session", 1), "expires_at": EXPIRY}
        candidate = model.prepare_action(self.before, "issue", self.inputs,
            actor_id=SOURCE_ACTOR, request_id="issue-fault-test", verification_time=LATER,
            expected_state_digest=self.old_digest)
        signed = model.sign_candidate(self.before, candidate, self.fixture.fixture.keys["source"])
        self.signed_path = self.fixture.write("issue-signed.json", signed)
        self.arguments = ["action", "apply", "--state-dir", str(self.fixture.source),
            "--signed", str(self.signed_path), "--expected-state-digest", self.old_digest,
            "--applied-at", LATER]

    def run_apply(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(self.arguments)
        return code, json.loads(output.getvalue())

    def inspect_then_replay(self):
        state = self.fixture.state(self.fixture.source)
        self.assertEqual(state["generation"], 1)
        self.assertTrue(state["projections"]["sealed"])
        self.assertTrue(model.inspect_state(state)["local_chain_valid"])
        code, result = self.run_apply()
        self.assertEqual(code, 0, result)
        self.assertTrue(result["idempotent"])
        self.assertEqual(self.fixture.state(self.fixture.source), state)

    def test_fsync_before_rename_leaves_source_state_unmodified(self):
        real = os.fsync
        def fail_regular(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("synthetic pre-rename fsync failure")
            return real(fd)
        with mock.patch.object(storage.os, "fsync", side_effect=fail_regular):
            code, result = self.run_apply()
        self.assertEqual(code, 2)
        self.assertFalse(result["commit_uncertain"])
        self.assertEqual(self.fixture.state(self.fixture.source), self.before)

    def test_directory_fsync_after_rename_is_uncertain_but_inspectable(self):
        real = os.fsync
        directory = self.fixture.source.stat()
        def fail_directory(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (directory.st_dev, directory.st_ino):
                raise OSError("synthetic post-rename fsync failure")
            return real(fd)
        with mock.patch.object(storage.os, "fsync", side_effect=fail_directory):
            code, result = self.run_apply()
        self.assertEqual(code, 2)
        self.assertTrue(result["commit_uncertain"])
        self.assertEqual(result["next_action"], "inspect_state_and_request_before_any_retry")
        self.inspect_then_replay()

    def test_lock_cleanup_after_commit_is_uncertain_and_never_double_issues(self):
        real = os.close
        lock = (self.fixture.source / "state.lock").stat()
        def fail_close(fd):
            info = os.fstat(fd)
            real(fd)
            if (info.st_dev, info.st_ino) == (lock.st_dev, lock.st_ino):
                raise OSError("synthetic post-commit close failure")
        with mock.patch.object(storage.os, "close", side_effect=fail_close):
            code, result = self.run_apply()
        self.assertEqual(code, 2)
        self.assertTrue(result["commit_uncertain"])
        self.inspect_then_replay()

    def test_new_candidate_output_fsync_uncertain_never_changes_state(self):
        inputs = self.fixture.write("issue-inputs.json", self.inputs)
        output = self.fixture.directory / "candidate-output.json"
        args = ["action", "prepare", "--state-dir", str(self.fixture.source),
            "--operation", "issue", "--inputs", str(inputs), "--actor-id", SOURCE_ACTOR,
            "--request-id", "prepare-fault", "--verification-time", LATER,
            "--expected-state-digest", self.old_digest, "--out", str(output)]
        real = os.fsync
        def fail_output(fd):
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and output.exists():
                target = output.stat()
                if (target.st_dev, target.st_ino) == (info.st_dev, info.st_ino):
                    raise OSError("synthetic output uncertainty")
            return real(fd)
        stream = io.StringIO()
        with mock.patch.object(os, "fsync", side_effect=fail_output), redirect_stdout(stream):
            code = cli.main(args)
        result = json.loads(stream.getvalue())
        self.assertEqual(code, 2)
        self.assertTrue(result["output_uncertain"])
        self.assertFalse(result["commit_uncertain"])
        self.assertTrue(output.exists())
        self.assertEqual(self.fixture.state(self.fixture.source), self.before)


if __name__ == "__main__":
    unittest.main()
