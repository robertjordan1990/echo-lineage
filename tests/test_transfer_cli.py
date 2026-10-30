"""Real private file/state CLI workflow; fixtures are published synthetic data."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest
from unittest import mock

from transfer_test_helpers import (TransferFixture, SOURCE_ACTOR, RECIPIENT_ACTOR,
    PAYLOAD_ID, ACTIVATION, T, LATER, EXPIRY)
from lineage_test_helpers import eid
from tools.tools.echo_canonical import canon_json_bytes
from tools.tools.echo_state_store import PrivateStateStore, snapshot_digest
from tools.tools import echo_transfer as cli
from tools.tools import echo_transfer_auth as auth
from tools.tools import echo_transfer_model as model
from tools.tools import echo_transfer_runtime as runtime


class TransferCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="echo-transfer-cli-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.injection_marker = self.directory / "context-must-not-execute"
        payload = ("Synthetic context.\n$(touch " + str(self.injection_marker) + ")\n").encode()
        self.fixture = TransferFixture(self.directory, payload=payload,
            code_digest=runtime.consumer_code_digest())
        self.source = self.directory / "source"
        self.receiver = self.directory / "recipient"
        self.control = self.directory / "control"
        self.policy = self.write("policy.json", self.fixture.policy)
        self.captured = self.write("capture.json", {"artifacts": self.fixture.artifacts})
        self.pin = auth.policy_digest(self.fixture.policy)
        self.counter = 0
        self.processes = []
        self.addCleanup(self.cleanup_processes)
        with PrivateStateStore(self.source).locked(initialize=True) as tx:
            tx.write(self.fixture.legacy)

    def cleanup_processes(self):
        if not self.processes:
            return
        try:
            runtime.stop_consumer(self.control, state_dir=self.receiver)
        except ValueError:
            pass
        for process in self.processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def write(self, name, value):
        path = self.directory / name
        path.write_bytes(canon_json_bytes(value) + b"\n")
        path.chmod(0o600)
        return path

    def state(self, directory):
        with PrivateStateStore(directory).locked() as tx:
            return tx.read()

    def invoke(self, *arguments, expected=0):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main([str(arg) for arg in arguments])
        result = json.loads(output.getvalue())
        self.assertEqual(code, expected, result)
        self.assertNotIn("PRIVATE KEY", output.getvalue())
        return result

    def migrate(self):
        digest = snapshot_digest(self.state(self.source))
        candidate = self.directory / "migration-candidate.json"
        signed = self.directory / "migration-signed.json"
        self.invoke("migration", "prepare", "--state-dir", self.source,
            "--policy", self.policy, "--expected-policy-digest", self.pin,
            "--artifacts", self.captured, "--actor-id", SOURCE_ACTOR,
            "--request-id", "migrate", "--verification-time", T,
            "--expected-state-digest", digest, "--out", candidate)
        self.assertEqual(snapshot_digest(self.state(self.source)), digest)
        self.invoke("candidate", "sign", "--state-dir", self.source,
            "--candidate", candidate, "--key-file", self.fixture.keys["source"],
            "--expected-policy-digest", self.pin, "--out", signed)
        args = ("migration", "apply", "--state-dir", self.source,
            "--signed", signed, "--expected-state-digest", digest,
            "--expected-policy-digest", self.pin, "--applied-at", T)
        self.invoke(*args)
        self.assertTrue(self.invoke(*args)["idempotent"])

    def action(self, directory, operation, inputs):
        self.counter += 1
        number = self.counter
        source = directory == self.source
        key = self.fixture.keys["source" if source else "recipient"]
        actor = SOURCE_ACTOR if source else RECIPIENT_ACTOR
        digest = snapshot_digest(self.state(directory))
        input_file = self.write(f"inputs-{number}.json", inputs)
        candidate = self.directory / f"candidate-{number}.json"
        signed = self.directory / f"signed-{number}.json"
        observed = (["--observed-envelope", self.directory / "envelope.json"]
            if operation == "export_confirm" else [])
        self.invoke("action", "prepare", "--state-dir", directory,
            "--operation", operation, "--inputs", input_file,
            "--actor-id", actor, "--request-id", f"request-{number}",
            "--verification-time", LATER, "--expected-state-digest", digest,
            "--out", candidate, *observed)
        self.assertEqual(snapshot_digest(self.state(directory)), digest)
        self.invoke("candidate", "sign", "--state-dir", directory,
            "--candidate", candidate, "--key-file", key, "--out", signed, *observed)
        apply_args = ("action", "apply", "--state-dir", directory,
            "--signed", signed, "--expected-state-digest", digest,
            "--applied-at", LATER, *observed)
        self.invoke(*apply_args)
        self.assertTrue(self.invoke(*apply_args)["idempotent"])

    def receive(self):
        self.migrate()
        self.action(self.source, "issue", {"producer_runtime_session_id": eid("runtime-session", 1),
            "expires_at": EXPIRY})
        self.action(self.source, "export_authorize", {})
        envelope_file = self.directory / "envelope.json"
        self.invoke("handoff", "export", "--state-dir", self.source, "--out", envelope_file)
        self.assertFalse(model.inspect_state(self.state(self.source))["export_confirmed"])
        facts = self.directory / "file-facts.json"
        self.invoke("handoff", "file-facts", "--file", envelope_file, "--out", facts)
        self.action(self.source, "export_confirm", json.loads(facts.read_text()))
        status = self.invoke("state", "status", "--state-dir", self.source)
        self.assertEqual(status["remote_milestones"]["received"], "UNKNOWN")
        self.invoke("receiver", "init", "--state-dir", self.receiver,
            "--policy", self.policy, "--expected-policy-digest", self.pin)
        self.action(self.receiver, "receive", {"envelope": json.loads(envelope_file.read_text()),
            "recipient_runtime_session_id": eid("runtime-session", 2)})
        return envelope_file

    def test_complete_cli_file_receipt_import_actual_consumer_read_and_revoke(self):
        self.receive()
        receipt_file = self.directory / "received-receipt.json"
        self.invoke("receipt", "sign", "--state-dir", self.receiver,
            "--kind", "received", "--actor-id", RECIPIENT_ACTOR,
            "--key-file", self.fixture.keys["recipient"], "--verification-time", LATER,
            "--out", receipt_file)
        self.action(self.source, "receipt_ingest", {"receipt": json.loads(receipt_file.read_text())})
        source_status = self.invoke("state", "status", "--state-dir", self.source)
        self.assertEqual(source_status["remote_milestones"]["received"], "RECEIPT_VERIFIED")
        self.assertEqual(source_status["remote_milestones"]["imported"], "UNKNOWN")
        self.action(self.receiver, "decide", {"decision": "accepted"})
        self.action(self.receiver, "import", {"artifact_ids": [PAYLOAD_ID]})
        self.assertFalse((self.control / runtime.SOCKET_NAME).exists())
        self.action(self.receiver, "activate", {"activation_id": ACTIVATION,
            "artifact_ids": [PAYLOAD_ID], "probe": {"artifact_id": PAYLOAD_ID,
                "offset": 0, "length": 9, "nonce": "a" * 64}})
        actual_popen = subprocess.Popen

        def capture(*args, **kwargs):
            process = actual_popen(*args, **kwargs)
            self.processes.append(process)
            return process

        with mock.patch.object(runtime.subprocess, "Popen", side_effect=capture):
            launched = self.invoke("activation", "request", "--state-dir", self.receiver,
                "--control-dir", self.control, "--activation-id", ACTIVATION,
                "--key-file", self.fixture.keys["consumer"])
        self.assertEqual(launched["current"], "available")
        request = self.write("read.json", {"operation": "read", "nonce": secrets.token_hex(32),
            "artifact_id": PAYLOAD_ID, "offset": 0, "limit": 4096})
        answer = self.invoke("consumer", "query", "--state-dir", self.receiver,
            "--control-dir", self.control, "--request", request)
        self.assertIn("$(touch " + str(self.injection_marker) + ")", answer["result"]["text"])
        self.assertFalse(self.injection_marker.exists())
        self.assertEqual(len(self.processes), 1)
        self.action(self.receiver, "deactivate", {"activation_id": ACTIVATION})
        denied = self.invoke("consumer", "query", "--state-dir", self.receiver, "--control-dir", self.control,
            "--request", request, expected=10)
        self.assertFalse(denied["result"]["grant_current"])
        historical = self.invoke("state", "verify", "--state-dir", self.receiver)
        self.assertTrue(historical["loaded_receipts_are_historical"])
        self.assertEqual(historical["current_process_liveness"], "UNKNOWN")

    def test_migration_sign_requires_independent_policy_pin_and_no_output(self):
        candidate = model.prepare_migration(self.fixture.legacy, self.fixture.policy,
            artifacts=self.fixture.artifacts, actor_id=SOURCE_ACTOR,
            request_id="migration", verification_time=T,
            expected_state_digest=snapshot_digest(self.fixture.legacy), expected_policy_digest=self.pin)
        path = self.write("candidate.json", candidate)
        out = self.directory / "no-signed.json"
        result = self.invoke("candidate", "sign", "--state-dir", self.source,
            "--candidate", path, "--key-file", self.fixture.keys["source"], "--out", out, expected=2)
        self.assertEqual(result["error"], "POLICY_PIN_REQUIRED")
        self.assertFalse(out.exists())
        self.assertEqual(self.state(self.source), self.fixture.legacy)

    def test_duplicate_output_does_not_overwrite_or_claim_commit(self):
        self.migrate()
        checkpoint = self.write("checkpoint.json", {"store_id": self.fixture.policy["source_pin"]["store_id"],
            "generation": 0, "journal_head": self.state(self.source)["journal_head"]})
        result = self.invoke("state", "verify", "--state-dir", self.source, "--checkpoint", checkpoint)
        self.assertTrue(result["external_checkpoint_satisfied"])
        original = checkpoint.read_bytes()
        self.invoke("handoff", "file-facts", "--file", checkpoint, "--out", checkpoint, expected=2)
        self.assertEqual(checkpoint.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
