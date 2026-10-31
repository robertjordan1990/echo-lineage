"""Adversarial boundary regressions with synthetic keys and real store locks."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Barrier
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage_test_helpers import eid
from transfer_test_helpers import (
    TransferFixture, SOURCE_ACTOR, RECIPIENT_ACTOR, PAYLOAD_ID, ACTIVATION, T, LATER, EXPIRY,
)
from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
from tools.tools.echo_lineage import VerificationBindings, validate_document
from tools.tools.echo_lineage_auth import sign_acceptance_document
from tools.tools.echo_state_store import PrivateStateStore, snapshot_digest
from tools.tools import echo_state_model as legacy_model
from tools.tools import echo_transfer as cli
from tools.tools import echo_transfer_auth as auth
from tools.tools import echo_transfer_model as model
from tools.tools import echo_transfer_runtime as runtime
from tools.tools import echo_context_consumer as consumer


class TransferSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="echo-transfer-security-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.f = TransferFixture(self.directory)
        self.state_dir = self.directory / "state"

    def write(self, name, value):
        path = self.directory / name
        path.write_bytes(canon_json_bytes(value) + b"\n")
        path.chmod(0o600)
        return path

    def initialize(self, state):
        with PrivateStateStore(self.state_dir).locked(initialize=True) as transaction:
            transaction.write(state)

    def read(self):
        with PrivateStateStore(self.state_dir).locked() as transaction:
            return transaction.read()

    def invoke(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main([str(value) for value in arguments])
        return code, json.loads(output.getvalue())

    def race(self, operations):
        """Independent descriptors contend on the real unchanged flock inode."""
        barrier = Barrier(len(operations))

        def contend(name, operation):
            barrier.wait(timeout=10)
            try:
                operation()
                return name, "committed"
            except ValueError as exc:
                return name, "refused:" + str(exc)

        with ThreadPoolExecutor(max_workers=len(operations)) as executor:
            futures = [executor.submit(contend, name, operation)
                       for name, operation in operations.items()]
            outcomes = dict(future.result(timeout=30) for future in futures)
        self.assertEqual(sum(value == "committed" for value in outcomes.values()), 1, outcomes)
        self.assertTrue(all(value == "committed" or value.startswith("refused:")
                            for value in outcomes.values()), outcomes)
        return next(name for name, value in outcomes.items() if value == "committed")

    def test_two_actual_issuers_commit_one_handoff_under_original_store_lock(self):
        state = self.f.migrate()
        self.initialize(state)
        original_inodes = {path.name: path.stat().st_ino for path in self.state_dir.iterdir()
                           if path.name != "state.json"}
        expected = snapshot_digest(state)
        packets = {}
        for name in ("issuer-a", "issuer-b"):
            candidate = model.prepare_action(state, "issue", {
                "producer_runtime_session_id": eid("runtime-session", 1), "expires_at": EXPIRY},
                actor_id=SOURCE_ACTOR, request_id=name, verification_time=LATER,
                expected_state_digest=expected)
            packets[name] = model.sign_candidate(state, candidate, self.f.keys["source"])

        def operation(packet):
            with PrivateStateStore(self.state_dir).locked() as transaction:
                updated, _ = model.apply_action(transaction.read(), packet,
                    expected_state_digest=expected, applied_at=LATER)
                transaction.write(updated)

        winner = self.race({name: lambda packet=packet: operation(packet)
                            for name, packet in packets.items()})
        final = self.read()
        self.assertTrue(model.inspect_state(final)["source_epoch_sealed"])
        self.assertEqual(final["generation"], 1)
        self.assertEqual(final["records"][0]["packet"], packets[winner])
        self.assertEqual(final["initial"], state["initial"])
        document = final["records"][0]["packet"]["payload"]["document"]
        latest = self.f.legacy["records"][-1]["document"]
        validate_document(document, expected_type="handoff",
            expected_previous_head=latest["resulting_head"],
            expected_event_index=latest["responsibility"]["event_index"] + 1)
        for name, inode in original_inodes.items():
            self.assertEqual((self.state_dir / name).stat().st_ino, inode)
        loser = next(packet for name, packet in packets.items() if name != winner)
        with self.assertRaises(model.TransferError):
            operation(loser)
        self.assertEqual(self.read(), final)

    def test_migration_and_legacy_writer_race_preserves_exact_winning_history(self):
        legacy = self.f.legacy
        expected = snapshot_digest(legacy)
        pin = auth.policy_digest(self.f.policy)
        self.initialize(legacy)
        inode_before = {path.name: path.stat().st_ino for path in self.state_dir.iterdir()
                        if path.name != "state.json"}
        candidate = model.prepare_migration(legacy, self.f.policy,
            artifacts=self.f.artifacts, actor_id=SOURCE_ACTOR, request_id="racing-migration",
            verification_time=T, expected_state_digest=expected, expected_policy_digest=pin)
        migration = model.sign_candidate(legacy, candidate, self.f.keys["source"], expected_policy_digest=pin)
        bindings = VerificationBindings(target_paths={PAYLOAD_ID: self.directory / "context.txt"},
                                        target_roots={PAYLOAD_ID: self.directory})
        bundle = legacy_model.prepare_decision(legacy, decision="accepted",
            actor_id=SOURCE_ACTOR, operator_id=SOURCE_ACTOR, request_id="racing-legacy",
            verification_time=LATER, bindings=bindings, expected_state_digest=expected)
        bundle["document"] = sign_acceptance_document(bundle["document"], legacy["policy"], self.f.keys["source"])

        def migrate():
            with PrivateStateStore(self.state_dir).locked() as transaction:
                updated, _ = model.apply_migration(transaction.read(), migration,
                    expected_state_digest=expected, applied_at=LATER, expected_policy_digest=pin)
                transaction.write(updated)

        def legacy_write():
            with PrivateStateStore(self.state_dir).locked() as transaction:
                updated, _ = legacy_model.apply_decision(transaction.read(), bundle,
                    bindings=bindings, expected_state_digest=expected, applied_at=LATER)
                transaction.write(updated)

        winner = self.race({"migration": migrate, "legacy": legacy_write})
        final = self.read()
        if winner == "migration":
            self.assertTrue(model.inspect_state(final)["local_chain_valid"])
            preserved = final["initial"]["migration"]["payload"]["inputs"]["legacy_state"]
            self.assertEqual(preserved, legacy)
            self.assertEqual(final["generation"], 0)
            with self.assertRaises(legacy_model.ModelError):
                legacy_write()
        else:
            status = legacy_model.inspect_state(final)
            self.assertTrue(status["local_acceptance_active"])
            self.assertEqual(final["records"][:-1], legacy["records"])
            self.assertEqual(final["records"][-1]["document"], bundle["document"])
            self.assertEqual(final["generation"], legacy["generation"] + 1)
            with self.assertRaises(model.TransferError):
                migrate()
        self.assertEqual(self.read(), final)
        for name, inode in inode_before.items():
            self.assertEqual((self.state_dir / name).stat().st_ino, inode)

    def test_two_actual_receiver_initializers_never_replace_winning_local_policy(self):
        policies = {"first": self.f.policy, "second": copy.deepcopy(self.f.policy)}
        policies["second"]["consumer"]["code_digest"] = "f" * 64
        receivers = {name: model.create_receiver(policy, expected_policy_digest=auth.policy_digest(policy))
                     for name, policy in policies.items()}

        def initialize(state):
            with PrivateStateStore(self.state_dir).locked(initialize=True) as transaction:
                transaction.write(state)

        winner = self.race({name: lambda state=state: initialize(state)
                           for name, state in receivers.items()})
        final = self.read()
        self.assertEqual(final, receivers[winner])
        self.assertEqual(final["generation"], 0)
        self.assertIsNone(final["projections"]["receive"])
        self.assertIsNone(final["projections"]["decision"])
        self.assertEqual(final["records"], [])
        loser = next(state for name, state in receivers.items() if name != winner)
        with self.assertRaises((ValueError, OSError)):
            initialize(loser)
        self.assertEqual(self.read(), final)

    def test_computed_export_hashes_do_not_replace_observed_durable_file(self):
        source, envelope = self.f.exported()
        self.initialize(source)
        raw = canon_json_bytes(envelope) + b"\n"
        inputs = {"envelope_digest": auth.digest("envelope", envelope),
                  "raw_sha256": sha256_hex(raw), "byte_length": len(raw)}
        input_file = self.write("computed-facts.json", inputs)
        candidate_file = self.directory / "candidate.json"
        signed_file = self.directory / "signed.json"
        expected = snapshot_digest(source)
        prepare = ("action", "prepare", "--state-dir", self.state_dir,
            "--operation", "export_confirm", "--inputs", input_file,
            "--actor-id", SOURCE_ACTOR, "--request-id", "computed-confirmation",
            "--verification-time", LATER, "--expected-state-digest", expected, "--out", candidate_file)
        code, _ = self.invoke(*prepare)
        self.assertEqual(code, 2)
        self.assertFalse(candidate_file.exists())
        candidate = model.prepare_action(source, "export_confirm", inputs,
            actor_id=SOURCE_ACTOR, request_id="computed-confirmation", verification_time=LATER,
            expected_state_digest=expected)
        self.write(candidate_file.name, candidate)
        with mock.patch.object(auth, "_read_private_key", side_effect=AssertionError("must observe before key")):
            code, _ = self.invoke("candidate", "sign", "--state-dir", self.state_dir,
                "--candidate", candidate_file, "--key-file", self.f.keys["source"], "--out", signed_file)
        self.assertEqual(code, 2)
        self.assertFalse(signed_file.exists())
        signed = model.sign_candidate(source, candidate, self.f.keys["source"])
        self.write(signed_file.name, signed)
        apply = ("action", "apply", "--state-dir", self.state_dir, "--signed", signed_file,
                 "--expected-state-digest", expected, "--applied-at", LATER)
        code, _ = self.invoke(*apply)
        self.assertEqual(code, 2)
        self.assertEqual(self.read(), source)
        observed = self.write("observed-envelope.json", {"synthetic": "different file"})
        code, _ = self.invoke(*apply, "--observed-envelope", observed)
        self.assertEqual(code, 2)
        self.assertEqual(self.read(), source)
        observed.write_bytes(raw)
        code, committed = self.invoke(*apply, "--observed-envelope", observed)
        self.assertEqual(code, 0, committed)
        self.assertEqual(committed["status"], "committed")
        final = self.read()
        self.assertTrue(model.inspect_state(final)["export_confirmed"])
        observed.unlink()
        code, replay = self.invoke(*apply)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(self.read(), final)

    def test_receiver_pin_cannot_be_overridden_by_policy_inside_valid_source_proof(self):
        _, envelope = self.f.exported()
        policy = copy.deepcopy(self.f.policy)
        policy["consumer"]["code_digest"] = "f" * 64
        receiver = model.create_receiver(policy, expected_policy_digest=auth.policy_digest(policy))
        before = copy.deepcopy(receiver)
        with self.assertRaisesRegex(model.TransferError, "ENVELOPE_POLICY_MISMATCH"):
            model.prepare_action(receiver, "receive", {"envelope": envelope,
                "recipient_runtime_session_id": eid("runtime-session", 2)},
                actor_id=RECIPIENT_ACTOR, request_id="different-local-pin", verification_time=LATER,
                expected_state_digest=snapshot_digest(receiver))
        self.assertEqual(receiver, before)

    def test_canonical_semantics_never_replace_actual_imported_raw_utf8_bytes(self):
        directory = self.directory / "canonical-fixture"
        directory.mkdir(mode=0o700)
        raw = '{  "text": "e\u0301 $(inert)" }\n'.encode("utf-8")
        fixture = TransferFixture(directory, payload=raw, canonical=True)
        _, imported = fixture.imported()
        activated = fixture.action(imported, "activate", {
            "activation_id": "00000000-0000-4000-8000-000000000701",
            "artifact_ids": [PAYLOAD_ID], "probe": {"artifact_id": PAYLOAD_ID,
                "offset": 0, "length": 4, "nonce": "7" * 64}})
        view = model.consumer_view(activated, "00000000-0000-4000-8000-000000000701")
        self.assertEqual(base64.b64decode(view["artifacts"][0]["bytes_b64"]), raw)
        self.assertEqual(view["artifacts"][0]["sha256"], sha256_hex(raw))
        self.assertNotEqual(sha256_hex(raw), fixture.legacy["root"]["body"]["inheritance_sources"][0]["artifact"]["sha256"])
        documents = consumer._load(view)
        self.assertEqual(documents[PAYLOAD_ID]["bytes"], raw)
        self.assertIn("e\u0301 $(inert)", documents[PAYLOAD_ID]["text"])

    def test_excluded_optional_target_cannot_be_reintroduced_by_import_selection(self):
        directory = self.directory / "excluded-fixture"
        directory.mkdir(mode=0o700)
        fixture = TransferFixture(directory, excluded=True)
        _, receiver = fixture.received()
        accepted = fixture.action(receiver, "decide", {"decision": "accepted_with_reservations"})
        with self.assertRaisesRegex(model.TransferError, "IMPORT_SCOPE_NOT_ACCEPTED"):
            fixture.action(accepted, "import", {"artifact_ids": [PAYLOAD_ID]})
        self.assertIsNone(accepted["projections"]["import"])

    def control_intent(self, view, policy, key_file, *, changes=None):
        intent = dict(view["launch"], kind="launch_intent", grant_digest=view["grant_digest"],
            import_digest=view["import_digest"], store_id=view["store_id"],
            installation_id=view["installation_id"], consumer_id=view["consumer"]["consumer_id"],
            observed_at=LATER)
        intent.update(changes or {})
        packet = auth.sign_packet(intent, policy, key_file, purpose="context_consumption_receipt",
            actor_id=view["consumer"]["consumer_id"], installation_id=view["installation_id"],
            role="local_context_consumer")
        return {"schema": "echo-context-control/v1", "policy": policy, "intent": packet}

    def test_self_signed_control_policy_cannot_impersonate_independently_pinned_consumer(self):
        _, state = self.f.loaded()
        self.initialize(state)
        view = model.consumer_view(state, ACTIVATION)
        # The attacker knows public grant/import/store facts, but none of the
        # actual operator/consumer private keys. Their policy is self-consistent.
        key = Ed25519PrivateKey.from_private_bytes(b"o" * 32)
        key_file = self.directory / "synthetic-unauthorized-consumer.pem"
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_file.chmod(0o600)
        policy = copy.deepcopy(self.f.policy)
        policy["keys"][2]["public_key"] = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        record = self.control_intent(view, policy, key_file)
        control_dir = self.directory / "counterfeit-control"
        with runtime._Control(control_dir, initialize=True) as control:
            control.write(runtime.LAUNCH_NAME, record)
        # A real private socket prevents missing-endpoint checks from masking
        # the policy flaw. Every client must reject before sending a challenge.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(control_dir / runtime.SOCKET_NAME))
            os.chmod(control_dir / runtime.SOCKET_NAME, 0o600)
            server.listen(1)
            for revoked in (False, True):
                if revoked:
                    state = self.f.action(state, "deactivate", {"activation_id": ACTIVATION})
                    with PrivateStateStore(self.state_dir).locked() as transaction:
                        transaction.write(state)
                with mock.patch.object(runtime.socket, "socket", side_effect=AssertionError("must pin before IPC")):
                    operations = (
                        lambda: runtime.query_consumer(control_dir, {"operation": "status", "nonce": "f" * 64},
                                                       state_dir=self.state_dir),
                        lambda: runtime.stop_consumer(control_dir, state_dir=self.state_dir),
                        lambda: runtime.reconcile_activation(self.state_dir, control_dir, activation_id=ACTIVATION),
                    )
                    for number, operation in enumerate(operations):
                        with self.subTest(revoked=revoked, endpoint=number), self.assertRaisesRegex(
                                runtime.TransferRuntimeError, "CONTROL_POLICY_PIN_MISMATCH"):
                            operation()
        self.assertEqual(self.read(), state)

    def test_authorized_consumer_signature_cannot_substitute_uncommitted_instance(self):
        _, state = self.f.loaded()
        self.initialize(state)
        view = model.consumer_view(state, ACTIVATION)
        record = self.control_intent(view, self.f.policy, self.f.keys["consumer"], changes={
            "instance_id": "00000000-0000-4000-8000-000000000999", "launch_nonce": "9" * 64})
        control_dir = self.directory / "wrong-instance-control"
        with runtime._Control(control_dir, initialize=True) as control:
            control.write(runtime.LAUNCH_NAME, record)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(control_dir / runtime.SOCKET_NAME))
            os.chmod(control_dir / runtime.SOCKET_NAME, 0o600)
            server.listen(1)
            with mock.patch.object(runtime.socket, "socket", side_effect=AssertionError("uncommitted instance IPC")):
                with self.assertRaisesRegex(runtime.TransferRuntimeError, "CONTROL_STATE_CONFLICT"):
                    runtime.query_consumer(control_dir, {"operation": "status", "nonce": "e" * 64},
                                           state_dir=self.state_dir)
                with self.assertRaisesRegex(runtime.TransferRuntimeError, "CONTROL_STATE_CONFLICT"):
                    runtime.reconcile_activation(self.state_dir, control_dir, activation_id=ACTIVATION)
        self.assertEqual(self.read(), state)

    def test_fresh_authorized_signature_with_wrong_ram_probe_is_not_availability_evidence(self):
        _, state = self.f.loaded()
        self.initialize(state)
        view = model.consumer_view(state, ACTIVATION)
        record = self.control_intent(view, self.f.policy, self.f.keys["consumer"])
        intent = record["intent"]["payload"]
        control_dir = self.directory / "wrong-probe-control"
        with runtime._Control(control_dir, initialize=True) as control:
            control.write(runtime.LAUNCH_NAME, record)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(control_dir / runtime.SOCKET_NAME))
            os.chmod(control_dir / runtime.SOCKET_NAME, 0o600)
            server.listen(1)
            server.settimeout(20)

            def answer_fresh_challenge_with_wrong_probe():
                connection, _ = server.accept()
                with connection:
                    request = runtime._receive(connection)
                    payload = {field: intent[field] for field in (
                        "activation_id", "instance_id", "launch_nonce", "grant_digest", "import_digest",
                        "store_id", "installation_id", "consumer_id", "code_digest")}
                    payload.update(kind="status", nonce=request["nonce"],
                        request_digest=auth.digest("consumer-query", request), observed_at=LATER,
                        result={"grant_current": True, "loaded": True, "read_set": view["read_set"],
                                "probe_result_sha256": "0" * 64})
                    # This is the actual provisioned adapter key and a fresh
                    # nonce, but its claimed RAM evidence contradicts the grant.
                    packet = auth.sign_packet(payload, self.f.policy, self.f.keys["consumer"],
                        purpose="context_consumption_receipt", actor_id=view["consumer"]["consumer_id"],
                        installation_id=view["installation_id"], role="local_context_consumer")
                    runtime._send(connection, packet)

            with ThreadPoolExecutor(max_workers=1) as executor:
                reply = executor.submit(answer_fresh_challenge_with_wrong_probe)
                with self.assertRaises(runtime.TransferRuntimeError):
                    runtime.query_consumer(control_dir, {"operation": "status", "nonce": "d" * 64},
                                           state_dir=self.state_dir)
                reply.result(timeout=25)
        self.assertEqual(self.read(), state)


if __name__ == "__main__":
    unittest.main()
