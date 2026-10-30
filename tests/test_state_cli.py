"""Subprocess CLI checks using public synthetic keys and private /tmp state."""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage_test_helpers import eid, root_document, source
from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
from tools.tools.echo_lineage import finalize_document
from tools.tools.echo_state_store import snapshot_digest


REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "tools" / "tools" / "echo_state.py"
ACTOR = eid("decision-actor", 1)
ROOT_ARTIFACT = eid("artifact", 100)
T = "2032-01-02T03:04:06Z"


class StateCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="echo-cli-test-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state_dir = self.base / "state"
        self.root_file = self.base / "root.json"
        self.policy_file = self.base / "policy.json"
        self.key_file = self.base / "synthetic-private.pem"
        self.root = root_document()
        # Public, deterministic fixture seed. Never load a user key in tests.
        key = Ed25519PrivateKey.from_private_bytes(bytes([72]) * 32)
        self.pem = key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.key_file.write_bytes(self.pem)
        self.key_file.chmod(0o600)
        self.policy = {"schema": "echo-lineage-trust/v1", "keys": [{
            "key_id": eid("key", 1),
            "public_key": base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            "decision_actor_id": ACTOR, "installation_id": eid("installation", 1),
            "decision_mode": "human_operator", "purpose": "lineage_acceptance"}]}
        self.write_json(self.root_file, self.root)
        self.write_json(self.policy_file, self.policy)
        self.bindings: list[str] = []

    def write_json(self, path: Path, value: dict) -> Path:
        path.write_bytes(canon_json_bytes(value) + b"\n")
        path.chmod(0o600)
        return path

    def cli(self, *arguments, expected=0, no_site=False):
        command = [sys.executable, "-B"]
        if no_site:
            command.append("-S")
        result = subprocess.run(command + [str(CLI)] + [str(arg) for arg in arguments],
            cwd=REPO, capture_output=True, text=True, timeout=20)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, expected, output)
        self.assertNotIn("Traceback (most recent call last)", output)
        self.assertNotIn(self.pem.decode().strip(), output)
        for private_line in self.pem.decode().splitlines()[1:-1]:
            self.assertNotIn(private_line, output)
        if expected == 0:
            self.assertEqual(result.stderr, "")
            value = json.loads(result.stdout)
            self.assertIsInstance(value, dict)
            return value
        return result

    def initialize(self, *, expected=0, root_hash=None):
        return self.cli("state", "init", "--state-dir", self.state_dir,
            "--root", self.root_file, "--trust-policy", self.policy_file,
            "--expected-root-hash", root_hash or self.root["document_hash"]["value"],
            "--root-artifact-id", ROOT_ARTIFACT, expected=expected)

    def state(self) -> dict:
        return json.loads((self.state_dir / "state.json").read_text())

    def digest(self) -> str:
        return snapshot_digest(self.state())

    def status(self):
        return self.cli("state", "status", "--state-dir", self.state_dir, "--json")

    def prepare(self, *, decision="accepted", request="request-1", digest=None,
                output=None, actor=ACTOR, operator=ACTOR, expected=0):
        path = output or self.base / (request + "-candidate.json")
        self.cli("decision", "prepare", "--state-dir", self.state_dir,
            "--root", self.root_file, "--decision", decision, "--actor-id", actor,
            "--operator-id", operator, "--request-id", request,
            "--verification-time", T, "--expected-state-digest", digest or self.digest(),
            "--out", path, *self.bindings, expected=expected)
        return path

    def sign(self, candidate, *, output=None, expected=0, no_site=False):
        path = output or candidate.with_name(candidate.stem + "-signed.json")
        self.cli("decision", "sign", "--state-dir", self.state_dir,
            "--candidate", candidate, "--key-file", self.key_file, "--out", path,
            expected=expected, no_site=no_site)
        return path

    def apply(self, signed, *, request="request-1", digest=None, expected=0, report=None):
        arguments = ["decision", "apply", "--state-dir", self.state_dir,
            "--decision", signed, "--expected-state-digest", digest or self.digest(),
            "--request-id", request, *self.bindings]
        if report is not None:
            arguments += ["--report", report]
        return self.cli(*arguments, expected=expected)

    def setup_source(self, *, criticality="optional"):
        self.target = self.base / "payload.bin"
        payload = b"synthetic target for CLI verification\n"
        self.target.write_bytes(payload)
        self.root = root_document(sources=[source(2, sha256=sha256_hex(payload),
            criticality=criticality)])
        self.write_json(self.root_file, self.root)
        self.bindings = ["--target", eid("artifact", 2) + "=" + str(self.target),
            "--target-root", eid("artifact", 2) + "=" + str(self.base)]

    def test_init_unaccepted_status_private_modes_and_no_reinitialization(self):
        self.initialize()
        status = self.status()
        self.assertEqual(status["generation"], 0)
        self.assertEqual(status["bootstrap_status"], "UNACCEPTED")
        self.assertFalse(status["local_acceptance_active"])
        self.assertFalse(status["runtime_activation"])
        self.assertFalse(status["root_author_authenticated"])
        original = (self.state_dir / "state.json").read_bytes()
        self.initialize(expected=2)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)
        for name in ("state.json", "state.lock"):
            self.assertEqual(stat.S_IMODE((self.state_dir / name).stat().st_mode), 0o600)
        self.assertFalse(self.state_dir.is_relative_to(REPO))
        self.assertNotIn(str(self.base), json.dumps(self.state()))

    def test_init_requires_domain_document_hash(self):
        artifact_hash = sha256_hex(canon_json_bytes(self.root))
        self.assertNotEqual(artifact_hash, self.root["document_hash"]["value"])
        self.initialize(root_hash=artifact_hash, expected=2)
        self.assertFalse(self.state_dir.exists())
        self.initialize()

    def test_unsupported_root_signature_policy_returns_unavailable(self):
        # Structurally valid 2A input, outside the explicit 2B-h1 profile.
        self.root["body"]["signature_policy"] = "out_of_band"
        self.root = finalize_document(self.root)
        self.write_json(self.root_file, self.root)
        self.initialize(expected=10)
        self.assertFalse(self.state_dir.exists())

    def test_init_refuses_existing_partial_directory_without_mutating_it(self):
        self.state_dir.mkdir(mode=0o700)
        marker = self.state_dir / "partial"
        marker.write_bytes(b"synthetic partial state")
        self.initialize(expected=2)
        self.assertEqual(list(self.state_dir.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b"synthetic partial state")

    def test_missing_status_and_verify_do_not_create_directory(self):
        for command in ("status", "verify"):
            self.cli("state", command, "--state-dir", self.state_dir, "--json", expected=2)
        self.assertFalse(self.state_dir.exists())

    def test_prepare_and_sign_are_private_and_do_not_activate_or_change_state(self):
        self.initialize()
        original = (self.state_dir / "state.json").read_bytes()
        candidate = self.prepare()
        unsigned = json.loads(candidate.read_text())
        self.assertEqual(set(unsigned), {"schema", "request_id", "report", "document"})
        self.assertEqual(unsigned["document"]["proofs"], [])
        signed = self.sign(candidate)
        authenticated = json.loads(signed.read_text())
        for field in ("schema", "request_id", "report"):
            self.assertEqual(authenticated[field], unsigned[field])
        self.assertEqual(authenticated["document"]["body"], unsigned["document"]["body"])
        self.assertEqual(len(authenticated["document"]["proofs"]), 1)
        for path in (candidate, signed):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(path.is_relative_to(REPO))
            self.assertNotIn(str(self.base), path.read_text())
            self.assertNotIn(self.pem.decode().strip(), path.read_text())
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)
        self.assertFalse(self.status()["local_acceptance_active"])

    def test_all_four_decisions_persist_and_quarantine_blocks_until_valid_reservations(self):
        self.setup_source()
        self.initialize()
        for number, decision in enumerate(("accepted", "declined",
                "quarantined_integrity_failure", "accepted_with_reservations"), start=1):
            if number == 3:
                self.target.write_bytes(b"changed synthetic optional target")
            request = "request-" + str(number)
            signed = self.sign(self.prepare(decision=decision, request=request))
            self.apply(signed, request=request)
            status = self.status()
            self.assertEqual(status["generation"], number)
            self.assertEqual(status["latest_decision"]["decision"], decision)
            self.assertFalse(status["runtime_activation"])
            self.assertEqual(status["local_acceptance_active"], number != 3)
            self.assertEqual(status["integrity_blocked"], number == 3)
        status = self.cli("state", "verify", "--state-dir", self.state_dir, "--json")
        self.assertTrue(status["local_chain_valid"])
        self.assertFalse(status["current_targets_rechecked"])
        self.assertEqual(status["active"]["accepted_artifact_ids"], [ROOT_ARTIFACT])
        self.assertEqual(len(self.state()["records"]), 4)

    def test_identical_retry_with_old_cas_returns_existing_event(self):
        self.initialize()
        original_digest = self.digest()
        signed = self.sign(self.prepare())
        self.apply(signed, digest=original_digest)
        original = (self.state_dir / "state.json").read_bytes()
        self.apply(signed, digest=original_digest)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)
        self.assertEqual(self.status()["generation"], 1)
        self.assertEqual(len(self.state()["records"]), 1)

    def test_conflicting_bundle_with_same_request_id_is_refused(self):
        self.initialize()
        first = self.sign(self.prepare())
        conflict = self.sign(self.prepare(decision="declined",
            output=self.base / "conflicting-candidate.json"))
        self.apply(first)
        original = (self.state_dir / "state.json").read_bytes()
        self.apply(conflict, expected=2)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)

    def test_stale_cas_refuses_second_signed_request_without_state_change(self):
        self.initialize()
        stale = self.digest()
        first = self.sign(self.prepare())
        second = self.sign(self.prepare(request="request-2"))
        self.apply(first)
        original = (self.state_dir / "state.json").read_bytes()
        self.apply(second, request="request-2", digest=stale, expected=2)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)
        self.prepare(request="request-3", digest=stale, expected=2)
        self.assertFalse((self.base / "request-3-candidate.json").exists())

    def test_apply_request_argument_must_match_signed_bundle(self):
        self.initialize()
        signed = self.sign(self.prepare())
        original = (self.state_dir / "state.json").read_bytes()
        self.apply(signed, request="different-request", expected=2)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)

    def test_prepare_refuses_unauthorized_actor_or_distinct_operator(self):
        self.initialize()
        for keyword in ("actor", "operator"):
            path = self.base / (keyword + "-candidate.json")
            self.prepare(output=path, expected=2, **{keyword: eid("decision-actor", 99)})
            self.assertFalse(path.exists())
        self.assertEqual(self.status()["generation"], 0)

    def test_sign_refuses_actor_and_operator_tampering(self):
        self.initialize()
        original = json.loads(self.prepare().read_text())
        for field in ("decision_actor", "recording_operator"):
            edited = copy.deepcopy(original)
            key = "decision_actor_id" if field == "decision_actor" else "operator_actor_id"
            edited["document"]["body"][field][key] = eid("decision-actor", 99)
            edited["document"] = finalize_document(edited["document"])
            candidate = self.write_json(self.base / (field + "-candidate.json"), edited)
            output = self.sign(candidate, expected=2)
            self.assertFalse(output.exists())
        self.assertEqual(self.status()["generation"], 0)

    def test_tampered_signature_or_payload_cannot_apply(self):
        self.initialize()
        signed = self.sign(self.prepare())
        original = json.loads(signed.read_text())
        for field in ("signature", "decision"):
            edited = copy.deepcopy(original)
            if field == "signature":
                edited["document"]["proofs"][0]["signature"] = base64.b64encode(bytes(64)).decode()
            else:
                edited["document"]["body"]["decision"] = "declined"
            tampered = self.write_json(self.base / (field + "-tampered.json"), edited)
            self.apply(tampered, expected=2)
        self.assertEqual(self.status()["generation"], 0)

    def test_separate_report_must_match_embedded_report_exactly(self):
        self.initialize()
        signed = self.sign(self.prepare())
        report = json.loads(signed.read_text())["report"]
        edited = copy.deepcopy(report)
        edited["verification_time"] = "2032-01-02T03:04:07Z"
        supplied = self.write_json(self.base / "report.json", edited)
        self.apply(signed, report=supplied, expected=2)
        self.assertEqual(self.status()["generation"], 0)
        self.write_json(supplied, report)
        self.apply(signed, report=supplied)
        self.assertEqual(self.status()["generation"], 1)

    def test_changed_current_target_refuses_stale_signed_report(self):
        self.setup_source(criticality="required_source")
        self.initialize()
        signed = self.sign(self.prepare())
        self.target.write_bytes(b"changed after verification")
        self.apply(signed, expected=2)
        self.assertEqual(self.status()["generation"], 0)

    def test_prepare_and_sign_refuse_existing_output_without_overwrite(self):
        self.initialize()
        candidate = self.prepare()
        original = candidate.read_bytes()
        self.prepare(output=candidate, expected=2)
        self.assertEqual(candidate.read_bytes(), original)
        signed = self.sign(candidate)
        original = signed.read_bytes()
        self.sign(candidate, output=signed, expected=2)
        self.assertEqual(signed.read_bytes(), original)

    def test_sign_refuses_symlink_output_and_unsafe_key_mode(self):
        self.initialize()
        candidate = self.prepare()
        outside = self.base / "must-stay-unchanged"
        outside.write_bytes(b"unchanged")
        link = self.base / "output-symlink.json"
        link.symlink_to(outside)
        self.sign(candidate, output=link, expected=2)
        self.assertEqual(outside.read_bytes(), b"unchanged")
        self.key_file.chmod(0o644)
        output = self.sign(candidate, expected=2)
        self.assertFalse(output.exists())

    def test_state_output_and_key_refuse_even_a_different_git_marked_checkout(self):
        checkout = self.base / "synthetic-checkout"
        checkout.mkdir(mode=0o700)
        (checkout / ".git").mkdir(mode=0o700)
        private_state = self.state_dir
        self.state_dir = checkout / "state"
        self.initialize(expected=2)
        self.assertFalse(self.state_dir.exists())
        self.state_dir = private_state
        self.initialize()
        candidate = self.prepare()
        forbidden_candidate = checkout / "candidate.json"
        self.prepare(output=forbidden_candidate, expected=2)
        self.assertFalse(forbidden_candidate.exists())
        forbidden_signed = checkout / "signed.json"
        self.sign(candidate, output=forbidden_signed, expected=2)
        self.assertFalse(forbidden_signed.exists())
        self.key_file = checkout / "synthetic-private.pem"
        self.key_file.write_bytes(self.pem)
        self.key_file.chmod(0o600)
        output = self.sign(candidate, expected=2)
        self.assertFalse(output.exists())
        self.assertEqual(self.status()["generation"], 0)

    def test_candidate_and_signed_bundle_inside_other_git_checkout_are_refused(self):
        self.initialize()
        candidate = self.prepare()
        signed = self.sign(candidate)
        original = (self.state_dir / "state.json").read_bytes()
        checkout = self.base / "other-synthetic-checkout"
        checkout.mkdir(mode=0o700)
        # A .git file also marks linked worktrees; no actual Git state is used.
        (checkout / ".git").write_text("gitdir: synthetic-only\n")
        forbidden_candidate = self.write_json(checkout / "candidate.json",
            json.loads(candidate.read_text()))
        output = self.sign(forbidden_candidate, expected=2)
        self.assertFalse(output.exists())
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)
        forbidden_bundle = self.write_json(checkout / "signed.json",
            json.loads(signed.read_text()))
        self.apply(forbidden_bundle, expected=2)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original)
        self.assertEqual(self.status()["generation"], 0)

    def test_missing_malformed_and_duplicate_json_inputs_are_safe_refusals(self):
        self.initialize()
        for name, raw in (("malformed", b'{'), ("duplicate", b'{"a":1,"a":2}'),
                          ("non-object", b'[]')):
            candidate = self.base / (name + ".json")
            candidate.write_bytes(raw)
            candidate.chmod(0o600)
            output = self.sign(candidate, expected=2)
            self.assertFalse(output.exists())
            self.apply(candidate, expected=2)
        self.sign(self.base / "missing.json", expected=2)
        self.apply(self.base / "missing.json", expected=2)
        self.assertEqual(self.status()["generation"], 0)

    def test_prepare_refuses_different_root_and_invalid_binding(self):
        self.initialize()
        self.write_json(self.root_file, root_document(2))
        self.prepare(expected=2)
        self.write_json(self.root_file, self.root)
        self.bindings = ["--target", "missing-equals"]
        self.prepare(expected=2)
        self.assertFalse((self.base / "request-1-candidate.json").exists())

    def test_checkpoint_verifies_exact_ancestor_and_rejects_wrong_head(self):
        self.initialize()
        self.apply(self.sign(self.prepare()))
        status = self.status()
        checkpoint = {field: status[field] for field in ("store_id", "generation", "journal_head")}
        path = self.write_json(self.base / "trusted-checkpoint.json", checkpoint)
        verified = self.cli("state", "verify", "--state-dir", self.state_dir,
            "--checkpoint", path, "--json")
        self.assertTrue(verified["external_checkpoint_satisfied"])
        self.assertEqual(verified["rollback_protection"], "checkpoint_ancestor_checked")
        checkpoint["journal_head"] = "0" * 64
        self.write_json(path, checkpoint)
        self.cli("state", "verify", "--state-dir", self.state_dir,
            "--checkpoint", path, "--json", expected=2)

    def test_sign_missing_crypto_reports_capability_unavailable(self):
        self.initialize()
        candidate = self.prepare()
        output = self.sign(candidate, no_site=True, expected=10)
        self.assertFalse(output.exists())
        self.assertEqual(self.status()["generation"], 0)


if __name__ == "__main__":
    unittest.main()
