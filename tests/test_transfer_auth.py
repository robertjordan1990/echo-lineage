"""Synthetic policy/scope/signature tests; no installation or user keys."""
from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from lineage_test_helpers import acceptance_document, eid, handoff_document
from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
from tools.tools.echo_lineage import (build_proof_payload, finalize_document,
                                      proof_message_bytes, validate_document)
from tools.tools.echo_lineage_auth import (
    CryptoUnavailable, policy_digest as lineage_policy_digest,
    verify_acceptance_signature,
)
from tools.tools.echo_transfer_auth import (
    TransferAuthError, digest, policy_digest, sign_packet, sign_protocol_document,
    validate_policy, verify_packet, verify_protocol_document,
)


def synthetic_key(number=1):
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)


def public(number):
    return base64.b64encode(synthetic_key(number).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")


def lineage_key(number=2, *, installation=2, actor=4):
    return {"key_id": eid("key", number), "public_key": public(number),
            "decision_actor_id": eid("decision-actor", actor),
            "installation_id": eid("installation", installation),
            "decision_mode": "human_operator", "purpose": "lineage_acceptance"}


def transfer_policy():
    source_policy = {"schema": "echo-lineage-trust/v1", "keys": [
        lineage_key(1, installation=1, actor=3)]}
    return {"schema": "echo-lineage-transfer-trust/v1", "profile": "2C-h1-bound",
        "transfer_id": eid("handoff", 1),
        "source_pin": {"store_id": "00000000-0000-4000-8000-000000000001",
            "installation_id": eid("installation", 1), "snapshot_digest": "a" * 64,
            "acceptance_policy_digest": lineage_policy_digest(source_policy)},
        "recipient": {"store_id": "00000000-0000-4000-8000-000000000002",
            "installation_id": eid("installation", 2),
            "lineage_policy": {"schema": "echo-lineage-trust/v1", "keys": [lineage_key()]}},
        "keys": [
            {"key_id": eid("key", 1), "public_key": public(1),
             "actor_id": eid("decision-actor", 3), "installation_id": eid("installation", 1),
             "role": "human_operator", "purposes": ["state_migration", "handoff_issue",
                 "transfer_export", "remote_receipt_ingest"]},
            {"key_id": eid("key", 2), "public_key": public(2),
             "actor_id": eid("decision-actor", 4), "installation_id": eid("installation", 2),
             "role": "human_operator", "purposes": ["transfer_receive", "transfer_receipt",
                 "receiver_decision", "context_import_authorize", "context_activation_authorize",
                 "context_deactivate"]},
            {"key_id": eid("key", 3), "public_key": public(3),
             "actor_id": eid("artifact", 99), "installation_id": eid("installation", 2),
             "role": "local_context_consumer", "purposes": ["context_consumption_receipt"]}],
        "consumer": {"consumer_id": eid("artifact", 99), "key_id": eid("key", 3),
            "version": "context-consumer-v1", "code_digest": "f" * 64,
            "capabilities": ["read", "search"]}}


def recipient_acceptance():
    document = acceptance_document()
    document["body"]["installation_id"] = eid("installation", 2)
    document["body"]["decision_actor"]["decision_actor_id"] = eid("decision-actor", 4)
    document["body"]["recording_operator"]["operator_actor_id"] = eid("decision-actor", 4)
    return finalize_document(document)


class PolicyTests(unittest.TestCase):
    def test_policy_is_detached_and_digest_has_distinct_domain(self):
        supplied = transfer_policy()
        result = validate_policy(supplied)
        self.assertEqual(result, supplied)
        result["keys"][0]["purposes"].clear()
        self.assertTrue(supplied["keys"][0]["purposes"])
        self.assertEqual(policy_digest(supplied), sha256_hex(
            b"ECHO|TRANSFER|v1|POLICY|" + canon_json_bytes(supplied)))
        self.assertNotEqual(policy_digest(supplied), digest("EVENT", supplied))

    def test_all_policy_objects_are_closed(self):
        for location in ("policy", "source_pin", "recipient", "consumer", "key", "lineage_key"):
            candidate = transfer_policy()
            target = (candidate if location == "policy" else
                      candidate["keys"][0] if location == "key" else
                      candidate["recipient"]["lineage_policy"]["keys"][0]
                      if location == "lineage_key" else candidate[location])
            target["authenticated"] = True
            with self.subTest(location=location), self.assertRaises(TransferAuthError):
                validate_policy(candidate)

    def test_every_outer_field_required(self):
        for field in transfer_policy():
            candidate = transfer_policy()
            del candidate[field]
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                validate_policy(candidate)

    def test_all_identity_and_digest_types_are_checked(self):
        mutations = [
            (lambda p: p, "transfer_id", eid("artifact", 1)),
            (lambda p: p["source_pin"], "store_id", "../private-path"),
            (lambda p: p["recipient"], "installation_id", True),
            (lambda p: p["source_pin"], "snapshot_digest", "A" * 64),
            (lambda p: p["source_pin"], "acceptance_policy_digest", "0" * 63),
            (lambda p: p["consumer"], "code_digest", True),
            (lambda p: p["keys"][0], "actor_id", eid("artifact", 1)),
            (lambda p: p["keys"][2], "actor_id", eid("decision-actor", 1)),
            (lambda p: p["keys"][0], "key_id", eid("handoff", 1)),
        ]
        for target, field, bad in mutations:
            candidate = transfer_policy()
            target(candidate)[field] = bad
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                validate_policy(candidate)

    def test_source_and_recipient_must_be_different_stores_and_installations(self):
        for field in ("store_id", "installation_id"):
            candidate = transfer_policy()
            candidate["recipient"][field] = candidate["source_pin"][field]
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                validate_policy(candidate)

    def test_grants_require_explicit_unique_allowed_purposes(self):
        for purposes in ([], ["handoff_issue", "handoff_issue"], ["all"],
                         ["lineage_acceptance"], [True], "handoff_issue"):
            candidate = transfer_policy()
            candidate["keys"][0]["purposes"] = purposes
            with self.subTest(purposes=purposes), self.assertRaises(TransferAuthError):
                validate_policy(candidate)

    def test_grants_cannot_cross_installations(self):
        for key_index in (0, 1, 2):
            candidate = transfer_policy()
            candidate["keys"][key_index]["installation_id"] = eid("installation", 9)
            with self.subTest(key=key_index), self.assertRaises(TransferAuthError):
                validate_policy(candidate)
        candidate = transfer_policy()
        candidate["keys"][0]["purposes"].append("receiver_decision")
        with self.assertRaises(TransferAuthError):
            validate_policy(candidate)

    def test_consumer_is_pinned_adapter_with_only_consumption_purpose(self):
        for field, bad in (("version", "new-version"), ("capabilities", ["read", "search", "execute"]),
                           ("consumer_id", eid("artifact", 100)), ("key_id", eid("key", 1))):
            candidate = transfer_policy()
            candidate["consumer"][field] = bad
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                validate_policy(candidate)
        candidate = transfer_policy()
        candidate["keys"][2]["purposes"].append("receiver_decision")
        with self.assertRaisesRegex(TransferAuthError, "CONSUMER_PURPOSE_DENIED"):
            validate_policy(candidate)

    def test_consumption_receipt_authority_cannot_be_granted_to_a_human(self):
        candidate = transfer_policy()
        candidate["keys"][1]["purposes"].append("context_consumption_receipt")
        with self.assertRaisesRegex(TransferAuthError, "CONSUMER_ROLE_REQUIRED"):
            validate_policy(candidate)

    def test_consumer_cannot_also_be_v1_human_acceptance_key(self):
        for field in ("public_key", "key_id"):
            candidate = transfer_policy()
            candidate["recipient"]["lineage_policy"]["keys"][0][field] = candidate["keys"][2][field]
            with self.subTest(field=field), self.assertRaisesRegex(
                    TransferAuthError, "CONSUMER_IS_NOT_HUMAN_OPERATOR"):
                validate_policy(candidate)

    def test_nested_lineage_policy_is_validated_independently(self):
        for field, bad in (("installation_id", eid("installation", 1)),
                           ("purpose", "receiver_decision"), ("decision_mode", "model_session")):
            candidate = transfer_policy()
            candidate["recipient"]["lineage_policy"]["keys"][0][field] = bad
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                validate_policy(candidate)

    def test_duplicate_keys_are_refused(self):
        for field in ("key_id", "public_key"):
            candidate = transfer_policy()
            candidate["keys"][1][field] = candidate["keys"][0][field]
            with self.subTest(field=field), self.assertRaisesRegex(TransferAuthError, "DUPLICATE_POLICY_KEY"):
                validate_policy(candidate)

    def test_weak_noncanonical_and_off_curve_public_keys_refused_before_crypto(self):
        values = [b"\x01" + bytes(31), bytes(32), (2).to_bytes(32, "little"),
                  (2**255 - 19).to_bytes(32, "little")]
        for raw in values:
            candidate = transfer_policy()
            candidate["keys"][0]["public_key"] = base64.b64encode(raw).decode("ascii")
            with self.subTest(raw=raw.hex()), mock.patch(
                    "tools.tools.echo_transfer_auth._crypto", side_effect=AssertionError("crypto")):
                with self.assertRaises(TransferAuthError):
                    validate_policy(candidate)

    def test_key_encoding_must_be_canonical_and_exact_length(self):
        for bad in (public(1).rstrip("="), public(1) + "\n", "!" * 44,
                    base64.b64encode(b"x" * 31).decode("ascii")):
            candidate = transfer_policy()
            candidate["keys"][0]["public_key"] = bad
            with self.subTest(value=bad), self.assertRaises(TransferAuthError):
                validate_policy(candidate)

    def test_key_count_is_bounded(self):
        for count in (0, 257):
            candidate = transfer_policy()
            candidate["keys"] = [candidate["keys"][0]] * count
            with self.subTest(count=count), self.assertRaisesRegex(TransferAuthError, "INVALID_KEY_COUNT"):
                validate_policy(candidate)

    def test_digest_normalizes_nfc_and_rejects_ambiguous_domains_values_and_depth(self):
        self.assertEqual(digest("TEST", {"x": "e\u0301"}), digest("TEST", {"x": "é"}))
        for domain in ("", "A|B", True, "é"):
            with self.subTest(domain=domain), self.assertRaises(TransferAuthError):
                digest(domain, {})
        deep = []
        for _ in range(66):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        for value in ({1: "x"}, {"é": 1, "e\u0301": 2}, float("nan"), deep, cycle,
                      {"private": "x" * (4 * 1024 * 1024)}):
            with self.subTest(kind=type(value).__name__), self.assertRaises(TransferAuthError):
                digest("TEST", value)

    def test_module_import_and_policy_validation_do_not_load_crypto(self):
        script = """
import builtins, json, sys
original = builtins.__import__
def restricted(name, *args, **kwargs):
    if name == 'cryptography' or name.startswith('cryptography.'):
        raise AssertionError('crypto imported eagerly')
    return original(name, *args, **kwargs)
builtins.__import__ = restricted
from tools.tools.echo_transfer_auth import validate_policy
assert validate_policy(json.loads(sys.stdin.read()))['profile'] == '2C-h1-bound'
"""
        result = subprocess.run([sys.executable, "-B", "-c", script],
            input=canon_json_bytes(transfer_policy()).decode("utf-8"), text=True,
            capture_output=True, cwd=Path(__file__).resolve().parents[1], check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.paths = {}
        for number in (1, 2, 3, 4):
            path = Path(self.directory.name) / f"synthetic-{number}.pem"
            path.write_bytes(synthetic_key(number).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            path.chmod(0o600)
            self.paths[number] = path
        self.policy = transfer_policy()

    def packet(self, **kwargs):
        return sign_packet({"kind": "synthetic", "text": "$(inert); rm -rf /"},
            self.policy, self.paths[1], purpose="handoff_issue",
            actor_id=eid("decision-actor", 3), installation_id=eid("installation", 1), **kwargs)

    def test_roundtrip_returns_detached_payload_and_mutates_nothing(self):
        before = copy.deepcopy(self.policy)
        packet = self.packet()
        original = copy.deepcopy(packet)
        payload = verify_packet(packet, self.policy, purpose="handoff_issue",
            actor_id=eid("decision-actor", 3), installation_id=eid("installation", 1))
        self.assertEqual(payload, packet["payload"])
        payload["text"] = "changed"
        self.assertEqual(packet, original)
        self.assertEqual(self.policy, before)

    def test_all_operator_and_consumer_purposes_roundtrip(self):
        for key in self.policy["keys"]:
            for purpose in key["purposes"]:
                number = int(key["key_id"].rsplit("-", 1)[1])
                packet = sign_packet({"kind": purpose}, self.policy, self.paths[number],
                    purpose=purpose, actor_id=key["actor_id"], installation_id=key["installation_id"],
                    role=key["role"])
                with self.subTest(purpose=purpose):
                    self.assertEqual(verify_packet(packet, self.policy, purpose=purpose,
                        role=key["role"]), {"kind": purpose})

    def test_every_signed_field_and_payload_are_authenticated(self):
        changes = {"schema": "different", "policy_digest": "b" * 64,
                   "purpose": "transfer_export", "actor_id": eid("decision-actor", 8),
                   "installation_id": eid("installation", 2), "role": "local_context_consumer",
                   "payload": {"kind": "forged"}}
        for field, value in changes.items():
            packet = self.packet()
            packet[field] = value
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                verify_packet(packet, self.policy, purpose="handoff_issue")

    def test_purpose_domain_separation_even_when_both_grants_exist(self):
        packet = self.packet()
        packet["purpose"] = "transfer_export"
        with self.assertRaisesRegex(TransferAuthError, "SIGNATURE_INVALID"):
            verify_packet(packet, self.policy, purpose="transfer_export")

    def test_independently_supplied_policy_and_explicit_expectations_must_match(self):
        packet = self.packet()
        changed = transfer_policy()
        changed["consumer"]["code_digest"] = "e" * 64
        for kwargs in ({"policy": changed}, {"actor_id": eid("decision-actor", 4)},
                       {"installation_id": eid("installation", 2)},
                       {"purpose": "transfer_export"}, {"role": "local_context_consumer"}):
            args = {"policy": self.policy, "purpose": "handoff_issue", **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(TransferAuthError):
                verify_packet(packet, **args)

    def test_packet_and_proof_shapes_are_closed_and_required(self):
        for location in ("packet", "proof"):
            packet = self.packet()
            (packet if location == "packet" else packet["proof"])["authenticated"] = True
            with self.subTest(location=location), self.assertRaises(TransferAuthError):
                verify_packet(packet, self.policy, purpose="handoff_issue")
        for field in self.packet():
            packet = self.packet()
            del packet[field]
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                verify_packet(packet, self.policy, purpose="handoff_issue")

    def test_proof_key_algorithm_and_signature_encoding_are_checked(self):
        for field, bad in (("key_id", eid("key", 2)), ("algorithm", "none"),
                           ("signature", "!" * 88), ("signature", "AA=="),
                           ("signature", base64.b64encode(bytes(64)).decode("ascii"))):
            packet = self.packet()
            packet["proof"][field] = bad
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                verify_packet(packet, self.policy, purpose="handoff_issue")

    def test_consumer_receipt_cannot_be_verified_as_human_consent(self):
        packet = sign_packet({"kind": "loaded"}, self.policy, self.paths[3],
            purpose="context_consumption_receipt", actor_id=eid("artifact", 99),
            installation_id=eid("installation", 2), role="local_context_consumer")
        with self.assertRaises(TransferAuthError):
            verify_packet(packet, self.policy, purpose="context_consumption_receipt")
        with self.assertRaises(TransferAuthError):
            sign_packet({}, self.policy, self.paths[3], purpose="receiver_decision",
                actor_id=eid("artifact", 99), installation_id=eid("installation", 2),
                role="local_context_consumer")

    def test_scope_and_payload_refusals_happen_before_private_key_read(self):
        with mock.patch("tools.tools.echo_transfer_auth._read_private_key",
                        side_effect=AssertionError("must not read a key")):
            for payload, purpose, actor, installation in (
                    ({}, "all", 3, 1), ({}, "handoff_issue", 4, 1),
                    ({}, "handoff_issue", 3, 2), ([], "handoff_issue", 3, 1),
                    ({"x": "x" * (4 * 1024 * 1024)}, "handoff_issue", 3, 1)):
                with self.subTest(purpose=purpose, actor=actor), self.assertRaises(TransferAuthError):
                    sign_packet(payload, self.policy, self.paths[1], purpose=purpose,
                        actor_id=eid("decision-actor", actor), installation_id=eid("installation", installation))

    def test_private_key_permissions_links_and_algorithm_are_refused_without_paths(self):
        self.paths[1].chmod(0o644)
        with self.assertRaises(TransferAuthError) as caught:
            self.packet()
        self.assertNotIn(str(self.paths[1]), str(caught.exception))
        self.paths[1].chmod(0o600)
        link = Path(self.directory.name) / "link.pem"
        link.symlink_to(self.paths[1])
        for key_file in (link, self.paths[4]):
            with self.subTest(path=key_file.name), self.assertRaises(TransferAuthError):
                sign_packet({}, self.policy, key_file, purpose="handoff_issue",
                    actor_id=eid("decision-actor", 3), installation_id=eid("installation", 1))
        self.paths[1].write_bytes(x25519.X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        with self.assertRaisesRegex(TransferAuthError, "SIGNING_KEY_NOT_ED25519"):
            self.packet()

    def test_crypto_unavailable_is_distinct_path_free_failure(self):
        packet = self.packet()
        with mock.patch("tools.tools.echo_transfer_auth._crypto", side_effect=CryptoUnavailable("private/path")):
            with self.assertRaisesRegex(TransferAuthError, "^AUTHENTICATION_UNAVAILABLE$"):
                self.packet()
            with self.assertRaisesRegex(TransferAuthError, "^AUTHENTICATION_UNAVAILABLE$"):
                verify_packet(packet, self.policy, purpose="handoff_issue")

    def test_handoff_uses_unchanged_v1_proof_payload_domain(self):
        document = handoff_document()
        signed = sign_protocol_document(document, self.policy, self.paths[1], purpose="handoff_issue",
            actor_id=eid("decision-actor", 3), installation_id=eid("installation", 1))
        self.assertEqual(document["proofs"], [])
        self.assertEqual(signed["document_hash"], document["document_hash"])
        validate_document(signed)
        self.assertEqual(signed["proofs"][0]["signed_payload"], build_proof_payload(document))
        synthetic_key(1).public_key().verify(base64.b64decode(signed["proofs"][0]["signature"]),
                                             proof_message_bytes(document))
        result = verify_protocol_document(signed, self.policy, purpose="handoff_issue")
        self.assertEqual(result["actor_id"], eid("decision-actor", 3))
        self.assertEqual(result["policy_digest"], policy_digest(self.policy))

    def test_acceptance_is_a_separate_actual_v1_signature_from_nested_policy(self):
        document = recipient_acceptance()
        signed = sign_protocol_document(document, self.policy, self.paths[2], purpose="lineage_acceptance",
            actor_id=eid("decision-actor", 4), installation_id=eid("installation", 2))
        old_evidence = verify_acceptance_signature(signed, self.policy["recipient"]["lineage_policy"])
        self.assertEqual(old_evidence["key_id"], eid("key", 2))
        evidence = verify_protocol_document(signed, self.policy, purpose="lineage_acceptance")
        self.assertEqual(evidence["purpose"], "lineage_acceptance")
        self.assertEqual(evidence["installation_id"], eid("installation", 2))

    def test_control_grant_does_not_infer_lineage_acceptance_authority(self):
        candidate = transfer_policy()
        candidate["recipient"]["lineage_policy"]["keys"] = [lineage_key(4)]
        with self.assertRaisesRegex(TransferAuthError, "SIGNING_KEY_NOT_AUTHORIZED"):
            sign_protocol_document(recipient_acceptance(), candidate, self.paths[2],
                purpose="lineage_acceptance", actor_id=eid("decision-actor", 4),
                installation_id=eid("installation", 2))
        # Independently provisioned acceptance-only key works without a control grant.
        signed = sign_protocol_document(recipient_acceptance(), candidate, self.paths[4],
            purpose="lineage_acceptance", actor_id=eid("decision-actor", 4),
            installation_id=eid("installation", 2))
        self.assertEqual(verify_protocol_document(signed, candidate,
            purpose="lineage_acceptance")["key_id"], eid("key", 4))

    def test_protocol_actor_installation_recipient_and_purpose_must_match(self):
        for purpose, actor, installation in (("handoff_issue", 4, 1), ("handoff_issue", 3, 2),
                                            ("receiver_decision", 3, 1), ("lineage_acceptance", 3, 1)):
            with self.subTest(purpose=purpose, actor=actor), self.assertRaises(TransferAuthError):
                sign_protocol_document(handoff_document(), self.policy, self.paths[1], purpose=purpose,
                    actor_id=eid("decision-actor", actor), installation_id=eid("installation", installation))
        for field, value in (("handoff_id", eid("handoff", 2)),
                             ("recipient_binding", {"mode": "unbound", "recipient_installation_id": None})):
            document = handoff_document()
            document["body"][field] = value
            document = finalize_document(document)
            with self.subTest(field=field), self.assertRaises(TransferAuthError):
                sign_protocol_document(document, self.policy, self.paths[1], purpose="handoff_issue",
                    actor_id=eid("decision-actor", 3), installation_id=eid("installation", 1))

    def test_acceptance_requires_same_actual_human_actor_and_recording_operator(self):
        document = recipient_acceptance()
        document["body"]["recording_operator"]["operator_actor_id"] = eid("decision-actor", 8)
        document = finalize_document(document)
        with self.assertRaisesRegex(TransferAuthError, "ACCEPTANCE_HUMAN_SCOPE_REQUIRED"):
            sign_protocol_document(document, self.policy, self.paths[2], purpose="lineage_acceptance",
                actor_id=eid("decision-actor", 4), installation_id=eid("installation", 2))

    def test_protocol_unsigned_multiple_forged_proofs_and_mutated_document_refused(self):
        unsigned = recipient_acceptance()
        signed = sign_protocol_document(unsigned, self.policy, self.paths[2], purpose="lineage_acceptance",
            actor_id=eid("decision-actor", 4), installation_id=eid("installation", 2))
        multiple = copy.deepcopy(signed)
        multiple["proofs"].append(copy.deepcopy(multiple["proofs"][0]))
        forged = copy.deepcopy(signed)
        forged["proofs"][0]["signature"] = base64.b64encode(bytes(64)).decode("ascii")
        mutated = copy.deepcopy(signed)
        mutated["body"]["decision_nonce"] = "ab" * 16
        mutated = finalize_document(mutated)
        for document in (unsigned, multiple, forged, mutated):
            with self.subTest(proofs=len(document["proofs"])), self.assertRaises(TransferAuthError):
                verify_protocol_document(document, self.policy, purpose="lineage_acceptance")
        with self.assertRaisesRegex(TransferAuthError, "PROTOCOL_DOCUMENT_ALREADY_SIGNED"):
            sign_protocol_document(signed, self.policy, self.paths[2], purpose="lineage_acceptance",
                actor_id=eid("decision-actor", 4), installation_id=eid("installation", 2))


if __name__ == "__main__":
    unittest.main()
