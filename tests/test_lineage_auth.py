from __future__ import annotations

import base64
import builtins
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

from lineage_test_helpers import (
    acceptance_document as base_acceptance_document, artifact, digest, eid, root_document,
)
from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
from tools.tools.echo_lineage import (
    build_proof_payload, finalize_document, proof_message_bytes,
    validate_document, verify_document_read_only,
)
from tools.tools.echo_lineage_auth import (
    AUTH_SCOPE, CryptoUnavailable, StateAuthError, policy_digest,
    sign_acceptance_document, validate_policy, verify_acceptance_signature,
)


def acceptance_document(**kwargs) -> dict:
    document = base_acceptance_document(**kwargs)
    document["body"]["recording_operator"]["operator_actor_id"] = (
        document["body"]["decision_actor"]["decision_actor_id"]
    )
    return finalize_document(document)


def synthetic_key(number: int = 1) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)


def policy_key(number: int = 1) -> dict:
    public = synthetic_key(number).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return {
        "key_id": eid("key", number),
        "public_key": base64.b64encode(public).decode("ascii"),
        "decision_actor_id": eid("decision-actor", 1),
        "installation_id": eid("installation", 1),
        "decision_mode": "human_operator",
        "purpose": "lineage_acceptance",
    }


def policy(*numbers: int) -> dict:
    return {"schema": "echo-lineage-trust/v1",
            "keys": [policy_key(number) for number in numbers or (1,)]}


def externally_signed(document: dict, number: int = 1) -> dict:
    result = copy.deepcopy(document)
    result["proofs"] = [{
        "proof_type": "responsibility_head", "algorithm": "ed25519",
        "key_id": eid("key", number),
        "signed_payload": build_proof_payload(result),
        "signature": base64.b64encode(
            synthetic_key(number).sign(proof_message_bytes(result)),
        ).decode("ascii"),
    }]
    return result


class PolicyTests(unittest.TestCase):
    def test_valid_policy_is_detached_and_domain_separated(self) -> None:
        supplied = policy(1, 2)
        normalized = validate_policy(supplied)
        self.assertEqual(normalized, supplied)
        self.assertIsNot(normalized["keys"][0], supplied["keys"][0])
        expected = sha256_hex(b"ECHO|STATE|v1|POLICY|" + canon_json_bytes(supplied))
        self.assertEqual(policy_digest(supplied), expected)
        self.assertNotEqual(policy_digest(policy(1)), policy_digest(policy(2)))

    def test_policy_fields_are_closed(self) -> None:
        for location in ("policy", "key"):
            supplied = policy()
            target = supplied if location == "policy" else supplied["keys"][0]
            target["authenticated"] = True
            with self.subTest(location=location), self.assertRaises(StateAuthError):
                validate_policy(supplied)

    def test_policy_fields_are_required(self) -> None:
        for field in policy_key():
            supplied = policy()
            del supplied["keys"][0][field]
            with self.subTest(field=field), self.assertRaises(StateAuthError):
                validate_policy(supplied)

    def test_typed_ids_reuse_protocol_uuid_rules(self) -> None:
        for field in ("key_id", "decision_actor_id", "installation_id"):
            for bad in (True, eid("trajectory", 1), "urn:echo:key:"
                        "00000000-0000-0000-8000-000000000001"):
                supplied = policy()
                supplied["keys"][0][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(StateAuthError):
                    validate_policy(supplied)

    def test_policy_wrong_types_and_modes_are_refused(self) -> None:
        for supplied in (True, [], {}, {"schema": True, "keys": []},
                         {"schema": "echo-lineage-trust/v1", "keys": True},
                         {"schema": "echo-lineage-trust/v1", "keys": [True]}):
            with self.subTest(value=supplied), self.assertRaises(StateAuthError):
                validate_policy(supplied)
        for field in policy_key():
            supplied = policy()
            supplied["keys"][0][field] = True
            with self.subTest(field=field), self.assertRaises(StateAuthError):
                validate_policy(supplied)

    def test_policy_key_count_is_bounded(self) -> None:
        for keys in ([], [policy_key()] * 257):
            with self.subTest(count=len(keys)), self.assertRaises(StateAuthError):
                validate_policy({"schema": "echo-lineage-trust/v1", "keys": keys})

    def test_duplicate_key_ids_or_public_keys_are_refused(self) -> None:
        for field in ("key_id", "public_key"):
            supplied = policy(1, 2)
            supplied["keys"][1][field] = supplied["keys"][0][field]
            with self.subTest(field=field), self.assertRaises(StateAuthError):
                validate_policy(supplied)

    def test_public_key_base64_is_canonical_and_exact_length(self) -> None:
        valid = policy_key()["public_key"]
        bad_values = [valid.rstrip("="), valid + "\n", "!" * 44,
                      base64.b64encode(b"x" * 31).decode(),
                      base64.b64encode(b"x" * 33).decode(),
                      valid[:-2] + "B="]
        for bad in bad_values:
            supplied = policy()
            supplied["keys"][0]["public_key"] = bad
            with self.subTest(public_key=bad), self.assertRaises(StateAuthError):
                validate_policy(supplied)

    def test_all_eight_canonical_torsion_points_are_refused(self) -> None:
        # Published libsodium 1.0.20 small-order table, with both x signs for
        # order-4/order-8 points and the sole canonical sign for x=0 points.
        order8_y = (
            bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
            bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        )
        p = 2**255 - 19
        points = [(1).to_bytes(32, "little"), (p - 1).to_bytes(32, "little")]
        for unsigned in (bytes(32), *order8_y):
            points.extend((unsigned, unsigned[:-1] + bytes([unsigned[-1] | 0x80])))
        self.assertEqual(len(set(points)), 8)
        for raw in points:
            supplied = policy()
            supplied["keys"][0]["public_key"] = base64.b64encode(raw).decode("ascii")
            with self.subTest(point=raw.hex()), self.assertRaisesRegex(StateAuthError, "small-order"):
                validate_policy(supplied)

    def test_all_noncanonical_y_values_and_zero_x_sign_aliases_are_refused(self) -> None:
        p = 2**255 - 19
        encodings = [((sign << 255) | y).to_bytes(32, "little")
                     for y in range(p, 2**255) for sign in (0, 1)]
        encodings.extend(((1 << 255) | y).to_bytes(32, "little") for y in (1, p - 1))
        self.assertEqual(len(encodings), 40)
        for raw in encodings:
            supplied = policy()
            supplied["keys"][0]["public_key"] = base64.b64encode(raw).decode("ascii")
            with self.subTest(point=raw.hex()), self.assertRaisesRegex(StateAuthError, "canonical"):
                validate_policy(supplied)

    def test_off_curve_public_key_is_refused(self) -> None:
        supplied = policy()
        supplied["keys"][0]["public_key"] = base64.b64encode((2).to_bytes(32, "little")).decode("ascii")
        with self.assertRaisesRegex(StateAuthError, "curve point"):
            validate_policy(supplied)

    def test_generated_public_keys_fill_policy_without_false_rejections(self) -> None:
        self.assertEqual(len(validate_policy(policy(*range(256)))["keys"]), 256)

    def test_only_acceptance_human_operator_scope_is_available(self) -> None:
        for field, values in (("decision_mode", ("model_session", "joint_human_model",
                                               "system_policy", "imported_historical_claim")),
                              ("purpose", ("trajectory_root", "handoff", "all"))):
            for value in values:
                supplied = policy()
                supplied["keys"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(StateAuthError):
                    validate_policy(supplied)


class SignatureTests(unittest.TestCase):
    def test_identity_key_forgery_is_refused_before_backend_verification(self) -> None:
        forged = acceptance_document()
        forged["proofs"] = [{
            "proof_type": "responsibility_head", "algorithm": "ed25519",
            "key_id": eid("key", 1), "signed_payload": build_proof_payload(forged),
            "signature": base64.b64encode(b"\x01" + bytes(63)).decode("ascii"),
        }]
        weak_policy = policy()
        weak_policy["keys"][0]["public_key"] = base64.b64encode(b"\x01" + bytes(31)).decode("ascii")
        validate_document(forged)
        with mock.patch("tools.tools.echo_lineage_auth._crypto", side_effect=AssertionError("weak key must be refused first")):
            with self.assertRaisesRegex(StateAuthError, "small-order"):
                verify_acceptance_signature(forged, weak_policy)

    def test_external_signature_produces_exact_scoped_evidence(self) -> None:
        signed = externally_signed(acceptance_document())
        before = copy.deepcopy(signed)
        validate_document(signed)
        self.assertEqual(verify_acceptance_signature(signed, policy()), {
            "key_id": eid("key", 1), "decision_actor_id": eid("decision-actor", 1),
            "installation_id": eid("installation", 1),
            "policy_digest": policy_digest(policy()), "scope": AUTH_SCOPE,
        })
        self.assertEqual(signed, before)

    def test_unsigned_and_multiple_proofs_are_refused(self) -> None:
        unsigned = acceptance_document()
        first = externally_signed(unsigned)
        first["proofs"].extend(externally_signed(unsigned, 2)["proofs"])
        for document in (unsigned, first):
            with self.subTest(count=len(document["proofs"])), self.assertRaises(StateAuthError):
                verify_acceptance_signature(document, policy(1, 2))

    def test_unknown_key_is_refused_even_with_valid_signature(self) -> None:
        with self.assertRaises(StateAuthError):
            verify_acceptance_signature(externally_signed(acceptance_document(), 2), policy())

    def test_wrong_known_key_cannot_borrow_another_key_id(self) -> None:
        signed = externally_signed(acceptance_document(), 2)
        signed["proofs"][0]["key_id"] = eid("key", 1)
        with self.assertRaises(StateAuthError):
            verify_acceptance_signature(signed, policy(1, 2))

    def test_policy_actor_and_installation_are_required(self) -> None:
        for field, kind in (("decision_actor_id", "decision-actor"),
                            ("installation_id", "installation")):
            scoped = policy()
            scoped["keys"][0][field] = eid(kind, 2)
            with self.subTest(field=field), self.assertRaises(StateAuthError):
                verify_acceptance_signature(externally_signed(acceptance_document()), scoped)

    def test_distinct_recording_operator_requires_authenticated_delegation(self) -> None:
        document = acceptance_document()
        document["body"]["recording_operator"]["operator_actor_id"] = eid("decision-actor", 3)
        document = finalize_document(document)
        signed = externally_signed(document)
        validate_document(signed)
        # The actor's signature is cryptographically valid; this first profile
        # still cannot authenticate a second person's recording/delegation role.
        synthetic_key().public_key().verify(
            base64.b64decode(signed["proofs"][0]["signature"]), proof_message_bytes(signed),
        )
        with self.assertRaisesRegex(StateAuthError, "authenticated delegation"):
            verify_acceptance_signature(signed, policy())
        with mock.patch("os.open", side_effect=AssertionError("must not read private key")):
            with self.assertRaisesRegex(StateAuthError, "authenticated delegation"):
                sign_acceptance_document(document, policy(), Path("unused-synthetic-key.pem"))

    def test_all_other_structurally_valid_modes_are_refused(self) -> None:
        for mode in ("model_session", "joint_human_model", "system_policy",
                     "imported_historical_claim"):
            document = acceptance_document(
                decision_mode=mode, include_evidence=True, decision="declined",
            )
            actor = document["body"]["decision_actor"]
            if mode == "system_policy":
                actor["policy_artifact_ref"] = artifact(91)
            if mode == "imported_historical_claim":
                actor["historical_claim_artifact_ref"] = artifact(91)
            document = externally_signed(finalize_document(document))
            validate_document(document)
            with self.subTest(mode=mode), self.assertRaises(StateAuthError):
                verify_acceptance_signature(document, policy())

    def test_signature_binds_report_actor_nonce_and_operator(self) -> None:
        signed = externally_signed(acceptance_document())
        mutations = (
            ("verification_report_hash", digest("f")),
            ("decision_nonce", "34" * 16),
            ("decision_actor", {"decision_actor_id": eid("decision-actor", 2),
                                "decision_mode": "human_operator"}),
        )
        for field, value in mutations:
            changed = copy.deepcopy(signed)
            changed["body"][field] = value
            changed = finalize_document(changed)
            changed["proofs"][0]["signed_payload"] = build_proof_payload(changed)
            with self.subTest(field=field), self.assertRaises(StateAuthError):
                verify_acceptance_signature(changed, policy())
        changed = copy.deepcopy(signed)
        changed["body"]["recording_operator"]["operator_actor_id"] = eid("decision-actor", 4)
        changed = finalize_document(changed)
        changed["proofs"][0]["signed_payload"] = build_proof_payload(changed)
        with self.assertRaises(StateAuthError):
            verify_acceptance_signature(changed, policy())

    def test_signature_bytes_and_lengths_are_verified(self) -> None:
        valid = externally_signed(acceptance_document())
        for bad in (base64.b64encode(b"x" * 64).decode(),
                    base64.b64encode(b"x" * 63).decode(),
                    base64.b64encode(b"x" * 65).decode(),
                    valid["proofs"][0]["signature"].rstrip("="), "A" * 86 + "B="):
            signed = copy.deepcopy(valid)
            signed["proofs"][0]["signature"] = bad
            with self.subTest(signature=bad), self.assertRaises(StateAuthError):
                verify_acceptance_signature(signed, policy())

    def test_only_finalized_acceptance_documents_are_authenticated(self) -> None:
        raw = acceptance_document()
        raw.pop("document_hash")
        for document in (raw, root_document(), True):
            with self.subTest(document_type=type(document)), self.assertRaises(StateAuthError):
                verify_acceptance_signature(document, policy())

    def test_authentication_does_not_promote_stage2a_or_validate_report(self) -> None:
        signed = externally_signed(acceptance_document())
        verify_acceptance_signature(signed, policy())
        code, report = verify_document_read_only(signed)
        self.assertEqual(code, 10)
        self.assertEqual(report["status"], "structure_valid_attribution_unverified")
        self.assertEqual(report["proof_status"], "structure_valid_signature_unverified")

    def test_unavailable_crypto_fails_closed(self) -> None:
        original_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("synthetic unavailable capability")
            return original_import(name, *args, **kwargs)

        signed = externally_signed(acceptance_document())
        trusted_policy = policy()
        with mock.patch("builtins.__import__", side_effect=blocked):
            self.assertEqual(validate_policy(trusted_policy), trusted_policy)
            with self.assertRaises(CryptoUnavailable):
                verify_acceptance_signature(signed, trusted_policy)
            with self.assertRaises(CryptoUnavailable):
                sign_acceptance_document(
                    acceptance_document(), trusted_policy, Path("unused-synthetic-key.pem"),
                )

    def test_module_import_does_not_import_optional_cryptography(self) -> None:
        script = """
import builtins
original = builtins.__import__
def blocked(name, *args, **kwargs):
    if name == 'cryptography' or name.startswith('cryptography.'):
        raise AssertionError('optional crypto imported eagerly')
    return original(name, *args, **kwargs)
builtins.__import__ = blocked
import tools.tools.echo_lineage_auth
"""
        result = subprocess.run([sys.executable, "-B", "-c", script],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


class SigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic-key.pem"
        self.path.write_bytes(synthetic_key().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        self.path.chmod(0o600)

    def sign(self, document: dict | None = None, scoped: dict | None = None) -> dict:
        return sign_acceptance_document(
            acceptance_document() if document is None else document,
            policy() if scoped is None else scoped, self.path,
        )

    def test_roundtrip_changes_only_proofs(self) -> None:
        document = acceptance_document()
        original = copy.deepcopy(document)
        signed = self.sign(document)
        validate_document(signed)
        self.assertEqual(signed, externally_signed(document))
        self.assertEqual({key: value for key, value in signed.items() if key != "proofs"},
                         {key: value for key, value in document.items() if key != "proofs"})
        self.assertEqual(document, original)
        self.assertEqual(verify_acceptance_signature(signed, policy())["scope"], AUTH_SCOPE)

    def test_decline_is_signed_without_activation_assertions(self) -> None:
        signed = self.sign(acceptance_document(decision="declined"))
        self.assertEqual(signed["body"]["effect"], "non_activating")
        self.assertEqual(verify_acceptance_signature(signed, policy())["key_id"], eid("key", 1))

    def test_existing_proof_cannot_be_overwritten(self) -> None:
        with self.assertRaises(StateAuthError):
            self.sign(externally_signed(acceptance_document()))

    def test_signing_requires_matching_policy_key(self) -> None:
        with self.assertRaises(StateAuthError):
            self.sign(scoped=policy(2))

    def test_signing_checks_actor_and_installation_scope(self) -> None:
        for field, kind in (("decision_actor_id", "decision-actor"),
                            ("installation_id", "installation")):
            scoped = policy()
            scoped["keys"][0][field] = eid(kind, 2)
            with self.subTest(field=field), self.assertRaises(StateAuthError):
                self.sign(scoped=scoped)

    def test_non_human_signing_is_refused_before_private_key_read(self) -> None:
        document = acceptance_document(decision_mode="model_session", include_evidence=True)
        with mock.patch("os.open", side_effect=AssertionError("must not read private key")):
            with self.assertRaises(StateAuthError):
                self.sign(document)

    def test_unfinalized_document_is_not_repaired_for_signing(self) -> None:
        document = acceptance_document()
        document["body"]["verification_report_hash"] = digest("f")
        with self.assertRaises(StateAuthError):
            self.sign(document)

    def test_private_key_permissions_must_be_exactly_0600(self) -> None:
        for mode in (0o400, 0o640, 0o644, 0o660, 0o700, 0o1600):
            self.path.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(StateAuthError):
                self.sign()

    def test_private_key_uid_must_match_current_user(self) -> None:
        with mock.patch("tools.tools.echo_lineage_auth.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(StateAuthError):
                self.sign()

    def test_private_key_hardlinks_are_refused(self) -> None:
        os.link(self.path, Path(self.directory.name) / "second-link.pem")
        with self.assertRaises(StateAuthError):
            self.sign()

    def test_private_key_symlink_is_refused(self) -> None:
        target = self.path.with_suffix(".real")
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(StateAuthError):
            self.sign()

    def test_private_key_fifo_and_directory_are_refused(self) -> None:
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(StateAuthError):
            self.sign()
        self.path.unlink()
        self.path.mkdir(mode=0o600)
        with self.assertRaises(StateAuthError):
            self.sign()

    def test_private_key_oversize_and_empty_are_refused(self) -> None:
        for raw in (b"", b"x" * (16 * 1024 + 1)):
            self.path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(StateAuthError):
                self.sign()

    def test_private_key_encrypted_or_not_ed25519_is_refused(self) -> None:
        encrypted = synthetic_key().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"synthetic-test-password"),
        )
        other = x25519.X25519PrivateKey.from_private_bytes(b"\x05" * 32).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        for raw in (encrypted, other, b"not a private key"):
            self.path.write_bytes(raw)
            with self.subTest(header=raw.splitlines()[0]), self.assertRaises(StateAuthError):
                self.sign()

    def test_private_key_change_during_read_is_refused(self) -> None:
        original_read = os.read

        def changed(descriptor, count):
            raw = original_read(descriptor, count)
            self.path.chmod(0o640)
            return raw

        with mock.patch("tools.tools.echo_lineage_auth.os.read", side_effect=changed):
            with self.assertRaises(StateAuthError):
                self.sign()

    def test_private_key_path_replacement_during_read_is_refused(self) -> None:
        original_read = os.read
        replaced = False

        def changed(descriptor, count):
            nonlocal replaced
            raw = original_read(descriptor, count)
            if not replaced:
                replaced = True
                self.path.rename(self.path.with_suffix(".old"))
                self.path.write_bytes(raw)
                self.path.chmod(0o600)
            return raw

        with mock.patch("tools.tools.echo_lineage_auth.os.read", side_effect=changed):
            with self.assertRaises(StateAuthError):
                self.sign()

    def test_private_key_errors_do_not_disclose_paths_or_raw_exceptions(self) -> None:
        self.path.unlink()
        try:
            self.sign()
        except StateAuthError as error:
            self.assertNotIn(str(self.path), str(error))
            self.assertNotIn("Errno", str(error))
            self.assertTrue(error.__suppress_context__)
        else:
            self.fail("missing private key must be refused")


if __name__ == "__main__":
    unittest.main()
