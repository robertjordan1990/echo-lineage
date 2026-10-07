from __future__ import annotations

import copy
import unittest
from pathlib import Path

from lineage_test_helpers import (
    acceptance_document,
    eid,
    handoff_document,
    root_document,
    source,
)
from tools.tools.echo_lineage import (
    LineageError,
    build_proof_payload,
    finalize_document,
    validate_document,
)
from tools.tools.echo_canonical import read_json_strict


class LineageDocumentTests(unittest.TestCase):
    def test_three_document_types_validate(self) -> None:
        validate_document(root_document(), expected_type="trajectory_root")
        validate_document(
            acceptance_document(), expected_type="lineage_acceptance"
        )
        validate_document(handoff_document(), expected_type="handoff")

    def test_unknown_field_rejected(self) -> None:
        document = root_document()
        document["body"]["surprise"] = True
        with self.assertRaisesRegex(LineageError, "unknown fields"):
            validate_document(document)

    def test_invalid_sha256_rejected(self) -> None:
        document = handoff_document()
        document["body"]["previous_handoff_hash"] = "not-a-hash"
        with self.assertRaisesRegex(LineageError, "lowercase SHA-256"):
            validate_document(document)

    def test_ledger_artifact_id_cannot_collide_with_target_namespace(
        self,
    ) -> None:
        self_ledger = source(1, ledger_sha256="1" * 64)
        self_ledger["artifact"]["ledger_ref"]["ledger_artifact_id"] = (
            self_ledger["artifact"]["artifact_id"]
        )
        with self.assertRaisesRegex(LineageError, "must differ from artifact_id"):
            validate_document(root_document(sources=[self_ledger]))

        first = source(1, ledger_sha256="1" * 64)
        second = source(2)
        first["artifact"]["ledger_ref"]["ledger_artifact_id"] = second[
            "artifact"
        ]["artifact_id"]
        with self.assertRaisesRegex(
            LineageError, "collides with document artifact_id"
        ):
            validate_document(root_document(sources=[first, second]))

        acceptance = acceptance_document(
            decision_mode="model_session",
            include_evidence=True,
        )
        acceptance_evidence = acceptance["body"]["decision_actor"][
            "decision_evidence_ref"
        ]
        acceptance_evidence["ledger_ref"] = {
            "ledger_artifact_id": acceptance["body"]["subject"][
                "trajectory_root_artifact_id"
            ],
            "ledger_sha256": "1" * 64,
        }
        with self.assertRaisesRegex(
            LineageError, "collides with document artifact_id"
        ):
            validate_document(acceptance)

        handoff = handoff_document()
        inherited_artifact = handoff["body"]["inheritance_sources"][0][
            "artifact"
        ]
        inherited_artifact["ledger_ref"] = {
            "ledger_artifact_id": handoff["body"]["lineage_root_ref"][
                "artifact_id"
            ],
            "ledger_sha256": "1" * 64,
        }
        with self.assertRaisesRegex(
            LineageError, "collides with document artifact_id"
        ):
            validate_document(handoff)

    def test_shared_ledger_requires_one_consistent_commitment(self) -> None:
        first = source(1, ledger_sha256="1" * 64)
        second = source(2, ledger_sha256="1" * 64)
        shared_ledger_id = eid("artifact", 900)
        first["artifact"]["ledger_ref"]["ledger_artifact_id"] = shared_ledger_id
        second["artifact"]["ledger_ref"]["ledger_artifact_id"] = shared_ledger_id
        validate_document(root_document(sources=[first, second]))

        second["artifact"]["ledger_ref"]["ledger_sha256"] = "2" * 64
        with self.assertRaisesRegex(
            LineageError, "conflicting ledger_sha256"
        ):
            validate_document(root_document(sources=[first, second]))

    def test_private_locator_and_path_rejected(self) -> None:
        for key, value in (
            ("local_locator", "opaque"),
            ("note", "/private/example"),
            ("note", "../secret"),
            ("note", "C:\\private\\example"),
        ):
            document = root_document()
            document["body"][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(
                    LineageError, "private locator|forbidden path"
                ):
                    validate_document(document)

    def test_protocol_codes_cannot_hide_relative_paths(self) -> None:
        reason_document = acceptance_document()
        reason_document["body"]["target_results"][0][
            "reason_code"
        ] = "private/handoff.json"
        reason_document = finalize_document(reason_document)

        reservation_document = acceptance_document()
        reservation_document["body"]["reservations"] = [
            {
                "artifact_id": reservation_document["body"][
                    "target_results"
                ][0]["artifact_id"],
                "code": "private/handoff.json",
            }
        ]
        reservation_document = finalize_document(reservation_document)
        for document in (reason_document, reservation_document):
            with self.assertRaisesRegex(
                LineageError, "without path separators"
            ):
                validate_document(document)

    def test_model_session_requires_decision_evidence(self) -> None:
        document = acceptance_document(decision_mode="model_session")
        with self.assertRaisesRegex(
            LineageError, "decision_evidence_ref"
        ):
            validate_document(document)
        validate_document(
            acceptance_document(
                decision_mode="model_session", include_evidence=True
            )
        )

    def test_decision_actor_not_reassigned_to_recording_operator(self) -> None:
        document = acceptance_document()
        self.assertNotEqual(
            document["body"]["decision_actor"]["decision_actor_id"],
            document["body"]["recording_operator"]["operator_actor_id"],
        )
        validate_document(document)

    def test_document_hash_change_detected(self) -> None:
        document = handoff_document()
        document["body"]["sequence"] += 1
        with self.assertRaisesRegex(LineageError, "document_hash mismatch"):
            validate_document(document)

    def test_structurally_invalid_timestamps_are_rejected(self) -> None:
        cases = [
            (root_document(), "created_at"),
            (acceptance_document(), "decided_at"),
            (handoff_document(), "issued_at"),
        ]
        for document, field in cases:
            with self.subTest(document=document["document_type"]):
                document["body"][field] = "2032-99-99 99:99:99"
                document = finalize_document(document)
                with self.assertRaisesRegex(LineageError, "RFC 3339"):
                    validate_document(document)

    def test_required_signature_policy_requires_proof(self) -> None:
        document = root_document()
        document["body"]["signature_policy"] = "required"
        document = finalize_document(document)
        with self.assertRaisesRegex(
            LineageError, "signature_policy required"
        ):
            validate_document(document)

    def test_private_path_cannot_hide_in_proof_key_id(self) -> None:
        document = root_document()
        document["proofs"] = [
            {
                "proof_type": "responsibility_head",
                "algorithm": "ed25519",
                "key_id": "/private/key",
                "signed_payload": build_proof_payload(document),
                "signature": "A" * 86 + "==",
            }
        ]
        with self.assertRaisesRegex(LineageError, "forbidden path"):
            validate_document(document)

    def test_signature_must_be_canonical_ed25519_base64(self) -> None:
        document = root_document()
        document["proofs"] = [
            {
                "proof_type": "responsibility_head",
                "algorithm": "ed25519",
                "key_id": eid("key", 1),
                "signed_payload": build_proof_payload(document),
                "signature": "/synthetic-fixture/not-a-real-key",
            }
        ]
        with self.assertRaisesRegex(
            LineageError, "canonical base64.*64-byte"
        ):
            validate_document(document)

    def test_trajectory_root_always_starts_local_responsibility_chain(self) -> None:
        document = root_document()
        document["responsibility"]["event_index"] = 1
        document["responsibility"]["previous_head"] = "1" * 64
        document = finalize_document(document)
        with self.assertRaisesRegex(LineageError, "event_index 0"):
            validate_document(document)

    def test_expected_chain_and_event_are_checked(self) -> None:
        document = acceptance_document()
        with self.assertRaisesRegex(LineageError, "expected chain"):
            validate_document(
                document,
                expected_chain_id=eid("responsibility-chain", 2),
            )
        with self.assertRaisesRegex(LineageError, "expected index"):
            validate_document(document, expected_event_index=2)

    def test_fictional_public_examples_are_internally_valid(self) -> None:
        examples = (
            Path(__file__).parents[1]
            / "tools"
            / "examples"
            / "echo-lineage-v1"
        )
        expected_types = {
            "TRAJECTORY_ROOT.example.json": "trajectory_root",
            "LINEAGE_ACCEPTANCE.example.json": "lineage_acceptance",
            "HANDOFF.example.json": "handoff",
        }
        for filename, expected_type in expected_types.items():
            with self.subTest(filename=filename):
                document = read_json_strict(examples / filename)
                validate_document(document, expected_type=expected_type)


if __name__ == "__main__":
    unittest.main()
