from __future__ import annotations

import copy
import unittest

from lineage_test_helpers import (
    acceptance_for_root,
    digest,
    eid,
    handoff_document,
    handoff_for_root,
    parent,
    root_document,
    source,
)
from tools.tools.echo_lineage import (
    LineageError,
    build_proof_payload,
    finalize_document,
    validate_document,
    verify_document_read_only,
)


class ResponsibilityHeadTests(unittest.TestCase):
    def test_resulting_head_is_recomputed(self) -> None:
        document = handoff_document()
        document["resulting_head"] = digest("9")
        with self.assertRaisesRegex(LineageError, "resulting_head mismatch"):
            validate_document(document)

    def test_expected_previous_head_detects_break(self) -> None:
        document = handoff_document()
        with self.assertRaisesRegex(LineageError, "broken previous_head"):
            validate_document(
                document,
                expected_previous_head=digest("3"),
            )

    def test_proof_covers_computed_responsibility_head(self) -> None:
        document = handoff_document()
        payload = build_proof_payload(document)
        document["proofs"] = [
            {
                "proof_type": "responsibility_head",
                "algorithm": "ed25519",
                "key_id": eid("key", 1),
                "signed_payload": payload,
                "signature": "A" * 86 + "==",
            }
        ]
        validate_document(document)

        tampered = copy.deepcopy(document)
        tampered["proofs"][0]["signed_payload"]["resulting_head"] = digest("4")
        with self.assertRaisesRegex(
            LineageError, "computed resulting_head"
        ):
            validate_document(tampered)

        type_confused = copy.deepcopy(document)
        type_confused["proofs"][0]["signed_payload"]["event_index"] = True
        with self.assertRaisesRegex(LineageError, "computed resulting_head"):
            validate_document(type_confused)

    def test_body_change_changes_both_hash_and_head(self) -> None:
        original = handoff_document()
        changed = copy.deepcopy(original)
        changed["body"]["sequence"] += 1
        changed = finalize_document(changed)
        self.assertNotEqual(
            original["document_hash"]["value"],
            changed["document_hash"]["value"],
        )
        self.assertNotEqual(original["resulting_head"], changed["resulting_head"])

    def test_acceptance_extends_bound_root_or_previous_acceptance(self) -> None:
        root = root_document()
        first = acceptance_for_root(root)
        code, report = verify_document_read_only(
            first, related_roots=[root]
        )
        self.assertEqual(code, 10)
        self.assertEqual(
            report["status"], "structure_valid_attribution_unverified"
        )
        self.assertEqual(report["evidence_status"], "incomplete")
        self.assertIn(
            "decision attribution was not cryptographically verified",
            " ".join(report["evidence_errors"]),
        )
        self.assertIn(
            "verification_report_hash artifact was not supplied and verified",
            " ".join(report["evidence_errors"]),
        )
        self.assertEqual(report["allowed_future_decisions"], ["declined"])

        second = acceptance_for_root(root, number=2, previous=first)
        code, report = verify_document_read_only(
            second,
            related_roots=[root],
            related_acceptances=[first],
        )
        self.assertEqual(code, 10)
        self.assertEqual(
            report["status"], "structure_valid_attribution_unverified"
        )
        self.assertEqual(report["evidence_status"], "incomplete")

        broken = copy.deepcopy(second)
        broken["responsibility"]["previous_head"] = digest("9")
        broken = finalize_document(broken)
        code, report = verify_document_read_only(
            broken,
            related_roots=[root],
            related_acceptances=[first],
        )
        self.assertEqual(code, 2)
        self.assertIn("responsibility head", report["errors"][0])

    def test_structural_proof_is_not_reported_as_cryptographically_verified(
        self,
    ) -> None:
        document = root_document()
        document["body"]["signature_policy"] = "required"
        document = finalize_document(document)
        document["proofs"] = [
            {
                "proof_type": "responsibility_head",
                "algorithm": "ed25519",
                "key_id": eid("key", 1),
                "signed_payload": build_proof_payload(document),
                "signature": "A" * 86 + "==",
            }
        ]
        code, report = verify_document_read_only(document)
        self.assertEqual(code, 10)
        self.assertEqual(
            report["proof_status"], "structure_valid_signature_unverified"
        )
        self.assertEqual(report["evidence_status"], "incomplete")
        self.assertEqual(report["allowed_future_decisions"], ["declined"])

    def test_omitting_acceptance_proof_cannot_strengthen_result(self) -> None:
        root = root_document()
        unsigned = acceptance_for_root(root)
        unsigned_code, unsigned_report = verify_document_read_only(
            unsigned, related_roots=[root]
        )

        proof_supplied = copy.deepcopy(unsigned)
        proof_supplied["proofs"] = [
            {
                "proof_type": "responsibility_head",
                "algorithm": "ed25519",
                "key_id": eid("key", 1),
                "signed_payload": build_proof_payload(proof_supplied),
                "signature": "A" * 86 + "==",
            }
        ]
        proof_code, proof_report = verify_document_read_only(
            proof_supplied, related_roots=[root]
        )

        self.assertEqual(unsigned_code, 10)
        self.assertEqual(proof_code, 10)
        self.assertEqual(
            unsigned_report["status"],
            "structure_valid_attribution_unverified",
        )
        self.assertEqual(proof_report["status"], unsigned_report["status"])
        self.assertEqual(unsigned_report["evidence_status"], "incomplete")
        self.assertEqual(proof_report["evidence_status"], "incomplete")
        self.assertEqual(
            unsigned_report["allowed_future_decisions"], ["declined"]
        )
        self.assertEqual(
            proof_report["allowed_future_decisions"], ["declined"]
        )
        self.assertEqual(unsigned_report["proof_status"], "unsigned")
        self.assertEqual(
            proof_report["proof_status"],
            "structure_valid_signature_unverified",
        )

    def test_conflicting_responsibility_forks_are_rejected(self) -> None:
        root = root_document()
        acceptance = acceptance_for_root(root)
        conflicting_acceptance = copy.deepcopy(acceptance)
        conflicting_acceptance["body"]["verification_report_hash"] = digest("9")
        conflicting_acceptance = finalize_document(conflicting_acceptance)
        code, report = verify_document_read_only(
            acceptance,
            related_roots=[root],
            related_acceptances=[conflicting_acceptance],
        )
        self.assertEqual(code, 2)
        self.assertIn("conflicting lineage_acceptance", report["errors"][0])

        handoff = handoff_for_root(
            root,
            acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        handoff["body"]["memory_heads"] = []
        handoff = finalize_document(handoff)
        conflicting_handoff = copy.deepcopy(handoff)
        conflicting_handoff["body"]["recipient_binding"][
            "recipient_installation_id"
        ] = eid("installation", 3)
        conflicting_handoff = finalize_document(conflicting_handoff)
        code, report = verify_document_read_only(
            handoff,
            related_roots=[root],
            related_acceptances=[acceptance],
            related_handoffs=[conflicting_handoff],
        )
        self.assertEqual(code, 2)
        self.assertIn("conflicting handoff", report["errors"][0])

    def test_acceptance_subject_handoff_is_bound_when_claimed(self) -> None:
        parent_root = root_document(1)
        parent_acceptance = acceptance_for_root(parent_root)
        handoff = handoff_for_root(
            parent_root,
            parent_acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        child_root = root_document(
            2,
            trajectory_number=1,
            origin="continuation",
            parents=[parent("predecessor", parent_root, handoff=handoff)],
            genesis_hash=parent_root["document_hash"]["value"],
        )
        child_acceptance = acceptance_for_root(child_root, number=2)
        child_acceptance["body"]["subject"]["handoff_artifact_id"] = eid(
            "artifact", 2002
        )
        child_acceptance["body"]["subject"]["handoff_document_hash"] = handoff[
            "document_hash"
        ]["value"]
        child_acceptance["body"]["target_results"].append(
            {
                "artifact_id": eid("artifact", 2002),
                "criticality": "critical_root",
                "status": "target_present_verified",
                "expected_sha256": handoff["document_hash"]["value"],
            }
        )
        child_acceptance = finalize_document(child_acceptance)

        code, report = verify_document_read_only(
            child_acceptance, related_roots=[child_root]
        )
        self.assertEqual(code, 10)
        self.assertIn("subject handoff", report["evidence_errors"][0])

        code, report = verify_document_read_only(
            child_acceptance,
            related_roots=[child_root],
            related_handoffs=[handoff],
        )
        self.assertEqual(code, 10)
        # The child root's parent chain itself still requires its parent root
        # and acceptance evidence; the subject handoff is nevertheless bound.
        self.assertNotIn("subject handoff", " ".join(report["evidence_errors"]))

    def test_previous_acceptance_chain_is_checked_recursively(self) -> None:
        root = root_document()
        first = acceptance_for_root(root, number=1)
        poisoned = acceptance_for_root(root, number=2, previous=first)
        poisoned["body"]["previous_acceptance_hash"] = digest("9")
        poisoned = finalize_document(poisoned)
        current = acceptance_for_root(root, number=3, previous=poisoned)

        code, report = verify_document_read_only(
            current,
            related_roots=[root],
            related_acceptances=[poisoned],
        )
        self.assertEqual(code, 10)
        self.assertIn(
            "previous acceptance evidence", report["evidence_errors"][0]
        )

        code, report = verify_document_read_only(
            first,
            related_roots=[root],
            related_acceptances=[first],
        )
        self.assertEqual(code, 2)
        self.assertIn("replayed", report["errors"][0])

    def test_subject_handoff_must_be_a_parent_of_subject_root(self) -> None:
        foreign_root = root_document(1, trajectory_number=1)
        foreign_acceptance = acceptance_for_root(foreign_root)
        foreign_handoff = handoff_for_root(
            foreign_root,
            foreign_acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        independent = root_document(2, trajectory_number=2)
        acceptance = acceptance_for_root(independent, number=2)
        acceptance["body"]["subject"]["handoff_artifact_id"] = eid(
            "artifact", 2002
        )
        acceptance["body"]["subject"]["handoff_document_hash"] = (
            foreign_handoff["document_hash"]["value"]
        )
        acceptance["body"]["target_results"].append(
            {
                "artifact_id": eid("artifact", 2002),
                "criticality": "critical_root",
                "status": "target_present_verified",
                "expected_sha256": foreign_handoff["document_hash"]["value"],
            }
        )
        acceptance = finalize_document(acceptance)
        code, report = verify_document_read_only(
            acceptance,
            related_roots=[independent, foreign_root],
            related_acceptances=[foreign_acceptance],
            related_handoffs=[foreign_handoff],
        )
        self.assertEqual(code, 2)
        self.assertIn("not a lineage parent", report["errors"][0])

    def test_acceptance_results_exactly_cover_root_sources(self) -> None:
        root = root_document(sources=[source(40)])
        acceptance = acceptance_for_root(root)
        code, _report = verify_document_read_only(
            acceptance, related_roots=[root]
        )
        self.assertEqual(code, 10)

        omitted = copy.deepcopy(acceptance)
        omitted["body"]["target_results"] = omitted["body"][
            "target_results"
        ][:1]
        omitted = finalize_document(omitted)
        code, report = verify_document_read_only(
            omitted, related_roots=[root]
        )
        self.assertEqual(code, 2)
        self.assertIn("exactly cover", report["errors"][0])

        changed = copy.deepcopy(acceptance)
        changed["body"]["target_results"][1]["expected_sha256"] = digest("9")
        changed = finalize_document(changed)
        code, report = verify_document_read_only(
            changed, related_roots=[root]
        )
        self.assertEqual(code, 2)
        self.assertIn("conflicts with inheritance", report["errors"][0])


if __name__ == "__main__":
    unittest.main()
