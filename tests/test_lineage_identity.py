from __future__ import annotations

import copy
import unittest

from lineage_test_helpers import (
    acceptance_for_root,
    continuation,
    digest,
    eid,
    handoff_for_root,
    parent,
    root_document,
    source,
)
from tools.tools.echo_lineage import (
    LineageError,
    effective_trajectory_identity,
    finalize_document,
    validate_document,
    validate_root_graph,
    verify_document_read_only,
)


class LineageIdentityTests(unittest.TestCase):
    def test_identifier_classes_are_not_interchangeable(self) -> None:
        document = root_document()
        document["body"]["installation_id"] = eid("trajectory", 2)
        with self.assertRaisesRegex(LineageError, "urn:echo:installation"):
            validate_document(document)

    def test_identifier_aliases_are_rejected(self) -> None:
        for replacement in (
            "urn:echo:installation:00000000-0000-4000-8000-00000000000A",
            "urn:echo:installation:00000000-0000-0000-8000-000000000001",
            "urn:echo:installation:00000000-0000-4000-7000-000000000001",
        ):
            with self.subTest(replacement=replacement):
                document = root_document()
                document["body"]["installation_id"] = replacement
                document = finalize_document(document)
                with self.assertRaisesRegex(
                    LineageError, "canonical lowercase RFC 4122 UUID"
                ):
                    validate_document(document)

    def test_independent_trajectory_and_continuation(self) -> None:
        genesis = root_document(1)
        child = continuation(genesis, 2)
        validate_root_graph([genesis, child])
        self.assertEqual(
            effective_trajectory_identity(genesis),
            effective_trajectory_identity(child),
        )
        self.assertEqual(child["responsibility"]["event_index"], 0)
        self.assertEqual(child["responsibility"]["previous_head"], digest("0"))

    def test_continuation_requires_bound_parent_evidence_for_verify(self) -> None:
        genesis = root_document(1)
        acceptance = acceptance_for_root(genesis)
        handoff = handoff_for_root(
            genesis,
            acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        child = root_document(
            2,
            trajectory_number=1,
            origin="continuation",
            parents=[parent("predecessor", genesis, handoff=handoff)],
            genesis_hash=genesis["document_hash"]["value"],
        )

        code, report = verify_document_read_only(
            child, related_roots=[genesis]
        )
        self.assertEqual(code, 10)
        self.assertEqual(report["evidence_status"], "incomplete")
        self.assertIn("handoff evidence", report["evidence_errors"][0])
        self.assertEqual(report["allowed_future_decisions"], ["declined"])

        code, report = verify_document_read_only(
            child,
            related_roots=[genesis],
            related_acceptances=[acceptance],
            related_handoffs=[handoff],
        )
        self.assertEqual(code, 10)
        self.assertEqual(report["evidence_status"], "incomplete")
        self.assertIn(
            "decision attribution was not cryptographically verified",
            " ".join(report["evidence_errors"]),
        )
        self.assertEqual(report["allowed_future_decisions"], ["declined"])

        wrong_parent = root_document(9, trajectory_number=1)
        code, report = verify_document_read_only(
            child,
            related_roots=[wrong_parent],
            related_acceptances=[acceptance],
            related_handoffs=[handoff],
        )
        self.assertEqual(code, 2)
        self.assertIn(
            "different genesis_root_document_hash", report["errors"][0]
        )

    def test_same_trajectory_uuid_with_other_genesis_rejected(self) -> None:
        genesis = root_document(1)
        child = continuation(genesis, 2)
        child["body"]["genesis_root_document_hash"] = digest("9")
        child["body"]["lineage_parents"][0][
            "parent_genesis_root_document_hash"
        ] = digest("9")
        child = finalize_document(child)
        with self.assertRaisesRegex(
            LineageError, "different genesis_root_document_hash"
        ):
            validate_root_graph([genesis, child])

    def test_parent_is_not_inheritance_source(self) -> None:
        genesis = root_document(1)
        child = continuation(genesis, 2)
        child["body"]["inheritance_sources"] = [
            source(20, role="memory"),
            source(21, role="memory"),
            source(22, role="governance"),
        ]
        child = finalize_document(child)
        validate_document(child)
        self.assertIn("parent_installation_id", child["body"]["lineage_parents"][0])
        self.assertNotIn(
            "parent_installation_id",
            child["body"]["inheritance_sources"][0],
        )

    def test_explicit_fork_creates_new_trajectory(self) -> None:
        genesis = root_document(1)
        fork = root_document(
            2,
            trajectory_number=2,
            origin="explicit_fork",
            parents=[parent("fork_origin", genesis)],
        )
        validate_root_graph([genesis, fork])
        self.assertNotEqual(
            effective_trajectory_identity(genesis)[0],
            effective_trajectory_identity(fork)[0],
        )

    def test_explicit_fork_handoff_intent_is_bound(self) -> None:
        genesis = root_document(1)
        acceptance = acceptance_for_root(genesis)
        handoff = handoff_for_root(
            genesis,
            acceptance,
            recipient_installation_id=eid("installation", 2),
            fork_intent="explicit_fork",
        )
        fork = root_document(
            2,
            trajectory_number=2,
            origin="explicit_fork",
            parents=[parent("fork_origin", genesis, handoff=handoff)],
        )
        code, _report = verify_document_read_only(
            fork,
            related_roots=[genesis],
            related_acceptances=[acceptance],
            related_handoffs=[handoff],
        )
        self.assertEqual(code, 10)

        wrong_intent = copy.deepcopy(handoff)
        wrong_intent["body"]["fork_intent"] = "none"
        wrong_intent = finalize_document(wrong_intent)
        fork["body"]["lineage_parents"][0] = parent(
            "fork_origin", genesis, handoff=wrong_intent
        )
        fork = finalize_document(fork)
        code, report = verify_document_read_only(
            fork,
            related_roots=[genesis],
            related_acceptances=[acceptance],
            related_handoffs=[wrong_intent],
        )
        self.assertEqual(code, 2)
        self.assertIn("fork_intent", report["errors"][0])

    def test_merge_creates_new_trajectory(self) -> None:
        left = root_document(1, trajectory_number=1)
        right = root_document(2, trajectory_number=2)
        merge = root_document(
            3,
            trajectory_number=3,
            origin="merge",
            parents=[
                parent("merge_input", left),
                parent("merge_input", right),
            ],
        )
        validate_root_graph([left, right, merge])

    def test_merge_requires_distinct_bound_handoffs(self) -> None:
        left = root_document(1, trajectory_number=1)
        right = root_document(2, trajectory_number=2)
        left_acceptance = acceptance_for_root(left, number=1)
        right_acceptance = acceptance_for_root(right, number=2)
        left_handoff = handoff_for_root(
            left,
            left_acceptance,
            recipient_installation_id=eid("installation", 3),
            number=1,
            fork_intent="merge_input",
        )
        right_handoff = handoff_for_root(
            right,
            right_acceptance,
            recipient_installation_id=eid("installation", 3),
            number=2,
            fork_intent="merge_input",
        )
        merge = root_document(
            3,
            trajectory_number=3,
            origin="merge",
            parents=[
                parent("merge_input", left, handoff=left_handoff),
                parent("merge_input", right, handoff=right_handoff),
            ],
        )
        code, report = verify_document_read_only(
            merge,
            related_roots=[left, right],
            related_acceptances=[left_acceptance, right_acceptance],
            related_handoffs=[left_handoff, right_handoff],
        )
        self.assertEqual(code, 10, report)
        self.assertEqual(report["evidence_status"], "incomplete")
        self.assertEqual(report["allowed_future_decisions"], ["declined"])

    def test_expired_unbound_parent_handoff_is_rejected(self) -> None:
        genesis = root_document(1)
        acceptance = acceptance_for_root(genesis)
        handoff = handoff_for_root(
            genesis,
            acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        handoff["body"]["recipient_binding"] = {
            "mode": "unbound",
            "recipient_installation_id": None,
        }
        handoff["body"]["expires_at"] = "2032-01-03T03:04:07Z"
        handoff = finalize_document(handoff)
        child = root_document(
            2,
            trajectory_number=1,
            origin="continuation",
            parents=[parent("predecessor", genesis, handoff=handoff)],
            genesis_hash=genesis["document_hash"]["value"],
        )
        code, report = verify_document_read_only(
            child,
            related_roots=[genesis],
            related_acceptances=[acceptance],
            related_handoffs=[handoff],
            verification_time="2032-01-04T00:00:00Z",
        )
        self.assertEqual(code, 2)
        self.assertIn("expired", report["errors"][0])

    def test_missing_parent_does_not_mask_other_parent_contradiction(self) -> None:
        missing = root_document(1, trajectory_number=1)
        supplied = root_document(2, trajectory_number=2)
        supplied_acceptance = acceptance_for_root(supplied, number=2)
        wrong_handoff = handoff_for_root(
            supplied,
            supplied_acceptance,
            recipient_installation_id=eid("installation", 999),
            number=2,
            fork_intent="merge_input",
        )
        missing_parent = parent("merge_input", missing)
        contradictory_parent = parent(
            "merge_input", supplied, handoff=wrong_handoff
        )
        for parents in (
            [missing_parent, contradictory_parent],
            [contradictory_parent, missing_parent],
        ):
            with self.subTest(order=parents[0]["parent_installation_id"]):
                merge = root_document(
                    3,
                    trajectory_number=3,
                    origin="merge",
                    parents=parents,
                )
                code, report = verify_document_read_only(
                    merge,
                    related_roots=[supplied],
                    related_acceptances=[supplied_acceptance],
                    related_handoffs=[wrong_handoff],
                )
                self.assertEqual(code, 2)
                self.assertIn(
                    "bound to another installation", report["errors"][0]
                )

    def test_known_identity_checks_unsupplied_parent_claim(self) -> None:
        parent_root = root_document(1, trajectory_number=1)
        fork = root_document(
            2,
            trajectory_number=2,
            origin="explicit_fork",
            parents=[parent("fork_origin", parent_root)],
        )
        code, report = verify_document_read_only(
            fork,
            known_identities={
                parent_root["body"]["trajectory_id"]: digest("9")
            },
        )
        self.assertEqual(code, 2)
        self.assertIn("known trajectory identity", report["errors"][0])

    def test_known_identity_checks_current_acceptance_and_handoff(self) -> None:
        root = root_document()
        acceptance = acceptance_for_root(root)
        handoff = handoff_for_root(
            root,
            acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        for document in (acceptance, handoff):
            with self.subTest(document_type=document["document_type"]):
                code, report = verify_document_read_only(
                    document,
                    known_identities={
                        document["body"]["trajectory_id"]: digest("9")
                    },
                )
                self.assertEqual(code, 2)
                self.assertIn(
                    "different genesis_root_document_hash",
                    report["errors"][0],
                )

    def test_duplicate_installation_id_rejected(self) -> None:
        one = root_document(1)
        two = root_document(1, trajectory_number=2)
        with self.assertRaisesRegex(LineageError, "duplicate installation_id"):
            validate_root_graph([one, two])

    def test_duplicate_responsibility_chain_id_rejected(self) -> None:
        one = root_document(1)
        two = root_document(2, trajectory_number=2)
        two["responsibility"]["chain_id"] = one["responsibility"]["chain_id"]
        two = finalize_document(two)
        with self.assertRaisesRegex(
            LineageError, "duplicate responsibility chain_id"
        ):
            validate_root_graph([one, two])

    def test_cycle_rejected(self) -> None:
        one = root_document(1)
        two = root_document(2, trajectory_number=2)
        one["body"]["origin_kind"] = "explicit_fork"
        one["body"]["lineage_parents"] = [parent("fork_origin", two)]
        one = finalize_document(one)
        two["body"]["origin_kind"] = "explicit_fork"
        two["body"]["lineage_parents"] = [parent("fork_origin", one)]
        two = finalize_document(two)
        with self.assertRaisesRegex(LineageError, "cycle"):
            validate_root_graph([one, two])


if __name__ == "__main__":
    unittest.main()
