from __future__ import annotations

import unittest

from lineage_test_helpers import (
    acceptance_document,
    artifact,
    digest,
    eid,
)
from tools.tools.echo_lineage import (
    LineageError,
    evaluate_future_decisions,
    finalize_document,
    validate_document,
)


def result(status: str, criticality: str = "critical_root") -> dict[str, str]:
    return {
        "artifact_id": eid("artifact", 1),
        "criticality": criticality,
        "status": status,
        "expected_sha256": digest("c"),
    }


class DecisionPolicyTests(unittest.TestCase):
    def test_verified_does_not_create_or_imply_acceptance(self) -> None:
        self.assertEqual(
            evaluate_future_decisions([result("target_present_verified")]),
            ["accepted", "declined"],
        )

    def test_critical_integrity_failure_cannot_be_accepted(self) -> None:
        for status in ("hash_mismatch", "target_invalid"):
            with self.subTest(status=status):
                allowed = evaluate_future_decisions([result(status)])
                self.assertEqual(
                    allowed,
                    ["declined", "quarantined_integrity_failure"],
                )
                document = acceptance_document(
                    target_results=[result(status)],
                    decision="accepted_with_reservations",
                    reservations=[
                        {
                            "code": "integrity-failure",
                            "artifact_id": eid("artifact", 1),
                        }
                    ],
                )
                with self.assertRaisesRegex(
                    LineageError, "forbidden by target status policy"
                ):
                    validate_document(document)

    def test_ledger_missing_can_be_accepted_with_reservation(self) -> None:
        target = result("ledger_known_target_missing")
        document = acceptance_document(
            target_results=[target],
            decision="accepted_with_reservations",
            reservations=[
                {
                    "code": "target-unavailable",
                    "artifact_id": eid("artifact", 1),
                }
            ],
        )
        validate_document(document)

    def test_model_and_joint_decisions_require_evidence(self) -> None:
        for mode in ("model_session", "joint_human_model"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(
                    LineageError, "decision_evidence_ref"
                ):
                    validate_document(acceptance_document(decision_mode=mode))
                validate_document(
                    acceptance_document(
                        decision_mode=mode,
                        include_evidence=True,
                    )
                )

    def test_empty_and_duplicate_target_results_are_rejected(self) -> None:
        with self.assertRaisesRegex(LineageError, "must not be empty"):
            validate_document(acceptance_document(target_results=[]))
        duplicate = [result("target_present_verified")] * 2
        with self.assertRaisesRegex(LineageError, "duplicate artifact_id"):
            validate_document(acceptance_document(target_results=duplicate))

    def test_reservations_exactly_match_nonverified_targets(self) -> None:
        target = result("ledger_known_target_missing")
        extra = {
            "code": "extra",
            "artifact_id": eid("artifact", 2),
        }
        with self.assertRaisesRegex(LineageError, "exactly one reservation"):
            validate_document(
                acceptance_document(
                    target_results=[target],
                    decision="accepted_with_reservations",
                    reservations=[
                        {
                            "code": "missing",
                            "artifact_id": eid("artifact", 1),
                        },
                        extra,
                    ],
                )
            )

    def test_unanchored_or_unattempted_target_cannot_activate(self) -> None:
        for status in (
            "target_missing_unanchored",
            "verification_not_attempted",
        ):
            with self.subTest(status=status):
                self.assertEqual(
                    evaluate_future_decisions([result(status)]),
                    ["declined"],
                )

    def test_verified_target_cannot_invent_reservations(self) -> None:
        document = acceptance_document(
            decision="accepted_with_reservations",
            reservations=[
                {
                    "code": "invented",
                    "artifact_id": eid("artifact", 1),
                }
            ],
        )
        with self.assertRaisesRegex(
            LineageError, "forbidden by target status policy"
        ):
            validate_document(document)

    def test_policy_and_historical_decisions_are_hash_bound(self) -> None:
        policy = acceptance_document(
            decision_mode="system_policy",
            decision="declined",
        )
        policy["body"]["decision_actor"]["policy_artifact_ref"] = artifact(70)
        policy = finalize_document(policy)
        validate_document(policy)

        historical = acceptance_document(
            decision_mode="imported_historical_claim",
            decision="declined",
        )
        historical["body"]["decision_actor"][
            "historical_claim_artifact_ref"
        ] = artifact(71)
        historical = finalize_document(historical)
        validate_document(historical)

    def test_mode_specific_actor_fields_cannot_be_mixed(self) -> None:
        document = acceptance_document()
        document["body"]["decision_actor"]["runtime_session_id"] = eid(
            "runtime-session", 5
        )
        document = finalize_document(document)
        with self.assertRaisesRegex(LineageError, "conflict"):
            validate_document(document)


if __name__ == "__main__":
    unittest.main()
