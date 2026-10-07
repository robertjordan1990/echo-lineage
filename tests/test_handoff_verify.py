from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from lineage_test_helpers import (
    acceptance_for_root,
    eid,
    handoff_document,
    handoff_for_root,
    parent,
    root_document,
    source,
)
from tools.tools.echo_lineage import (
    LineageError,
    finalize_document,
    main,
    validate_document,
    verify_document_read_only,
)


class HandoffVerifyTests(unittest.TestCase):
    def test_bound_and_expiring_unbound_handoffs_validate(self) -> None:
        validate_document(handoff_document(bound=True), expected_type="handoff")
        validate_document(handoff_document(bound=False), expected_type="handoff")

    def test_unbound_handoff_without_expiry_is_invalid(self) -> None:
        document = handoff_document(bound=False)
        del document["body"]["expires_at"]
        with self.assertRaisesRegex(LineageError, "requires expires_at"):
            validate_document(document, expected_type="handoff")

    def test_handoff_document_refs_require_canonical_scope(self) -> None:
        for field_name in ("lineage_root_ref", "latest_acceptance_ref"):
            with self.subTest(field_name=field_name):
                document = handoff_document(bound=False)
                document["body"][field_name]["hash_scope"] = "file_bytes"
                document = finalize_document(document)
                with self.assertRaisesRegex(
                    LineageError, "hash_scope must be canonical_document"
                ):
                    validate_document(document, expected_type="handoff")
                code, report = verify_document_read_only(
                    document, expected_type="handoff"
                )
                self.assertEqual(code, 2)
                self.assertIn(
                    "hash_scope must be canonical_document",
                    report["errors"][0],
                )

    def test_handoff_rejects_duplicate_parents_and_ht_log_ids(self) -> None:
        root = root_document()
        duplicate_parent = parent("predecessor", root)
        document = handoff_document()
        document["body"]["lineage_parents"] = [
            duplicate_parent,
            copy.deepcopy(duplicate_parent),
        ]
        document = finalize_document(document)
        with self.assertRaisesRegex(LineageError, "duplicate entries"):
            validate_document(document)

        for duplicate_head in (
            copy.deepcopy(handoff_document()["body"]["ht_heads"][0]),
            {
                "log_id": handoff_document()["body"]["ht_heads"][0]["log_id"],
                "t": 8,
                "msg_sha256": "2" * 64,
            },
        ):
            with self.subTest(duplicate_head=duplicate_head):
                document = handoff_document()
                document["body"]["ht_heads"].append(duplicate_head)
                document = finalize_document(document)
                with self.assertRaisesRegex(LineageError, "duplicate log_id"):
                    validate_document(document)

    def test_tampered_handoff_is_detected(self) -> None:
        document = handoff_document()
        document["body"]["handoff_nonce"] = "56" * 16
        with self.assertRaisesRegex(LineageError, "document_hash mismatch"):
            validate_document(document, expected_type="handoff")

    def test_handoff_verify_does_not_import_or_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            document_path = directory / "handoff.json"
            document_path.write_text(
                json.dumps(handoff_document()), encoding="utf-8"
            )
            before = {
                path.name: path.read_bytes() for path in directory.iterdir()
            }
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "handoff",
                        "verify",
                        "--document",
                        str(document_path),
                    ]
                )
            after = {
                path.name: path.read_bytes() for path in directory.iterdir()
            }
            self.assertEqual(code, 10)
            self.assertEqual(before, after)
            self.assertIn("HANDOFF VERIFIED != IMPORTED", stdout.getvalue())

    def test_handoff_evidence_binds_root_acceptance_and_previous_head(self) -> None:
        root = root_document()
        acceptance = acceptance_for_root(root)
        first = handoff_for_root(
            root,
            acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        second = handoff_for_root(
            root,
            acceptance,
            recipient_installation_id=eid("installation", 3),
            number=2,
            previous=first,
        )
        code, report = verify_document_read_only(
            second,
            expected_type="handoff",
            related_roots=[root],
            related_acceptances=[acceptance],
            related_handoffs=[first],
        )
        self.assertEqual(code, 10)  # inherited targets have no local bindings
        self.assertEqual(report["evidence_status"], "incomplete")
        self.assertIn(
            "decision attribution was not cryptographically verified",
            " ".join(report["evidence_errors"]),
        )
        self.assertEqual(report["allowed_future_decisions"], ["declined"])

        broken = copy.deepcopy(second)
        broken["responsibility"]["previous_head"] = "9" * 64
        broken = finalize_document(broken)
        code, report = verify_document_read_only(
            broken,
            expected_type="handoff",
            related_roots=[root],
            related_acceptances=[acceptance],
            related_handoffs=[first],
        )
        self.assertEqual(code, 2)
        self.assertIn("responsibility head", report["errors"][0])

    def test_handoff_replay_and_rollback_evidence_are_rejected(self) -> None:
        root = root_document()
        acceptance = acceptance_for_root(root)
        first = handoff_for_root(
            root,
            acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        second = handoff_for_root(
            root,
            acceptance,
            recipient_installation_id=eid("installation", 3),
            number=2,
            previous=first,
        )
        code, report = verify_document_read_only(
            second,
            expected_type="handoff",
            related_roots=[root],
            related_acceptances=[acceptance],
            related_handoffs=[first, first],
        )
        self.assertEqual(code, 2)
        self.assertIn("duplicate handoff", report["errors"][0])

        rollback = copy.deepcopy(second)
        rollback["body"]["sequence"] = 2
        rollback = finalize_document(rollback)
        code, report = verify_document_read_only(
            rollback,
            expected_type="handoff",
            related_roots=[root],
            related_acceptances=[acceptance],
            related_handoffs=[first],
        )
        self.assertEqual(code, 2)
        self.assertIn("not contiguous", report["errors"][0])

        code, report = verify_document_read_only(
            first,
            expected_type="handoff",
            related_handoffs=[first],
        )
        self.assertEqual(code, 2)
        self.assertIn("replayed", report["errors"][0])

    def test_handoff_expiry_order_is_structurally_checked(self) -> None:
        document = handoff_document(bound=False)
        document["body"]["expires_at"] = document["body"]["issued_at"]
        document = finalize_document(document)
        with self.assertRaisesRegex(LineageError, "later than issued_at"):
            validate_document(document)

    def test_unbound_expiry_needs_explicit_time_and_rejects_expired(self) -> None:
        document = handoff_document(bound=False)
        code, report = verify_document_read_only(
            document, expected_type="handoff"
        )
        self.assertEqual(code, 10)
        self.assertIn(
            "expiry was not evaluated", " ".join(report["evidence_errors"])
        )

        code, report = verify_document_read_only(
            document,
            expected_type="handoff",
            verification_time="2032-01-04T00:00:00Z",
        )
        self.assertEqual(code, 2)
        self.assertIn("expired", report["errors"][0])

    def test_handoff_cannot_omit_or_change_root_inheritance_source(self) -> None:
        root = root_document(sources=[source(40)])
        acceptance = acceptance_for_root(root)
        handoff = handoff_for_root(
            root,
            acceptance,
            recipient_installation_id=eid("installation", 2),
        )
        handoff["body"]["inheritance_sources"] = []
        handoff = finalize_document(handoff)
        code, report = verify_document_read_only(
            handoff,
            expected_type="handoff",
            related_roots=[root],
            related_acceptances=[acceptance],
        )
        self.assertEqual(code, 2)
        self.assertIn("omits inheritance sources", report["errors"][0])

    def test_handoff_sequence_cannot_switch_to_sibling_acceptance(self) -> None:
        root = root_document()
        acceptance_a = acceptance_for_root(root, number=1)
        acceptance_b = acceptance_for_root(root, number=2)
        first = handoff_for_root(
            root,
            acceptance_a,
            recipient_installation_id=eid("installation", 2),
        )
        second = handoff_for_root(
            root,
            acceptance_b,
            recipient_installation_id=eid("installation", 3),
            number=2,
            previous=first,
        )
        code, report = verify_document_read_only(
            second,
            expected_type="handoff",
            related_roots=[root],
            related_acceptances=[acceptance_a, acceptance_b],
            related_handoffs=[first],
        )
        self.assertEqual(code, 2)
        self.assertIn("responsibility fork", report["errors"][0])

    def test_handoff_requires_privacy_and_verification_constraints(self) -> None:
        for missing in ("no_public_commitment", "verify_before_use"):
            with self.subTest(missing=missing):
                document = handoff_document()
                document["body"]["constraints"].remove(missing)
                document = finalize_document(document)
                with self.assertRaisesRegex(
                    LineageError, "mandatory safety constraints"
                ):
                    validate_document(document)


if __name__ == "__main__":
    unittest.main()
