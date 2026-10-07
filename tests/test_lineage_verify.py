from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lineage_test_helpers import eid, root_document, source
from tools.tools.echo_canonical import canon_json_bytes
from tools.tools.echo_lineage import (
    LineageError,
    VerificationBindings,
    finalize_document,
    main,
    validate_document,
    verify_document_read_only,
)
from tools.tools import echo_lineage as lineage_module


class LineageVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact_id = eid("artifact", 1)

    def _document(self, content: bytes, ledger_hash: str | None = None):
        return root_document(
            sources=[
                source(
                    1,
                    sha256=hashlib.sha256(content).hexdigest(),
                    ledger_sha256=ledger_hash,
                )
            ]
        )

    def test_present_target_and_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.bin"
            target.write_bytes(b"expected")
            document = self._document(b"expected")
            bindings = VerificationBindings(
                target_paths={self.artifact_id: target},
                target_roots={self.artifact_id: root},
            )
            code, report = verify_document_read_only(
                document, bindings=bindings
            )
            self.assertEqual(code, 0)
            self.assertEqual(
                report["target_results"][0]["status"],
                "target_present_verified",
            )
            target.write_bytes(b"changed")
            code, report = verify_document_read_only(
                document, bindings=bindings
            )
            self.assertEqual(code, 2)
            self.assertEqual(
                report["target_results"][0]["status"], "hash_mismatch"
            )

    def test_ledger_known_target_missing_is_exact_and_code_10(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            content = b"expected"
            expected = hashlib.sha256(content).hexdigest()
            ledger = root / "ledger.txt"
            ledger.write_text(f"{expected}  absent.bin\n", encoding="utf-8")
            ledger_hash = hashlib.sha256(ledger.read_bytes()).hexdigest()
            document = self._document(content, ledger_hash)
            ledger_artifact_id = document["body"]["inheritance_sources"][0][
                "artifact"
            ]["ledger_ref"]["ledger_artifact_id"]
            bindings = VerificationBindings(
                ledger_paths={ledger_artifact_id: ledger},
                ledger_roots={self.artifact_id: root},
                ledger_entries={self.artifact_id: "absent.bin"},
            )
            code, report = verify_document_read_only(
                document, bindings=bindings
            )
            result = report["target_results"][0]
            self.assertEqual(code, 10)
            self.assertEqual(result["status"], "ledger_known_target_missing")
            self.assertEqual(result["message"], "ledger known, target missing")

    def test_no_binding_is_verification_not_attempted(self) -> None:
        document = self._document(b"expected")
        code, report = verify_document_read_only(document)
        self.assertEqual(code, 10)
        self.assertEqual(
            report["target_results"][0]["status"],
            "verification_not_attempted",
        )

    def test_explicit_missing_target_without_anchor_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            document = self._document(b"expected")
            bindings = VerificationBindings(
                target_paths={self.artifact_id: root / "absent.bin"},
                target_roots={self.artifact_id: root},
            )
            code, report = verify_document_read_only(
                document, bindings=bindings
            )
            self.assertEqual(code, 10)
            self.assertEqual(
                report["target_results"][0]["status"],
                "target_missing_unanchored",
            )

    def test_unsafe_path_and_symlink_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root.parent / "fictional-outside-target"
            document = self._document(b"x")
            bindings = VerificationBindings(
                target_paths={self.artifact_id: outside},
                target_roots={self.artifact_id: root},
            )
            code, report = verify_document_read_only(
                document, bindings=bindings
            )
            self.assertEqual(code, 2)
            self.assertEqual(
                report["target_results"][0]["status"], "target_invalid"
            )

            if hasattr(os, "symlink"):
                target = root / "link"
                target.symlink_to(outside)
                bindings.target_paths[self.artifact_id] = target
                code, report = verify_document_read_only(
                    document, bindings=bindings
                )
                self.assertEqual(code, 2)
                self.assertIn(
                    "symlink", report["target_results"][0]["message"]
                )

    def test_hash_scope_is_applied_instead_of_raw_hashing_everything(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                (
                    "canonical_document",
                    b'{ "b": 2, "a": 1 }',
                    hashlib.sha256(
                        canon_json_bytes({"a": 1, "b": 2})
                    ).hexdigest(),
                ),
                (
                    "echohash_head",
                    (digest := "7" * 64).encode("ascii") + b"\n",
                    digest,
                ),
                (
                    "ciphertext",
                    b"fictional-ciphertext",
                    hashlib.sha256(b"fictional-ciphertext").hexdigest(),
                ),
            ]
            for index, (scope, content, expected) in enumerate(cases, start=1):
                with self.subTest(scope=scope):
                    target = root / f"target-{index}"
                    target.write_bytes(content)
                    document = self._document(content)
                    artifact_ref = document["body"]["inheritance_sources"][0][
                        "artifact"
                    ]
                    artifact_ref["hash_scope"] = scope
                    artifact_ref["sha256"] = expected
                    document = finalize_document(document)
                    bindings = VerificationBindings(
                        target_paths={self.artifact_id: target},
                        target_roots={self.artifact_id: root},
                    )
                    code, report = verify_document_read_only(
                        document, bindings=bindings
                    )
                    self.assertEqual(code, 0)
                    self.assertEqual(
                        report["target_results"][0]["status"],
                        "target_present_verified",
                    )

    def test_invalid_canonical_document_and_echohash_head_are_target_invalid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for scope, content in (
                ("canonical_document", b'{"a":1,"a":2}'),
                ("echohash_head", b"A" * 64 + b"\n"),
            ):
                with self.subTest(scope=scope):
                    target = root / scope
                    target.write_bytes(content)
                    document = self._document(content)
                    artifact_ref = document["body"]["inheritance_sources"][0][
                        "artifact"
                    ]
                    artifact_ref["hash_scope"] = scope
                    document = finalize_document(document)
                    code, report = verify_document_read_only(
                        document,
                        bindings=VerificationBindings(
                            target_paths={self.artifact_id: target},
                            target_roots={self.artifact_id: root},
                        ),
                    )
                    self.assertEqual(code, 2)
                    self.assertEqual(
                        report["target_results"][0]["status"],
                        "target_invalid",
                    )

    def test_ledger_ref_is_not_misapplied_to_semantic_hash_scope(self) -> None:
        document = self._document(b"x", ledger_hash="1" * 64)
        document["body"]["inheritance_sources"][0]["artifact"][
            "hash_scope"
        ] = "canonical_document"
        document = finalize_document(document)
        with self.assertRaisesRegex(LineageError, "raw-byte hash scopes"):
            validate_document(document)

    def test_unknown_and_partial_private_bindings_fail_closed(self) -> None:
        document = self._document(b"x")
        unknown_id = eid("artifact", 999)
        code, report = verify_document_read_only(
            document,
            bindings=VerificationBindings(
                target_paths={unknown_id: Path("unused")}
            ),
        )
        self.assertEqual(code, 2)
        self.assertIn("not referenced", report["errors"][0])

        code, report = verify_document_read_only(
            document,
            bindings=VerificationBindings(
                target_paths={self.artifact_id: Path("incomplete")}
            ),
        )
        self.assertEqual(code, 2)
        self.assertIn("requires both", report["errors"][0])

    def test_bad_ledger_cannot_be_masked_by_explicit_missing_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            content = b"expected"
            expected = hashlib.sha256(content).hexdigest()
            ledger = root / "ledger.txt"
            ledger.write_text(f"{expected}  absent.bin\n", encoding="utf-8")
            document = self._document(content, ledger_hash="0" * 64)
            ledger_id = document["body"]["inheritance_sources"][0][
                "artifact"
            ]["ledger_ref"]["ledger_artifact_id"]
            code, report = verify_document_read_only(
                document,
                bindings=VerificationBindings(
                    target_paths={self.artifact_id: root / "absent.bin"},
                    target_roots={self.artifact_id: root},
                    ledger_paths={ledger_id: ledger},
                    ledger_roots={self.artifact_id: root},
                    ledger_entries={self.artifact_id: "absent.bin"},
                ),
            )
            self.assertEqual(code, 2)
            self.assertEqual(
                report["target_results"][0]["status"], "target_invalid"
            )
            self.assertIn(
                "ledger SHA-256 mismatch",
                report["target_results"][0]["message"],
            )

    def test_ledger_root_and_entry_symlinks_fail_even_with_valid_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            content = b"expected"
            target = root / "target.bin"
            target.write_bytes(content)
            expected = hashlib.sha256(content).hexdigest()
            ledger = root / "ledger.txt"
            ledger.write_text(f"{expected}  target.bin\n", encoding="utf-8")
            ledger_hash = hashlib.sha256(ledger.read_bytes()).hexdigest()
            document = self._document(content, ledger_hash)
            ledger_id = document["body"]["inheritance_sources"][0][
                "artifact"
            ]["ledger_ref"]["ledger_artifact_id"]
            bindings = VerificationBindings(
                target_paths={self.artifact_id: target},
                target_roots={self.artifact_id: root},
                ledger_paths={ledger_id: ledger},
                ledger_roots={self.artifact_id: target},
                ledger_entries={self.artifact_id: "target.bin"},
            )
            code, report = verify_document_read_only(
                document, bindings=bindings
            )
            self.assertEqual(code, 2)
            self.assertIn(
                "not a directory", report["target_results"][0]["message"]
            )

            if hasattr(os, "symlink"):
                link = root / "link.bin"
                link.symlink_to(target.name)
                ledger.write_text(f"{expected}  link.bin\n", encoding="utf-8")
                ledger_hash = hashlib.sha256(ledger.read_bytes()).hexdigest()
                document = self._document(content, ledger_hash)
                bindings.ledger_roots[self.artifact_id] = root
                bindings.ledger_entries[self.artifact_id] = "link.bin"
                code, report = verify_document_read_only(
                    document, bindings=bindings
                )
                self.assertEqual(code, 2)
                self.assertIn(
                    "symlink", report["target_results"][0]["message"]
                )

    def test_target_path_inspection_error_becomes_controlled_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.bin"
            target.write_bytes(b"x")
            document = self._document(b"x")
            bindings = VerificationBindings(
                target_paths={self.artifact_id: target},
                target_roots={self.artifact_id: root},
            )
            original_lstat = Path.lstat

            def guarded_lstat(path: Path):
                if path == root:
                    raise PermissionError("fictional denied")
                return original_lstat(path)

            with mock.patch.object(Path, "lstat", guarded_lstat):
                code, report = verify_document_read_only(
                    document, bindings=bindings
                )
            self.assertEqual(code, 2)
            self.assertEqual(
                report["target_results"][0]["status"], "target_invalid"
            )
            self.assertIn(
                "fictional denied", report["target_results"][0]["message"]
            )

            with mock.patch.object(
                Path,
                "cwd",
                side_effect=PermissionError("fictional cwd denied"),
            ):
                code, report = verify_document_read_only(
                    document,
                    bindings=VerificationBindings(
                        target_paths={self.artifact_id: Path("target.bin")},
                        target_roots={self.artifact_id: Path(".")},
                    ),
                )
            self.assertEqual(code, 2)
            self.assertIn(
                "fictional cwd denied",
                report["target_results"][0]["message"],
            )

    def test_shared_bad_ledger_failure_uses_one_snapshot_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "ledger.txt"
            ledger.write_text(
                f"{hashlib.sha256(b'a').hexdigest()}  a.bin\n"
                f"{hashlib.sha256(b'b').hexdigest()}  b.bin\n",
                encoding="utf-8",
            )
            sources = [
                source(1, sha256=hashlib.sha256(b"a").hexdigest(), ledger_sha256="0" * 64),
                source(2, sha256=hashlib.sha256(b"b").hexdigest(), ledger_sha256="0" * 64),
            ]
            ledger_id = sources[0]["artifact"]["ledger_ref"][
                "ledger_artifact_id"
            ]
            sources[1]["artifact"]["ledger_ref"]["ledger_artifact_id"] = (
                ledger_id
            )
            document = root_document(sources=sources)
            first_id = sources[0]["artifact"]["artifact_id"]
            second_id = sources[1]["artifact"]["artifact_id"]
            bindings = VerificationBindings(
                ledger_paths={ledger_id: ledger},
                ledger_roots={first_id: root, second_id: root},
                ledger_entries={first_id: "a.bin", second_id: "b.bin"},
            )
            with mock.patch.object(
                lineage_module,
                "load_ledger_entries",
                wraps=lineage_module.load_ledger_entries,
            ) as loader:
                code, report = verify_document_read_only(
                    document, bindings=bindings
                )
            self.assertEqual(code, 2)
            self.assertEqual(loader.call_count, 1)
            self.assertEqual(
                [result["status"] for result in report["target_results"]],
                ["target_invalid", "target_invalid"],
            )

    def test_cli_verify_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            document_path = directory / "root.json"
            document_path.write_text(
                json.dumps(root_document()), encoding="utf-8"
            )
            before = sorted(path.name for path in directory.iterdir())
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "lineage",
                        "verify",
                        "--document",
                        str(document_path),
                        "--json",
                    ]
                )
            after = sorted(path.name for path in directory.iterdir())
            self.assertEqual(code, 0)
            self.assertEqual(before, after)

    def test_report_schema_forces_acceptance_incomplete_and_decline_only(
        self,
    ) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "tools"
            / "spec"
            / "echo-lineage-v1"
            / "verification-report.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        acceptance_rules = [
            rule
            for rule in schema["allOf"]
            if rule.get("if", {}).get("properties", {}).get("document_type")
            == {"const": "lineage_acceptance"}
        ]
        self.assertEqual(len(acceptance_rules), 1)
        properties = acceptance_rules[0]["then"]["properties"]
        self.assertEqual(
            properties["evidence_status"], {"const": "incomplete"}
        )
        self.assertEqual(
            properties["allowed_future_decisions"]["enum"],
            [
                ["declined"],
                ["declined", "quarantined_integrity_failure"],
            ],
        )

    def test_direct_cli_does_not_create_pycache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source_dir = Path(__file__).parents[1] / "tools" / "tools"
            for name in (
                "echo_lineage.py",
                "echo_canonical.py",
                "echo_ledger.py",
            ):
                (directory / name).write_bytes((source_dir / name).read_bytes())
            document_path = directory / "root.json"
            document_path.write_text(
                json.dumps(root_document()), encoding="utf-8"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(directory / "echo_lineage.py"),
                    "lineage",
                    "verify",
                    "--document",
                    str(document_path),
                    "--json",
                ],
                cwd=directory,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((directory / "__pycache__").exists())

    def test_module_cli_with_dash_b_does_not_create_pycache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source_dir = Path(__file__).parents[1] / "tools" / "tools"
            module_dir = directory / "tools" / "tools"
            module_dir.mkdir(parents=True)
            for name in (
                "echo_lineage.py",
                "echo_canonical.py",
                "echo_ledger.py",
            ):
                (module_dir / name).write_bytes((source_dir / name).read_bytes())
            document_path = directory / "root.json"
            document_path.write_text(
                json.dumps(root_document()), encoding="utf-8"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "tools.tools.echo_lineage",
                    "lineage",
                    "verify",
                    "--document",
                    str(document_path),
                    "--json",
                ],
                cwd=directory,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(any(directory.rglob("__pycache__")))

    def test_cli_rejects_duplicate_keys_and_document_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            duplicate = directory / "duplicate.json"
            duplicate.write_text(
                '{"protocol":"echo-lineage/v1","protocol":"other"}',
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "lineage",
                        "verify",
                        "--document",
                        str(duplicate),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("duplicate JSON key", output.getvalue())

            if hasattr(os, "symlink"):
                valid = directory / "valid.json"
                valid.write_text(json.dumps(root_document()), encoding="utf-8")
                link = directory / "link.json"
                link.symlink_to(valid)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main(
                        [
                            "lineage",
                            "verify",
                            "--document",
                            str(link),
                        ]
                    )
                self.assertEqual(code, 2)
                self.assertIn("symlink component", output.getvalue())


if __name__ == "__main__":
    unittest.main()
