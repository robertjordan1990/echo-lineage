from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.tools.echo_stack import cmd_make


REPO_ROOT = Path(__file__).resolve().parents[1]
STACK_CLI = REPO_ROOT / "tools" / "tools" / "echo_stack.py"


class StackPrivacyTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, str(STACK_CLI), *args],
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    def test_default_omits_raw_and_preserves_source_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source_bytes = b"private source\n"
            source.write_bytes(source_bytes)
            out = base / "stacks"

            result = self.run_cli(
                "make",
                "--in",
                str(source),
                "--out",
                str(out),
                "--name",
                "demo",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            pack = out / "demo"
            self.assertFalse((pack / "00_raw.txt").exists())
            want = hashlib.sha256(source_bytes).hexdigest()
            self.assertEqual(
                (pack / "SOURCE_SHA256.txt").read_text(encoding="utf-8"),
                f"source_sha256: {want}\n",
            )
            sums = (pack / "SHA256SUMS.txt").read_text(encoding="utf-8")
            self.assertIn("SOURCE_SHA256.txt", sums)
            self.assertNotIn("00_raw.txt", sums)

    def test_raw_requires_explicit_include_raw_option(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")
            out = base / "stacks"

            result = self.run_cli(
                "make",
                "--in",
                str(source),
                "--out",
                str(out),
                "--name",
                "private-demo",
                "--include-raw",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (out / "private-demo" / "00_raw.txt").read_text(encoding="utf-8"),
                "private source\n",
            )
            source_hash = hashlib.sha256(b"private source\n").hexdigest()
            self.assertEqual(
                (
                    out / "private-demo" / "SOURCE_SHA256.txt"
                ).read_text(encoding="utf-8"),
                f"source_sha256: {source_hash}\n",
            )

    def test_deprecated_no_raw_alias_is_accepted_as_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")
            out = base / "stacks"

            result = self.run_cli(
                "make",
                "--in",
                str(source),
                "--out",
                str(out),
                "--name",
                "legacy-demo",
                "--no-raw",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((out / "legacy-demo" / "00_raw.txt").exists())
            self.assertTrue((out / "legacy-demo" / "SOURCE_SHA256.txt").is_file())

    def test_deprecated_no_raw_alias_emits_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")

            result = self.run_cli(
                "make",
                "--in",
                str(source),
                "--out",
                str(base / "stacks"),
                "--name",
                "warning-demo",
                "--no-raw",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("WARNING: --no-raw is deprecated", result.stderr)

    def test_include_raw_conflicts_with_deprecated_no_raw(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")
            out = base / "stacks"

            result = self.run_cli(
                "make",
                "--in",
                str(source),
                "--out",
                str(out),
                "--name",
                "conflict-demo",
                "--include-raw",
                "--no-raw",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("not allowed with argument", result.stderr)
            self.assertFalse((out / "conflict-demo").exists())

    def test_existing_pack_is_not_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")
            out = base / "stacks"
            pack = out / "demo"
            pack.mkdir(parents=True)
            (pack / "00_raw.txt").write_text("stale private data\n", encoding="utf-8")

            result = self.run_cli(
                "make",
                "--in",
                str(source),
                "--out",
                str(out),
                "--name",
                "demo",
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                (pack / "00_raw.txt").read_text(encoding="utf-8"),
                "stale private data\n",
            )

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits are unavailable")
    def test_creation_modes_are_restrictive_with_liberal_umask(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")
            out = base / "stacks"

            old_umask = os.umask(0)
            try:
                # If chmod were the only protection, disabling it here would
                # leave liberal modes behind and this test would fail.
                with patch("tools.tools.echo_stack.os.chmod"):
                    cmd_make(
                        source,
                        out,
                        "secure-demo",
                        include_raw=False,
                        rules_path=None,
                    )
            finally:
                os.umask(old_umask)

            pack = out / "secure-demo"
            self.assertEqual(stat.S_IMODE(pack.stat().st_mode), 0o700)
            for path in pack.iterdir():
                with self.subTest(path=path.name):
                    self.assertTrue(path.is_file())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits are unavailable")
    def test_included_raw_and_source_hash_are_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")
            out = base / "stacks"

            old_umask = os.umask(0)
            try:
                result = self.run_cli(
                    "make",
                    "--in",
                    str(source),
                    "--out",
                    str(out),
                    "--name",
                    "private-demo",
                    "--include-raw",
                )
            finally:
                os.umask(old_umask)

            self.assertEqual(result.returncode, 0, result.stderr)
            pack = out / "private-demo"
            self.assertEqual(
                stat.S_IMODE((pack / "00_raw.txt").stat().st_mode), 0o600
            )
            self.assertEqual(
                stat.S_IMODE((pack / "SOURCE_SHA256.txt").stat().st_mode),
                0o600,
            )

    def test_cmd_make_include_raw_is_keyword_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source.write_text("private source\n", encoding="utf-8")

            with self.assertRaisesRegex(TypeError, "positional"):
                cmd_make(source, base / "stacks", "demo", False, None)  # type: ignore[misc]

            self.assertFalse((base / "stacks" / "demo").exists())

    def test_source_is_read_once_for_hash_raw_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "private.txt"
            source_bytes = b"private test@example.com\n"
            source.write_bytes(source_bytes)
            out = base / "stacks"
            original_read_bytes = Path.read_bytes
            source_reads = 0

            def tracked_read_bytes(path: Path) -> bytes:
                nonlocal source_reads
                if path == source:
                    source_reads += 1
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", tracked_read_bytes):
                cmd_make(
                    source,
                    out,
                    "snapshot-demo",
                    include_raw=True,
                    rules_path=None,
                )

            pack = out / "snapshot-demo"
            self.assertEqual(source_reads, 1)
            self.assertEqual((pack / "00_raw.txt").read_bytes(), source_bytes)
            self.assertEqual(
                (pack / "SOURCE_SHA256.txt").read_text(encoding="utf-8"),
                f"source_sha256: {hashlib.sha256(source_bytes).hexdigest()}\n",
            )
            self.assertEqual(
                (pack / "10_redacted.txt").read_text(encoding="utf-8"),
                "private [REDACTED_EMAIL]\n",
            )


if __name__ == "__main__":
    unittest.main()
