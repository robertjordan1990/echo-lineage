from __future__ import annotations

import contextlib
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.tools.echo_ledger import (
    LINE_SEPARATORS,
    LedgerError,
    load_ledger_entries,
    verify_ledger,
    write_ledger,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER_CLI = REPO_ROOT / "tools" / "tools" / "echo_ledger.py"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ledger_line(data: bytes, rel_path: str) -> str:
    return f"{sha256_bytes(data)}  {rel_path}\n"


class LedgerHardeningTests(unittest.TestCase):
    def run_quietly(self, func, *args, **kwargs) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return func(*args, **kwargs)

    def run_with_output(self, func, *args, **kwargs) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            return func(*args, **kwargs), output.getvalue()

    def assert_ledger_error(
        self, expected: str, func, *args, **kwargs
    ) -> None:
        result, output = self.run_with_output(func, *args, **kwargs)
        self.assertEqual(result, 2, output)
        self.assertIn(expected, output)

    def test_shared_loader_returns_normalized_lowercase_map(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.txt"
            want = sha256_bytes(b"content")
            ledger.write_text(
                f"{want.upper()}  folder/./item.bin\n", encoding="utf-8"
            )

            self.assertEqual(
                load_ledger_entries(ledger),
                {"folder/item.bin": want},
            )

    def test_shared_loader_checks_expected_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.txt"
            ledger_bytes = ledger_line(b"content", "item.bin").encode("utf-8")
            ledger.write_bytes(ledger_bytes)

            self.assertEqual(
                load_ledger_entries(
                    ledger,
                    expected_sha256=sha256_bytes(ledger_bytes),
                ),
                {"item.bin": sha256_bytes(b"content")},
            )
            with self.assertRaisesRegex(
                LedgerError, "ledger SHA-256 mismatch"
            ):
                load_ledger_entries(ledger, expected_sha256="0" * 64)

    def test_shared_loader_hashes_and_parses_one_byte_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.txt"
            ledger_bytes = ledger_line(b"content", "item.bin").encode("utf-8")
            ledger.write_bytes(ledger_bytes)
            original_read_bytes = Path.read_bytes
            reads: list[Path] = []

            def counted_read_bytes(path: Path) -> bytes:
                reads.append(path)
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", new=counted_read_bytes):
                entries = load_ledger_entries(
                    ledger,
                    expected_sha256=sha256_bytes(ledger_bytes),
                )

            self.assertEqual(reads, [ledger])
            self.assertEqual(
                entries, {"item.bin": sha256_bytes(b"content")}
            )

    def test_shared_loader_rejects_missing_and_irregular_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for ledger in (root / "missing.txt", root):
                with self.subTest(ledger=ledger):
                    with self.assertRaisesRegex(
                        LedgerError,
                        "ledger not found or not a regular file",
                    ):
                        load_ledger_entries(ledger)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_shared_loader_rejects_final_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            target.write_text(
                ledger_line(b"content", "item.bin"), encoding="utf-8"
            )
            ledger = root / "ledger.txt"
            ledger.symlink_to(target)

            with self.assertRaisesRegex(
                LedgerError, "input ledger must not be a symlink"
            ):
                load_ledger_entries(ledger)

    def test_shared_loader_rejects_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.txt"
            ledger.write_bytes(b"\xff")

            with self.assertRaisesRegex(
                LedgerError, "ledger is not valid UTF-8"
            ):
                load_ledger_entries(ledger)

    def test_shared_loader_rejects_every_unsupported_separator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.txt"
            valid = ledger_line(b"content", "item.bin").rstrip("\n")
            separators = sorted(LINE_SEPARATORS - {"\n"}) + ["\r\n"]

            for separator in separators:
                with self.subTest(separator=ascii(separator)):
                    ledger.write_bytes((valid + separator).encode("utf-8"))
                    with self.assertRaisesRegex(
                        LedgerError,
                        "ledger contains an unsupported line separator",
                    ):
                        load_ledger_entries(ledger)

    def test_shared_loader_rejects_malformed_duplicate_empty_and_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.txt"
            valid_line = ledger_line(b"content", "item.bin")
            cases = (
                ("malformed", b"not-a-ledger\n", "malformed ledger entry"),
                (
                    "duplicate",
                    (valid_line + valid_line).encode("utf-8"),
                    "duplicate path: item.bin",
                ),
                (
                    "normalized duplicate",
                    (
                        valid_line
                        + ledger_line(b"content", "./item.bin")
                    ).encode("utf-8"),
                    "duplicate path: item.bin",
                ),
                (
                    "empty path",
                    f"{sha256_bytes(b'content')}  \n".encode("utf-8"),
                    "empty path",
                ),
                ("empty", b"# comment only\n", "no file entries"),
                (
                    "unsafe",
                    ledger_line(b"content", "../item.bin").encode("utf-8"),
                    "must not contain '..'",
                ),
            )

            for name, content, message in cases:
                with self.subTest(case=name):
                    ledger.write_bytes(content)
                    with self.assertRaisesRegex(LedgerError, message):
                        load_ledger_entries(ledger)

    def test_rejects_malformed_ledger_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text("not-a-valid-ledger-line\n", encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "malformed ledger entry",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_rejects_duplicate_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"same"
            (root / "same.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(
                ledger_line(data, "same.txt") + ledger_line(data, "same.txt"),
                encoding="utf-8",
            )

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "duplicate path: same.txt",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_rejects_empty_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text("# comments do not make a ledger non-empty\n", encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "ledger contains no file entries",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_rejects_input_ledger_symlink_in_subset_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            real_ledger = root / "real-ledger.txt"
            real_ledger.write_text(
                ledger_line(data, "listed.txt"), encoding="utf-8"
            )
            linked_ledger = root / "linked-ledger.txt"
            linked_ledger.symlink_to(real_ledger)

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "input ledger must not be a symlink",
                        verify_ledger,
                        root,
                        linked_ledger,
                        strict=strict,
                    )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_make_rejects_output_symlink_without_changing_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "listed.txt").write_text("listed", encoding="utf-8")
            target = root / "existing-ledger.txt"
            original = b"existing ledger must survive\n"
            target.write_bytes(original)
            linked_output = root / "linked-output.txt"
            linked_output.symlink_to(target)

            self.assert_ledger_error(
                "output ledger must not be a symlink",
                write_ledger,
                root,
                linked_output,
                [],
            )
            self.assertEqual(target.read_bytes(), original)
            self.assertTrue(linked_output.is_symlink())

    def test_make_rejects_filename_with_line_separator_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "LEDGER__sha256.txt"
            original = b"previous valid ledger\n"
            output.write_bytes(original)
            (root / "unsafe\nname.txt").write_text("unsafe", encoding="utf-8")

            self.assert_ledger_error(
                "generated ledger path contains an unsupported line separator",
                write_ledger,
                root,
                output,
                [],
            )
            self.assertEqual(output.read_bytes(), original)
            self.assertFalse(
                any(
                    path.name.startswith(f".{output.name}.")
                    for path in root.iterdir()
                )
            )

    def test_rejects_non_lf_line_separator_in_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(
                ledger_line(data, "listed.txt").rstrip("\n") + "\u2028",
                encoding="utf-8",
            )

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "ledger contains an unsupported line separator",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_rejects_bare_cr_record_separator_in_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_bytes(
                ledger_line(data, "listed.txt").rstrip("\n").encode("utf-8")
                + b"\r"
            )

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "ledger contains an unsupported line separator",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_rejects_crlf_record_separator_in_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_bytes(
                ledger_line(data, "listed.txt").rstrip("\n").encode("utf-8")
                + b"\r\n"
            )

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "ledger contains an unsupported line separator",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_two_valid_entries_separated_only_by_cr_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = b"first"
            second = b"second"
            (root / "first.txt").write_bytes(first)
            (root / "second.txt").write_bytes(second)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_bytes(
                (
                    ledger_line(first, "first.txt").rstrip("\n")
                    + "\r"
                    + ledger_line(second, "second.txt").rstrip("\n")
                ).encode("utf-8")
            )

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "ledger contains an unsupported line separator",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_rejects_line_separator_in_exclude(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(
                ledger_line(data, "listed.txt"), encoding="utf-8"
            )

            self.assert_ledger_error(
                "exclude path contains an unsupported line separator",
                verify_ledger,
                root,
                ledger,
                exclude=[Path("bad\u0085name")],
                strict=True,
            )

    def test_rejects_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(b"x", "/etc/passwd"), encoding="utf-8")

            self.assert_ledger_error(
                "ledger path must be relative", verify_ledger, root, ledger
            )

    def test_rejects_windows_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(b"x", r"C:\outside.txt"), encoding="utf-8")

            self.assert_ledger_error(
                "ledger path must be relative", verify_ledger, root, ledger
            )

    def test_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(b"x", "safe/../outside.txt"), encoding="utf-8")

            self.assert_ledger_error(
                "must not contain '..'", verify_ledger, root, ledger
            )

    def test_detects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(b"missing", "missing.txt"), encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "MISSING: missing.txt",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_extra_file_passes_in_subset_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            (root / "extra.txt").write_text("extra", encoding="utf-8")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            self.assertEqual(self.run_quietly(verify_ledger, root, ledger), 0)

    def test_same_extra_file_fails_in_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            (root / "extra.txt").write_text("extra", encoding="utf-8")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            self.assert_ledger_error(
                "EXTRA: extra.txt",
                verify_ledger,
                root,
                ledger,
                strict=True,
            )

    def test_detects_hidden_extra_file_in_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            (root / ".unexpected").write_text("extra", encoding="utf-8")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            self.assert_ledger_error(
                "EXTRA: .unexpected",
                verify_ledger,
                root,
                ledger,
                strict=True,
            )

    def test_explicit_exclude_allows_intentional_extra_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            (root / "FINGERPRINT.txt").write_text("derived\n", encoding="utf-8")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            self.assertEqual(
                self.run_quietly(
                    verify_ledger,
                    root,
                    ledger,
                    exclude=[Path("FINGERPRINT.txt")],
                    strict=True,
                ),
                0,
            )

    def test_exclude_without_strict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(LEDGER_CLI),
                    "verify",
                    str(ledger),
                    "--root",
                    str(root),
                    "--exclude",
                    "extra.txt",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--exclude requires --strict", result.stdout)

    def test_nested_dot_git_is_not_a_strict_mode_blind_spot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            nested_git = root / "nested" / ".git"
            nested_git.mkdir(parents=True)
            (nested_git / "config").write_text("extra\n", encoding="utf-8")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            result, output = self.run_with_output(
                verify_ledger, root, ledger, strict=True
            )

            self.assertEqual(result, 2)
            self.assertIn("EXTRA: nested/.git/config", output)

    def test_root_dot_git_is_the_only_automatic_strict_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            root_git = root / ".git"
            root_git.mkdir()
            (root_git / "config").write_text("administrative\n", encoding="utf-8")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            result, output = self.run_with_output(
                verify_ledger, root, ledger, strict=True
            )

            self.assertEqual(result, 0, output)
            self.assertIn("strict mode", output)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_root_dot_git_symlink_is_not_treated_as_administrative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            administrative_target = root / "administrative-target"
            administrative_target.mkdir()
            (root / ".git").symlink_to(administrative_target)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "symlink is unsupported: .git",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    def test_changed_file_fails_in_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "changed.txt").write_bytes(b"changed")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(
                ledger_line(b"original", "changed.txt"), encoding="utf-8"
            )

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "FAIL: changed.txt",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_rejects_ledger_target_symlinked_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "root"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_bytes(b"outside")
            (root / "linked.txt").symlink_to(outside)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(b"outside", "linked.txt"), encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "target escapes root",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_make_rejects_unlisted_symlink_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "root"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_bytes(b"outside")
            (root / "linked.txt").symlink_to(outside)
            ledger = root / "LEDGER__sha256.txt"

            self.assert_ledger_error(
                "target escapes root",
                write_ledger,
                root,
                ledger,
                exclude=[],
            )
            self.assertFalse(ledger.exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_verify_rejects_unlisted_symlink_escape_in_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "root"
            root.mkdir()
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            outside = base / "outside.txt"
            outside.write_bytes(b"outside")
            (root / "unlisted-link.txt").symlink_to(outside)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "target escapes root",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_verify_rejects_internal_symlink_in_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            (root / "linked.txt").symlink_to(root / "listed.txt")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    self.assert_ledger_error(
                        "symlink is unsupported: linked.txt",
                        verify_ledger,
                        root,
                        ledger,
                        strict=strict,
                    )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_strict_rejects_dangling_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            (root / "dangling").symlink_to(root / "missing")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            self.assert_ledger_error(
                "dangling symlink is unsupported: dangling",
                verify_ledger,
                root,
                ledger,
                strict=True,
            )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "mkfifo"),
        "POSIX FIFO semantics are unavailable",
    )
    def test_strict_rejects_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            os.mkfifo(root / "pipe")
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            self.assert_ledger_error(
                "unsupported entry type: pipe",
                verify_ledger,
                root,
                ledger,
                strict=True,
            )

    def test_strict_rejects_socket_entry(self) -> None:
        class SocketEntry:
            name = "endpoint.sock"

            def __init__(self, root: Path) -> None:
                self.path = str(root / self.name)

            def is_symlink(self) -> bool:
                return False

            def is_file(self, *, follow_symlinks: bool) -> bool:
                return False

            def is_dir(self, *, follow_symlinks: bool) -> bool:
                return False

        @contextlib.contextmanager
        def fake_scandir(directory):
            yield [SocketEntry(Path(directory))]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            with patch(
                "tools.tools.echo_ledger.os.scandir", side_effect=fake_scandir
            ):
                self.assert_ledger_error(
                    "unsupported entry type: endpoint.sock",
                    verify_ledger,
                    root,
                    ledger,
                    strict=True,
                )

    def test_enumeration_error_is_fail_closed_in_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"listed"
            (root / "listed.txt").write_bytes(data)
            ledger = root / "LEDGER__sha256.txt"
            ledger.write_text(ledger_line(data, "listed.txt"), encoding="utf-8")

            for strict in (False, True):
                with self.subTest(strict=strict):
                    with patch(
                        "tools.tools.echo_ledger.os.scandir",
                        side_effect=PermissionError("enumeration denied"),
                    ):
                        self.assert_ledger_error(
                            "enumeration denied",
                            verify_ledger,
                            root,
                            ledger,
                            strict=strict,
                        )

    def test_make_refuses_empty_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "LEDGER__sha256.txt"

            self.assert_ledger_error(
                "refusing to create an empty ledger",
                write_ledger,
                root,
                ledger,
                exclude=[],
            )
            self.assertFalse(ledger.exists())

if __name__ == "__main__":
    unittest.main()
