#!/usr/bin/env python3
"""Echo-Lite: make/verify SHA-256 ledger (sha256sum compatible).

Examples:
  # create ledger for current dir
  python3 tools/tools/echo_ledger.py make . --out ledger/LEDGER__sha256.txt

  # verify ledger
  python3 tools/tools/echo_ledger.py verify ledger/LEDGER__sha256.txt

Notes:
- Ledger format matches coreutils sha256sum: '<hash>  <path>' (or '<hash> *<path>')
- Verification defaults to subset mode: every ledger entry is checked, while
  additional files under root are tolerated.
- Strict verification checks an exact manifest of regular files (including hidden
  files). Only the administrative .git entry directly under root is excluded.
- In strict mode, the ledger file itself is excluded automatically. Other files
  may be excluded explicitly with --exclude.
- Absolute paths, parent traversal and symlink escapes are rejected.

Important:
- We parse sha256sum-compatible lines without using split(), because <path> may contain spaces.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Iterable, List, Set, Tuple


class LedgerError(ValueError):
    """A malformed or unsafe ledger/root condition."""


LINE_SEPARATORS = frozenset(
    "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def normalize_relative_path(raw_path: str, *, label: str = "ledger path") -> Path:
    """Return a safe relative path or raise LedgerError."""
    if "\x00" in raw_path:
        raise LedgerError(f"{label} contains a NUL byte")
    if any(character in LINE_SEPARATORS for character in raw_path):
        raise LedgerError(
            f"{label} contains an unsupported line separator"
        )

    path = Path(raw_path)
    if path.is_absolute() or PureWindowsPath(raw_path).is_absolute():
        raise LedgerError(f"{label} must be relative: {raw_path!r}")
    if any(part == ".." for part in path.parts):
        raise LedgerError(f"{label} must not contain '..': {raw_path!r}")
    if not path.parts or path == Path("."):
        raise LedgerError(f"{label} must name a file")
    return path


def resolve_inside_root(root: Path, rel_path: Path) -> Tuple[Path, Path]:
    """Return (lexical target, resolved target), requiring root containment."""
    target = root / rel_path
    resolved = target.resolve(strict=False)
    if not _is_within(resolved, root):
        raise LedgerError(
            f"target escapes root after resolving symlinks: {rel_path.as_posix()!r}"
        )
    return target, resolved


def parse_ledger_line(line: str, line_no: int) -> Tuple[str, str] | None:
    """Parse a sha256sum-compatible ledger line.

    Core format (coreutils):
        <64hex><space><space|*><path>

    We avoid split() because <path> may contain spaces.

    Returns (want_hash, rel_path) or None if the line should be skipped.
    """

    if not line.strip():
        return None

    if line.lstrip().startswith("#"):
        return None

    raw = line.rstrip("\n")

    # Fast path: strict sha256sum layout (supports spaces in filenames).
    if len(raw) >= 66 and raw[64] == " ":
        want = raw[:64]
        marker = raw[65]
        if all(c in "0123456789abcdefABCDEF" for c in want) and marker in (" ", "*"):
            rel = raw[66:]
            if rel == "":
                raise LedgerError(f"line {line_no}: empty path")
            return want, rel

    # Fallback: tolerate non-standard whitespace (leading spaces in paths are ambiguous).
    parts = raw.split(maxsplit=1)
    if len(parts) < 2:
        raise LedgerError(f"line {line_no}: malformed ledger entry")

    want, rel = parts
    if len(want) != 64 or not all(c in "0123456789abcdefABCDEF" for c in want):
        raise LedgerError(f"line {line_no}: SHA-256 must be 64 hexadecimal characters")
    if not rel:
        raise LedgerError(f"line {line_no}: empty path")
    return want, rel


class _LoadedLedgerEntries(dict[str, str]):
    """Ledger map with private diagnostics retained for ``verify_ledger``."""

    def __init__(
        self,
        entries: dict[str, str],
        *,
        line_numbers: dict[str, int],
        display_hashes: dict[str, str],
    ) -> None:
        super().__init__(entries)
        self.line_numbers = line_numbers
        self.display_hashes = display_hashes


def load_ledger_entries(
    ledger_path: Path, *, expected_sha256: str | None = None
) -> dict[str, str]:
    """Load and validate a ledger as ``relative-path -> lowercase SHA-256``.

    The ledger is read exactly once. The optional whole-ledger digest and the
    parser therefore consume the same byte snapshot.

    ``Path.is_symlink()``, ``Path.is_file()`` and ``Path.read_bytes()`` cannot
    be combined into one portable, atomic stdlib operation. There is a residual
    TOCTOU window if an attacker can replace the final path component between
    those calls. Callers must keep the ledger's containing directory trusted.
    """
    if ledger_path.is_symlink():
        raise LedgerError("input ledger must not be a symlink")
    if not ledger_path.is_file():
        raise LedgerError(
            "ledger not found or not a regular file: "
            f"{ledger_path.resolve()}"
        )

    try:
        ledger_bytes = ledger_path.read_bytes()
    except OSError as exc:
        raise LedgerError(f"cannot read ledger: {exc}") from exc

    if expected_sha256 is not None:
        got_ledger_sha256 = hashlib.sha256(ledger_bytes).hexdigest()
        if got_ledger_sha256 != expected_sha256.lower():
            raise LedgerError("ledger SHA-256 mismatch")

    try:
        ledger_text = ledger_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LedgerError("ledger is not valid UTF-8") from exc

    unsupported_separators = LINE_SEPARATORS - {"\n"}
    if any(character in ledger_text for character in unsupported_separators):
        raise LedgerError("ledger contains an unsupported line separator")

    entries: dict[str, str] = {}
    line_numbers: dict[str, int] = {}
    display_hashes: dict[str, str] = {}
    for line_no, line in enumerate(ledger_text.split("\n"), start=1):
        parsed = parse_ledger_line(line, line_no)
        if parsed is None:
            continue

        want, raw_rel = parsed
        rel = normalize_relative_path(
            raw_rel, label=f"line {line_no} ledger path"
        ).as_posix()
        if rel in entries:
            raise LedgerError(f"line {line_no}: duplicate path: {rel}")
        entries[rel] = want.lower()
        line_numbers[rel] = line_no
        display_hashes[rel] = want

    if not entries:
        raise LedgerError("ledger contains no file entries")

    return _LoadedLedgerEntries(
        entries,
        line_numbers=line_numbers,
        display_hashes=display_hashes,
    )


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def iter_files(root: Path, *, reject_unsupported: bool = True) -> Iterable[Path]:
    """Yield supported files below root, rejecting unsafe or unsupported entries.

    Only the checkout-administrative ``root/.git`` entry is skipped. A nested
    entry named ``.git`` is ordinary pack content and must not create a blind
    spot during strict verification.
    """
    root = root.resolve()
    if not root.is_dir():
        raise LedgerError(f"root is not a directory: {root}")

    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if (
                    directory == root
                    and entry.name == ".git"
                    and not entry.is_symlink()
                    and (
                        entry.is_file(follow_symlinks=False)
                        or entry.is_dir(follow_symlinks=False)
                    )
                ):
                    continue

                rel = path.relative_to(root)
                if entry.is_symlink():
                    resolve_inside_root(root, rel)
                    if not path.exists():
                        raise LedgerError(
                            f"dangling symlink is unsupported: {rel.as_posix()}"
                        )
                    raise LedgerError(f"symlink is unsupported: {rel.as_posix()}")

                if entry.is_file(follow_symlinks=False):
                    yield path
                elif entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif reject_unsupported:
                    raise LedgerError(
                        f"unsupported entry type: {rel.as_posix()}"
                    )


def write_ledger(root: Path, out_path: Path, exclude: List[Path]) -> int:
    temporary_path: Path | None = None
    try:
        root = root.resolve()
        if not root.is_dir():
            raise LedgerError(f"root is not a directory: {root}")

        exclude_set = {
            normalize_relative_path(str(path), label="exclude path").as_posix()
            for path in exclude
        }
        if out_path.is_symlink():
            raise LedgerError("output ledger must not be a symlink")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Resolve only the containing directory. Resolving the final component
        # would follow an attacker-controlled output symlink.
        out_path = out_path.parent.resolve() / out_path.name
        if out_path.is_symlink():
            raise LedgerError("output ledger must not be a symlink")

        entries: List[Tuple[str, str]] = []
        for p in iter_files(root):
            rel = normalize_relative_path(
                p.relative_to(root).as_posix(),
                label="generated ledger path",
            ).as_posix()
            if rel in exclude_set:
                continue
            # Also skip the output ledger path even if it is inside root.
            if p == out_path:
                continue
            entries.append((sha256_file(p), rel))

        entries.sort(key=lambda x: x[1])
        if not entries:
            raise LedgerError("refusing to create an empty ledger")

        descriptor, temporary_name = tempfile.mkstemp(
            dir=out_path.parent,
            prefix=f".{out_path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as f:
            for h, rel in entries:
                f.write(f"{h}  {rel}\n")
            f.flush()
            os.fsync(f.fileno())

        # Replacing a final symlink replaces the link itself rather than
        # following it; a regular destination is published atomically.
        os.replace(temporary_path, out_path)
        temporary_path = None

        print(f"Wrote ledger: {out_path} ({len(entries)} files)")
        return 0
    except (LedgerError, OSError, RuntimeError, UnicodeError) as exc:
        print(f"ERROR: {exc}")
        return 2
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def verify_ledger(
    root: Path,
    ledger_path: Path,
    exclude: List[Path] | None = None,
    *,
    strict: bool = False,
) -> int:
    try:
        root = root.resolve()
        if not root.is_dir():
            raise LedgerError(f"root is not a directory: {root}")

        if exclude and not strict:
            raise LedgerError("--exclude requires --strict")

        ledger_entries = load_ledger_entries(ledger_path)
        ledger_path = ledger_path.resolve()

        exclude_set: Set[str] = {
            normalize_relative_path(str(path), label="exclude path").as_posix()
            for path in (exclude or [])
        }
        if _is_within(ledger_path, root):
            exclude_set.add(ledger_path.relative_to(root).as_posix())

        bad = 0
        total = len(ledger_entries)
        listed_paths: Set[str] = set(ledger_entries)
        line_numbers = getattr(ledger_entries, "line_numbers", {})
        display_hashes = getattr(ledger_entries, "display_hashes", {})

        for rel, want in ledger_entries.items():
            line_no = line_numbers.get(rel)
            line_prefix = f"line {line_no}: " if line_no is not None else ""
            rel_path = Path(rel)

            target, _resolved = resolve_inside_root(root, rel_path)
            if target.is_symlink():
                raise LedgerError(
                    f"{line_prefix}symlink ledger target is unsupported: {rel}"
                )
            if not target.exists() or not target.is_file():
                bad += 1
                print(f"MISSING: {rel}")
                continue

            got = sha256_file(target)
            if got.lower() != want:
                bad += 1
                display_want = display_hashes.get(rel, want)
                print(f"FAIL: {rel}\n  want {display_want}\n  got  {got}")
            else:
                print(f"OK: {rel}")

        extra_paths: List[str] = []
        if strict:
            actual_paths = {
                p.relative_to(root).as_posix()
                for p in iter_files(root)
                if p.relative_to(root).as_posix() not in exclude_set
            }
            extra_paths = sorted(actual_paths - listed_paths)
            for rel in extra_paths:
                bad += 1
                print(f"EXTRA: {rel}")
        else:
            # Subset mode tolerates extra regular and irregular entries, but
            # symlinks are never accepted. Enumeration errors remain fatal.
            for _path in iter_files(root, reject_unsupported=False):
                pass

        mode = "strict" if strict else "subset"
        print(
            f"\nSummary: {total} checked | {len(extra_paths)} extra | "
            f"{bad} failed | {mode} mode"
        )
        return 0 if bad == 0 else 2
    except (LedgerError, OSError, RuntimeError, UnicodeError) as exc:
        print(f"ERROR: {exc}")
        return 2


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_make = sub.add_parser("make", help="create ledger")
    ap_make.add_argument("root", help="root directory")
    ap_make.add_argument("--out", required=True, help="output ledger path")
    ap_make.add_argument(
        "--exclude", action="append", default=[], help="relative paths to exclude (repeatable)"
    )

    ap_ver = sub.add_parser("verify", help="verify ledger")
    ap_ver.add_argument("ledger", help="ledger file path")
    ap_ver.add_argument(
        "--root", default=".", help="root directory used when ledger was made (default: .)"
    )
    ap_ver.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="relative paths excluded from strict checks (requires --strict; repeatable)",
    )
    ap_ver.add_argument(
        "--strict",
        action="store_true",
        help="require an exact closed-pack match and reject unsupported entries",
    )

    args = ap.parse_args()

    if args.cmd == "make":
        root = Path(args.root)
        out = Path(args.out)
        exclude = [Path(x) for x in args.exclude]
        return write_ledger(root, out, exclude=exclude)

    if args.cmd == "verify":
        root = Path(args.root)
        ledger = Path(args.ledger)
        exclude = [Path(x) for x in args.exclude]
        return verify_ledger(root, ledger, exclude=exclude, strict=args.strict)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
