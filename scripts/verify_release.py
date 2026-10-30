#!/usr/bin/env python3
"""Verify the complete release manifest and run the offline regression gate.

Run from any working directory with Python 3.10 or newer:
    python3 -B scripts/verify_release.py
The full profile requires the pinned optional Stage 2B dependencies.  To check
the unchanged 151-test Stage 2A baseline in an environment without cryptography:
    python3 -B scripts/verify_release.py --profile stage2a

SHA256SUMS covers every regular release file except itself and root .git
metadata. Missing, extra, special and symbolic-link files are rejected.
The existing public-pack check also needs Bash and standard Unix utilities.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "SHA256SUMS"
EXPECTED_TESTS = 306
STAGE2A_EXPECTED_TESTS = 151
# Frozen test modules from the published Stage 2A release a1fc9c5.  Select them
# explicitly so the stdlib-only profile never imports or silently skips 2B tests.
STAGE2A_TEST_MODULES = (
    "test_echo_canonical", "test_echohash_recompute", "test_handoff_verify",
    "test_ledger_hardening", "test_lineage_decision_policy", "test_lineage_documents",
    "test_lineage_heads", "test_lineage_identity", "test_lineage_verify", "test_stack_privacy",
)
HEX64 = re.compile(r"[0-9a-f]{64}")


class GateError(Exception):
    """An incomplete or inconsistent public release."""


def hash_regular_file(path: Path) -> str:
    """Reject links and non-regular files before and after opening."""
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode):
        raise GateError(f"not a regular file: {path.relative_to(ROOT)}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GateError(f"not a regular file: {path.relative_to(ROOT)}")
        if (initial.st_dev, initial.st_ino) != (opened.st_dev, opened.st_ino):
            raise GateError(f"file changed while opening: {path.relative_to(ROOT)}")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def snapshot() -> dict[str, str]:
    """Hash the exact tree without following any symlink."""
    result: dict[str, str] = {}

    def visit(directory: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                if directory == ROOT and entry.name == ".git":
                    continue
                path = Path(entry.path)
                relative = path.relative_to(ROOT).as_posix()
                if entry.is_symlink():
                    raise GateError(f"symbolic link is forbidden: {relative}")
                if entry.is_dir(follow_symlinks=False):
                    visit(path)
                elif entry.is_file(follow_symlinks=False):
                    result[relative] = hash_regular_file(path)
                else:
                    raise GateError(f"special file is forbidden: {relative}")

    visit(ROOT)
    return result


def read_manifest() -> dict[str, str]:
    path = ROOT / MANIFEST
    if path.is_symlink() or not path.is_file():
        raise GateError("SHA256SUMS is missing or is not a regular file")
    data = path.read_bytes()
    if not data.endswith(b"\n") or b"\r" in data:
        raise GateError("SHA256SUMS must use LF lines and a final newline")
    expected: dict[str, str] = {}
    for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if len(line) < 67 or line[64:66] != "  " or not HEX64.fullmatch(line[:64]):
            raise GateError(f"invalid SHA256SUMS record at line {number}")
        name = line[66:]
        relative = PurePosixPath(name)
        if (
            not name
            or relative.is_absolute()
            or "\\" in name
            or ":" in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or name == MANIFEST
            or name == ".git"
            or name.startswith(".git/")
        ):
            raise GateError(f"unsafe or excluded manifest path at line {number}")
        if name in expected:
            raise GateError(f"duplicate manifest path at line {number}")
        expected[name] = line[:64]
    if not expected:
        raise GateError("SHA256SUMS has no entries")
    return expected


def check_manifest(actual: dict[str, str]) -> None:
    expected = read_manifest()
    release_files = {name: digest for name, digest in actual.items() if name != MANIFEST}
    missing = sorted(expected.keys() - release_files.keys())
    extra = sorted(release_files.keys() - expected.keys())
    changed = sorted(name for name in expected.keys() & release_files.keys() if expected[name] != release_files[name])
    if missing or extra or changed:
        details = []
        for label, paths in (("missing", missing), ("extra", extra), ("hash mismatch", changed)):
            if paths:
                details.append(f"{label}: {', '.join(paths[:10])}")
        raise GateError("manifest mismatch; " + "; ".join(details))
    print(f"PASS release manifest ({len(expected)} files)", flush=True)


def run_checks(profile: str = "full") -> None:
    python = [sys.executable, "-B"]
    expected_tests = STAGE2A_EXPECTED_TESTS if profile == "stage2a" else EXPECTED_TESTS
    if profile == "stage2a" and importlib.util.find_spec("cryptography") is not None:
        raise GateError("stage2a profile requires an environment without cryptography")
    unit_tests = python + ["-m", "unittest"]
    if profile == "stage2a":
        unit_tests += [*STAGE2A_TEST_MODULES, "-v"]
    else:
        unit_tests += ["discover", "-s", "tests", "-v"]
    lineage = python + ["tools/tools/echo_lineage.py", "lineage", "verify"]
    fixture = "tools/examples/echo-lineage-v1/"
    checks = [
        ("unit tests", unit_tests, 0),
        ("public-pack manifest", ["bash", "scripts/verify_public_pack.sh"], 0),
        ("H_t seed", python + ["tools/tools/echo_ht_validate.py", "tools/examples/ECHO_Ht__seed__2026-01-31.jsonl", "--lmax", "5"], 0),
        ("H_t pair", python + ["tools/tools/echo_ht_validate.py", "Ht_pair.jsonl", "--lmax", "5", "--profile", "autolog"], 0),
        ("H_t content hash chain", python + ["tools/tools/echo_msg_hash.py", "verify", "--in", "Ht_pair.jsonl", "--recompute"], 0),
        ("verified independent root", lineage + ["--document", fixture + "TRAJECTORY_ROOT.example.json", "--json"], 0),
        ("incomplete acceptance", lineage + ["--document", fixture + "LINEAGE_ACCEPTANCE.example.json", "--related-root", fixture + "TRAJECTORY_ROOT.example.json", "--json"], 10),
        ("mutated root", lineage + ["--document", "examples/MUTATED_ROOT.json", "--json"], 2),
    ]
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    if profile == "stage2a":
        environment["PYTHONPATH"] = os.pathsep.join(
            item for item in (str(ROOT / "tests"), environment.get("PYTHONPATH", "")) if item
        )
    for label, command, expected_exit in checks:
        process = subprocess.run(command, cwd=ROOT, env=environment, text=True, capture_output=True, timeout=180, check=False)
        if process.returncode != expected_exit:
            details = (process.stdout + process.stderr)[-6000:].strip()
            raise GateError(f"{label}: expected exit {expected_exit}, got {process.returncode}\n{details}")
        suffix = f"exit {expected_exit}"
        if label == "unit tests":
            count = re.search(r"^Ran (\d+) tests? in ", process.stderr, re.MULTILINE)
            if count is None or int(count.group(1)) != expected_tests:
                raise GateError(f"unit test count must equal {expected_tests}; got {count.group(1) if count else 'unknown'}")
            skipped = re.search(r"\bskipped=([1-9][0-9]*)\b", process.stderr)
            if profile == "full" and skipped:
                raise GateError("full profile must run every test without skips")
            suffix = f"{expected_tests}/{expected_tests}; profile {profile}"
        print(f"PASS {label} ({suffix})", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("full", "stage2a"), default="full")
    arguments = parser.parse_args()
    try:
        before = snapshot()
        check_manifest(before)
        try:
            run_checks(arguments.profile)
        finally:
            after = snapshot()
            if before != after:
                paths = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
                raise GateError("release tree changed during verification: " + ", ".join(paths[:10]))
        print("PASS release tree unchanged; all 8 checks passed", flush=True)
        return 0
    except (GateError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
