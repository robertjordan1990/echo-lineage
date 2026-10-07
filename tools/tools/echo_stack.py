#!/usr/bin/env python3
"""echo_stack.py — build a public-safe “stack pack” from a private source.

A stack pack is a small folder containing:
- redacted excerpt (shareable)
- claims template
- action template
- SHA-256 sums

Optionally it may also include a copy of the raw input (PRIVATE — do not commit).

Usage:
  python3 tools/tools/echo_stack.py make --in transcript.txt --out stacks --name demo
  python3 tools/tools/echo_stack.py make --in transcript.txt --out private_stacks --name demo --include-raw
  python3 tools/tools/echo_stack.py make --in transcript.txt --out stacks --name demo --rules rules.txt
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import List, Tuple
import re

# keep redaction logic self-contained (no import gymnastics)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?:(?:\+|00)?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d(?:[\s-]?\d){6,14}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_rules(path: Path) -> List[Tuple[re.Pattern, str]]:
    rules: List[Tuple[re.Pattern, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=>" in s:
            pat, repl = s.split("=>", 1)
            pat = pat.strip()
            repl = repl.strip()
        else:
            pat, repl = s, "[REDACTED_CUSTOM]"
        rules.append((re.compile(pat), repl))
    return rules


def redact_text(text: str, extra_rules: List[Tuple[re.Pattern, str]] | None) -> str:
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)

    def _phone_sub(m: re.Match) -> str:
        s = m.group(0)
        digits = re.sub(r"\D", "", s)
        if len(digits) < 7:
            return s
        return "[REDACTED_PHONE]"

    text = PHONE_RE.sub(_phone_sub, text)

    if extra_rules:
        for pat, repl in extra_rules:
            text = pat.sub(repl, text)
    return text


CLAIMS_TEMPLATE = """# Claims (template)

Source: <describe the private source briefly>
Risk level (L0–L5): <fill>

List claims derived from the excerpt, tagging each:

- [SUPPORTED] <claim>  (pointer: <file/hash>)
- [PLAUSIBLE] <claim>
- [UNKNOWN] <claim> (needs data)

Notes:
- Keep this factual. Avoid speculation.
"""

ACTIONS_TEMPLATE = """# Actions / decisions (template)

What this excerpt *shows*:
- ...

What it does *not* show:
- ...

Next steps:
1) ...
2) ...

Constraints / assumptions:
- ...

Publish checklist:
- [ ] excerpt anonymized
- [ ] no personal identifiers remain
- [ ] hashes recorded
"""


def write_private_text(path: Path, text: str) -> None:
    """Create a stack file without exposing it through the process umask."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = -1
            stream.write(text)
    finally:
        if fd != -1:
            os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)


def write_private_bytes(path: Path, data: bytes) -> None:
    """Create a binary stack file with restrictive permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
    finally:
        if fd != -1:
            os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)


def cmd_make(
    inp: Path,
    out_root: Path,
    name: str,
    *,
    include_raw: bool,
    rules_path: Path | None,
) -> None:
    if not inp.is_file():
        raise FileNotFoundError(str(inp))
    if Path(name).name != name or name in ("", ".", ".."):
        raise ValueError("stack name must be one safe path component")

    pack = out_root / name
    pack.mkdir(mode=0o700, parents=True, exist_ok=False)
    if os.name == "posix":
        os.chmod(pack, 0o700)

    ext = inp.suffix or ".txt"
    raw_dst = pack / f"00_raw{ext}"
    red_dst = pack / f"10_redacted{ext}"

    rules = load_rules(rules_path) if rules_path else None

    # One byte snapshot is the source for the anchor, optional raw copy, and
    # redaction. This avoids internally inconsistent packs if the input changes
    # while a pack is being built.
    source_data = inp.read_bytes()
    source_hash = hashlib.sha256(source_data).hexdigest()
    write_private_text(
        pack / "SOURCE_SHA256.txt",
        f"source_sha256: {source_hash}\n",
    )

    # Copy raw only after explicit opt-in.
    if include_raw:
        write_private_bytes(raw_dst, source_data)

    # produce redacted
    data = source_data.decode("utf-8", errors="replace")
    write_private_text(red_dst, redact_text(data, rules))

    write_private_text(pack / "20_claims.md", CLAIMS_TEMPLATE)
    write_private_text(pack / "30_actions.md", ACTIONS_TEMPLATE)

    # sha256 sums
    lines = []
    for p in sorted(pack.iterdir()):
        if p.is_file():
            lines.append(f"{sha256_file(p)}  {p.name}")
    write_private_text(pack / "SHA256SUMS.txt", "\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("make", help="create a stack pack")
    m.add_argument("--in", dest="inp", required=True, help="input transcript/text file")
    m.add_argument("--out", dest="out", required=True, help="output folder (will create <out>/<name>/)")
    m.add_argument("--name", required=True, help="stack pack name")
    raw_options = m.add_mutually_exclusive_group()
    raw_options.add_argument(
        "--include-raw",
        action="store_true",
        help="explicitly include a PRIVATE copy of raw input (unsafe for public packs)",
    )
    raw_options.add_argument(
        "--no-raw",
        action="store_true",
        help="deprecated compatibility alias; raw is already omitted by default",
    )
    m.add_argument("--rules", default=None, help="optional redaction rules file")

    args = ap.parse_args()

    if args.cmd == "make":
        if args.no_raw:
            print(
                "WARNING: --no-raw is deprecated and has no effect; "
                "raw input is omitted by default.",
                file=sys.stderr,
            )
        cmd_make(
            Path(args.inp),
            Path(args.out),
            args.name,
            include_raw=args.include_raw,
            rules_path=Path(args.rules) if args.rules else None,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
