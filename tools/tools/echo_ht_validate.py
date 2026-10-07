#!/usr/bin/env python3
"""Echo-Lite: validate H_t JSONL log (v0.1).

Design goals:
- zero external deps
- strict enough to catch drift/garbage early

Profiles:
- full: strict v0.1 schema intent (requires w_t and y_t)
- autolog: minimal HT_APPEND-friendly profile (requires only t, timestamp, mode, L_t;
  warns if w_t/y_t missing; accepts hash-chain fields; accepts 'HT_APPEND {json}' lines)

Exit codes:
- 0: OK
- 2: validation errors
- 3: file/parse errors
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

ALLOWED_MODES = {"VAULT", "LEGAL", "DRAFT", "RESEARCH", "TECH", "OTHER"}
ALLOWED_CLAIM_KINDS = {"WYNIKA", "PRAWDOPODOBNE", "BRAKI"}
ALLOWED_ROLES = {"user", "assistant"}
HEX64_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class Profile:
    FULL = "full"  # strict v0.1 schema intent
    AUTOLOG = "autolog"  # minimal HT_APPEND-friendly profile


@dataclass
class Issue:
    line_no: int
    level: str  # ERROR/WARN
    msg: str


def _is_str_list(x: Any) -> bool:
    return isinstance(x, list) and all(isinstance(i, str) for i in x)


def validate_entry(obj: Dict[str, Any], line_no: int, lmax: int, profile: str) -> List[Issue]:
    issues: List[Issue] = []

    def err(m: str) -> None:
        issues.append(Issue(line_no, "ERROR", m))

    def warn(m: str) -> None:
        issues.append(Issue(line_no, "WARN", m))

    # required fields depend on profile
    if profile == Profile.AUTOLOG:
        required = ("t", "timestamp", "mode", "L_t")
        optional_but_recommended = ("w_t", "y_t")
    else:
        required = ("t", "timestamp", "w_t", "y_t", "mode", "L_t")
        optional_but_recommended = ()

    for k in required:
        if k not in obj:
            err(f"missing required field: {k}")

    for k in optional_but_recommended:
        if k not in obj:
            warn(f"missing recommended field in {Profile.AUTOLOG} profile: {k}")

    # basic types
    if "t" in obj and not isinstance(obj["t"], int):
        err("t must be integer")
    if "t" in obj and isinstance(obj["t"], int) and obj["t"] < 0:
        err("t must be >= 0")

    if "timestamp" in obj and not isinstance(obj["timestamp"], str):
        err("timestamp must be string")

    if "w_t" in obj and not isinstance(obj["w_t"], str):
        err("w_t must be string")

    if "y_t" in obj and not isinstance(obj["y_t"], str):
        err("y_t must be string")

    if "mode" in obj:
        if not isinstance(obj["mode"], str):
            err("mode must be string")
        elif obj["mode"] not in ALLOWED_MODES:
            err(f"mode must be one of {sorted(ALLOWED_MODES)}")

    if "L_t" in obj:
        if not isinstance(obj["L_t"], int):
            err("L_t must be integer")
        else:
            if obj["L_t"] < 0:
                err("L_t must be >= 0")
            # schema allows up to 15; Echo-Lite runtime often uses lmax=5
            if obj["L_t"] > 15:
                err("L_t must be <= 15 (schema)")
            if obj["L_t"] > lmax:
                warn(
                    f"L_t={obj['L_t']} exceeds Echo-Lite L_max={lmax} (allowed by schema, but outside Lite policy)"
                )

    # optional fields
    if "model_id" in obj and not isinstance(obj["model_id"], str):
        err("model_id must be string")

    if "sources" in obj and not _is_str_list(obj["sources"]):
        err("sources must be array of strings")

    if "claims" in obj:
        claims = obj["claims"]
        if not isinstance(claims, list):
            err("claims must be array")
        else:
            for i, c in enumerate(claims):
                if not isinstance(c, dict):
                    err(f"claims[{i}] must be object")
                    continue
                if "kind" not in c or "text" not in c:
                    err(f"claims[{i}] must include kind and text")
                    continue
                if c.get("kind") not in ALLOWED_CLAIM_KINDS:
                    err(f"claims[{i}].kind must be one of {sorted(ALLOWED_CLAIM_KINDS)}")
                if not isinstance(c.get("text"), str):
                    err(f"claims[{i}].text must be string")
                if "evidence" in c and not _is_str_list(c["evidence"]):
                    err(f"claims[{i}].evidence must be array of strings")

    if "F1" in obj:
        if obj["F1"] not in (0, 1):
            err("F1 must be 0 or 1")

    if "F2" in obj:
        f2 = obj["F2"]
        if not isinstance(f2, (int, float)):
            err("F2 must be number")
        else:
            if f2 < 0.0 or f2 > 1.0:
                err("F2 must be in [0,1]")

    if "hash_y" in obj:
        hy = obj["hash_y"]
        if not isinstance(hy, str) or not HEX64_RE.match(hy):
            err("hash_y must be 64 hex chars")

    if "notes" in obj and not isinstance(obj["notes"], str):
        err("notes must be string")

    # optional: PAIR-mode helpers
    if "role" in obj:
        if not isinstance(obj["role"], str):
            err("role must be string")
        elif obj["role"] not in ALLOWED_ROLES:
            err(f"role must be one of {sorted(ALLOWED_ROLES)}")

    if "turn" in obj:
        if not isinstance(obj["turn"], int):
            err("turn must be integer")
        elif obj["turn"] < 0:
            err("turn must be >= 0")

    if "turn_id" in obj and not isinstance(obj["turn_id"], str):
        err("turn_id must be string")

    # autolog/hash-chain fields (optional)
    if "algo" in obj and not isinstance(obj["algo"], str):
        err("algo must be string")

    # Accept both names for prev hash to match docs/tooling.
    prev_val = obj.get("prev_msg_sha256", obj.get("prev"))
    if (
        "prev_msg_sha256" in obj
        and "prev" in obj
        and obj.get("prev_msg_sha256") != obj.get("prev")
    ):
        warn("prev and prev_msg_sha256 differ; prefer prev_msg_sha256")

    if prev_val is not None:
        if not isinstance(prev_val, str) or not HEX64_RE.match(prev_val):
            err("prev/prev_msg_sha256 must be 64 hex chars")

    for k in ("payload_sha256", "context_sha256", "msg_sha256"):
        if k in obj:
            v = obj[k]
            if not isinstance(v, str) or not HEX64_RE.match(v):
                err(f"{k} must be 64 hex chars")

    # additionalProperties=false in schema — here only warn (to avoid breaking future extensions)
    allowed_full = {
        "t",
        "timestamp",
        "w_t",
        "y_t",
        "mode",
        "L_t",
        "model_id",
        "sources",
        "claims",
        "F1",
        "F2",
        "hash_y",
        "notes",
    }
    allowed_autolog = allowed_full | {
        "algo",
        "prev",
        "prev_msg_sha256",
        "payload_sha256",
        "context_sha256",
        "msg_sha256",
        "role",
        "turn",
        "turn_id",
    }
    allowed = allowed_autolog if profile == Profile.AUTOLOG else allowed_full

    extra = sorted(set(obj.keys()) - allowed)
    if extra:
        if profile == Profile.AUTOLOG:
            warn(f"extra fields not in autolog profile: {extra}")
        else:
            warn(f"extra fields not in v0.1 schema: {extra}")

    return issues


def load_jsonl(path: Path) -> Tuple[List[Dict[str, Any]], List[Issue]]:
    issues: List[Issue] = []
    rows: List[Dict[str, Any]] = []

    try:
        txt = path.read_text(encoding="utf-8")
    except Exception as e:
        return [], [Issue(0, "ERROR", f"cannot read file: {e}")]

    for idx, line in enumerate(txt.splitlines(), start=1):
        if not line.strip():
            continue

        # Allow users to paste HT_APPEND lines directly.
        s = line.lstrip()
        if s.startswith("HT_APPEND"):
            # Accept: 'HT_APPEND {json}' or 'HT_APPEND\t{json}'
            rest = s[len("HT_APPEND") :].lstrip()
            line = rest

        try:
            obj = json.loads(line)
        except Exception as e:
            issues.append(Issue(idx, "ERROR", f"invalid JSON: {e}"))
            continue
        if not isinstance(obj, dict):
            issues.append(Issue(idx, "ERROR", "top-level JSON must be object"))
            continue
        rows.append(obj)

    return rows, issues


def check_sequence(rows: List[Dict[str, Any]]) -> List[Issue]:
    issues: List[Issue] = []
    ts: List[Tuple[int, int]] = []  # (lineNo, t)
    for line_no, obj in enumerate(rows, start=1):
        if isinstance(obj.get("t"), int):
            ts.append((line_no, obj["t"]))
    if not ts:
        return issues

    # duplicates
    seen: dict[int, int] = {}
    for ln, t in ts:
        if t in seen:
            issues.append(Issue(ln, "ERROR", f"duplicate t value: {t} (previous at line {seen[t]})"))
        else:
            seen[t] = ln

    # gaps / monotonic
    sorted_ts = sorted(ts, key=lambda x: x[1])
    min_t = sorted_ts[0][1]
    max_t = sorted_ts[-1][1]
    expected = set(range(min_t, max_t + 1))
    missing = sorted(expected - set(t for _, t in sorted_ts))
    if missing:
        issues.append(
            Issue(0, "WARN", f"t sequence has gaps: missing {missing[:20]}{' ...' if len(missing)>20 else ''}")
        )

    return issues


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", type=str, help="H_t log as JSONL")
    ap.add_argument("--lmax", type=int, default=5, help="Echo-Lite L_max policy (default: 5)")
    ap.add_argument(
        "--profile",
        type=str,
        default=Profile.FULL,
        choices=[Profile.FULL, Profile.AUTOLOG],
        help="validation profile: full (strict v0.1) or autolog (minimal HT_APPEND)",
    )
    args = ap.parse_args()

    path = Path(args.log)
    rows, issues = load_jsonl(path)
    if issues and any(i.level == "ERROR" for i in issues):
        for i in issues:
            print(f"[{i.level}] line {i.line_no}: {i.msg}")
        return 3

    all_issues: List[Issue] = []
    for idx, obj in enumerate(rows, start=1):
        all_issues.extend(validate_entry(obj, idx, args.lmax, profile=args.profile))

    all_issues.extend(check_sequence(rows))

    errs = [i for i in all_issues if i.level == "ERROR"]
    warns = [i for i in all_issues if i.level == "WARN"]

    for i in errs + warns:
        ln = i.line_no if i.line_no else "-"
        print(f"[{i.level}] line {ln}: {i.msg}")

    print(f"\nSummary: {len(rows)} entries | {len(errs)} errors | {len(warns)} warnings")

    return 0 if not errs else 2


if __name__ == "__main__":
    raise SystemExit(main())
