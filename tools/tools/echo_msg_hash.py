#!/usr/bin/env python3
"""Echo-Lite: optional hash chaining for H_t JSONL logs.

Commands:
  chain   - add payload/context/msg hashes to each record
  verify  - verify an existing hash chain

Design goals:
  - lightweight, no external deps
  - versioned algorithm id to avoid silent mismatches
  - can verify chain even if content is stripped (uses stored payload/context hashes)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator

try:
    from .echo_canonical import (
        CanonicalJSONError,
        canon_json_bytes,
        loads_json_strict,
        sha256_hex,
    )
except ImportError:  # direct script execution
    from echo_canonical import (
        CanonicalJSONError,
        canon_json_bytes,
        loads_json_strict,
        sha256_hex,
    )

ALGO_ID = "ECHOHASH/v1"
MSG_PREFIX = "ECHO|MSG|v1|"


def read_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = loads_json_strict(line)
            except CanonicalJSONError as exc:
                raise SystemExit(
                    f"ERROR: invalid JSON at line {line_no}: {exc}"
                ) from exc
            if not isinstance(record, dict):
                raise SystemExit(
                    "ERROR: JSON value at line "
                    f"{line_no} must be an object, got {type(record).__name__}"
                )
            yield record


def write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=False))
            f.write("\n")


def build_payload(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "t": rec.get("t"),
        "w_t": rec.get("w_t", ""),
        "y_t": rec.get("y_t", ""),
    }


def build_context(rec: Dict[str, Any], include_params: bool) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "algo": ALGO_ID,
        "timestamp": rec.get("timestamp", ""),
        "mode": rec.get("mode", ""),
        "L_t": rec.get("L_t"),
        "model_id": rec.get("model_id", ""),
    }
    if include_params:
        ctx["params"] = rec.get("params", {})
    return ctx


def chain_cmd(in_path: Path, out_path: Path, strip_content: bool, include_params: bool) -> int:
    prev = "0" * 64
    out_records = []
    for rec in read_jsonl(in_path):
        payload = build_payload(rec)
        context = build_context(rec, include_params=include_params)

        payload_h = sha256_hex(canon_json_bytes(payload))
        context_h = sha256_hex(canon_json_bytes(context))
        msg_h = sha256_hex((MSG_PREFIX + prev + "|" + payload_h + "|" + context_h).encode("utf-8"))

        r2 = dict(rec)
        r2["payload_sha256"] = payload_h
        r2["context_sha256"] = context_h
        r2["prev_msg_sha256"] = prev
        r2["msg_sha256"] = msg_h

        if strip_content:
            if "w_t" in r2:
                r2["w_t"] = "[redacted]"
            if "y_t" in r2:
                r2["y_t"] = "[redacted]"

        out_records.append(r2)
        prev = msg_h

    write_jsonl(out_path, out_records)
    print(f"Wrote hash-chained log: {out_path} ({len(out_records)} records)")
    return 0


def verify_cmd(path: Path, recompute: bool, include_params: bool) -> int:
    prev = "0" * 64
    bad = 0
    total = 0

    for rec in read_jsonl(path):
        total += 1
        # Accept 'prev' as an alias (used in some HT_APPEND templates).
        want_prev = rec.get("prev_msg_sha256", rec.get("prev"))
        payload_h = rec.get("payload_sha256")
        context_h = rec.get("context_sha256")
        msg_h = rec.get("msg_sha256")

        if want_prev is None or payload_h is None or context_h is None or msg_h is None:
            bad += 1
            print(f"FAIL record {total}: missing required hash fields")
            prev = msg_h or prev
            continue

        if want_prev != prev:
            bad += 1
            print(f"FAIL record {total}: prev mismatch\n  want prev={want_prev}\n  got  prev={prev}")

        calc = sha256_hex((MSG_PREFIX + prev + "|" + payload_h + "|" + context_h).encode("utf-8"))
        if calc != msg_h:
            bad += 1
            print(f"FAIL record {total}: msg hash mismatch\n  want {msg_h}\n  got  {calc}")

        if recompute:
            payload2 = build_payload(rec)
            context2 = build_context(rec, include_params=include_params)
            payload2_h = sha256_hex(canon_json_bytes(payload2))
            context2_h = sha256_hex(canon_json_bytes(context2))
            if payload2_h != payload_h:
                bad += 1
                print(f"FAIL record {total}: payload_sha256 does not match recomputed")
            if context2_h != context_h:
                bad += 1
                print(f"FAIL record {total}: context_sha256 does not match recomputed")

        prev = msg_h

    print(f"Summary: {total} records | {bad} failures")
    return 0 if bad == 0 else 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_chain = sub.add_parser("chain", help="add hash chain to an H_t JSONL file")
    ap_chain.add_argument("--in", dest="in_path", required=True, help="input JSONL")
    ap_chain.add_argument("--out", dest="out_path", required=True, help="output JSONL")
    ap_chain.add_argument("--strip-content", action="store_true", help="replace w_t/y_t with [redacted] in output")
    ap_chain.add_argument("--include-params", action="store_true", help="include rec.params in context hash (if present)")

    ap_ver = sub.add_parser("verify", help="verify an existing hash chain")
    ap_ver.add_argument("--in", dest="in_path", required=True, help="input JSONL")
    ap_ver.add_argument("--recompute", action="store_true", help="recompute payload/context hashes from content")
    ap_ver.add_argument("--include-params", action="store_true", help="include rec.params in recomputed context hash")

    args = ap.parse_args(argv)

    if args.cmd == "chain":
        return chain_cmd(Path(args.in_path), Path(args.out_path), strip_content=args.strip_content, include_params=args.include_params)
    if args.cmd == "verify":
        return verify_cmd(Path(args.in_path), recompute=args.recompute, include_params=args.include_params)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
