#!/usr/bin/env python3
"""Shared canonical JSON primitives for EchoHash and echo-lineage/v1.

The canonical byte representation is the existing ECHOHASH/v1 representation:
NFC-normalized strings and keys, UTF-8 JSON, sorted keys, compact separators,
and no NaN or Infinity.  Strict parsing additionally rejects duplicate keys and
non-finite JSON numbers, including values that overflow a finite float.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from pathlib import Path
from typing import Any, Iterable, NoReturn, Tuple


class CanonicalJSONError(ValueError):
    """Input cannot be represented as unambiguous canonical JSON."""


def _normalize_text(value: str) -> str:
    """NFC-normalize one Unicode scalar string.

    Python strings can contain surrogate code points even though they cannot be
    encoded as strict UTF-8.  Reject them here so callers consistently receive
    CanonicalJSONError instead of a late UnicodeEncodeError.
    """
    for offset, char in enumerate(value):
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CanonicalJSONError(
                "Unicode surrogate code point is forbidden "
                f"(U+{codepoint:04X} at string offset {offset})"
            )
    try:
        return unicodedata.normalize("NFC", value)
    except UnicodeError as exc:
        raise CanonicalJSONError(f"invalid Unicode string: {exc}") from exc


def normalize_nfc(obj: Any) -> Any:
    """Recursively NFC-normalize strings, rejecting normalized key collisions."""
    if isinstance(obj, str):
        return _normalize_text(obj)
    if isinstance(obj, list):
        return [normalize_nfc(item) for item in obj]
    if isinstance(obj, dict):
        normalized: dict[str, Any] = {}
        for key, value in obj.items():
            normalized_key = _normalize_text(str(key))
            if normalized_key in normalized:
                raise CanonicalJSONError(
                    f"duplicate key after NFC normalization: {normalized_key!r}"
                )
            normalized[normalized_key] = normalize_nfc(value)
        return normalized
    return obj


def canon_json_bytes(obj: Any) -> bytes:
    """Return the canonical JSON bytes frozen by ECHOHASH/v1."""
    normalized = normalize_nfc(obj)
    try:
        serialized = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return serialized.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalJSONError(str(exc)) from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_pairs(pairs: Iterable[Tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise CanonicalJSONError(f"non-finite JSON number is forbidden: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CanonicalJSONError(f"non-finite JSON number is forbidden: {value}")
    return parsed


def loads_json_strict(text: str) -> Any:
    """Parse one JSON value without ambiguity or non-finite numbers."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
    except CanonicalJSONError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CanonicalJSONError(f"invalid JSON: {exc}") from exc
    # Detect collisions introduced by NFC normalization before the caller uses
    # the value in a hash.
    return normalize_nfc(value)


def read_json_strict(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CanonicalJSONError(f"cannot read JSON file: {exc}") from exc
    return loads_json_strict(text)
