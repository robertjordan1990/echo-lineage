#!/usr/bin/env python3
"""Public, read-only verifier for echo-lineage/v1 documents.

Stage 2A deliberately implements verification only.  It does not create an
acceptance, local state, commitments, imports, exports, or responsibility-head
updates.
"""

from __future__ import annotations

import sys

# Verification is specified as read-only.  Set this before importing sibling
# modules so direct CLI execution does not create a local __pycache__.
sys.dont_write_bytecode = True

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

try:
    from .echo_canonical import (
        CanonicalJSONError,
        canon_json_bytes,
        loads_json_strict,
        sha256_hex,
    )
    from .echo_ledger import (
        LedgerError,
        load_ledger_entries,
        normalize_relative_path,
        resolve_inside_root,
    )
except ImportError:  # direct script execution
    from echo_canonical import (
        CanonicalJSONError,
        canon_json_bytes,
        loads_json_strict,
        sha256_hex,
    )
    from echo_ledger import (
        LedgerError,
        load_ledger_entries,
        normalize_relative_path,
        resolve_inside_root,
    )


PROTOCOL = "echo-lineage/v1"
ZERO_HASH = "0" * 64
DOCUMENT_DOMAIN = "ECHO|LINEAGE|v1|DOCUMENT|"
HEAD_DOMAIN = b"ECHO|LINEAGE|v1|RESPONSIBILITY|"
PROOF_DOMAIN = b"ECHO|LINEAGE|v1|PROOF|RESPONSIBILITY_HEAD|"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_NONCE_RE = re.compile(r"^[0-9a-f]{32,}$")
PROTOCOL_CODE_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
UUID_SUFFIX_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)

DOCUMENT_TYPES = {"trajectory_root", "lineage_acceptance", "handoff"}
TARGET_STATUSES = {
    "target_present_verified",
    "ledger_known_target_missing",
    "hash_mismatch",
    "target_invalid",
    "verification_not_attempted",
    "target_missing_unanchored",
}
CRITICALITIES = {"critical_root", "required_source", "supporting", "optional"}
PARENT_RELATIONS = {"predecessor", "fork_origin", "merge_input"}
SOURCE_ROLES = {"memory", "governance", "runtime", "archive", "canon"}
DECISIONS = {
    "accepted",
    "accepted_with_reservations",
    "declined",
    "quarantined_integrity_failure",
}
DECISION_MODES = {
    "model_session",
    "human_operator",
    "joint_human_model",
    "system_policy",
    "imported_historical_claim",
}


class LineageError(ValueError):
    """A structurally invalid or unsafe lineage document."""


class LineageEvidenceUnavailable(LineageError):
    """Required external lineage evidence was not supplied for verification."""


def _require_object(value: Any, context: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise LineageError(f"{context} must be an object")
    return value


def _require_list(value: Any, context: str) -> List[Any]:
    if not isinstance(value, list):
        raise LineageError(f"{context} must be an array")
    return value


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise LineageError(f"{context} must be a non-empty string")
    return value


def _check_fields(
    obj: Mapping[str, Any],
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    context: str,
) -> None:
    non_string_keys = [key for key in obj if not isinstance(key, str)]
    if non_string_keys:
        raise LineageError(f"{context} keys must be strings")
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - set(obj))
    unknown = sorted(set(obj) - allowed)
    if missing:
        raise LineageError(f"{context} missing required fields: {missing}")
    if unknown:
        raise LineageError(f"{context} contains unknown fields: {unknown}")


def _validate_sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise LineageError(f"{context} must be lowercase SHA-256 hex")
    return value


def _validate_protocol_code(value: Any, context: str) -> str:
    value = _require_string(value, context)
    if not PROTOCOL_CODE_RE.fullmatch(value):
        raise LineageError(
            f"{context} must be a lowercase protocol code without path separators"
        )
    return value


def _validate_ed25519_signature(value: Any, context: str) -> str:
    value = _require_string(value, context)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LineageError(
            f"{context} must be canonical base64 for a 64-byte Ed25519 signature"
        ) from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise LineageError(
            f"{context} must be canonical base64 for a 64-byte Ed25519 signature"
        )
    return value


def _validate_typed_id(value: Any, kind: str, context: str) -> str:
    value = _require_string(value, context)
    prefix = f"urn:echo:{kind}:"
    if not value.startswith(prefix):
        raise LineageError(f"{context} must use {prefix}<uuid>")
    suffix = value[len(prefix) :]
    if not UUID_SUFFIX_RE.fullmatch(suffix):
        raise LineageError(
            f"{context} must contain a canonical lowercase RFC 4122 UUID"
        )
    return value


def _validate_timestamp(value: Any, context: str) -> str:
    value = _require_string(value, context)
    if not TIMESTAMP_RE.fullmatch(value):
        raise LineageError(f"{context} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LineageError(f"{context} must be a valid RFC 3339 timestamp") from exc
    offset = parsed.utcoffset()
    if offset is None or abs(offset.total_seconds()) > 14 * 60 * 60:
        raise LineageError(f"{context} has an invalid UTC offset")
    return value


def _looks_private_path(value: str) -> bool:
    if value.startswith(("file:", "/", "~/", "~\\")):
        return True
    if PureWindowsPath(value).is_absolute():
        return True
    normalized = value.replace("\\", "/")
    return (
        normalized == ".."
        or normalized.startswith("../")
        or "/../" in normalized
        or normalized.endswith("/..")
    )


def _reject_private_locators(value: Any, context: str = "document") -> None:
    forbidden_names = {
        "locator",
        "local_locator",
        "local_path",
        "target_path",
        "ledger_path",
        "root_path",
        "state_dir",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise LineageError(f"{context} keys must be strings")
            key_lower = key.lower()
            if (
                key_lower in forbidden_names
                or "locator" in key_lower
                or key_lower.endswith("_path")
            ):
                raise LineageError(
                    f"{context} contains forbidden private locator field: {key}"
                )
            # Cryptographic encodings are opaque byte strings represented as
            # text.  A valid base64 signature may begin with "/", so path
            # heuristics must not reinterpret its contents as a locator.
            if key_lower != "signature":
                _reject_private_locators(item, f"{context}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_private_locators(item, f"{context}[{index}]")
    elif isinstance(value, str) and _looks_private_path(value):
        raise LineageError(f"{context} contains a forbidden path or locator")


def _validate_ledger_ref(value: Any, context: str) -> None:
    ref = _require_object(value, context)
    _check_fields(
        ref,
        required={"ledger_artifact_id", "ledger_sha256"},
        context=context,
    )
    _validate_typed_id(
        ref["ledger_artifact_id"], "artifact", f"{context}.ledger_artifact_id"
    )
    _validate_sha256(ref["ledger_sha256"], f"{context}.ledger_sha256")


def validate_artifact_ref(value: Any, context: str) -> Dict[str, Any]:
    ref = _require_object(value, context)
    _check_fields(
        ref,
        required={"artifact_id", "sha256", "hash_scope"},
        optional={"media_type", "ledger_ref"},
        context=context,
    )
    _validate_typed_id(ref["artifact_id"], "artifact", f"{context}.artifact_id")
    _validate_sha256(ref["sha256"], f"{context}.sha256")
    if ref["hash_scope"] not in {
        "file_bytes",
        "canonical_document",
        "ciphertext",
        "echohash_head",
    }:
        raise LineageError(f"{context}.hash_scope is unsupported")
    if "media_type" in ref:
        _require_string(ref["media_type"], f"{context}.media_type")
    if "ledger_ref" in ref:
        _validate_ledger_ref(ref["ledger_ref"], f"{context}.ledger_ref")
        if ref["ledger_ref"]["ledger_artifact_id"] == ref["artifact_id"]:
            raise LineageError(
                f"{context}.ledger_ref.ledger_artifact_id must differ from "
                "artifact_id"
            )
        if ref["hash_scope"] not in {"file_bytes", "ciphertext"}:
            raise LineageError(
                f"{context}.ledger_ref is only valid for raw-byte hash scopes"
            )
    return ref


def _validate_ledger_artifact_namespace(
    artifacts: Sequence[Mapping[str, Any]],
    *,
    document_artifact_ids: Iterable[str],
    context: str,
) -> None:
    artifact_ids = set(document_artifact_ids)
    ledger_commitments: Dict[str, str] = {}
    for artifact in artifacts:
        ledger_ref = artifact.get("ledger_ref")
        if ledger_ref is None:
            continue
        ledger_id = ledger_ref["ledger_artifact_id"]
        if ledger_id in artifact_ids:
            raise LineageError(
                f"{context} ledger_artifact_id collides with document "
                f"artifact_id: {ledger_id}"
            )
        previous_sha = ledger_commitments.get(ledger_id)
        ledger_sha = ledger_ref["ledger_sha256"]
        if previous_sha is not None and previous_sha != ledger_sha:
            raise LineageError(
                f"{context} shared ledger_artifact_id has conflicting "
                f"ledger_sha256: {ledger_id}"
            )
        ledger_commitments[ledger_id] = ledger_sha


def _validate_lineage_parent(value: Any, context: str) -> Dict[str, Any]:
    parent = _require_object(value, context)
    _check_fields(
        parent,
        required={
            "relation",
            "parent_trajectory_id",
            "parent_genesis_root_document_hash",
            "parent_installation_id",
            "handoff_document_hash",
            "parent_responsibility_head",
        },
        context=context,
    )
    if parent["relation"] not in PARENT_RELATIONS:
        raise LineageError(f"{context}.relation is unsupported")
    _validate_typed_id(
        parent["parent_trajectory_id"],
        "trajectory",
        f"{context}.parent_trajectory_id",
    )
    _validate_sha256(
        parent["parent_genesis_root_document_hash"],
        f"{context}.parent_genesis_root_document_hash",
    )
    _validate_typed_id(
        parent["parent_installation_id"],
        "installation",
        f"{context}.parent_installation_id",
    )
    _validate_sha256(
        parent["handoff_document_hash"], f"{context}.handoff_document_hash"
    )
    _validate_sha256(
        parent["parent_responsibility_head"],
        f"{context}.parent_responsibility_head",
    )
    return parent


def _validate_inheritance_source(value: Any, context: str) -> Dict[str, Any]:
    source = _require_object(value, context)
    _check_fields(
        source,
        required={
            "source_role",
            "artifact",
            "criticality",
            "required_for_acceptance",
        },
        context=context,
    )
    if source["source_role"] not in SOURCE_ROLES:
        raise LineageError(f"{context}.source_role is unsupported")
    validate_artifact_ref(source["artifact"], f"{context}.artifact")
    if source["criticality"] not in CRITICALITIES:
        raise LineageError(f"{context}.criticality is unsupported")
    if not isinstance(source["required_for_acceptance"], bool):
        raise LineageError(f"{context}.required_for_acceptance must be boolean")
    expected_required = source["criticality"] in {
        "critical_root",
        "required_source",
    }
    if source["required_for_acceptance"] is not expected_required:
        raise LineageError(
            f"{context}.required_for_acceptance conflicts with criticality"
        )
    return source


def _validate_trajectory_body(body: Dict[str, Any]) -> None:
    context = "trajectory_root.body"
    _check_fields(
        body,
        required={
            "trajectory_id",
            "genesis_root_document_hash",
            "installation_id",
            "created_by_runtime_session_id",
            "origin_kind",
            "lineage_parents",
            "inheritance_sources",
            "fork_policy",
            "acceptance_required",
            "signature_policy",
            "created_at",
        },
        context=context,
    )
    trajectory_id = _validate_typed_id(
        body["trajectory_id"], "trajectory", f"{context}.trajectory_id"
    )
    genesis_hash = body["genesis_root_document_hash"]
    if genesis_hash is not None:
        _validate_sha256(genesis_hash, f"{context}.genesis_root_document_hash")
    installation_id = _validate_typed_id(
        body["installation_id"], "installation", f"{context}.installation_id"
    )
    runtime_id = body["created_by_runtime_session_id"]
    if runtime_id is not None:
        _validate_typed_id(
            runtime_id, "runtime-session", f"{context}.created_by_runtime_session_id"
        )

    origin = body["origin_kind"]
    if origin not in {
        "independent_no_lineage_claim",
        "continuation",
        "explicit_fork",
        "merge",
    }:
        raise LineageError(f"{context}.origin_kind is unsupported")

    parents = [
        _validate_lineage_parent(parent, f"{context}.lineage_parents[{index}]")
        for index, parent in enumerate(
            _require_list(body["lineage_parents"], f"{context}.lineage_parents")
        )
    ]
    sources = [
        _validate_inheritance_source(
            source, f"{context}.inheritance_sources[{index}]"
        )
        for index, source in enumerate(
            _require_list(
                body["inheritance_sources"], f"{context}.inheritance_sources"
            )
        )
    ]
    artifact_ids = [source["artifact"]["artifact_id"] for source in sources]
    if len(set(artifact_ids)) != len(artifact_ids):
        raise LineageError(f"{context}.inheritance_sources has duplicate artifact_id")
    _validate_ledger_artifact_namespace(
        [source["artifact"] for source in sources],
        document_artifact_ids=artifact_ids,
        context=context,
    )

    if body["fork_policy"] != "explicit_only":
        raise LineageError(f"{context}.fork_policy must be explicit_only")
    if body["acceptance_required"] is not True:
        raise LineageError(f"{context}.acceptance_required must be true")
    if body["signature_policy"] not in {"optional", "required", "out_of_band"}:
        raise LineageError(f"{context}.signature_policy is unsupported")
    _validate_timestamp(body["created_at"], f"{context}.created_at")

    relations = [parent["relation"] for parent in parents]
    if any(parent["parent_installation_id"] == installation_id for parent in parents):
        raise LineageError(f"{context} cannot name itself as a lineage parent")

    if origin == "independent_no_lineage_claim":
        if parents:
            raise LineageError("independent genesis must not have lineage parents")
        if genesis_hash is not None:
            raise LineageError(
                "independent genesis must derive genesis hash from its document"
            )
    elif origin == "continuation":
        if relations != ["predecessor"]:
            raise LineageError("continuation requires exactly one predecessor")
        if genesis_hash is None:
            raise LineageError("continuation requires genesis_root_document_hash")
        parent = parents[0]
        if parent["parent_trajectory_id"] != trajectory_id:
            raise LineageError(
                "continuation predecessor must use the same trajectory_id"
            )
        if parent["parent_genesis_root_document_hash"] != genesis_hash:
            raise LineageError(
                "trajectory_id does not match genesis_root_document_hash"
            )
    elif origin == "explicit_fork":
        if relations != ["fork_origin"]:
            raise LineageError("explicit fork requires exactly one fork_origin")
        if genesis_hash is not None:
            raise LineageError(
                "explicit fork creates a new trajectory genesis document"
            )
        if parents[0]["parent_trajectory_id"] == trajectory_id:
            raise LineageError("explicit fork must create a new trajectory_id")
    elif origin == "merge":
        if len(parents) < 2 or any(relation != "merge_input" for relation in relations):
            raise LineageError("merge requires at least two merge_input parents")
        if genesis_hash is not None:
            raise LineageError("merge creates a new trajectory genesis document")
        parent_identities = {
            (
                parent["parent_trajectory_id"],
                parent["parent_genesis_root_document_hash"],
            )
            for parent in parents
        }
        if len(parent_identities) != len(parents):
            raise LineageError("merge contains duplicate parent trajectory identity")
        if any(parent[0] == trajectory_id for parent in parent_identities):
            raise LineageError("merge must create a new trajectory_id")


def _validate_decision_actor(value: Any, context: str) -> None:
    actor = _require_object(value, context)
    _check_fields(
        actor,
        required={"decision_actor_id", "decision_mode"},
        optional={
            "runtime_session_id",
            "human_actor_id",
            "policy_artifact_ref",
            "historical_claim_artifact_ref",
            "decision_evidence_ref",
        },
        context=context,
    )
    _validate_typed_id(
        actor["decision_actor_id"],
        "decision-actor",
        f"{context}.decision_actor_id",
    )
    mode = actor["decision_mode"]
    if mode not in DECISION_MODES:
        raise LineageError(f"{context}.decision_mode is unsupported")

    runtime_id = actor.get("runtime_session_id")
    if runtime_id is not None:
        _validate_typed_id(
            runtime_id, "runtime-session", f"{context}.runtime_session_id"
        )
    human_id = actor.get("human_actor_id")
    if human_id is not None:
        _validate_typed_id(
            human_id, "decision-actor", f"{context}.human_actor_id"
        )
    for name in ("policy_artifact_ref", "historical_claim_artifact_ref"):
        if actor.get(name) is not None:
            validate_artifact_ref(actor[name], f"{context}.{name}")
    if actor.get("decision_evidence_ref") is not None:
        validate_artifact_ref(
            actor["decision_evidence_ref"], f"{context}.decision_evidence_ref"
        )
    actor_refs = [
        actor[name]
        for name in (
            "policy_artifact_ref",
            "historical_claim_artifact_ref",
            "decision_evidence_ref",
        )
        if actor.get(name) is not None
    ]
    actor_artifact_ids = [ref["artifact_id"] for ref in actor_refs]
    if len(set(actor_artifact_ids)) != len(actor_artifact_ids):
        raise LineageError(f"{context} contains duplicate evidence artifact_id")

    if mode == "model_session":
        if runtime_id is None or actor.get("decision_evidence_ref") is None:
            raise LineageError(
                "model_session decision requires runtime_session_id and "
                "decision_evidence_ref"
            )
        forbidden = {"human_actor_id", "policy_artifact_ref", "historical_claim_artifact_ref"}
    elif mode == "joint_human_model":
        if (
            runtime_id is None
            or human_id is None
            or actor.get("decision_evidence_ref") is None
        ):
            raise LineageError(
                "joint_human_model decision requires human_actor_id, "
                "runtime_session_id, and decision_evidence_ref"
            )
        forbidden = {"policy_artifact_ref", "historical_claim_artifact_ref"}
    elif mode == "human_operator":
        forbidden = {
            "runtime_session_id",
            "human_actor_id",
            "policy_artifact_ref",
            "historical_claim_artifact_ref",
        }
    elif mode == "system_policy":
        if actor.get("policy_artifact_ref") is None:
            raise LineageError(
                "system_policy decision requires policy_artifact_ref"
            )
        forbidden = {
            "runtime_session_id",
            "human_actor_id",
            "historical_claim_artifact_ref",
        }
    else:
        if actor.get("historical_claim_artifact_ref") is None:
            raise LineageError(
                "imported_historical_claim requires historical_claim_artifact_ref"
            )
        forbidden = {
            "runtime_session_id",
            "human_actor_id",
            "policy_artifact_ref",
        }
    present_forbidden = sorted(name for name in forbidden if name in actor)
    if present_forbidden:
        raise LineageError(
            f"{context} fields conflict with {mode}: {present_forbidden}"
        )


def _validate_recording_operator(value: Any, context: str) -> None:
    operator = _require_object(value, context)
    _check_fields(
        operator,
        required={
            "operator_actor_id",
            "role",
            "confirmed_at",
            "confirmation_scope",
        },
        context=context,
    )
    _validate_typed_id(
        operator["operator_actor_id"],
        "decision-actor",
        f"{context}.operator_actor_id",
    )
    if operator["role"] != "recording_operator":
        raise LineageError(f"{context}.role must be recording_operator")
    _validate_timestamp(operator["confirmed_at"], f"{context}.confirmed_at")
    if operator["confirmation_scope"] != "recorded_decision_without_reassignment":
        raise LineageError(
            f"{context}.confirmation_scope must preserve decision attribution"
        )


def evaluate_future_decisions(
    target_results: Sequence[Mapping[str, Any]],
) -> List[str]:
    """Return decisions permitted by the frozen Stage 2A policy matrix."""
    if not target_results:
        return ["accepted", "declined"]
    statuses = [result["status"] for result in target_results]
    if all(status == "target_present_verified" for status in statuses):
        return ["accepted", "declined"]

    critical_integrity_failure = any(
        result["criticality"] in {"critical_root", "required_source"}
        and result["status"] in {"hash_mismatch", "target_invalid"}
        for result in target_results
    )
    integrity_failure = any(
        status in {"hash_mismatch", "target_invalid"} for status in statuses
    )
    unverified_without_ledger = any(
        status in {"verification_not_attempted", "target_missing_unanchored"}
        for status in statuses
    )
    if critical_integrity_failure:
        return ["declined", "quarantined_integrity_failure"]

    decisions: List[str] = []
    if not unverified_without_ledger:
        decisions.append("accepted_with_reservations")
    decisions.append("declined")
    if integrity_failure:
        decisions.append("quarantined_integrity_failure")
    return decisions


def _validate_acceptance_body(body: Dict[str, Any]) -> None:
    context = "lineage_acceptance.body"
    _check_fields(
        body,
        required={
            "acceptance_id",
            "trajectory_id",
            "genesis_root_document_hash",
            "installation_id",
            "subject",
            "decision",
            "decision_actor",
            "recording_operator",
            "verification_report_hash",
            "target_results",
            "reservations",
            "decision_nonce",
            "decided_at",
            "effect",
        },
        optional={"previous_acceptance_hash"},
        context=context,
    )
    _validate_typed_id(
        body["acceptance_id"], "acceptance", f"{context}.acceptance_id"
    )
    _validate_typed_id(
        body["trajectory_id"], "trajectory", f"{context}.trajectory_id"
    )
    _validate_sha256(
        body["genesis_root_document_hash"],
        f"{context}.genesis_root_document_hash",
    )
    _validate_typed_id(
        body["installation_id"], "installation", f"{context}.installation_id"
    )

    subject = _require_object(body["subject"], f"{context}.subject")
    _check_fields(
        subject,
        required={
            "trajectory_root_artifact_id",
            "trajectory_root_document_hash",
        },
        optional={"handoff_artifact_id", "handoff_document_hash"},
        context=f"{context}.subject",
    )
    _validate_typed_id(
        subject["trajectory_root_artifact_id"],
        "artifact",
        f"{context}.subject.trajectory_root_artifact_id",
    )
    _validate_sha256(
        subject["trajectory_root_document_hash"],
        f"{context}.subject.trajectory_root_document_hash",
    )
    handoff_subject_fields = {
        "handoff_artifact_id",
        "handoff_document_hash",
    } & set(subject)
    if handoff_subject_fields and len(handoff_subject_fields) != 2:
        raise LineageError(
            f"{context}.subject handoff artifact ID and hash must appear together"
        )
    if "handoff_document_hash" in subject:
        _validate_typed_id(
            subject["handoff_artifact_id"],
            "artifact",
            f"{context}.subject.handoff_artifact_id",
        )
        _validate_sha256(
            subject["handoff_document_hash"],
            f"{context}.subject.handoff_document_hash",
        )

    decision = body["decision"]
    if decision not in DECISIONS:
        raise LineageError(f"{context}.decision is unsupported")
    _validate_decision_actor(body["decision_actor"], f"{context}.decision_actor")
    _validate_recording_operator(
        body["recording_operator"], f"{context}.recording_operator"
    )
    _validate_sha256(
        body["verification_report_hash"], f"{context}.verification_report_hash"
    )

    target_results: List[Dict[str, Any]] = []
    for index, raw_result in enumerate(
        _require_list(body["target_results"], f"{context}.target_results")
    ):
        result_context = f"{context}.target_results[{index}]"
        result = _require_object(raw_result, result_context)
        _check_fields(
            result,
            required={
                "artifact_id",
                "criticality",
                "status",
                "expected_sha256",
            },
            optional={
                "reason_code",
                "excluded_from_active_inheritance",
            },
            context=result_context,
        )
        _validate_typed_id(
            result["artifact_id"], "artifact", f"{result_context}.artifact_id"
        )
        if result["criticality"] not in CRITICALITIES:
            raise LineageError(f"{result_context}.criticality is unsupported")
        if result["status"] not in TARGET_STATUSES:
            raise LineageError(f"{result_context}.status is unsupported")
        _validate_sha256(
            result["expected_sha256"], f"{result_context}.expected_sha256"
        )
        if "reason_code" in result:
            _validate_protocol_code(
                result["reason_code"], f"{result_context}.reason_code"
            )
        if "excluded_from_active_inheritance" in result and not isinstance(
            result["excluded_from_active_inheritance"], bool
        ):
            raise LineageError(
                f"{result_context}.excluded_from_active_inheritance must be boolean"
            )
        if (
            result["criticality"] in {"supporting", "optional"}
            and result["status"] in {"hash_mismatch", "target_invalid"}
            and not result.get("excluded_from_active_inheritance", False)
        ):
            raise LineageError(
                f"{result_context} integrity failure must be excluded from active "
                "inheritance"
            )
        target_results.append(result)
    if not target_results:
        raise LineageError(f"{context}.target_results must not be empty")
    result_ids = [result["artifact_id"] for result in target_results]
    if len(set(result_ids)) != len(result_ids):
        raise LineageError(f"{context}.target_results has duplicate artifact_id")
    actor = body["decision_actor"]
    actor_artifacts = [
        actor[name]
        for name in (
            "decision_evidence_ref",
            "policy_artifact_ref",
            "historical_claim_artifact_ref",
        )
        if name in actor
    ]
    _validate_ledger_artifact_namespace(
        actor_artifacts,
        document_artifact_ids=[
            *result_ids,
            *(artifact["artifact_id"] for artifact in actor_artifacts),
        ],
        context=context,
    )
    result_by_id = {
        result["artifact_id"]: result for result in target_results
    }
    subject_bindings = [
        (
            subject["trajectory_root_artifact_id"],
            subject["trajectory_root_document_hash"],
            "trajectory root",
        )
    ]
    if "handoff_artifact_id" in subject:
        subject_bindings.append(
            (
                subject["handoff_artifact_id"],
                subject["handoff_document_hash"],
                "handoff",
            )
        )
    for artifact_id, expected_hash, label in subject_bindings:
        result = result_by_id.get(artifact_id)
        if result is None:
            raise LineageError(
                f"{context}.target_results is missing the subject {label}"
            )
        if (
            result["criticality"] != "critical_root"
            or result["expected_sha256"] != expected_hash
        ):
            raise LineageError(
                f"{context}.target_results does not bind the subject {label}"
            )

    reservations: List[Dict[str, Any]] = []
    for index, raw_reservation in enumerate(
        _require_list(body["reservations"], f"{context}.reservations")
    ):
        reservation_context = f"{context}.reservations[{index}]"
        reservation = _require_object(raw_reservation, reservation_context)
        _check_fields(
            reservation,
            required={"code", "artifact_id"},
            context=reservation_context,
        )
        _validate_protocol_code(
            reservation["code"], f"{reservation_context}.code"
        )
        _validate_typed_id(
            reservation["artifact_id"],
            "artifact",
            f"{reservation_context}.artifact_id",
        )
        reservations.append(reservation)
    reservation_ids = [reservation["artifact_id"] for reservation in reservations]
    if len(set(reservation_ids)) != len(reservation_ids):
        raise LineageError(f"{context}.reservations has duplicate artifact_id")

    if not isinstance(body["decision_nonce"], str) or not HEX_NONCE_RE.fullmatch(
        body["decision_nonce"]
    ):
        raise LineageError(f"{context}.decision_nonce must be >=128-bit lowercase hex")
    _validate_timestamp(body["decided_at"], f"{context}.decided_at")
    if body["effect"] not in {"activating", "non_activating"}:
        raise LineageError(f"{context}.effect is unsupported")
    if "previous_acceptance_hash" in body:
        _validate_sha256(
            body["previous_acceptance_hash"],
            f"{context}.previous_acceptance_hash",
        )

    mode = body["decision_actor"]["decision_mode"]
    if mode == "imported_historical_claim" and body["effect"] != "non_activating":
        raise LineageError("imported historical claim must be non-activating")
    if decision in {"accepted", "accepted_with_reservations"}:
        if body["effect"] != "activating":
            raise LineageError(f"{decision} must have activating effect")
    elif body["effect"] != "non_activating":
        raise LineageError(f"{decision} must have non-activating effect")

    allowed = evaluate_future_decisions(target_results)
    if decision not in allowed:
        raise LineageError(
            f"decision {decision} is forbidden by target status policy; "
            f"allowed: {allowed}"
        )
    if decision == "accepted_with_reservations":
        reserved_ids = {reservation["artifact_id"] for reservation in reservations}
        required_reservations = {
            result["artifact_id"]
            for result in target_results
            if result["status"] != "target_present_verified"
        }
        if not required_reservations or reserved_ids != required_reservations:
            raise LineageError(
                "accepted_with_reservations requires exactly one reservation "
                "for every non-verified target"
            )
    elif reservations:
        raise LineageError(
            f"{decision} decision must not contain acceptance reservations"
        )


def _validate_handoff_body(body: Dict[str, Any]) -> None:
    context = "handoff.body"
    _check_fields(
        body,
        required={
            "handoff_id",
            "trajectory_id",
            "genesis_root_document_hash",
            "issuer_installation_id",
            "issuer_runtime_session_id",
            "recipient_binding",
            "recording_operator_id",
            "sequence",
            "handoff_nonce",
            "issued_at",
            "lineage_root_ref",
            "latest_acceptance_ref",
            "previous_handoff_hash",
            "lineage_parents",
            "inheritance_sources",
            "memory_heads",
            "ht_heads",
            "fork_intent",
            "constraints",
        },
        optional={"expires_at"},
        context=context,
    )
    _validate_typed_id(body["handoff_id"], "handoff", f"{context}.handoff_id")
    _validate_typed_id(
        body["trajectory_id"], "trajectory", f"{context}.trajectory_id"
    )
    _validate_sha256(
        body["genesis_root_document_hash"],
        f"{context}.genesis_root_document_hash",
    )
    _validate_typed_id(
        body["issuer_installation_id"],
        "installation",
        f"{context}.issuer_installation_id",
    )
    _validate_typed_id(
        body["issuer_runtime_session_id"],
        "runtime-session",
        f"{context}.issuer_runtime_session_id",
    )
    _validate_typed_id(
        body["recording_operator_id"],
        "decision-actor",
        f"{context}.recording_operator_id",
    )

    recipient = _require_object(body["recipient_binding"], f"{context}.recipient_binding")
    _check_fields(
        recipient,
        required={"mode", "recipient_installation_id"},
        context=f"{context}.recipient_binding",
    )
    if recipient["mode"] not in {"bound", "unbound"}:
        raise LineageError(f"{context}.recipient_binding.mode is unsupported")
    if recipient["mode"] == "bound":
        _validate_typed_id(
            recipient["recipient_installation_id"],
            "installation",
            f"{context}.recipient_binding.recipient_installation_id",
        )
        if recipient["recipient_installation_id"] == body["issuer_installation_id"]:
            raise LineageError("bound handoff recipient must differ from issuer")
    elif recipient["recipient_installation_id"] is not None:
        raise LineageError("unbound handoff must not name a recipient installation")

    if not isinstance(body["sequence"], int) or isinstance(body["sequence"], bool):
        raise LineageError(f"{context}.sequence must be an integer")
    if body["sequence"] < 0:
        raise LineageError(f"{context}.sequence must be >= 0")
    if not isinstance(body["handoff_nonce"], str) or not HEX_NONCE_RE.fullmatch(
        body["handoff_nonce"]
    ):
        raise LineageError(f"{context}.handoff_nonce must be >=128-bit lowercase hex")
    issued_at = _validate_timestamp(body["issued_at"], f"{context}.issued_at")
    if "expires_at" in body:
        expires_at = _validate_timestamp(
            body["expires_at"], f"{context}.expires_at"
        )
        issued_dt = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
        expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expires_dt <= issued_dt:
            raise LineageError("handoff expires_at must be later than issued_at")
    if recipient["mode"] == "unbound" and "expires_at" not in body:
        raise LineageError("unbound handoff requires expires_at")

    lineage_root_ref = validate_artifact_ref(
        body["lineage_root_ref"], f"{context}.lineage_root_ref"
    )
    latest_acceptance_ref = validate_artifact_ref(
        body["latest_acceptance_ref"], f"{context}.latest_acceptance_ref"
    )
    for name, ref in (
        ("lineage_root_ref", lineage_root_ref),
        ("latest_acceptance_ref", latest_acceptance_ref),
    ):
        if ref["hash_scope"] != "canonical_document":
            raise LineageError(
                f"{context}.{name}.hash_scope must be canonical_document"
            )
    _validate_sha256(
        body["previous_handoff_hash"], f"{context}.previous_handoff_hash"
    )
    if body["sequence"] == 0 and body["previous_handoff_hash"] != ZERO_HASH:
        raise LineageError("first handoff must use the zero previous_handoff_hash")
    if body["sequence"] > 0 and body["previous_handoff_hash"] == ZERO_HASH:
        raise LineageError(
            "non-first handoff has a broken previous_handoff_hash"
        )
    parents = [
        _validate_lineage_parent(parent, f"{context}.lineage_parents[{index}]")
        for index, parent in enumerate(
            _require_list(body["lineage_parents"], f"{context}.lineage_parents")
        )
    ]
    parent_keys = [canon_json_bytes(parent) for parent in parents]
    if len(set(parent_keys)) != len(parent_keys):
        raise LineageError(f"{context}.lineage_parents contains duplicate entries")
    sources = [
        _validate_inheritance_source(
            source, f"{context}.inheritance_sources[{index}]"
        )
        for index, source in enumerate(
            _require_list(
                body["inheritance_sources"], f"{context}.inheritance_sources"
            )
        )
    ]
    memory_heads = [
        validate_artifact_ref(head, f"{context}.memory_heads[{index}]")
        for index, head in enumerate(
            _require_list(body["memory_heads"], f"{context}.memory_heads")
        )
    ]
    all_artifact_ids = [
        body["lineage_root_ref"]["artifact_id"],
        body["latest_acceptance_ref"]["artifact_id"],
    ] + [
        source["artifact"]["artifact_id"] for source in sources
    ] + [head["artifact_id"] for head in memory_heads]
    if len(set(all_artifact_ids)) != len(all_artifact_ids):
        raise LineageError(f"{context} contains duplicate inherited artifact_id")
    _validate_ledger_artifact_namespace(
        [
            lineage_root_ref,
            latest_acceptance_ref,
            *(source["artifact"] for source in sources),
            *memory_heads,
        ],
        document_artifact_ids=all_artifact_ids,
        context=context,
    )

    ht_head_keys: List[Tuple[str, int, str]] = []
    ht_log_ids: set[str] = set()
    for index, raw_head in enumerate(
        _require_list(body["ht_heads"], f"{context}.ht_heads")
    ):
        head_context = f"{context}.ht_heads[{index}]"
        head = _require_object(raw_head, head_context)
        _check_fields(
            head,
            required={"log_id", "t", "msg_sha256"},
            context=head_context,
        )
        _validate_typed_id(head["log_id"], "log", f"{head_context}.log_id")
        if (
            not isinstance(head["t"], int)
            or isinstance(head["t"], bool)
            or head["t"] < 0
        ):
            raise LineageError(f"{head_context}.t must be an integer >= 0")
        _validate_sha256(head["msg_sha256"], f"{head_context}.msg_sha256")
        if head["log_id"] in ht_log_ids:
            raise LineageError(
                f"{context}.ht_heads contains duplicate log_id: {head['log_id']}"
            )
        ht_log_ids.add(head["log_id"])
        ht_head_keys.append((head["log_id"], head["t"], head["msg_sha256"]))
    if len(set(ht_head_keys)) != len(ht_head_keys):
        raise LineageError(f"{context}.ht_heads contains duplicate entries")

    if body["fork_intent"] not in {"none", "explicit_fork", "merge_input"}:
        raise LineageError(f"{context}.fork_intent is unsupported")
    constraints = _require_list(body["constraints"], f"{context}.constraints")
    allowed_constraints = {
        "manual_acceptance_required",
        "no_public_commitment",
        "verify_before_use",
    }
    if not all(
        isinstance(item, str) and item in allowed_constraints
        for item in constraints
    ):
        raise LineageError(f"{context}.constraints contains an unsupported value")
    required_constraints = {
        "manual_acceptance_required",
        "no_public_commitment",
        "verify_before_use",
    }
    missing_constraints = sorted(required_constraints - set(constraints))
    if missing_constraints:
        raise LineageError(
            "handoff is missing mandatory safety constraints: "
            f"{missing_constraints}"
        )
    if len(set(constraints)) != len(constraints):
        raise LineageError(f"{context}.constraints contains duplicate values")


def _validate_responsibility(value: Any) -> Dict[str, Any]:
    responsibility = _require_object(value, "responsibility")
    _check_fields(
        responsibility,
        required={"chain_id", "event_index", "previous_head"},
        context="responsibility",
    )
    _validate_typed_id(
        responsibility["chain_id"],
        "responsibility-chain",
        "responsibility.chain_id",
    )
    event_index = responsibility["event_index"]
    if (
        not isinstance(event_index, int)
        or isinstance(event_index, bool)
        or event_index < 0
    ):
        raise LineageError("responsibility.event_index must be an integer >= 0")
    previous_head = _validate_sha256(
        responsibility["previous_head"], "responsibility.previous_head"
    )
    if event_index == 0 and previous_head != ZERO_HASH:
        raise LineageError("genesis responsibility event must use the zero head")
    if event_index > 0 and previous_head == ZERO_HASH:
        raise LineageError("non-genesis responsibility event has a broken previous_head")
    return responsibility


def compute_document_hash(document: Mapping[str, Any]) -> str:
    document_type = document.get("document_type")
    if document_type not in DOCUMENT_TYPES:
        raise LineageError("document_type is unsupported")
    payload = {
        "protocol": document.get("protocol"),
        "document_type": document_type,
        "body": document.get("body"),
        "responsibility": document.get("responsibility"),
    }
    prefix = f"{DOCUMENT_DOMAIN}{document_type.upper()}|".encode("utf-8")
    return sha256_hex(prefix + canon_json_bytes(payload))


def compute_resulting_head(previous_head: str, document_hash: str) -> str:
    _validate_sha256(previous_head, "previous_head")
    _validate_sha256(document_hash, "document_hash")
    return sha256_hex(
        HEAD_DOMAIN + bytes.fromhex(previous_head) + bytes.fromhex(document_hash)
    )


def build_proof_payload(document: Mapping[str, Any]) -> Dict[str, Any]:
    body = _require_object(document.get("body"), "body")
    responsibility = _require_object(
        document.get("responsibility"), "responsibility"
    )
    installation_id = body.get(
        "installation_id", body.get("issuer_installation_id")
    )
    return {
        "protocol": PROTOCOL,
        "proof_scope": "responsibility_head",
        "document_type": document["document_type"],
        "trajectory_id": body["trajectory_id"],
        "installation_id": installation_id,
        "chain_id": responsibility["chain_id"],
        "event_index": responsibility["event_index"],
        "previous_head": responsibility["previous_head"],
        "document_hash": document["document_hash"]["value"],
        "resulting_head": document["resulting_head"],
    }


def proof_message_bytes(document: Mapping[str, Any]) -> bytes:
    return PROOF_DOMAIN + canon_json_bytes(build_proof_payload(document))


def _validate_proofs(document: Mapping[str, Any]) -> None:
    proofs = _require_list(document["proofs"], "proofs")
    expected_payload = build_proof_payload(document)
    expected_payload_bytes = canon_json_bytes(expected_payload)
    seen_key_ids: set[str] = set()
    for index, raw_proof in enumerate(proofs):
        context = f"proofs[{index}]"
        proof = _require_object(raw_proof, context)
        _check_fields(
            proof,
            required={
                "proof_type",
                "algorithm",
                "key_id",
                "signed_payload",
                "signature",
            },
            context=context,
        )
        if proof["proof_type"] != "responsibility_head":
            raise LineageError(f"{context}.proof_type is unsupported")
        if proof["algorithm"] != "ed25519":
            raise LineageError(f"{context}.algorithm must be ed25519")
        key_id = _validate_typed_id(
            proof["key_id"], "key", f"{context}.key_id"
        )
        if key_id in seen_key_ids:
            raise LineageError(f"proofs contains duplicate key_id: {key_id}")
        seen_key_ids.add(key_id)
        _validate_ed25519_signature(
            proof["signature"], f"{context}.signature"
        )
        try:
            actual_payload_bytes = canon_json_bytes(proof["signed_payload"])
        except CanonicalJSONError as exc:
            raise LineageError(f"{context}.signed_payload is invalid: {exc}") from exc
        if actual_payload_bytes != expected_payload_bytes:
            raise LineageError(
                f"{context} does not cover the computed resulting_head"
            )


def validate_document(
    document: Any,
    *,
    expected_type: str | None = None,
    expected_previous_head: str | None = None,
    expected_chain_id: str | None = None,
    expected_event_index: int | None = None,
) -> Dict[str, Any]:
    doc = _require_object(document, "document")
    _check_fields(
        doc,
        required={
            "protocol",
            "document_type",
            "body",
            "responsibility",
            "document_hash",
            "resulting_head",
            "proofs",
        },
        context="document",
    )
    if doc["protocol"] != PROTOCOL:
        raise LineageError("protocol must be echo-lineage/v1")
    if doc["document_type"] not in DOCUMENT_TYPES:
        raise LineageError("document_type is unsupported")
    if expected_type is not None and doc["document_type"] != expected_type:
        raise LineageError(f"expected {expected_type} document")
    _reject_private_locators(doc)
    body = _require_object(doc["body"], f"{doc['document_type']}.body")

    if doc["document_type"] == "trajectory_root":
        _validate_trajectory_body(body)
    elif doc["document_type"] == "lineage_acceptance":
        _validate_acceptance_body(body)
    else:
        _validate_handoff_body(body)

    responsibility = _validate_responsibility(doc["responsibility"])
    if doc["document_type"] == "trajectory_root":
        if responsibility["event_index"] != 0:
            raise LineageError(
                "trajectory root must begin its installation responsibility "
                "chain at event_index 0"
            )
    elif responsibility["event_index"] == 0:
        raise LineageError(
            f"{doc['document_type']} cannot be a genesis responsibility event"
        )
    if expected_previous_head is not None:
        _validate_sha256(expected_previous_head, "expected_previous_head")
        if responsibility["previous_head"] != expected_previous_head:
            raise LineageError(
                "broken previous_head: document does not extend expected head"
            )
    if expected_chain_id is not None:
        _validate_typed_id(
            expected_chain_id, "responsibility-chain", "expected_chain_id"
        )
        if responsibility["chain_id"] != expected_chain_id:
            raise LineageError(
                "responsibility chain_id does not match the expected chain"
            )
    if expected_event_index is not None:
        if (
            not isinstance(expected_event_index, int)
            or isinstance(expected_event_index, bool)
            or expected_event_index < 0
        ):
            raise LineageError("expected_event_index must be an integer >= 0")
        if responsibility["event_index"] != expected_event_index:
            raise LineageError(
                "responsibility event_index does not match the expected index"
            )

    hash_record = _require_object(doc["document_hash"], "document_hash")
    _check_fields(
        hash_record,
        required={"algorithm", "value"},
        context="document_hash",
    )
    if hash_record["algorithm"] != "sha256":
        raise LineageError("document_hash.algorithm must be sha256")
    stored_hash = _validate_sha256(hash_record["value"], "document_hash.value")
    computed_hash = compute_document_hash(doc)
    if stored_hash != computed_hash:
        raise LineageError(
            f"document_hash mismatch: want {stored_hash}, got {computed_hash}"
        )

    stored_head = _validate_sha256(doc["resulting_head"], "resulting_head")
    computed_head = compute_resulting_head(
        responsibility["previous_head"], computed_hash
    )
    if stored_head != computed_head:
        raise LineageError(
            f"resulting_head mismatch: want {stored_head}, got {computed_head}"
        )
    _validate_proofs(doc)
    if (
        doc["document_type"] == "trajectory_root"
        and body["signature_policy"] == "required"
        and not doc["proofs"]
    ):
        raise LineageError("signature_policy required but proofs is empty")
    return doc


def finalize_document(document: Mapping[str, Any]) -> Dict[str, Any]:
    """Pure helper for producers/tests; it never writes or mutates its input."""
    result = copy.deepcopy(dict(document))
    result.setdefault("proofs", [])
    result["document_hash"] = {
        "algorithm": "sha256",
        "value": compute_document_hash(result),
    }
    result["resulting_head"] = compute_resulting_head(
        result["responsibility"]["previous_head"],
        result["document_hash"]["value"],
    )
    return result


def effective_trajectory_identity(
    document: Mapping[str, Any],
) -> Tuple[str, str]:
    if document["document_type"] != "trajectory_root":
        raise LineageError("trajectory identity requires a trajectory_root")
    body = document["body"]
    genesis_hash = body["genesis_root_document_hash"]
    if genesis_hash is None:
        genesis_hash = document["document_hash"]["value"]
    return body["trajectory_id"], genesis_hash


def validate_root_graph(
    roots: Sequence[Mapping[str, Any]],
    known_identities: Mapping[str, str] | None = None,
    *,
    related_handoffs: Sequence[Mapping[str, Any]] = (),
    related_acceptances: Sequence[Mapping[str, Any]] = (),
    require_parent_evidence: bool = False,
    verification_time: str | None = None,
) -> None:
    if not roots:
        raise LineageError("lineage root graph must not be empty")
    by_installation: Dict[str, Mapping[str, Any]] = {}
    by_chain: Dict[str, str] = {}
    identities: Dict[str, str] = {}
    for trajectory_id, genesis_hash in (known_identities or {}).items():
        _validate_typed_id(
            trajectory_id, "trajectory", "known trajectory identity"
        )
        _validate_sha256(genesis_hash, "known trajectory genesis hash")
        identities[trajectory_id] = genesis_hash
    for root in roots:
        validate_document(root, expected_type="trajectory_root")
        body = root["body"]
        installation_id = body["installation_id"]
        if installation_id in by_installation:
            raise LineageError(f"duplicate installation_id: {installation_id}")
        by_installation[installation_id] = root
        chain_id = root["responsibility"]["chain_id"]
        if chain_id in by_chain:
            raise LineageError(
                "duplicate responsibility chain_id across installations: "
                f"{chain_id}"
            )
        by_chain[chain_id] = installation_id
        trajectory_id, genesis_hash = effective_trajectory_identity(root)
        previous = identities.get(trajectory_id)
        if previous is not None and previous != genesis_hash:
            raise LineageError(
                "trajectory_id is paired with a different "
                "genesis_root_document_hash"
            )
        identities[trajectory_id] = genesis_hash

    graph: Dict[str, List[str]] = {
        installation_id: [
            parent["parent_installation_id"]
            for parent in root["body"]["lineage_parents"]
            if parent["parent_installation_id"] in by_installation
        ]
        for installation_id, root in by_installation.items()
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise LineageError("lineage graph contains a cycle")
        if node in visited:
            return
        visiting.add(node)
        for parent in graph[node]:
            visit(parent)
        visiting.remove(node)
        visited.add(node)

    for installation_id in graph:
        visit(installation_id)

    handoffs_by_hash: Dict[str, Mapping[str, Any]] = {}
    for handoff in related_handoffs:
        validate_document(handoff, expected_type="handoff")
        handoff_hash = handoff["document_hash"]["value"]
        if handoff_hash in handoffs_by_hash:
            raise LineageError(f"duplicate handoff document: {handoff_hash}")
        handoffs_by_hash[handoff_hash] = handoff

    used_handoffs: set[str] = set()
    unavailable: List[str] = []
    for child in roots:
        child_body = child["body"]
        for parent in child_body["lineage_parents"]:
            known_parent_genesis = identities.get(
                parent["parent_trajectory_id"]
            )
            if (
                known_parent_genesis is not None
                and known_parent_genesis
                != parent["parent_genesis_root_document_hash"]
            ):
                raise LineageError(
                    "lineage parent claim conflicts with known trajectory "
                    "identity"
                )
            parent_root = by_installation.get(parent["parent_installation_id"])
            if parent_root is None:
                if require_parent_evidence:
                    unavailable.append(
                        "lineage parent root evidence was not supplied: "
                        f"{parent['parent_installation_id']}"
                    )
                continue
            parent_identity = effective_trajectory_identity(parent_root)
            claimed_identity = (
                parent["parent_trajectory_id"],
                parent["parent_genesis_root_document_hash"],
            )
            if parent_identity != claimed_identity:
                raise LineageError(
                    "lineage parent claim does not match the supplied parent root"
                )

            handoff_hash = parent["handoff_document_hash"]
            handoff = handoffs_by_hash.get(handoff_hash)
            if handoff is None:
                if require_parent_evidence:
                    unavailable.append(
                        "lineage parent handoff evidence was not supplied: "
                        f"{handoff_hash}"
                    )
                continue
            if handoff_hash in used_handoffs:
                raise LineageError("the same handoff is replayed by multiple parents")
            used_handoffs.add(handoff_hash)
            handoff_body = handoff["body"]
            if (
                handoff_body["issuer_installation_id"]
                != parent["parent_installation_id"]
                or (
                    handoff_body["trajectory_id"],
                    handoff_body["genesis_root_document_hash"],
                )
                != claimed_identity
            ):
                raise LineageError(
                    "lineage parent handoff issuer does not match parent identity"
                )
            if (
                handoff_body["lineage_root_ref"]["sha256"]
                != _canonical_document_artifact_hash(parent_root)
            ):
                raise LineageError(
                    "lineage parent handoff does not bind the supplied parent root"
                )
            if handoff["resulting_head"] != parent["parent_responsibility_head"]:
                raise LineageError(
                    "lineage parent responsibility head does not match handoff head"
                )
            recipient = handoff_body["recipient_binding"]
            if (
                recipient["mode"] == "bound"
                and recipient["recipient_installation_id"]
                != child_body["installation_id"]
            ):
                raise LineageError(
                    "lineage parent handoff is bound to another installation"
                )
            expected_intent = {
                "predecessor": "none",
                "fork_origin": "explicit_fork",
                "merge_input": "merge_input",
            }[parent["relation"]]
            if handoff_body["fork_intent"] != expected_intent:
                raise LineageError(
                    "lineage parent relation conflicts with handoff fork_intent"
                )
            if require_parent_evidence:
                try:
                    _validate_handoff_evidence(
                        handoff,
                        related_roots=roots,
                        related_acceptances=related_acceptances,
                        related_handoffs=[
                            item
                            for item in related_handoffs
                            if item["document_hash"]["value"] != handoff_hash
                        ],
                        verification_time=verification_time,
                    )
                except LineageEvidenceUnavailable as exc:
                    unavailable.append(str(exc))
    if unavailable:
        raise LineageEvidenceUnavailable("; ".join(unavailable))

def _documents_by_hash(
    documents: Sequence[Mapping[str, Any]],
    *,
    expected_type: str,
) -> Dict[str, Mapping[str, Any]]:
    result: Dict[str, Mapping[str, Any]] = {}
    for document in documents:
        validate_document(document, expected_type=expected_type)
        document_hash = document["document_hash"]["value"]
        if document_hash in result:
            raise LineageError(
                f"duplicate {expected_type} document: {document_hash}"
            )
        result[document_hash] = document
    return result


def _validate_known_trajectory_claims(
    documents: Sequence[Mapping[str, Any]],
    known_identities: Mapping[str, str] | None,
) -> None:
    known: Dict[str, str] = {}
    for trajectory_id, genesis_hash in (known_identities or {}).items():
        _validate_typed_id(
            trajectory_id, "trajectory", "known trajectory identity"
        )
        _validate_sha256(genesis_hash, "known trajectory genesis hash")
        known[trajectory_id] = genesis_hash
    for document in documents:
        body = document["body"]
        trajectory_id = body["trajectory_id"]
        if document["document_type"] == "trajectory_root":
            _trajectory_id, genesis_hash = effective_trajectory_identity(document)
        else:
            genesis_hash = body["genesis_root_document_hash"]
        known_genesis = known.get(trajectory_id)
        if known_genesis is not None and known_genesis != genesis_hash:
            raise LineageError(
                "trajectory_id is paired with a different "
                "genesis_root_document_hash"
            )


def _validate_supplied_document_conflicts(
    documents: Sequence[Mapping[str, Any]],
) -> None:
    document_ids: Dict[Tuple[str, str], str] = {}
    nonces: Dict[Tuple[str, str], str] = {}
    chain_slots: Dict[Tuple[str, int], str] = {}
    chain_predecessors: Dict[Tuple[str, str], str] = {}
    id_fields = {
        "lineage_acceptance": ("acceptance_id", "decision_nonce"),
        "handoff": ("handoff_id", "handoff_nonce"),
    }
    for document in documents:
        document_type = document["document_type"]
        document_hash = document["document_hash"]["value"]
        body = document["body"]
        if document_type in id_fields:
            id_field, nonce_field = id_fields[document_type]
            document_id = body[id_field]
            id_key = (document_type, document_id)
            previous_hash = document_ids.get(id_key)
            if previous_hash is not None and previous_hash != document_hash:
                raise LineageError(
                    f"conflicting {document_type} documents reuse {id_field}: "
                    f"{document_id}"
                )
            document_ids[id_key] = document_hash

            nonce_key = (document_type, body[nonce_field])
            previous_hash = nonces.get(nonce_key)
            if previous_hash is not None and previous_hash != document_hash:
                raise LineageError(
                    f"conflicting {document_type} documents reuse {nonce_field}"
                )
            nonces[nonce_key] = document_hash

        responsibility = document["responsibility"]
        chain_id = responsibility["chain_id"]
        slot_key = (chain_id, responsibility["event_index"])
        previous_hash = chain_slots.get(slot_key)
        if previous_hash is not None and previous_hash != document_hash:
            raise LineageError(
                "responsibility fork: one chain_id/event_index maps to "
                "different documents"
            )
        chain_slots[slot_key] = document_hash

        predecessor_key = (chain_id, responsibility["previous_head"])
        previous_hash = chain_predecessors.get(predecessor_key)
        if previous_hash is not None and previous_hash != document_hash:
            raise LineageError(
                "responsibility fork: one chain_id/previous_head maps to "
                "different documents"
            )
        chain_predecessors[predecessor_key] = document_hash


def _canonical_document_artifact_hash(document: Mapping[str, Any]) -> str:
    return sha256_hex(canon_json_bytes(document))


def _relevant_acceptances(
    document: Mapping[str, Any],
    *,
    related_roots: Sequence[Mapping[str, Any]],
    related_acceptances: Sequence[Mapping[str, Any]],
    related_handoffs: Sequence[Mapping[str, Any]],
) -> List[Mapping[str, Any]]:
    if document["document_type"] == "lineage_acceptance":
        return [document]

    acceptances_by_artifact_hash = {
        _canonical_document_artifact_hash(acceptance): acceptance
        for acceptance in related_acceptances
    }
    acceptance_artifact_hashes: set[str] = set()
    if document["document_type"] == "handoff":
        acceptance_artifact_hashes.add(
            document["body"]["latest_acceptance_ref"]["sha256"]
        )
    else:
        handoffs_by_document_hash = {
            handoff["document_hash"]["value"]: handoff
            for handoff in related_handoffs
        }
        for root in [document, *related_roots]:
            for parent in root["body"]["lineage_parents"]:
                handoff = handoffs_by_document_hash.get(
                    parent["handoff_document_hash"]
                )
                if handoff is not None:
                    acceptance_artifact_hashes.add(
                        handoff["body"]["latest_acceptance_ref"]["sha256"]
                    )

    result: List[Mapping[str, Any]] = []
    seen_document_hashes: set[str] = set()
    for artifact_hash in sorted(acceptance_artifact_hashes):
        acceptance = acceptances_by_artifact_hash.get(artifact_hash)
        if acceptance is None:
            continue
        document_hash = acceptance["document_hash"]["value"]
        if document_hash not in seen_document_hashes:
            result.append(acceptance)
            seen_document_hashes.add(document_hash)
    return result


def _acceptance_authentication_errors(
    acceptances: Sequence[Mapping[str, Any]],
) -> List[str]:
    errors: List[str] = []
    for acceptance in acceptances:
        body = acceptance["body"]
        errors.extend(
            [
                "LINEAGE_ACCEPTANCE decision attribution was not "
                f"cryptographically verified: {body['acceptance_id']}",
                "LINEAGE_ACCEPTANCE verification_report_hash artifact was "
                f"not supplied and verified: {body['verification_report_hash']}",
            ]
        )
    return errors


def _validate_unbound_handoff_expiry(
    handoff: Mapping[str, Any],
    verification_time: str | None,
) -> None:
    body = handoff["body"]
    if body["recipient_binding"]["mode"] != "unbound":
        return
    if verification_time is None:
        raise LineageEvidenceUnavailable(
            "unbound handoff expiry was not evaluated because no "
            "verification time was supplied"
        )
    checked_time = _validate_timestamp(
        verification_time, "verification_time"
    )
    checked_dt = datetime.fromisoformat(checked_time.replace("Z", "+00:00"))
    expires_dt = datetime.fromisoformat(
        body["expires_at"].replace("Z", "+00:00")
    )
    if checked_dt >= expires_dt:
        raise LineageError("unbound handoff is expired at verification_time")


def _validate_acceptance_evidence(
    acceptance: Mapping[str, Any],
    *,
    related_roots: Sequence[Mapping[str, Any]],
    related_acceptances: Sequence[Mapping[str, Any]],
    related_handoffs: Sequence[Mapping[str, Any]] = (),
    verification_time: str | None = None,
    evidence_path: Tuple[Tuple[str, str], ...] = (),
) -> None:
    evidence_key = ("lineage_acceptance", acceptance["document_hash"]["value"])
    if evidence_key in evidence_path:
        raise LineageError("lineage evidence graph contains a cycle")
    evidence_path = (*evidence_path, evidence_key)
    body = acceptance["body"]
    roots_by_hash = _documents_by_hash(
        related_roots, expected_type="trajectory_root"
    )
    root_hash = body["subject"]["trajectory_root_document_hash"]
    root = roots_by_hash.get(root_hash)
    if root is None:
        for candidate in roots_by_hash.values():
            candidate_identity = effective_trajectory_identity(candidate)
            if candidate["body"]["installation_id"] == body["installation_id"]:
                raise LineageError(
                    "supplied acceptance installation root has a different "
                    "document hash"
                )
            if (
                candidate["body"]["trajectory_id"] == body["trajectory_id"]
                and candidate_identity[1]
                != body["genesis_root_document_hash"]
            ):
                raise LineageError(
                    "acceptance trajectory_id is paired with a different "
                    "genesis_root_document_hash"
                )
        raise LineageEvidenceUnavailable(
            f"acceptance subject root evidence was not supplied: {root_hash}"
        )
    root_identity = effective_trajectory_identity(root)
    if root_identity != (
        body["trajectory_id"],
        body["genesis_root_document_hash"],
    ):
        raise LineageError("acceptance trajectory identity does not match subject root")
    if root["body"]["installation_id"] != body["installation_id"]:
        raise LineageError("acceptance installation does not match subject root")
    result_by_id = {
        result["artifact_id"]: result for result in body["target_results"]
    }
    root_result = result_by_id[body["subject"]["trajectory_root_artifact_id"]]
    if root_result["status"] != "target_present_verified":
        raise LineageError(
            "acceptance subject root status conflicts with supplied valid root"
        )
    subject_handoff_hash = body["subject"].get("handoff_document_hash")
    if subject_handoff_hash is not None:
        handoffs_by_hash = _documents_by_hash(
            related_handoffs, expected_type="handoff"
        )
        subject_handoff = handoffs_by_hash.get(subject_handoff_hash)
        if subject_handoff is None:
            raise LineageEvidenceUnavailable(
                "acceptance subject handoff evidence was not supplied: "
                f"{subject_handoff_hash}"
            )
        recipient = subject_handoff["body"]["recipient_binding"]
        if (
            recipient["mode"] == "bound"
            and recipient["recipient_installation_id"]
            != body["installation_id"]
        ):
            raise LineageError(
                "acceptance subject handoff is bound to another installation"
            )
        matching_parent = next(
            (
                parent
                for parent in root["body"]["lineage_parents"]
                if parent["handoff_document_hash"] == subject_handoff_hash
            ),
            None,
        )
        if matching_parent is None:
            raise LineageError(
                "acceptance subject handoff is not a lineage parent handoff "
                "of the subject root"
            )
        handoff_body = subject_handoff["body"]
        if (
            handoff_body["issuer_installation_id"]
            != matching_parent["parent_installation_id"]
            or handoff_body["trajectory_id"]
            != matching_parent["parent_trajectory_id"]
            or handoff_body["genesis_root_document_hash"]
            != matching_parent["parent_genesis_root_document_hash"]
            or subject_handoff["resulting_head"]
            != matching_parent["parent_responsibility_head"]
        ):
            raise LineageError(
                "acceptance subject handoff conflicts with root parent claim"
            )
        handoff_result = result_by_id[body["subject"]["handoff_artifact_id"]]
        if handoff_result["status"] != "target_present_verified":
            raise LineageError(
                "acceptance subject handoff status conflicts with supplied "
                "valid handoff"
            )
        _validate_handoff_evidence(
            subject_handoff,
            related_roots=related_roots,
            related_acceptances=related_acceptances,
            related_handoffs=[
                item
                for item in related_handoffs
                if item["document_hash"]["value"] != subject_handoff_hash
            ],
            verification_time=verification_time,
            evidence_path=evidence_path,
        )

    subject_result_ids = {body["subject"]["trajectory_root_artifact_id"]}
    if "handoff_artifact_id" in body["subject"]:
        subject_result_ids.add(body["subject"]["handoff_artifact_id"])
    inherited_results = {
        artifact_id: result
        for artifact_id, result in result_by_id.items()
        if artifact_id not in subject_result_ids
    }
    expected_sources = {
        source["artifact"]["artifact_id"]: source
        for source in root["body"]["inheritance_sources"]
    }
    if set(inherited_results) != set(expected_sources):
        raise LineageError(
            "acceptance target_results do not exactly cover root "
            "inheritance_sources"
        )
    for artifact_id, source in expected_sources.items():
        result = inherited_results[artifact_id]
        if (
            result["expected_sha256"] != source["artifact"]["sha256"]
            or result["criticality"] != source["criticality"]
        ):
            raise LineageError(
                "acceptance target result conflicts with inheritance source: "
                f"{artifact_id}"
            )

    previous_hash = body.get("previous_acceptance_hash")
    if previous_hash is None:
        previous = root
    else:
        previous_by_hash = _documents_by_hash(
            related_acceptances, expected_type="lineage_acceptance"
        )
        previous = previous_by_hash.get(previous_hash)
        if previous is None:
            raise LineageEvidenceUnavailable(
                "previous acceptance evidence was not supplied: "
                f"{previous_hash}"
            )
        previous_body = previous["body"]
        if (
            previous_body["trajectory_id"],
            previous_body["genesis_root_document_hash"],
            previous_body["installation_id"],
        ) != (
            body["trajectory_id"],
            body["genesis_root_document_hash"],
            body["installation_id"],
        ):
            raise LineageError("previous acceptance belongs to another installation")
        _validate_acceptance_evidence(
            previous,
            related_roots=related_roots,
            related_acceptances=[
                item
                for item in related_acceptances
                if item["document_hash"]["value"] != previous_hash
            ],
            related_handoffs=related_handoffs,
            verification_time=verification_time,
            evidence_path=evidence_path,
        )
    current_resp = acceptance["responsibility"]
    previous_resp = previous["responsibility"]
    if (
        current_resp["chain_id"] != previous_resp["chain_id"]
        or current_resp["event_index"] != previous_resp["event_index"] + 1
        or current_resp["previous_head"] != previous["resulting_head"]
    ):
        raise LineageError(
            "acceptance does not extend the supplied responsibility head"
        )


def _validate_handoff_evidence(
    handoff: Mapping[str, Any],
    *,
    related_roots: Sequence[Mapping[str, Any]],
    related_acceptances: Sequence[Mapping[str, Any]],
    related_handoffs: Sequence[Mapping[str, Any]],
    verification_time: str | None = None,
    evidence_path: Tuple[Tuple[str, str], ...] = (),
) -> None:
    evidence_key = ("handoff", handoff["document_hash"]["value"])
    if evidence_key in evidence_path:
        raise LineageError("lineage evidence graph contains a cycle")
    evidence_path = (*evidence_path, evidence_key)
    body = handoff["body"]
    _validate_unbound_handoff_expiry(handoff, verification_time)
    validated_roots = [
        validate_document(root, expected_type="trajectory_root")
        for root in related_roots
    ]
    if body["lineage_root_ref"]["hash_scope"] != "canonical_document":
        raise LineageError(
            "handoff lineage_root_ref must use canonical_document hash_scope"
        )
    root_hash = body["lineage_root_ref"]["sha256"]
    roots_by_artifact_hash = {
        _canonical_document_artifact_hash(root): root for root in validated_roots
    }
    root = roots_by_artifact_hash.get(root_hash)
    if root is None:
        for candidate in validated_roots:
            candidate_identity = effective_trajectory_identity(candidate)
            if (
                candidate["body"]["installation_id"]
                == body["issuer_installation_id"]
            ):
                raise LineageError(
                    "supplied handoff issuer root has a different canonical "
                    "artifact hash"
                )
            if (
                candidate["body"]["trajectory_id"] == body["trajectory_id"]
                and candidate_identity[1]
                != body["genesis_root_document_hash"]
            ):
                raise LineageError(
                    "handoff trajectory_id is paired with a different "
                    "genesis_root_document_hash"
                )
        raise LineageEvidenceUnavailable(
            f"handoff lineage root evidence was not supplied: {root_hash}"
        )
    if effective_trajectory_identity(root) != (
        body["trajectory_id"],
        body["genesis_root_document_hash"],
    ):
        raise LineageError("handoff trajectory identity does not match lineage root")
    if root["body"]["installation_id"] != body["issuer_installation_id"]:
        raise LineageError("handoff issuer does not match lineage root installation")
    if canon_json_bytes(body["lineage_parents"]) != canon_json_bytes(
        root["body"]["lineage_parents"]
    ):
        raise LineageError("handoff lineage parents do not match lineage root")
    root_sources = {
        source["artifact"]["artifact_id"]: source
        for source in root["body"]["inheritance_sources"]
    }
    handoff_sources = {
        source["artifact"]["artifact_id"]: source
        for source in body["inheritance_sources"]
    }
    missing_sources = sorted(set(root_sources) - set(handoff_sources))
    if missing_sources:
        raise LineageError(
            "handoff omits inheritance sources required by lineage root: "
            f"{missing_sources}"
        )
    for artifact_id, source in root_sources.items():
        if canon_json_bytes(source) != canon_json_bytes(
            handoff_sources[artifact_id]
        ):
            raise LineageError(
                "handoff changes a lineage-root inheritance source: "
                f"{artifact_id}"
            )

    validated_acceptances = [
        validate_document(acceptance, expected_type="lineage_acceptance")
        for acceptance in related_acceptances
    ]
    if body["latest_acceptance_ref"]["hash_scope"] != "canonical_document":
        raise LineageError(
            "handoff latest_acceptance_ref must use canonical_document hash_scope"
        )
    acceptance_hash = body["latest_acceptance_ref"]["sha256"]
    acceptances_by_artifact_hash = {
        _canonical_document_artifact_hash(acceptance): acceptance
        for acceptance in validated_acceptances
    }
    acceptance = acceptances_by_artifact_hash.get(acceptance_hash)
    if acceptance is None:
        raise LineageEvidenceUnavailable(
            f"handoff acceptance evidence was not supplied: {acceptance_hash}"
        )
    acceptance_body = acceptance["body"]
    if (
        acceptance_body["trajectory_id"],
        acceptance_body["genesis_root_document_hash"],
        acceptance_body["installation_id"],
    ) != (
        body["trajectory_id"],
        body["genesis_root_document_hash"],
        body["issuer_installation_id"],
    ):
        raise LineageError("handoff latest acceptance belongs to another installation")
    if acceptance_body["decision"] not in {
        "accepted",
        "accepted_with_reservations",
    }:
        raise LineageError("handoff latest acceptance is not activating")
    _validate_acceptance_evidence(
        acceptance,
        related_roots=related_roots,
        related_acceptances=[
            item
            for item in related_acceptances
            if _canonical_document_artifact_hash(item) != acceptance_hash
        ],
        related_handoffs=related_handoffs,
        verification_time=verification_time,
        evidence_path=evidence_path,
    )

    if body["sequence"] == 0:
        previous = acceptance
    else:
        handoffs_by_hash = _documents_by_hash(
            related_handoffs, expected_type="handoff"
        )
        previous_hash = body["previous_handoff_hash"]
        previous = handoffs_by_hash.get(previous_hash)
        if previous is None:
            raise LineageEvidenceUnavailable(
                f"previous handoff evidence was not supplied: {previous_hash}"
            )
        previous_body = previous["body"]
        if (
            previous_body["trajectory_id"],
            previous_body["genesis_root_document_hash"],
            previous_body["issuer_installation_id"],
        ) != (
            body["trajectory_id"],
            body["genesis_root_document_hash"],
            body["issuer_installation_id"],
        ):
            raise LineageError("previous handoff belongs to another installation")
        if previous_body["sequence"] + 1 != body["sequence"]:
            raise LineageError("handoff sequence is not contiguous")
        if (
            previous_body["latest_acceptance_ref"]["sha256"]
            != body["latest_acceptance_ref"]["sha256"]
        ):
            raise LineageError(
                "handoff sequence changes latest_acceptance_ref without a "
                "verifiable intervening responsibility event"
            )
        _validate_handoff_evidence(
            previous,
            related_roots=related_roots,
            related_acceptances=related_acceptances,
            related_handoffs=[
                item
                for item in related_handoffs
                if item["document_hash"]["value"] != previous_hash
            ],
            verification_time=verification_time,
            evidence_path=evidence_path,
        )
    current_resp = handoff["responsibility"]
    previous_resp = previous["responsibility"]
    if (
        current_resp["chain_id"] != previous_resp["chain_id"]
        or current_resp["event_index"] != previous_resp["event_index"] + 1
        or current_resp["previous_head"] != previous["resulting_head"]
    ):
        raise LineageError("handoff does not extend the supplied responsibility head")


@dataclass
class VerificationBindings:
    target_paths: Dict[str, Path] = field(default_factory=dict)
    target_roots: Dict[str, Path] = field(default_factory=dict)
    ledger_paths: Dict[str, Path] = field(default_factory=dict)
    ledger_roots: Dict[str, Path] = field(default_factory=dict)
    ledger_entries: Dict[str, str] = field(default_factory=dict)
    ledger_cache: Dict[
        Tuple[str, str, Path], Dict[str, str] | str
    ] = field(
        default_factory=dict,
        repr=False,
    )


def _validate_bindings_for_artifacts(
    artifacts: Sequence[Tuple[Mapping[str, Any], str]],
    bindings: VerificationBindings,
) -> None:
    artifacts_by_id = {
        artifact["artifact_id"]: artifact for artifact, _criticality in artifacts
    }
    target_maps = {
        "target": bindings.target_paths,
        "target-root": bindings.target_roots,
        "ledger-root": bindings.ledger_roots,
        "ledger-entry": bindings.ledger_entries,
    }
    for option, values in target_maps.items():
        unknown = sorted(set(values) - set(artifacts_by_id))
        if unknown:
            raise LineageError(
                f"--{option} names an artifact not referenced by the document: "
                f"{unknown}"
            )
    ledger_ids = {
        artifact["ledger_ref"]["ledger_artifact_id"]
        for artifact in artifacts_by_id.values()
        if "ledger_ref" in artifact
    }
    unknown_ledgers = sorted(set(bindings.ledger_paths) - ledger_ids)
    if unknown_ledgers:
        raise LineageError(
            "--ledger names a ledger artifact not referenced by the document: "
            f"{unknown_ledgers}"
        )
    ledger_commitments: Dict[str, str] = {}
    for artifact in artifacts_by_id.values():
        ledger_ref = artifact.get("ledger_ref")
        if ledger_ref is None:
            continue
        ledger_id = ledger_ref["ledger_artifact_id"]
        previous_sha = ledger_commitments.get(ledger_id)
        if previous_sha is not None and previous_sha != ledger_ref["ledger_sha256"]:
            raise LineageError(
                "one ledger_artifact_id is paired with conflicting SHA-256 "
                f"commitments: {ledger_id}"
            )
        ledger_commitments[ledger_id] = ledger_ref["ledger_sha256"]
    for artifact_id, artifact in artifacts_by_id.items():
        has_target = artifact_id in bindings.target_paths
        has_target_root = artifact_id in bindings.target_roots
        if has_target != has_target_root:
            raise LineageError(
                "target binding requires both --target and --target-root for "
                f"{artifact_id}"
            )
        ledger_id = (
            artifact.get("ledger_ref", {}).get("ledger_artifact_id")
        )
        ledger_parts = (
            ledger_id in bindings.ledger_paths if ledger_id is not None else False,
            artifact_id in bindings.ledger_roots,
            artifact_id in bindings.ledger_entries,
        )
        if any(ledger_parts) and not all(ledger_parts):
            raise LineageError(
                "ledger binding requires --ledger, --ledger-root, and "
                f"--ledger-entry for {artifact_id}"
            )
        if all(ledger_parts) and "ledger_ref" not in artifact:
            raise LineageError(
                f"ledger binding supplied for artifact without ledger_ref: "
                f"{artifact_id}"
            )


def _check_no_symlink_components(root: Path, rel_path: Path) -> None:
    current = root
    for part in rel_path.parts:
        current = current / part
        try:
            is_symlink = current.is_symlink()
        except (OSError, RuntimeError) as exc:
            raise LineageError(
                f"target_invalid: cannot inspect target path component: {exc}"
            ) from exc
        if is_symlink:
            raise LineageError(
                f"target_invalid: symlink is unsupported: {rel_path.as_posix()}"
            )


def _resolve_declared_root(root: Path, *, label: str) -> Path:
    try:
        lexical = root if root.is_absolute() else Path.cwd() / root
        if ".." in lexical.parts:
            raise LineageError(
                f"target_invalid: {label} contains parent traversal"
            )
        current = Path(lexical.anchor)
        for part in lexical.parts[1:]:
            if part in {"", "."}:
                continue
            current = current / part
            entry_stat = current.lstat()
            if stat.S_ISLNK(entry_stat.st_mode):
                raise LineageError(
                    f"target_invalid: {label} contains a symlink component"
                )
        root_stat = lexical.stat()
    except LineageError:
        raise
    except (OSError, RuntimeError) as exc:
        raise LineageError(
            f"target_invalid: cannot inspect {label}: {exc}"
        ) from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise LineageError(f"target_invalid: {label} is not a directory")
    return lexical


def _safe_target(root: Path, target: Path) -> Tuple[Path, bool]:
    root = _resolve_declared_root(root, label="target root")
    if target.is_absolute():
        try:
            rel = target.relative_to(root)
        except ValueError as exc:
            raise LineageError("target_invalid: target is outside declared root") from exc
    else:
        rel = target
    try:
        rel = normalize_relative_path(str(rel), label="target path")
        lexical, _resolved = resolve_inside_root(root, rel)
    except (LedgerError, OSError, RuntimeError) as exc:
        raise LineageError(f"target_invalid: {exc}") from exc
    _check_no_symlink_components(root, rel)
    try:
        target_stat = lexical.lstat()
    except FileNotFoundError:
        return lexical, False
    except OSError as exc:
        raise LineageError(f"target_invalid: cannot inspect target: {exc}") from exc
    if not stat.S_ISREG(target_stat.st_mode):
        raise LineageError("target_invalid: target is not a regular file")
    return lexical, True


def _read_regular_file_once(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise LineageError("target_invalid: target is not a regular file")
        chunks: List[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise LineageError(f"target_invalid: cannot read target: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _artifact_observed_hash(data: bytes, hash_scope: str) -> str:
    if hash_scope in {"file_bytes", "ciphertext"}:
        return hashlib.sha256(data).hexdigest()
    if hash_scope == "canonical_document":
        try:
            text = data.decode("utf-8")
            value = loads_json_strict(text)
            return sha256_hex(canon_json_bytes(value))
        except (UnicodeError, CanonicalJSONError) as exc:
            raise LineageError(
                f"target_invalid: canonical document is invalid: {exc}"
            ) from exc
    if hash_scope == "echohash_head":
        try:
            text = data.decode("ascii")
        except UnicodeError as exc:
            raise LineageError(
                "target_invalid: EchoHash head must be ASCII"
            ) from exc
        if text.endswith("\n"):
            text = text[:-1]
        if not HEX64_RE.fullmatch(text):
            raise LineageError(
                "target_invalid: EchoHash head file must contain one lowercase "
                "SHA-256 value with an optional final LF"
            )
        return text
    raise LineageError(f"target_invalid: unsupported hash_scope: {hash_scope}")


def verify_artifact_target(
    artifact: Mapping[str, Any],
    *,
    criticality: str,
    bindings: VerificationBindings,
) -> Dict[str, Any]:
    artifact_id = artifact["artifact_id"]
    result: Dict[str, Any] = {
        "artifact_id": artifact_id,
        "criticality": criticality,
        "expected_sha256": artifact["sha256"],
    }
    target_path = bindings.target_paths.get(artifact_id)
    target_root = bindings.target_roots.get(artifact_id)
    ledger_ref = artifact.get("ledger_ref")

    ledger_known = False
    derived_target: Path | None = None
    ledger_error: str | None = None
    if ledger_ref is not None:
        ledger_artifact_id = ledger_ref["ledger_artifact_id"]
        ledger_path = bindings.ledger_paths.get(ledger_artifact_id)
        ledger_root = bindings.ledger_roots.get(artifact_id)
        ledger_entry = bindings.ledger_entries.get(artifact_id)
        if ledger_path is not None and ledger_root is not None and ledger_entry is not None:
            try:
                rel = normalize_relative_path(
                    ledger_entry, label="private ledger binding path"
                )
                resolved_ledger_root = _resolve_declared_root(
                    ledger_root, label="ledger root"
                )
                resolved_ledger_directory = _resolve_declared_root(
                    ledger_path.parent, label="ledger directory"
                )
                safe_ledger_path = (
                    resolved_ledger_directory / ledger_path.name
                )
                _lexical, _resolved = resolve_inside_root(
                    resolved_ledger_root, rel
                )
                _check_no_symlink_components(resolved_ledger_root, rel)
                cache_key = (
                    ledger_artifact_id,
                    ledger_ref["ledger_sha256"],
                    safe_ledger_path,
                )
                entries = bindings.ledger_cache.get(cache_key)
                if isinstance(entries, str):
                    raise LineageError(entries)
                if entries is None:
                    try:
                        entries = load_ledger_entries(
                            safe_ledger_path,
                            expected_sha256=ledger_ref["ledger_sha256"],
                        )
                    except (LedgerError, OSError, RuntimeError) as exc:
                        cached_error = str(exc)
                        bindings.ledger_cache[cache_key] = cached_error
                        raise LineageError(cached_error) from exc
                    bindings.ledger_cache[cache_key] = entries
                rel_text = rel.as_posix()
                if entries.get(rel_text) != artifact["sha256"]:
                    raise LineageError(
                        "target_invalid: ledger entry does not bind expected SHA-256"
                    )
                ledger_known = True
                derived_target = resolved_ledger_root / rel
            except (LedgerError, LineageError, OSError, RuntimeError) as exc:
                ledger_error = str(exc)

    if target_path is None and derived_target is not None:
        target_path = derived_target
        target_root = bindings.ledger_roots[artifact_id]

    if target_path is None:
        if ledger_error is not None:
            result.update(status="target_invalid", message=ledger_error)
        elif ledger_ref is not None:
            result.update(
                status="verification_not_attempted",
                message="verification not attempted: ledger binding unavailable",
            )
        else:
            result.update(
                status="verification_not_attempted",
                message="verification not attempted: no target binding supplied",
            )
        return result
    if target_root is None:
        result.update(
            status="target_invalid",
            message="target_invalid: target root was not declared",
        )
        return result

    try:
        safe_target, present = _safe_target(target_root, target_path)
    except LineageError as exc:
        result.update(status="target_invalid", message=str(exc))
        return result
    if not present:
        if ledger_error is not None:
            result.update(status="target_invalid", message=ledger_error)
        elif ledger_known:
            result.update(
                status="ledger_known_target_missing",
                message="ledger known, target missing",
            )
        else:
            result.update(
                status="target_missing_unanchored",
                message="target missing, no verified ledger anchor",
            )
        return result

    try:
        target_bytes = _read_regular_file_once(safe_target)
        got = _artifact_observed_hash(target_bytes, artifact["hash_scope"])
    except (OSError, LineageError) as exc:
        result.update(
            status="target_invalid",
            message=(
                str(exc)
                if str(exc).startswith("target_invalid:")
                else f"target_invalid: cannot hash target: {exc}"
            ),
        )
        return result
    result["observed_sha256"] = got
    if got != artifact["sha256"]:
        result.update(status="hash_mismatch", message="target SHA-256 mismatch")
    elif ledger_error is not None:
        result.update(status="target_invalid", message=ledger_error)
    else:
        result.update(
            status="target_present_verified",
            message="target present, SHA-256 verified",
        )
    return result


def _document_artifacts(
    document: Mapping[str, Any],
) -> List[Tuple[Mapping[str, Any], str]]:
    body = document["body"]
    artifacts: List[Tuple[Mapping[str, Any], str]] = []
    if document["document_type"] == "trajectory_root":
        artifacts.extend(
            (source["artifact"], source["criticality"])
            for source in body["inheritance_sources"]
        )
    elif document["document_type"] == "lineage_acceptance":
        actor = body["decision_actor"]
        for field_name in (
            "decision_evidence_ref",
            "policy_artifact_ref",
            "historical_claim_artifact_ref",
        ):
            if field_name in actor:
                artifacts.append((actor[field_name], "critical_root"))
    elif document["document_type"] == "handoff":
        artifacts.extend(
            (source["artifact"], source["criticality"])
            for source in body["inheritance_sources"]
        )
        artifacts.extend((head, "supporting") for head in body["memory_heads"])
    return artifacts


def verify_document_read_only(
    document: Mapping[str, Any],
    *,
    expected_type: str | None = None,
    expected_previous_head: str | None = None,
    expected_chain_id: str | None = None,
    expected_event_index: int | None = None,
    related_roots: Sequence[Mapping[str, Any]] = (),
    related_acceptances: Sequence[Mapping[str, Any]] = (),
    related_handoffs: Sequence[Mapping[str, Any]] = (),
    known_identities: Mapping[str, str] | None = None,
    bindings: VerificationBindings | None = None,
    verification_time: str | None = None,
) -> Tuple[int, Dict[str, Any]]:
    bindings = bindings or VerificationBindings()
    # The cache is scoped to one verification call: it makes a shared ledger a
    # single snapshot without letting a reused bindings object retain stale
    # filesystem state across calls.
    bindings.ledger_cache.clear()
    evidence_errors: List[str] = []
    try:
        validated = validate_document(
            document,
            expected_type=expected_type,
            expected_previous_head=expected_previous_head,
            expected_chain_id=expected_chain_id,
            expected_event_index=expected_event_index,
        )
        _documents_by_hash(
            related_roots, expected_type="trajectory_root"
        )
        _documents_by_hash(
            related_acceptances, expected_type="lineage_acceptance"
        )
        _documents_by_hash(
            related_handoffs, expected_type="handoff"
        )
        supplied_documents = [
            validated,
            *related_roots,
            *related_acceptances,
            *related_handoffs,
        ]
        _validate_known_trajectory_claims(
            supplied_documents, known_identities
        )
        _validate_supplied_document_conflicts(supplied_documents)
        same_type_related = {
            "trajectory_root": related_roots,
            "lineage_acceptance": related_acceptances,
            "handoff": related_handoffs,
        }[validated["document_type"]]
        if any(
            item["document_hash"]["value"]
            == validated["document_hash"]["value"]
            for item in same_type_related
        ):
            raise LineageError(
                "current document is replayed in its related evidence set"
            )
        if validated["document_type"] == "trajectory_root":
            try:
                validate_root_graph(
                    [validated, *related_roots],
                    known_identities=known_identities,
                    related_handoffs=related_handoffs,
                    related_acceptances=related_acceptances,
                    require_parent_evidence=True,
                    verification_time=verification_time,
                )
            except LineageEvidenceUnavailable as exc:
                evidence_errors.append(str(exc))
        elif validated["document_type"] == "lineage_acceptance":
            try:
                _validate_acceptance_evidence(
                    validated,
                    related_roots=related_roots,
                    related_acceptances=related_acceptances,
                    related_handoffs=related_handoffs,
                    verification_time=verification_time,
                )
            except LineageEvidenceUnavailable as exc:
                evidence_errors.append(str(exc))
        else:
            try:
                _validate_handoff_evidence(
                    validated,
                    related_roots=related_roots,
                    related_acceptances=related_acceptances,
                    related_handoffs=related_handoffs,
                    verification_time=verification_time,
                )
            except LineageEvidenceUnavailable as exc:
                evidence_errors.append(str(exc))
        if related_roots and validated["document_type"] != "trajectory_root":
            try:
                validate_root_graph(
                    related_roots,
                    known_identities=known_identities,
                    related_handoffs=related_handoffs,
                    related_acceptances=related_acceptances,
                    require_parent_evidence=True,
                    verification_time=verification_time,
                )
            except LineageEvidenceUnavailable as exc:
                evidence_errors.append(str(exc))
        _validate_bindings_for_artifacts(
            _document_artifacts(validated), bindings
        )
    except (
        LineageError,
        CanonicalJSONError,
        LedgerError,
        OSError,
        UnicodeError,
        RecursionError,
        RuntimeError,
    ) as exc:
        return 2, {
            "protocol": PROTOCOL,
            "operation": "verify",
            "status": "invalid",
            "errors": [str(exc)],
            "semantics": [
                "VERIFY SUCCESS != ACCEPTED",
                "HANDOFF VERIFIED != IMPORTED",
                "TARGET MISSING != HASH MISMATCH",
            ],
        }

    evidence_errors.extend(
        _acceptance_authentication_errors(
            _relevant_acceptances(
                validated,
                related_roots=related_roots,
                related_acceptances=related_acceptances,
                related_handoffs=related_handoffs,
            )
        )
    )
    if validated["proofs"]:
        evidence_errors.append(
            "proof structure covers the responsibility head, but the "
            "cryptographic signature was not verified"
        )
    if (
        validated["document_type"] == "trajectory_root"
        and validated["body"]["signature_policy"] == "out_of_band"
    ):
        evidence_errors.append(
            "signature_policy requires out-of-band proof verification"
        )
    evidence_errors = list(dict.fromkeys(evidence_errors))
    target_results = [
        verify_artifact_target(
            artifact,
            criticality=criticality,
            bindings=bindings,
        )
        for artifact, criticality in _document_artifacts(validated)
    ]
    allowed = (
        evaluate_future_decisions(target_results)
        if validated["document_type"] != "lineage_acceptance"
        else evaluate_future_decisions(validated["body"]["target_results"])
    )
    if evidence_errors:
        allowed = [
            decision
            for decision in allowed
            if decision in {"declined", "quarantined_integrity_failure"}
        ]
        if not allowed:
            allowed = ["declined"]
    statuses = {result["status"] for result in target_results}
    if statuses & {"hash_mismatch", "target_invalid"}:
        code = 2
        status = "integrity_failure"
    elif validated["document_type"] == "lineage_acceptance":
        code = 10
        status = "structure_valid_attribution_unverified"
    elif evidence_errors or statuses & {
        "ledger_known_target_missing",
        "verification_not_attempted",
        "target_missing_unanchored",
    }:
        code = 10
        status = "verified_with_unavailable_targets"
    else:
        code = 0
        status = "verified"

    report: Dict[str, Any] = {
        "protocol": PROTOCOL,
        "operation": "verify",
        "document_type": validated["document_type"],
        "document_hash": validated["document_hash"]["value"],
        "resulting_head": validated["resulting_head"],
        "status": status,
        "target_results": target_results,
        "allowed_future_decisions": allowed,
        "proof_status": (
            "structure_valid_signature_unverified"
            if validated["proofs"]
            else "unsigned"
        ),
        "evidence_status": (
            "incomplete" if evidence_errors else "complete"
        ),
        "evidence_errors": evidence_errors,
        "semantics": [
            "VERIFY SUCCESS != ACCEPTED",
            "HANDOFF VERIFIED != IMPORTED",
            "TARGET MISSING != HASH MISMATCH",
        ],
    }
    if validated["document_type"] == "trajectory_root":
        trajectory_id, genesis_hash = effective_trajectory_identity(validated)
        report["trajectory_identity"] = {
            "trajectory_id": trajectory_id,
            "genesis_root_document_hash": genesis_hash,
        }
    return code, report


def _parse_key_values(values: Sequence[str], option: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise LineageError(f"{option} requires ID=VALUE")
        key, value = raw.split("=", 1)
        if not key or not value:
            raise LineageError(f"{option} requires non-empty ID=VALUE")
        if key in result:
            raise LineageError(f"{option} repeats ID: {key}")
        result[key] = value
    return result


def _load_document(path: Path) -> Dict[str, Any]:
    lexical = path if path.is_absolute() else Path.cwd() / path
    if ".." in lexical.parts:
        raise LineageError("document path must not contain parent traversal")
    current = Path(lexical.anchor)
    try:
        for part in lexical.parts[1:]:
            if part in {"", "."}:
                continue
            current = current / part
            component_stat = current.lstat()
            if stat.S_ISLNK(component_stat.st_mode):
                raise LineageError(
                    "document path must not contain a symlink component"
                )
        path_stat = lexical.stat()
    except LineageError:
        raise
    except (OSError, RuntimeError) as exc:
        raise LineageError(f"cannot inspect document: {exc}") from exc
    if not stat.S_ISREG(path_stat.st_mode):
        raise LineageError("document path must be a regular file")
    data = _read_regular_file_once(lexical)
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise LineageError(f"document is not valid UTF-8: {exc}") from exc
    value = loads_json_strict(text)
    return _require_object(value, str(path))


def _add_verify_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--document", required=True, help="lineage JSON document")
    parser.add_argument(
        "--related-root",
        action="append",
        default=[],
        help="additional TRAJECTORY_ROOT for graph checks (repeatable)",
    )
    parser.add_argument(
        "--related-acceptance",
        action="append",
        default=[],
        help="related LINEAGE_ACCEPTANCE evidence (repeatable)",
    )
    parser.add_argument(
        "--related-handoff",
        action="append",
        default=[],
        help="related HANDOFF evidence (repeatable)",
    )
    parser.add_argument(
        "--known-trajectory",
        action="append",
        default=[],
        metavar="TRAJECTORY_ID=GENESIS_SHA256",
    )
    parser.add_argument(
        "--expected-previous-head",
        help="known previous responsibility head",
    )
    parser.add_argument(
        "--expected-chain-id",
        help="known responsibility chain identifier",
    )
    parser.add_argument(
        "--expected-event-index",
        type=int,
        help="known responsibility event index",
    )
    parser.add_argument(
        "--verification-time",
        help=(
            "explicit untrusted RFC 3339 comparison time for unbound handoff "
            "expiry"
        ),
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="ARTIFACT_ID=PATH",
    )
    parser.add_argument(
        "--target-root",
        action="append",
        default=[],
        metavar="ARTIFACT_ID=ROOT",
    )
    parser.add_argument(
        "--ledger",
        action="append",
        default=[],
        metavar="LEDGER_ARTIFACT_ID=LEDGER",
    )
    parser.add_argument(
        "--ledger-root",
        action="append",
        default=[],
        metavar="ARTIFACT_ID=ROOT",
    )
    parser.add_argument(
        "--ledger-entry",
        action="append",
        default=[],
        metavar="ARTIFACT_ID=RELATIVE_PATH",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON report")


def _bindings_from_args(args: argparse.Namespace) -> VerificationBindings:
    return VerificationBindings(
        target_paths={
            key: Path(value)
            for key, value in _parse_key_values(args.target, "--target").items()
        },
        target_roots={
            key: Path(value)
            for key, value in _parse_key_values(
                args.target_root, "--target-root"
            ).items()
        },
        ledger_paths={
            key: Path(value)
            for key, value in _parse_key_values(args.ledger, "--ledger").items()
        },
        ledger_roots={
            key: Path(value)
            for key, value in _parse_key_values(
                args.ledger_root, "--ledger-root"
            ).items()
        },
        ledger_entries=_parse_key_values(args.ledger_entry, "--ledger-entry"),
    )


def _emit_report(report: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return
    print(f"status: {report['status']}")
    for error in report.get("errors", []):
        print(f"ERROR: {error}")
    for error in report.get("evidence_errors", []):
        print(f"EVIDENCE UNAVAILABLE: {error}")
    for result in report.get("target_results", []):
        print(f"{result['artifact_id']}: {result['message']}")
    if "allowed_future_decisions" in report:
        print(
            "allowed future decisions: "
            + ", ".join(report["allowed_future_decisions"])
        )
    print("VERIFY SUCCESS != ACCEPTED")
    print("HANDOFF VERIFIED != IMPORTED")
    print("TARGET MISSING != HASH MISMATCH")


def _run_verify(args: argparse.Namespace, expected_type: str | None) -> int:
    try:
        document = _load_document(Path(args.document))
        related = [_load_document(Path(path)) for path in args.related_root]
        related_acceptances = [
            _load_document(Path(path)) for path in args.related_acceptance
        ]
        related_handoffs = [
            _load_document(Path(path)) for path in args.related_handoff
        ]
        known = _parse_key_values(
            args.known_trajectory, "--known-trajectory"
        )
        for trajectory_id, genesis_hash in known.items():
            _validate_typed_id(
                trajectory_id, "trajectory", "--known-trajectory ID"
            )
            _validate_sha256(
                genesis_hash, "--known-trajectory genesis hash"
            )
        bindings = _bindings_from_args(args)
        code, report = verify_document_read_only(
            document,
            expected_type=expected_type,
            expected_previous_head=args.expected_previous_head,
            expected_chain_id=args.expected_chain_id,
            expected_event_index=args.expected_event_index,
            related_roots=related,
            related_acceptances=related_acceptances,
            related_handoffs=related_handoffs,
            known_identities=known,
            bindings=bindings,
            verification_time=args.verification_time,
        )
    except (
        LineageError,
        CanonicalJSONError,
        OSError,
        UnicodeError,
        RecursionError,
        RuntimeError,
    ) as exc:
        code = 2
        report = {
            "protocol": PROTOCOL,
            "operation": "verify",
            "status": "invalid",
            "errors": [str(exc)],
            "semantics": [
                "VERIFY SUCCESS != ACCEPTED",
                "HANDOFF VERIFIED != IMPORTED",
                "TARGET MISSING != HASH MISMATCH",
            ],
        }
    _emit_report(report, as_json=args.json)
    return code


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="read-only echo-lineage/v1 verifier"
    )
    top = parser.add_subparsers(dest="family", required=True)

    lineage = top.add_parser("lineage")
    lineage_commands = lineage.add_subparsers(dest="command", required=True)
    lineage_verify = lineage_commands.add_parser("verify")
    _add_verify_arguments(lineage_verify)

    handoff = top.add_parser("handoff")
    handoff_commands = handoff.add_subparsers(dest="command", required=True)
    handoff_verify = handoff_commands.add_parser("verify")
    _add_verify_arguments(handoff_verify)

    args = parser.parse_args(argv)
    if args.family == "lineage" and args.command == "verify":
        return _run_verify(args, expected_type=None)
    if args.family == "handoff" and args.command == "verify":
        return _run_verify(args, expected_type="handoff")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
