from __future__ import annotations

from typing import Any

from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
from tools.tools.echo_lineage import ZERO_HASH, finalize_document


def eid(kind: str, number: int) -> str:
    return (
        f"urn:echo:{kind}:"
        f"00000000-0000-4000-8000-{number:012d}"
    )


def digest(character: str) -> str:
    return character * 64


def artifact(
    number: int,
    *,
    sha256: str | None = None,
    ledger_sha256: str | None = None,
    hash_scope: str = "file_bytes",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "artifact_id": eid("artifact", number),
        "sha256": sha256 or digest("a"),
        "hash_scope": hash_scope,
        "media_type": "application/octet-stream",
    }
    if ledger_sha256 is not None:
        result["ledger_ref"] = {
            "ledger_artifact_id": eid("artifact", number + 500),
            "ledger_sha256": ledger_sha256,
        }
    return result


def source(
    number: int,
    *,
    role: str = "memory",
    criticality: str = "required_source",
    sha256: str | None = None,
    ledger_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "source_role": role,
        "artifact": artifact(
            number,
            sha256=sha256,
            ledger_sha256=ledger_sha256,
        ),
        "criticality": criticality,
        "required_for_acceptance": criticality
        in {"critical_root", "required_source"},
    }


def parent(
    relation: str,
    root: dict[str, Any],
    *,
    installation_id: str | None = None,
    handoff: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = root["body"]
    genesis = body["genesis_root_document_hash"]
    if genesis is None:
        genesis = root["document_hash"]["value"]
    return {
        "relation": relation,
        "parent_trajectory_id": body["trajectory_id"],
        "parent_genesis_root_document_hash": genesis,
        "parent_installation_id": installation_id or body["installation_id"],
        "handoff_document_hash": (
            handoff["document_hash"]["value"] if handoff else digest("b")
        ),
        "parent_responsibility_head": (
            handoff["resulting_head"] if handoff else root["resulting_head"]
        ),
    }


def canonical_artifact_hash(document: dict[str, Any]) -> str:
    return sha256_hex(canon_json_bytes(document))


def root_document(
    number: int = 1,
    *,
    trajectory_number: int | None = None,
    origin: str = "independent_no_lineage_claim",
    parents: list[dict[str, Any]] | None = None,
    sources: list[dict[str, Any]] | None = None,
    genesis_hash: str | None = None,
    previous_head: str = ZERO_HASH,
    event_index: int = 0,
) -> dict[str, Any]:
    raw = {
        "protocol": "echo-lineage/v1",
        "document_type": "trajectory_root",
        "body": {
            "trajectory_id": eid("trajectory", trajectory_number or number),
            "genesis_root_document_hash": genesis_hash,
            "installation_id": eid("installation", number),
            "created_by_runtime_session_id": eid("runtime-session", number),
            "origin_kind": origin,
            "lineage_parents": parents or [],
            "inheritance_sources": sources or [],
            "fork_policy": "explicit_only",
            "acceptance_required": True,
            "signature_policy": "optional",
            "created_at": "2032-01-02T03:04:05Z",
        },
        "responsibility": {
            "chain_id": eid("responsibility-chain", number),
            "event_index": event_index,
            "previous_head": previous_head,
        },
        "proofs": [],
    }
    return finalize_document(raw)


def continuation(parent_root: dict[str, Any], number: int = 2) -> dict[str, Any]:
    trajectory_id = parent_root["body"]["trajectory_id"]
    trajectory_number = int(trajectory_id.rsplit("-", 1)[1])
    genesis = parent_root["body"]["genesis_root_document_hash"]
    if genesis is None:
        genesis = parent_root["document_hash"]["value"]
    return root_document(
        number,
        trajectory_number=trajectory_number,
        origin="continuation",
        parents=[parent("predecessor", parent_root)],
        genesis_hash=genesis,
    )


def acceptance_document(
    *,
    decision_mode: str = "human_operator",
    include_evidence: bool = False,
    target_results: list[dict[str, Any]] | None = None,
    decision: str = "accepted",
    reservations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    actor: dict[str, Any] = {
        "decision_actor_id": eid("decision-actor", 1),
        "decision_mode": decision_mode,
    }
    if decision_mode in {"model_session", "joint_human_model"}:
        actor["runtime_session_id"] = eid("runtime-session", 9)
    if decision_mode == "joint_human_model":
        actor["human_actor_id"] = eid("decision-actor", 2)
    if include_evidence:
        actor["decision_evidence_ref"] = artifact(90)
    results = target_results
    if results is None:
        results = [
            {
                "artifact_id": eid("artifact", 1),
                "criticality": "critical_root",
                "status": "target_present_verified",
                "expected_sha256": digest("c"),
            }
        ]
    raw = {
        "protocol": "echo-lineage/v1",
        "document_type": "lineage_acceptance",
        "body": {
            "acceptance_id": eid("acceptance", 1),
            "trajectory_id": eid("trajectory", 1),
            "genesis_root_document_hash": digest("c"),
            "installation_id": eid("installation", 1),
            "subject": {
                "trajectory_root_artifact_id": eid("artifact", 1),
                "trajectory_root_document_hash": digest("c"),
            },
            "decision": decision,
            "decision_actor": actor,
            "recording_operator": {
                "operator_actor_id": eid("decision-actor", 3),
                "role": "recording_operator",
                "confirmed_at": "2032-01-02T03:04:06Z",
                "confirmation_scope": "recorded_decision_without_reassignment",
            },
            "verification_report_hash": digest("d"),
            "target_results": results,
            "reservations": reservations or [],
            "decision_nonce": "12" * 16,
            "decided_at": "2032-01-02T03:04:06Z",
            "effect": (
                "activating"
                if decision in {"accepted", "accepted_with_reservations"}
                else "non_activating"
            ),
        },
        "responsibility": {
            "chain_id": eid("responsibility-chain", 1),
            "event_index": 1,
            "previous_head": digest("e"),
        },
        "proofs": [],
    }
    return finalize_document(raw)


def acceptance_for_root(
    root: dict[str, Any],
    *,
    number: int = 1,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    document = acceptance_document()
    body = document["body"]
    root_body = root["body"]
    genesis_hash = root_body["genesis_root_document_hash"]
    if genesis_hash is None:
        genesis_hash = root["document_hash"]["value"]
    body["acceptance_id"] = eid("acceptance", number)
    body["decision_nonce"] = f"{number:032x}"
    body["trajectory_id"] = root_body["trajectory_id"]
    body["genesis_root_document_hash"] = genesis_hash
    body["installation_id"] = root_body["installation_id"]
    body["subject"]["trajectory_root_document_hash"] = root[
        "document_hash"
    ]["value"]
    body["subject"]["trajectory_root_artifact_id"] = eid(
        "artifact", 1000 + number
    )
    body["target_results"] = [
        {
            "artifact_id": body["subject"]["trajectory_root_artifact_id"],
            "criticality": "critical_root",
            "status": "target_present_verified",
            "expected_sha256": root["document_hash"]["value"],
        }
    ]
    body["target_results"].extend(
        {
            "artifact_id": inherited["artifact"]["artifact_id"],
            "criticality": inherited["criticality"],
            "status": "target_present_verified",
            "expected_sha256": inherited["artifact"]["sha256"],
        }
        for inherited in root_body["inheritance_sources"]
    )
    responsibility = document["responsibility"]
    responsibility["chain_id"] = root["responsibility"]["chain_id"]
    if previous is None:
        body.pop("previous_acceptance_hash", None)
        responsibility["event_index"] = root["responsibility"]["event_index"] + 1
        responsibility["previous_head"] = root["resulting_head"]
    else:
        body["previous_acceptance_hash"] = previous["document_hash"]["value"]
        responsibility["event_index"] = (
            previous["responsibility"]["event_index"] + 1
        )
        responsibility["previous_head"] = previous["resulting_head"]
    return finalize_document(document)


def handoff_document(*, bound: bool = True) -> dict[str, Any]:
    body: dict[str, Any] = {
        "handoff_id": eid("handoff", 1),
        "trajectory_id": eid("trajectory", 1),
        "genesis_root_document_hash": digest("c"),
        "issuer_installation_id": eid("installation", 1),
        "issuer_runtime_session_id": eid("runtime-session", 1),
        "recipient_binding": {
            "mode": "bound" if bound else "unbound",
            "recipient_installation_id": (
                eid("installation", 2) if bound else None
            ),
        },
        "recording_operator_id": eid("decision-actor", 3),
        "sequence": 1,
        "handoff_nonce": "34" * 16,
        "issued_at": "2032-01-02T03:04:07Z",
        "lineage_root_ref": artifact(
            10, sha256=digest("c"), hash_scope="canonical_document"
        ),
        "latest_acceptance_ref": artifact(
            11, sha256=digest("d"), hash_scope="canonical_document"
        ),
        "previous_handoff_hash": digest("e"),
        "lineage_parents": [],
        "inheritance_sources": [source(12, role="memory")],
        "memory_heads": [artifact(13, sha256=digest("f"))],
        "ht_heads": [
            {
                "log_id": eid("log", 1),
                "t": 7,
                "msg_sha256": digest("1"),
            }
        ],
        "fork_intent": "none",
        "constraints": [
            "manual_acceptance_required",
            "verify_before_use",
            "no_public_commitment",
        ],
    }
    if not bound:
        body["expires_at"] = "2032-01-03T03:04:07Z"
    return finalize_document(
        {
            "protocol": "echo-lineage/v1",
            "document_type": "handoff",
            "body": body,
            "responsibility": {
                "chain_id": eid("responsibility-chain", 1),
                "event_index": 2,
                "previous_head": digest("2"),
            },
            "proofs": [],
        }
    )


def handoff_for_root(
    root: dict[str, Any],
    acceptance: dict[str, Any],
    *,
    recipient_installation_id: str,
    number: int = 1,
    fork_intent: str = "none",
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    document = handoff_document(bound=True)
    body = document["body"]
    root_body = root["body"]
    genesis_hash = root_body["genesis_root_document_hash"]
    if genesis_hash is None:
        genesis_hash = root["document_hash"]["value"]
    body["handoff_id"] = eid("handoff", number)
    body["handoff_nonce"] = f"{number:032x}"
    body["trajectory_id"] = root_body["trajectory_id"]
    body["genesis_root_document_hash"] = genesis_hash
    body["issuer_installation_id"] = root_body["installation_id"]
    body["recipient_binding"]["recipient_installation_id"] = (
        recipient_installation_id
    )
    body["lineage_root_ref"]["sha256"] = canonical_artifact_hash(root)
    body["latest_acceptance_ref"]["sha256"] = canonical_artifact_hash(
        acceptance
    )
    body["lineage_parents"] = root_body["lineage_parents"]
    body["inheritance_sources"] = root_body["inheritance_sources"]
    body["fork_intent"] = fork_intent
    responsibility = document["responsibility"]
    responsibility["chain_id"] = root["responsibility"]["chain_id"]
    if previous is None:
        body["sequence"] = 0
        body["previous_handoff_hash"] = ZERO_HASH
        responsibility["event_index"] = (
            acceptance["responsibility"]["event_index"] + 1
        )
        responsibility["previous_head"] = acceptance["resulting_head"]
    else:
        body["sequence"] = previous["body"]["sequence"] + 1
        body["previous_handoff_hash"] = previous["document_hash"]["value"]
        responsibility["event_index"] = (
            previous["responsibility"]["event_index"] + 1
        )
        responsibility["previous_head"] = previous["resulting_head"]
    return finalize_document(document)
