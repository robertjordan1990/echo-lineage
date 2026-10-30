"""Pure bounded 2B-h1-local decisions; no persistence or runtime activation.

History inspection verifies signed historical observations, not current targets.
Whole-store restoration is undetectable without an independently trusted
checkpoint. The owner of the account/keys remains inside the trust boundary.
A satisfied checkpoint proves ancestor inclusion, not that no later state was lost.
"""
from __future__ import annotations

import functools
import re
import secrets
from datetime import datetime, timezone
from uuid import UUID, uuid4

try:
    from .echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from .echo_lineage import (validate_document, verify_document_read_only,
        evaluate_future_decisions, finalize_document, _validate_typed_id)
    from .echo_lineage_auth import (validate_policy, policy_digest,
        verify_acceptance_signature, CryptoUnavailable)
    from .echo_state_store import snapshot_digest
except ImportError:  # direct script imports
    from echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from echo_lineage import (validate_document, verify_document_read_only,
        evaluate_future_decisions, finalize_document, _validate_typed_id)
    from echo_lineage_auth import (validate_policy, policy_digest,
        verify_acceptance_signature, CryptoUnavailable)
    from echo_state_store import snapshot_digest

SCHEMA = "echo-lineage-state/v1"
PROFILE = "2B-h1-local"
REPORT_SCHEMA = "echo-lineage-state-report/v1"
BUNDLE_SCHEMA = "echo-lineage-decision-bundle/v1"
MAX_RECORDS = 1024
MAX_BYTES = 8 * 1024 * 1024
GENESIS_DOMAIN = b"ECHO|STATE|v1|GENESIS|"
EVENT_DOMAIN = b"ECHO|STATE|v1|EVENT|"
STATE_KEYS = {"schema", "profile", "store_id", "root", "root_artifact_id",
    "policy", "generation", "journal_head", "records", "requests",
    "decision_ids", "nonces", "slots", "edges", "active", "integrity_blocked"}
RECORD_KEYS = {"generation", "previous_journal_head", "request_id", "document",
    "report", "applied_at", "event_hash"}
REPORT_KEYS = {"schema", "profile", "verifier_version", "canonicalization",
    "request_id", "store_id", "installation_id", "trajectory_id",
    "genesis_root_document_hash", "root_artifact_id", "root_document_hash", "root_artifact_hash",
    "policy_digest", "pre_state", "verification_time", "root_verification",
    "target_observations"}
BASE_TARGET = {"artifact_id", "criticality", "status", "expected_sha256"}
STATUSES = {"target_present_verified", "ledger_known_target_missing",
    "hash_mismatch", "target_invalid", "verification_not_attempted",
    "target_missing_unanchored"}
ACCEPTING = {"accepted", "accepted_with_reservations"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
REQUEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")


class ModelError(ValueError):
    """Closed, path-free refusal code; the caller's input remains unchanged."""


def _public(function):
    @functools.wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ModelError:
            raise
        except CryptoUnavailable:
            raise ModelError("AUTHENTICATION_UNAVAILABLE") from None
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError,
                RecursionError, OSError):
            raise ModelError("INVALID_MODEL_INPUT") from None
    return checked


def _require(condition, code):
    if not condition:
        raise ModelError(code)


def _closed(value, keys, code):
    _require(isinstance(value, dict) and set(value) == keys, code)


def _copy(value):
    raw = canon_json_bytes(value)
    _require(len(raw) + 1 <= MAX_BYTES, "MODEL_SIZE_LIMIT")
    return loads_json_strict(raw)


def _same(left, right):
    return canon_json_bytes(left) == canon_json_bytes(right)


def _hash(value):
    return sha256_hex(canon_json_bytes(value))


def _hex(value):
    _require(isinstance(value, str) and HEX.fullmatch(value), "INVALID_DIGEST")


def _integer(value):
    _require(type(value) is int and value >= 0, "INVALID_GENERATION")


def _time(value):
    _require(isinstance(value, str) and UTC_TIME.fullmatch(value), "INVALID_UTC_CLAIM")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(parsed.utcoffset().total_seconds() == 0, "INVALID_UTC_CLAIM")


def _request(value):
    _require(isinstance(value, str) and REQUEST.fullmatch(value), "INVALID_REQUEST_ID")


def _uuid(value):
    _require(isinstance(value, str), "INVALID_STORE_ID")
    parsed = UUID(value)
    _require(str(parsed) == value and parsed.version in range(1, 6), "INVALID_STORE_ID")


def _root(root, artifact_id):
    validate_document(root, expected_type="trajectory_root")
    _validate_typed_id(artifact_id, "artifact", "root artifact")
    body = root["body"]
    _require(body["origin_kind"] == "independent_no_lineage_claim"
        and body["signature_policy"] == "optional" and root["proofs"] == []
        and body["lineage_parents"] == []
        and body["genesis_root_document_hash"] is None, "UNSUPPORTED_ROOT_PROFILE")
    source_ids = {s["artifact"]["artifact_id"] for s in body["inheritance_sources"]}
    source_ids.update(s["artifact"]["ledger_ref"]["ledger_artifact_id"]
        for s in body["inheritance_sources"] if "ledger_ref" in s["artifact"])
    _require(artifact_id not in source_ids, "ROOT_ARTIFACT_ID_COLLISION")


def _slot(document):
    r = document["responsibility"]
    return r["chain_id"] + ":" + str(r["event_index"])


def _edge(document):
    r = document["responsibility"]
    return r["chain_id"] + ":" + r["previous_head"]


def _initial(root, policy, artifact_id, store_id):
    _root(root, artifact_id)
    policy = validate_policy(policy)
    _uuid(store_id)
    installation = root["body"]["installation_id"]
    _require(all(k["installation_id"] == installation for k in policy["keys"]),
        "POLICY_INSTALLATION_MISMATCH")
    genesis = {"store_id": store_id, "root": root,
        "root_artifact_id": artifact_id, "policy": policy}
    root_hash = root["document_hash"]["value"]
    return {"schema": SCHEMA, "profile": PROFILE, **genesis,
        "generation": 0, "journal_head": sha256_hex(GENESIS_DOMAIN + canon_json_bytes(genesis)),
        "records": [], "requests": {}, "decision_ids": {}, "nonces": {},
        "slots": {_slot(root): root_hash}, "edges": {_edge(root): root_hash},
        "active": None, "integrity_blocked": False}


@_public
def create_state(root: dict, policy: dict, root_artifact_id: str, *, store_id=None) -> dict:
    """Bind an existing unaccepted root; no target read, signing or persistence."""
    return _copy(_initial(_copy(root), _copy(policy), root_artifact_id,
        str(uuid4()) if store_id is None else store_id))


def _prestate(state):
    return {"store_id": state["store_id"], "generation": state["generation"],
        "journal_head": state["journal_head"], "snapshot_digest": snapshot_digest(state)}


def _identities(state):
    root = state["root"]
    body = root["body"]
    return {"store_id": state["store_id"], "installation_id": body["installation_id"],
        "trajectory_id": body["trajectory_id"],
        "genesis_root_document_hash": root["document_hash"]["value"],
        "root_artifact_id": state["root_artifact_id"],
        "root_document_hash": root["document_hash"]["value"],
        "root_artifact_hash": _hash(root)}


def _expected_targets(state):
    result = [{"artifact_id": state["root_artifact_id"], "criticality": "critical_root",
        "expected_sha256": state["root"]["document_hash"]["value"]}]
    result.extend({"artifact_id": s["artifact"]["artifact_id"],
        "criticality": s["criticality"], "expected_sha256": s["artifact"]["sha256"]}
        for s in state["root"]["body"]["inheritance_sources"])
    return result


def _root_facts(observations, evidence_errors=0):
    statuses = {r["status"] for r in observations}
    if statuses & {"hash_mismatch", "target_invalid"}:
        code, status = 2, "integrity_failure"
    elif evidence_errors or statuses & {"ledger_known_target_missing",
            "verification_not_attempted", "target_missing_unanchored"}:
        code, status = 10, "verified_with_unavailable_targets"
    else:
        code, status = 0, "verified"
    return {"exit_code": code, "status": status, "proof_status": "unsigned",
        "evidence_status": "incomplete" if evidence_errors else "complete",
        "evidence_error_count": evidence_errors}


def _report(state, request_id, verification_time, bindings):
    # The 2A bindings cache is mutable; protect caller-owned bindings as well.
    import copy
    code, raw = verify_document_read_only(state["root"],
        bindings=copy.deepcopy(bindings), verification_time=verification_time)
    _require(raw.get("status") != "invalid" and "target_results" in raw,
        "ROOT_VERIFICATION_INVALID")
    observations = [{**_expected_targets(state)[0], "status": "target_present_verified",
        "observed_sha256": state["root"]["document_hash"]["value"]}]
    observations.extend({k: r[k] for k in BASE_TARGET | {"observed_sha256"} if k in r}
        for r in raw["target_results"])
    facts = {"exit_code": code, "status": raw["status"],
        "proof_status": raw["proof_status"], "evidence_status": raw["evidence_status"],
        "evidence_error_count": len(raw["evidence_errors"])}
    report = {"schema": REPORT_SCHEMA, "profile": PROFILE,
        "verifier_version": "2B-h1-local/1", "canonicalization": "ECHOHASH/v1",
        "request_id": request_id, **_identities(state),
        "policy_digest": policy_digest(state["policy"]), "pre_state": _prestate(state),
        "verification_time": verification_time, "root_verification": facts,
        "target_observations": observations}
    _check_report(state, report, request_id)
    return report


def _check_report(state, report, request_id):
    _closed(report, REPORT_KEYS, "INVALID_REPORT_FIELDS")
    for k, value in {"schema": REPORT_SCHEMA, "profile": PROFILE,
            "verifier_version": "2B-h1-local/1", "canonicalization": "ECHOHASH/v1",
            "request_id": request_id, **_identities(state),
            "policy_digest": policy_digest(state["policy"]),
            "pre_state": _prestate(state)}.items():
        _require(_same(report[k], value), "REPORT_BINDING_MISMATCH")
    _time(report["verification_time"])
    observations = report["target_observations"]
    expected = _expected_targets(state)
    _require(isinstance(observations, list) and len(observations) == len(expected),
        "REPORT_TARGET_COVERAGE_MISMATCH")
    for position, (observation, target) in enumerate(zip(observations, expected)):
        _require(isinstance(observation, dict) and BASE_TARGET <= set(observation)
            <= BASE_TARGET | {"observed_sha256"}, "INVALID_OBSERVATION_FIELDS")
        _require(all(_same(observation[k], v) for k, v in target.items()),
            "REPORT_TARGET_BINDING_MISMATCH")
        status = observation["status"]
        _require(status in STATUSES, "INVALID_TARGET_STATUS")
        if "observed_sha256" in observation:
            _hex(observation["observed_sha256"])
            _require(status in {"target_present_verified", "hash_mismatch", "target_invalid"},
                "UNEXPECTED_OBSERVED_HASH")
        if status in {"target_present_verified", "hash_mismatch"}:
            _require("observed_sha256" in observation, "MISSING_OBSERVED_HASH")
            _require((observation["observed_sha256"] == target["expected_sha256"])
                == (status == "target_present_verified"), "OBSERVED_HASH_STATUS_MISMATCH")
        if position == 0:
            _require(status == "target_present_verified", "ROOT_NOT_VERIFIED")
    facts = report["root_verification"]
    _closed(facts, {"exit_code", "status", "proof_status", "evidence_status",
        "evidence_error_count"}, "INVALID_ROOT_FACTS")
    errors = facts["evidence_error_count"]
    _integer(errors)
    _require(errors <= 1024 and _same(facts, _root_facts(observations, errors)),
        "ROOT_FACTS_MISMATCH")


def _projection(report):
    result = []
    for observed in report["target_observations"]:
        row = {k: observed[k] for k in BASE_TARGET}
        # The existing v1 contract requires this explicit exclusion for even a
        # declined/quarantined noncritical integrity failure.
        if row["criticality"] in {"supporting", "optional"} and row["status"] in {
                "hash_mismatch", "target_invalid"}:
            row["excluded_from_active_inheritance"] = True
        result.append(row)
    return result


def _allowed(report):
    allowed = evaluate_future_decisions(_projection(report))
    if report["root_verification"]["evidence_status"] != "complete":
        allowed = [d for d in allowed if d not in ACCEPTING]
    return allowed


def _authorize(state, actor_id):
    _validate_typed_id(actor_id, "decision-actor", "decision actor")
    _require(any(k["decision_actor_id"] == actor_id for k in state["policy"]["keys"]),
        "ACTOR_NOT_AUTHORIZED")


def _responsibility(state):
    previous = state["records"][-1]["document"] if state["records"] else state["root"]
    return {"chain_id": state["root"]["responsibility"]["chain_id"],
        "event_index": state["generation"] + 1, "previous_head": previous["resulting_head"]}


def _reservations(report, decision):
    return [{"artifact_id": r["artifact_id"], "code": r["status"]}
        for r in report["target_observations"] if r["status"] != "target_present_verified"] \
        if decision == "accepted_with_reservations" else []


def _body(state, report, decision, actor_id, operator_id, acceptance_id, nonce):
    identities = _identities(state)
    result = {"acceptance_id": acceptance_id,
        "trajectory_id": identities["trajectory_id"],
        "genesis_root_document_hash": identities["genesis_root_document_hash"],
        "installation_id": identities["installation_id"],
        "subject": {"trajectory_root_artifact_id": state["root_artifact_id"],
            "trajectory_root_document_hash": identities["root_document_hash"]},
        "decision": decision,
        "decision_actor": {"decision_actor_id": actor_id, "decision_mode": "human_operator"},
        "recording_operator": {"operator_actor_id": operator_id, "role": "recording_operator",
            "confirmed_at": report["verification_time"],
            "confirmation_scope": "recorded_decision_without_reassignment"},
        "verification_report_hash": _hash(report), "target_results": _projection(report),
        "reservations": _reservations(report, decision), "decision_nonce": nonce,
        "decided_at": report["verification_time"],
        "effect": "activating" if decision in ACCEPTING else "non_activating"}
    if state["records"]:
        result["previous_acceptance_hash"] = state["records"][-1]["document"]["document_hash"]["value"]
    return result


def _bundle_shape(bundle):
    _closed(bundle, {"schema", "request_id", "report", "document"}, "INVALID_BUNDLE_FIELDS")
    _require(bundle["schema"] == BUNDLE_SCHEMA, "INVALID_BUNDLE_SCHEMA")
    _request(bundle["request_id"])


def _check_bundle(state, bundle, *, unsigned=False):
    _bundle_shape(bundle)
    report, document = bundle["report"], bundle["document"]
    _check_report(state, report, bundle["request_id"])
    validate_document(document, expected_type="lineage_acceptance",
        expected_chain_id=state["root"]["responsibility"]["chain_id"],
        expected_event_index=state["generation"] + 1,
        expected_previous_head=_responsibility(state)["previous_head"])
    body = document["body"]
    actor_id = body["decision_actor"]["decision_actor_id"]
    operator_id = body["recording_operator"]["operator_actor_id"]
    _authorize(state, actor_id)
    _require(operator_id == actor_id, "DISTINCT_OPERATOR_REQUIRES_DELEGATION")
    _require(body["decision"] in _allowed(report), "DECISION_NOT_PERMITTED")
    expected = _body(state, report, body["decision"], actor_id, operator_id,
        body["acceptance_id"], body["decision_nonce"])
    _require(_same(body, expected), "DECISION_REPORT_BINDING_MISMATCH")
    _require(_same(document["responsibility"], _responsibility(state)), "RESPONSIBILITY_MISMATCH")
    if unsigned:
        _require(document["proofs"] == [], "CANDIDATE_ALREADY_SIGNED")
    else:
        verify_acceptance_signature(document, state["policy"])
    _require(bundle["request_id"] not in state["requests"], "REQUEST_CONFLICT")
    for index, key in (("decision_ids", body["acceptance_id"]), ("nonces", body["decision_nonce"]),
            ("slots", _slot(document)), ("edges", _edge(document))):
        _require(key not in state[index], "DECISION_REPLAY_CONFLICT")


def _event_hash(record):
    return sha256_hex(EVENT_DOMAIN + canon_json_bytes(
        {k: v for k, v in record.items() if k != "event_hash"}))


def _append(state, record):
    document = record["document"]
    body = document["body"]
    digest = document["document_hash"]["value"]
    bundle = {"schema": BUNDLE_SCHEMA, "request_id": record["request_id"],
        "report": record["report"], "document": document}
    state["records"].append(record)
    state["generation"] = record["generation"]
    state["journal_head"] = record["event_hash"]
    state["requests"][record["request_id"]] = {"generation": record["generation"],
        "bundle_digest": _hash(bundle)}
    for index, key in (("decision_ids", body["acceptance_id"]), ("nonces", body["decision_nonce"]),
            ("slots", _slot(document)), ("edges", _edge(document))):
        state[index][key] = digest
    if body["decision"] in ACCEPTING:
        state["active"] = {"acceptance_id": body["acceptance_id"], "document_hash": digest,
            "generation": record["generation"], "decision": body["decision"],
            "accepted_artifact_ids": [r["artifact_id"] for r in body["target_results"]
                if r["status"] == "target_present_verified"]}
        # This transition was permitted by the signed report's target matrix.
        # A reserved noncritical failure is excluded from the replacement scope.
        state["integrity_blocked"] = False
    elif (body["decision"] == "quarantined_integrity_failure"
            or record["report"]["root_verification"]["status"] == "integrity_failure"):
        state["integrity_blocked"] = True
    # Declining a now-valid root does not revoke a historical acceptance and
    # does not undo an earlier integrity block. Only a new accepting decision can.


def _replay(state):
    _closed(state, STATE_KEYS, "INVALID_STATE_FIELDS")
    _require(state["schema"] == SCHEMA and state["profile"] == PROFILE, "UNSUPPORTED_STATE_PROFILE")
    _integer(state["generation"])
    _require(type(state["integrity_blocked"]) is bool, "INVALID_INTEGRITY_BLOCK")
    _hex(state["journal_head"])
    records = state["records"]
    _require(isinstance(records, list) and len(records) <= MAX_RECORDS, "RECORD_LIMIT")
    replay = _initial(state["root"], state["policy"], state["root_artifact_id"], state["store_id"])
    genesis_head = replay["journal_head"]
    for record in records:
        _closed(record, RECORD_KEYS, "INVALID_RECORD_FIELDS")
        _integer(record["generation"])
        _require(record["generation"] == replay["generation"] + 1, "RECORD_GENERATION_MISMATCH")
        _require(record["previous_journal_head"] == replay["journal_head"], "BROKEN_JOURNAL_CHAIN")
        _time(record["applied_at"])
        _hex(record["event_hash"])
        _require(record["event_hash"] == _event_hash(record), "RECORD_HASH_MISMATCH")
        bundle = {"schema": BUNDLE_SCHEMA, "request_id": record["request_id"],
            "report": record["report"], "document": record["document"]}
        _check_bundle(replay, bundle)
        _append(replay, record)
    _require(_same(replay, state), "SNAPSHOT_REPLAY_MISMATCH")
    return replay, genesis_head


def _checkpoint(state, genesis_head, checkpoint):
    if checkpoint is None:
        return None
    _closed(checkpoint, {"store_id", "generation", "journal_head"}, "INVALID_CHECKPOINT_FIELDS")
    _integer(checkpoint["generation"])
    _hex(checkpoint["journal_head"])
    n = checkpoint["generation"]
    _require(checkpoint["store_id"] == state["store_id"] and n <= state["generation"],
        "CHECKPOINT_NOT_IN_HISTORY")
    head = genesis_head if n == 0 else state["records"][n - 1]["event_hash"]
    _require(checkpoint["journal_head"] == head, "CHECKPOINT_NOT_IN_HISTORY")
    return True


@_public
def inspect_state(state, checkpoint=None) -> dict:
    """Replay signatures/metadata, with no reads of historical external targets."""
    state, genesis = _replay(_copy(state))
    checked = _checkpoint(state, genesis, checkpoint)
    latest = state["records"][-1] if state["records"] else None
    return {"schema": "echo-lineage-state-status/v1", "profile": PROFILE,
        "store_id": state["store_id"], "generation": state["generation"],
        "journal_head": state["journal_head"], "snapshot_digest": snapshot_digest(state),
        "local_chain_valid": True, "external_checkpoint_satisfied": checked,
        "rollback_protection": "checkpoint_ancestor_checked" if checked else "not_externally_anchored",
        "latest_decision": None if latest is None else {"generation": latest["generation"],
            "request_id": latest["request_id"], "decision": latest["document"]["body"]["decision"],
            "acceptance_id": latest["document"]["body"]["acceptance_id"]},
        "active": _copy(state["active"]), "active_is_historical": True,
        "integrity_blocked": state["integrity_blocked"],
        "local_acceptance_active": state["active"] is not None and not state["integrity_blocked"],
        "bootstrap_status": "UNACCEPTED" if latest is None else "DECISIONS_RECORDED",
        "root_author_authenticated": False, "runtime_activation": False,
        "actor_authentication": "scoped_key_holder_not_biological_or_model_identity",
        "current_targets_rechecked": False}


@_public
def prepare_decision(state, *, decision, actor_id, operator_id, request_id,
                     verification_time, bindings=None, expected_state_digest) -> dict:
    state, _ = _replay(_copy(state))
    _require(len(state["records"]) < MAX_RECORDS, "RECORD_LIMIT")
    _hex(expected_state_digest)
    _require(snapshot_digest(state) == expected_state_digest, "STALE_STATE")
    _request(request_id)
    _require(request_id not in state["requests"], "REQUEST_ALREADY_RECORDED")
    _time(verification_time)
    _authorize(state, actor_id)
    _validate_typed_id(operator_id, "decision-actor", "recording operator")
    _require(operator_id == actor_id, "DISTINCT_OPERATOR_REQUIRES_DELEGATION")
    report = _report(state, request_id, verification_time, bindings)
    _require(decision in _allowed(report), "DECISION_NOT_PERMITTED")
    document = finalize_document({"protocol": "echo-lineage/v1", "document_type": "lineage_acceptance",
        "body": _body(state, report, decision, actor_id, operator_id,
            "urn:echo:acceptance:" + str(uuid4()), secrets.token_hex(16)),
        "responsibility": _responsibility(state), "proofs": []})
    validate_document(document, expected_type="lineage_acceptance")
    return _copy({"schema": BUNDLE_SCHEMA, "request_id": request_id,
        "report": report, "document": document})


@_public
def validate_candidate(state, bundle: dict) -> dict:
    """Check an unsigned candidate against current state before accessing a key.

    This checks signed-report bindings and the historical pre-state. External
    targets are rechecked by apply, not authenticated by this signing step.
    """
    state, _ = _replay(_copy(state))
    bundle = _copy(bundle)
    _check_bundle(state, bundle, unsigned=True)
    return bundle


def _result(state, record, idempotent):
    return {"status": "already_recorded" if idempotent else "applied_in_memory",
        "idempotent": idempotent, "request_id": record["request_id"],
        "generation": state["generation"], "journal_head": state["journal_head"],
        "snapshot_digest": snapshot_digest(state), "record_generation": record["generation"],
        "event_hash": record["event_hash"], "decision": record["document"]["body"]["decision"],
        "integrity_blocked": state["integrity_blocked"],
        "local_acceptance_active": state["active"] is not None and not state["integrity_blocked"],
        "runtime_activation": False, "current_targets_rechecked": not idempotent}


@_public
def apply_decision(state, bundle: dict, *, bindings=None, expected_state_digest,
                   applied_at=None) -> tuple[dict, dict]:
    state, _ = _replay(_copy(state))
    bundle = _copy(bundle)
    _bundle_shape(bundle)
    request_id = bundle["request_id"]
    if request_id in state["requests"]:
        previous = state["requests"][request_id]
        _require(_hash(bundle) == previous["bundle_digest"], "REQUEST_CONFLICT")
        record = state["records"][previous["generation"] - 1]
        return state, _result(state, record, True)
    _require(len(state["records"]) < MAX_RECORDS, "RECORD_LIMIT")
    _hex(expected_state_digest)
    _require(snapshot_digest(state) == expected_state_digest, "STALE_STATE")
    _check_bundle(state, bundle)
    fresh = _report(state, request_id, bundle["report"]["verification_time"], bindings)
    _require(_same(fresh, bundle["report"]), "FRESH_REPORT_MISMATCH")
    stamp = applied_at if applied_at is not None else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    _time(stamp)
    record = {"generation": state["generation"] + 1,
        "previous_journal_head": state["journal_head"], "request_id": request_id,
        "document": bundle["document"], "report": bundle["report"], "applied_at": stamp}
    record["event_hash"] = _event_hash(record)
    _append(state, record)
    state = _copy(state)  # Refuse a snapshot exceeding the store's byte limit.
    return state, _result(state, record, False)
