"""Pure 2C-h1-bound lifecycle. No persistence, networking or text execution.

The journal is the authority: projections are regenerated from verified signed
operations. Timestamps are signed local claims, and a loaded receipt is historical
access evidence, never a current process-liveness claim. Public operation inputs
are closed and documented by OPERATION_FIELDS below. All functions detach inputs.
"""
from __future__ import annotations

import base64
import functools
import re
import secrets
from datetime import datetime, timezone
from uuid import UUID, uuid4, uuid5

try:
    from .echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from .echo_lineage import (finalize_document, validate_document,
        evaluate_future_decisions, validate_root_graph, _validate_typed_id, ZERO_HASH,
        _validate_handoff_evidence, _validate_acceptance_evidence)
    from .echo_ledger import parse_ledger_line, normalize_relative_path, LINE_SEPARATORS
    from . import echo_lineage_auth as legacy_auth
    from . import echo_state_model as legacy_model
    from .echo_state_store import snapshot_digest
    from . import echo_transfer_auth as auth
except ImportError:
    from echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from echo_lineage import (finalize_document, validate_document,
        evaluate_future_decisions, validate_root_graph, _validate_typed_id, ZERO_HASH,
        _validate_handoff_evidence, _validate_acceptance_evidence)
    from echo_ledger import parse_ledger_line, normalize_relative_path, LINE_SEPARATORS
    import echo_lineage_auth as legacy_auth
    import echo_state_model as legacy_model
    from echo_state_store import snapshot_digest
    import echo_transfer_auth as auth

SCHEMA = "echo-lineage-transfer-state/v1"
PROFILE = "2C-h1-bound"
CANDIDATE_SCHEMA = "echo-lineage-transfer-candidate/v1"
ACTION_SCHEMA = "echo-lineage-transfer-action/v1"
ENVELOPE_SCHEMA = "echo-lineage-transfer-envelope/v1"
RECEIPT_SCHEMA = "echo-lineage-transfer-receipt/v1"
MAX_BYTES = 8 * 1024 * 1024
MAX_ENVELOPE = 4 * 1024 * 1024
MAX_PROOF = MAX_PAYLOAD = 1024 * 1024
MAX_RECORDS = 64
# Reserve room for the remaining bounded control journal before epoch ownership.
METADATA_RESERVE = 512 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32,128}\Z")
REQUEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")
ACCEPTING = {"accepted", "accepted_with_reservations"}
DECISIONS = ACCEPTING | {"declined", "quarantined_integrity_failure"}
OPERATION_FIELDS = {
    "issue": {"producer_runtime_session_id", "expires_at"},
    "export_authorize": set(),
    "export_confirm": {"envelope_digest", "raw_sha256", "byte_length"},
    "receive": {"envelope", "recipient_runtime_session_id"},
    "decide": {"decision"}, "import": {"artifact_ids"},
    "activate": {"activation_id", "artifact_ids", "probe"},
    "activation_start": {"activation_id", "instance_id", "launch_nonce", "code_digest"},
    "activation_loaded": {"activation_id", "instance_id", "receipt"},
    "deactivate": {"activation_id"}, "receipt_ingest": {"receipt"},
}
PURPOSES = {"migrate": "state_migration", "issue": "handoff_issue",
    "export_authorize": "transfer_export", "export_confirm": "transfer_export",
    "receive": "transfer_receive", "decide": "receiver_decision",
    "import": "context_import_authorize", "activate": "context_activation_authorize",
    "activation_start": "context_consumption_receipt",
    "activation_loaded": "context_consumption_receipt", "deactivate": "context_deactivate",
    "receipt_ingest": "remote_receipt_ingest"}
STATE_FIELDS = {"schema", "profile", "role", "store_id", "policy", "initial",
    "generation", "journal_head", "records", "requests", "nonces", "projections"}
BODY_FIELDS = {"schema", "operation", "transfer_id", "request_id", "action_id", "nonce",
    "policy_digest", "actor_id", "installation_id", "role", "verification_time",
    "pre_state", "inputs", "report", "document"}
RECORD_FIELDS = {"generation", "previous_journal_head", "packet", "applied_at", "event_hash"}


class TransferError(ValueError):
    """Closed path-free lifecycle refusal code."""


def _public(fn):
    @functools.wraps(fn)
    def checked(*args, **kw):
        try:
            return fn(*args, **kw)
        except TransferError:
            raise
        except legacy_auth.CryptoUnavailable:
            raise TransferError("AUTHENTICATION_UNAVAILABLE") from None
        except (auth.TransferAuthError, legacy_model.ModelError) as exc:
            # Preserve this one closed capability result only from the trusted
            # verifier exception types; unrelated error strings confer nothing.
            code = "AUTHENTICATION_UNAVAILABLE" if exc.args == ("AUTHENTICATION_UNAVAILABLE",) else "INVALID_TRANSFER_INPUT"
            raise TransferError(code) from None
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError,
                RecursionError, OSError, UnicodeError):
            raise TransferError("INVALID_TRANSFER_INPUT") from None
    return checked


def _require(condition, code):
    if not condition:
        raise TransferError(code)


def _closed(value, fields, code="INVALID_INPUT_FIELDS"):
    _require(isinstance(value, dict) and set(value) == fields, code)


def _depth(value, n=0):
    _require(n <= 64, "PROFILE_SIZE_LIMIT")
    if isinstance(value, dict):
        for v in value.values():
            _depth(v, n + 1)
    elif isinstance(value, list):
        for v in value:
            _depth(v, n + 1)


def _copy(value, limit=MAX_BYTES):
    _depth(value)
    raw = canon_json_bytes(value)
    _require(len(raw) + 1 <= limit, "PROFILE_SIZE_LIMIT")
    return loads_json_strict(raw)


def _same(a, b):
    return canon_json_bytes(a) == canon_json_bytes(b)


def _hash(value):
    return sha256_hex(canon_json_bytes(value))


def _hex(value):
    _require(isinstance(value, str) and HEX.fullmatch(value), "INVALID_DIGEST")


def _uuid(value):
    _require(isinstance(value, str) and str(UUID(value)) == value
        and UUID(value).version in range(1, 6), "INVALID_UUID")


def _id(value, kind):
    _validate_typed_id(value, kind, "identity")


def _typed(kind, transfer_id, label):
    return "urn:echo:" + kind + ":" + str(uuid5(UUID(transfer_id.rsplit(":", 1)[1]), label))


def _time(value):
    _require(isinstance(value, str) and UTC.fullmatch(value), "INVALID_UTC_CLAIM")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(stamp.utcoffset().total_seconds() == 0, "INVALID_UTC_CLAIM")
    return stamp


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _request(value):
    _require(isinstance(value, str) and REQUEST.fullmatch(value), "INVALID_REQUEST_ID")


def _b64(value):
    _require(isinstance(value, str) and len(value) <= 4 * ((MAX_PAYLOAD + 2) // 3),
        "PROFILE_SIZE_LIMIT")
    raw = base64.b64decode(value, validate=True)
    _require(base64.b64encode(raw).decode() == value, "INVALID_BASE64")
    return raw


def _policy(policy, expected=None):
    policy = auth.validate_policy(_copy(policy))
    if expected is not None:
        _hex(expected)
        _require(auth.policy_digest(policy) == expected, "POLICY_PIN_MISMATCH")
    _require(policy["source_pin"]["installation_id"] != policy["recipient"]["installation_id"]
        and policy["source_pin"]["store_id"] != policy["recipient"]["store_id"],
        "RECIPIENT_NOT_INDEPENDENT")
    return policy


def _prestate(state):
    return {"store_id": state["store_id"], "generation": state["generation"],
        "journal_head": state["journal_head"], "snapshot_digest": snapshot_digest(state)}


def _authorize(policy, actor, installation, role, purpose):
    _id(actor, "artifact" if role == "local_context_consumer" else "decision-actor")
    _require(any(k["actor_id"] == actor and k["installation_id"] == installation
        and k["role"] == role and purpose in k["purposes"] for k in policy["keys"]),
        "ACTOR_NOT_AUTHORIZED")


def _source_parts(state):
    inputs = state["initial"]["migration"]["payload"]["inputs"]
    return inputs["legacy_state"], inputs["artifacts"]


def _legacy(legacy, policy):
    _copy(legacy, MAX_PROOF)
    status = legacy_model.inspect_state(legacy)
    pin = policy["source_pin"]
    _require(snapshot_digest(legacy) == pin["snapshot_digest"]
        and legacy["store_id"] == pin["store_id"]
        and legacy["root"]["body"]["installation_id"] == pin["installation_id"],
        "SOURCE_PIN_MISMATCH")
    _require(legacy_auth.policy_digest(legacy["policy"]) == pin["acceptance_policy_digest"],
        "SOURCE_ACCEPTANCE_POLICY_PIN_MISMATCH")
    _require(legacy["records"] and not status["integrity_blocked"]
        and status["local_acceptance_active"], "SOURCE_NOT_ACTIVE")
    latest = legacy["records"][-1]
    active = legacy["active"]
    _require(latest["document"]["body"]["decision"] in ACCEPTING
        and latest["document"]["body"]["effect"] == "activating"
        and active["document_hash"] == latest["document"]["document_hash"]["value"],
        "SOURCE_LATEST_NOT_ACTIVE_ACCEPTANCE")
    return latest


def _capture(legacy, artifacts):
    """Recompute byte observations. Missing facts require the signed ledger pin."""
    _require(isinstance(artifacts, list) and len(artifacts) <= 16, "PROFILE_SIZE_LIMIT")
    expected = {s["artifact"]["artifact_id"]: s for s in legacy["root"]["body"]["inheritance_sources"]}
    _require(len(expected) == len(artifacts), "ARTIFACT_COVERAGE_MISMATCH")
    latest = legacy["records"][-1]
    observations = {r["artifact_id"]: r for r in latest["report"]["target_observations"]}
    seen, total, facts = set(), 0, []
    for item in artifacts:
        _require(isinstance(item, dict) and item.get("artifact_id") in expected
            and item["artifact_id"] not in seen, "ARTIFACT_COVERAGE_MISMATCH")
        aid = item["artifact_id"]
        seen.add(aid)
        src, ref = expected[aid], expected[aid]["artifact"]
        _require(ref["hash_scope"] in {"file_bytes", "canonical_document"}, "UNSUPPORTED_HASH_SCOPE")
        row = {"artifact_id": aid, "criticality": src["criticality"],
            "expected_sha256": ref["sha256"], "hash_scope": ref["hash_scope"]}
        if item.get("status") == "present":
            _closed(item, {"artifact_id", "status", "data_b64"})
            data = _b64(item["data_b64"])
            total += len(data)
            observed = sha256_hex(data) if ref["hash_scope"] == "file_bytes" else _hash(loads_json_strict(data))
            _require(observed == ref["sha256"], "CAPTURE_HASH_MISMATCH")
            row.update(status="target_present_verified", raw_sha256=sha256_hex(data), byte_length=len(data))
        elif item.get("status") == "missing":
            _closed(item, {"artifact_id", "status", "ledger_b64", "ledger_entry"})
            _require("ledger_ref" in ref and observations[aid]["status"] == "ledger_known_target_missing",
                "MISSING_FACT_NOT_LEDGER_BOUND")
            ledger = _b64(item["ledger_b64"])
            total += len(ledger)
            _require(sha256_hex(ledger) == ref["ledger_ref"]["ledger_sha256"], "LEDGER_HASH_MISMATCH")
            name = normalize_relative_path(item["ledger_entry"]).as_posix()
            ledger_text = ledger.decode("utf-8")
            _require(not any(c in ledger_text for c in LINE_SEPARATORS - {"\n"}), "INVALID_LEDGER_ENTRY")
            entries = {}
            for number, line in enumerate(ledger_text.split("\n"), 1):
                parsed = parse_ledger_line(line, number)
                if parsed is None:
                    continue
                wanted, raw_name = parsed
                relative = normalize_relative_path(raw_name).as_posix()
                _require(relative not in entries, "DUPLICATE_LEDGER_ENTRY")
                entries[relative] = wanted.lower()
            _require(entries.get(name) == ref["sha256"], "LEDGER_MEMBERSHIP_MISMATCH")
            row.update(status="ledger_known_target_missing", raw_sha256=None, byte_length=0)
        elif item.get("status") == "excluded":
            _closed(item, {"artifact_id", "status"})
            obs = observations[aid]
            _require(src["criticality"] in {"supporting", "optional"}
                and obs["status"] in {"hash_mismatch", "target_invalid"}, "EXCLUSION_NOT_AUTHORIZED")
            row.update(status=obs["status"], raw_sha256=None, byte_length=0,
                excluded_from_active_inheritance=True)
        else:
            raise TransferError("INVALID_ARTIFACT_STATUS")
        facts.append(row)
    _require(total <= MAX_PAYLOAD, "PROFILE_SIZE_LIMIT")
    return facts


def _migration_report(legacy, policy, artifacts):
    latest = _legacy(legacy, policy)
    facts = _capture(legacy, artifacts)
    # Capacity belongs to the complete lifecycle, before source ownership or
    # issuance. The source prefix holds L + A + 2P: preserved legacy, captured
    # bytes, and policy in both the migration packet and state. Issue/export add
    # one root-sized inheritance description; the signed receive report adds a
    # second continuation description. Reserve another A conservatively and
    # 512 KiB for fixed wire metadata, signatures and predecessor overhead.
    # P is measured whole, including both bounded 256-key lists (the closed
    # policy is below 256 KiB). R is bounded by the 1 MiB legacy proof limit.
    # After receive, each closed control record is below 32 KiB at <=16 targets
    # and a <=256-character probe. Even reserving 64 such records (2 MiB), plus
    # the receiver's extra P and R projections, remains below the 8 MiB store
    # limit. The stricter 4 MiB bound here covers the signed receive payload.
    # Legal maxima in individual dimensions need not be jointly admissible.
    legacy_bytes = len(canon_json_bytes(legacy))
    capture_bytes = len(canon_json_bytes(artifacts))
    policy_bytes = len(canon_json_bytes(policy))
    root_bytes = len(canon_json_bytes(legacy["root"]))
    _require(legacy_bytes + 2 * capture_bytes + 2 * policy_bytes + 2 * root_bytes
        + METADATA_RESERVE < MAX_ENVELOPE, "PROFILE_SIZE_LIMIT")
    return {"schema": "echo-lineage-transfer-report/v1", "operation": "migrate",
        "legacy_snapshot_digest": snapshot_digest(legacy),
        "source_acceptance_hash": latest["document"]["document_hash"]["value"],
        "source_policy_digest": legacy_auth.policy_digest(legacy["policy"]),
        "artifacts": facts, "root_author_authenticated": False}


def _empty_projection():
    return {"sealed": False, "issue": None, "export_authorized": None,
        "export_confirmed": None, "receive": None, "decision": None,
        "import": None, "activations": {}, "remote_receipts": {}, "integrity_blocked": False}


def _initial(role, policy, initial):
    sid = policy["source_pin" if role == "source" else "recipient"]["store_id"]
    genesis = {"schema": SCHEMA, "profile": PROFILE, "role": role,
        "store_id": sid, "policy": policy, "initial": initial}
    return {**genesis, "generation": 0, "journal_head": auth.digest("genesis", genesis),
        "records": [], "requests": {}, "nonces": {}, "projections": _empty_projection()}


@_public
def create_receiver(policy, *, expected_policy_digest):
    policy = _policy(policy, expected_policy_digest)
    return _copy(_initial("receiver", policy, {"kind": "receiver_policy_only"}))


def _body(state, operation, inputs, actor, request, stamp, *, action_id=None, nonce=None):
    role = "local_context_consumer" if operation in {"activation_start", "activation_loaded"} else "human_operator"
    installation = state["policy"]["source_pin" if state["role"] == "source" else "recipient"]["installation_id"]
    _authorize(state["policy"], actor, installation, role, PURPOSES[operation])
    return {"schema": ACTION_SCHEMA, "operation": operation,
        "transfer_id": state["policy"]["transfer_id"], "request_id": request,
        "action_id": str(uuid4()) if action_id is None else action_id,
        "nonce": secrets.token_hex(32) if nonce is None else nonce,
        "policy_digest": auth.policy_digest(state["policy"]), "actor_id": actor,
        "installation_id": installation, "role": role, "verification_time": stamp,
        "pre_state": _prestate(state), "inputs": inputs, "report": None, "document": None}


@_public
def prepare_migration(legacy_state, policy, *, artifacts, actor_id, request_id,
                      verification_time, expected_state_digest, expected_policy_digest):
    legacy = _copy(legacy_state, MAX_PROOF)
    policy = _policy(policy, expected_policy_digest)
    _request(request_id)
    _time(verification_time)
    _hex(expected_state_digest)
    _require(snapshot_digest(legacy) == expected_state_digest, "STALE_STATE")
    report = _migration_report(legacy, policy, artifacts)
    actor_install = policy["source_pin"]["installation_id"]
    _authorize(policy, actor_id, actor_install, "human_operator", "state_migration")
    body = {"schema": ACTION_SCHEMA, "operation": "migrate", "transfer_id": policy["transfer_id"],
        "request_id": request_id, "action_id": str(uuid4()), "nonce": secrets.token_hex(32),
        "policy_digest": auth.policy_digest(policy), "actor_id": actor_id,
        "installation_id": actor_install, "role": "human_operator",
        "verification_time": verification_time, "pre_state": _prestate(legacy),
        "inputs": {"legacy_state": legacy, "artifacts": _copy(artifacts), "transfer_policy": policy},
        "report": report, "document": None}
    candidate = {"schema": CANDIDATE_SCHEMA, "policy": policy, "body": body}
    _copy(candidate, MAX_ENVELOPE - METADATA_RESERVE)
    return candidate


def _body_common(state, body, policy, *, migration=False):
    _closed(body, BODY_FIELDS, "INVALID_ACTION_FIELDS")
    op = body["operation"]
    _require(body["schema"] == ACTION_SCHEMA and op in PURPOSES, "INVALID_ACTION_SCHEMA")
    _request(body["request_id"])
    _uuid(body["action_id"])
    _require(isinstance(body["nonce"], str) and NONCE.fullmatch(body["nonce"]), "INVALID_NONCE")
    _time(body["verification_time"])
    _require(body["transfer_id"] == policy["transfer_id"]
        and body["policy_digest"] == auth.policy_digest(policy), "POLICY_PIN_MISMATCH")
    expected_role = "local_context_consumer" if op in {"activation_start", "activation_loaded"} else "human_operator"
    _require(body["role"] == expected_role, "ROLE_MISMATCH")
    installation = policy["source_pin" if migration or state["role"] == "source" else "recipient"]["installation_id"]
    _require(body["installation_id"] == installation, "INSTALLATION_MISMATCH")
    _authorize(policy, body["actor_id"], installation, expected_role, PURPOSES[op])
    _require(_same(body["pre_state"], _prestate(state)), "STALE_STATE")


def _verify_migration(legacy, body, policy):
    _body_common(legacy, body, policy, migration=True)
    _require(body["operation"] == "migrate", "INVALID_MIGRATION")
    _closed(body["inputs"], {"legacy_state", "artifacts", "transfer_policy"})
    _require(_same(body["inputs"]["transfer_policy"], policy), "POLICY_PIN_MISMATCH")
    _require(_same(body["inputs"]["legacy_state"], legacy), "SOURCE_PIN_MISMATCH")
    report = _migration_report(legacy, policy, body["inputs"]["artifacts"])
    _require(_same(body["report"], report) and body["document"] is None, "REPORT_MISMATCH")


def _packet_body(packet, policy, *, operation=None):
    _require(isinstance(packet, dict), "INVALID_SIGNED_ACTION")
    body = packet.get("payload")
    _require(isinstance(body, dict) and body.get("operation") in PURPOSES, "INVALID_ACTION_SCHEMA")
    op = body["operation"]
    if operation is not None:
        _require(op == operation, "OPERATION_MISMATCH")
    role = "local_context_consumer" if op in {"activation_start", "activation_loaded"} else "human_operator"
    return auth.verify_packet(packet, policy, purpose=PURPOSES[op],
        actor_id=body.get("actor_id"), installation_id=body.get("installation_id"), role=role)


def _source_prefix(state):
    prefix = _initial_source(state["policy"], state["initial"]["migration"], state["initial"]["applied_at"])
    for record in state["records"]:
        if record["packet"]["payload"]["operation"] == "issue":
            break
        _replay_record(prefix, record)
    return prefix


def _protocol_ref(aid, document):
    return {"artifact_id": aid, "sha256": _hash(document),
        "hash_scope": "canonical_document", "media_type": "application/json"}


def _issue_document(state, body):
    legacy, _ = _source_parts(state)
    root, acceptance = legacy["root"], legacy["records"][-1]["document"]
    inp, tid = body["inputs"], body["transfer_id"]
    _id(inp["producer_runtime_session_id"], "runtime-session")
    _require(_time(inp["expires_at"]) > _time(body["verification_time"]), "INVALID_EXPIRY")
    doc = {"protocol": "echo-lineage/v1", "document_type": "handoff", "body": {
        "handoff_id": tid, "trajectory_id": root["body"]["trajectory_id"],
        "genesis_root_document_hash": root["document_hash"]["value"],
        "issuer_installation_id": body["installation_id"],
        "issuer_runtime_session_id": inp["producer_runtime_session_id"],
        "recipient_binding": {"mode": "bound", "recipient_installation_id": state["policy"]["recipient"]["installation_id"]},
        "recording_operator_id": body["actor_id"], "sequence": 0, "handoff_nonce": body["nonce"],
        "issued_at": body["verification_time"], "expires_at": inp["expires_at"],
        "lineage_root_ref": _protocol_ref(legacy["root_artifact_id"], root),
        "latest_acceptance_ref": _protocol_ref(_typed("artifact", tid, "source-acceptance"), acceptance),
        "previous_handoff_hash": ZERO_HASH, "lineage_parents": root["body"]["lineage_parents"],
        "inheritance_sources": root["body"]["inheritance_sources"], "memory_heads": [], "ht_heads": [],
        "fork_intent": "none", "constraints": ["manual_acceptance_required", "verify_before_use", "no_public_commitment"]},
        "responsibility": {"chain_id": root["responsibility"]["chain_id"],
            "event_index": acceptance["responsibility"]["event_index"] + 1,
            "previous_head": acceptance["resulting_head"]}, "proofs": []}
    return finalize_document(doc)


def _received(state):
    p = state["projections"]["receive"]
    _require(p is not None, "TRANSFER_NOT_RECEIVED")
    record = state["records"][p["generation"] - 1]
    return record["packet"]["payload"]["inputs"]["envelope"]


def _continuation(state):
    received = state["projections"]["receive"]
    _require(received is not None, "TRANSFER_NOT_RECEIVED")
    return received["root"]


def _receiver_facts(state):
    envelope = _received(state)
    prefix = envelope["source_prefix"]
    legacy, artifacts = _source_parts(prefix)
    return legacy, artifacts, _capture(legacy, artifacts)


def _acceptance_verification(state):
    root = _continuation(state)
    envelope = _received(state)
    handoff = envelope["issue"]["packet"]["payload"]["document"]
    tid = state["policy"]["transfer_id"]
    _, _, rows = _receiver_facts(state)
    observations = [{"artifact_id": _typed("artifact", tid, "recipient-root"),
        "criticality": "critical_root", "status": "target_present_verified",
        "expected_sha256": root["document_hash"]["value"]},
        {"artifact_id": _typed("artifact", tid, "handoff"), "criticality": "critical_root",
        "status": "target_present_verified", "expected_sha256": handoff["document_hash"]["value"]}]
    for fact in rows:
        observations.append({k: v for k, v in fact.items() if k in {
            "artifact_id", "criticality", "status", "expected_sha256", "excluded_from_active_inheritance"}})
    return {"schema": "echo-lineage-transfer-verification/v1", "profile": PROFILE,
        "envelope_digest": state["projections"]["receive"]["envelope_digest"],
        "root_document_hash": root["document_hash"]["value"], "target_observations": observations,
        "source_proof_verified": True, "root_author_authenticated": False}


def _acceptance_document(state, body, verification):
    decision = body["inputs"]["decision"]
    allowed = evaluate_future_decisions(verification["target_observations"])
    if decision not in allowed:
        _require(decision not in ACCEPTING, "DECISION_NOT_PERMITTED")
        return None
    root = _continuation(state)
    tid = body["transfer_id"]
    handoff = _received(state)["issue"]["packet"]["payload"]["document"]
    target = verification["target_observations"]
    return finalize_document({"protocol": "echo-lineage/v1", "document_type": "lineage_acceptance",
        "body": {"acceptance_id": "urn:echo:acceptance:" + body["action_id"],
            "trajectory_id": root["body"]["trajectory_id"],
            "genesis_root_document_hash": root["body"]["genesis_root_document_hash"],
            "installation_id": body["installation_id"], "subject": {
                "trajectory_root_artifact_id": _typed("artifact", tid, "recipient-root"),
                "trajectory_root_document_hash": root["document_hash"]["value"],
                "handoff_artifact_id": _typed("artifact", tid, "handoff"),
                "handoff_document_hash": handoff["document_hash"]["value"]},
            "decision": decision,
            "decision_actor": {"decision_actor_id": body["actor_id"], "decision_mode": "human_operator"},
            "recording_operator": {"operator_actor_id": body["actor_id"], "role": "recording_operator",
                "confirmed_at": body["verification_time"], "confirmation_scope": "recorded_decision_without_reassignment"},
            "verification_report_hash": _hash(verification), "target_results": target,
            "reservations": [{"artifact_id": r["artifact_id"], "code": r["status"]}
                for r in target if r["status"] != "target_present_verified"] if decision == "accepted_with_reservations" else [],
            "decision_nonce": body["nonce"], "decided_at": body["verification_time"],
            "effect": "activating" if decision in ACCEPTING else "non_activating"},
        "responsibility": {"chain_id": root["responsibility"]["chain_id"], "event_index": 1,
            "previous_head": root["resulting_head"]}, "proofs": []})


def _artifact_ids(value):
    _require(isinstance(value, list) and len(value) <= 16 and len(set(value)) == len(value), "INVALID_READ_SET")
    for aid in value:
        _id(aid, "artifact")
    _require(value == sorted(value), "NONCANONICAL_READ_SET")


def _import_data(state, artifact_ids):
    legacy, captured, rows = _receiver_facts(state)
    byid = {i["artifact_id"]: i for i in captured}
    allowed = {r["artifact_id"] for r in rows if r["status"] == "target_present_verified"}
    _artifact_ids(artifact_ids)
    _require(set(artifact_ids) <= allowed, "IMPORT_SCOPE_NOT_ACCEPTED")
    return [{"artifact_id": aid, "sha256": sha256_hex(_b64(byid[aid]["data_b64"])),
        "bytes_b64": byid[aid]["data_b64"]} for aid in artifact_ids]


def _grant_view(state, activation_id):
    _uuid(activation_id)
    p = state["projections"]
    _require(not p["integrity_blocked"], "INTEGRITY_BLOCKED")
    activation = p["activations"].get(activation_id)
    _require(activation is not None, "ACTIVATION_NOT_AUTHORIZED")
    _require(not activation["revoked"], "ACTIVATION_REVOKED")
    grant = state["records"][activation["generation"] - 1]["packet"]
    inp = grant["payload"]["inputs"]
    data = _import_data(state, inp["artifact_ids"])
    return {"activation_id": activation_id, "grant_digest": auth.digest("grant", grant),
        "grant": grant, "import_digest": p["import"]["import_digest"], "artifacts": data,
        "policy": state["policy"], "store_id": state["store_id"],
        "installation_id": state["policy"]["recipient"]["installation_id"],
        "consumer": state["policy"]["consumer"], "probe": inp["probe"],
        "launch": activation["launch"], "status": activation["status"],
        "read_set": [{"artifact_id": d["artifact_id"], "sha256": d["sha256"]} for d in data]}


def _probe_result(view):
    probe = view["probe"]
    item = next(a for a in view["artifacts"] if a["artifact_id"] == probe["artifact_id"])
    text = _b64(item["bytes_b64"]).decode("utf-8")
    return text[probe["offset"]:probe["offset"] + probe["length"]]


def _loaded_receipt(state, inputs):
    view = _grant_view(state, inputs["activation_id"])
    _require(view["launch"] is not None, "ACTIVATION_NOT_STARTED")
    launch = view["launch"]
    _require(inputs["instance_id"] == launch["instance_id"], "CONSUMER_INSTANCE_MISMATCH")
    payload = auth.verify_packet(inputs["receipt"], state["policy"], purpose="context_consumption_receipt",
        actor_id=view["consumer"]["consumer_id"], installation_id=view["installation_id"], role="local_context_consumer")
    fields = {"kind", "activation_id", "instance_id", "launch_nonce", "grant_digest", "import_digest",
        "read_set", "store_id", "installation_id", "consumer_id", "code_digest", "probe", "probe_result", "probe_result_sha256", "observed_at"}
    _closed(payload, fields, "INVALID_LOADED_RECEIPT_FIELDS")
    _time(payload["observed_at"])
    expected = {"kind": "loaded", "activation_id": inputs["activation_id"],
        "instance_id": launch["instance_id"], "launch_nonce": launch["launch_nonce"],
        "grant_digest": view["grant_digest"], "import_digest": view["import_digest"],
        "read_set": view["read_set"], "store_id": view["store_id"],
        "installation_id": view["installation_id"], "consumer_id": view["consumer"]["consumer_id"],
        "code_digest": view["consumer"]["code_digest"], "probe": view["probe"],
        "probe_result": _probe_result(view), "probe_result_sha256": sha256_hex(_probe_result(view).encode("utf-8")),
        "observed_at": payload["observed_at"]}
    _require(_same(payload, expected), "LOADED_RECEIPT_BINDING_MISMATCH")
    return payload


def _receipt(state, packet):
    policy = state["policy"]
    payload = auth.verify_packet(packet, policy, purpose="transfer_receipt",
        installation_id=policy["recipient"]["installation_id"], role="human_operator")
    _closed(payload, {"schema", "kind", "transfer_id", "envelope_digest", "recipient_store_id",
        "recipient_installation_id", "policy_digest", "generation", "journal_head", "snapshot_digest",
        "milestone_digest", "observed_at"}, "INVALID_RECEIPT_FIELDS")
    _require(payload["schema"] == RECEIPT_SCHEMA and payload["kind"] in {"received", "decided", "imported", "loaded"},
        "INVALID_RECEIPT_KIND")
    _require(payload["transfer_id"] == policy["transfer_id"]
        and payload["policy_digest"] == auth.policy_digest(policy)
        and payload["recipient_store_id"] == policy["recipient"]["store_id"]
        and payload["recipient_installation_id"] == policy["recipient"]["installation_id"], "RECEIPT_BINDING_MISMATCH")
    _require(type(payload["generation"]) is int and payload["generation"] > 0, "INVALID_RECEIPT_GENERATION")
    for key in ("journal_head", "snapshot_digest", "milestone_digest", "envelope_digest"):
        _hex(payload[key])
    _time(payload["observed_at"])
    _require(payload["envelope_digest"] == auth.digest("envelope", _make_envelope(state)), "RECEIPT_ENVELOPE_MISMATCH")
    return payload


def _derive(state, body, *, signed=False):
    op, inp, p = body["operation"], body["inputs"], state["projections"]
    _closed(inp, OPERATION_FIELDS[op])
    _require(op not in {"issue", "export_authorize", "export_confirm", "receipt_ingest"} or state["role"] == "source",
        "WRONG_STORE_ROLE")
    _require(op not in {"receive", "decide", "import", "activate", "activation_start", "activation_loaded", "deactivate"}
        or state["role"] == "receiver", "WRONG_STORE_ROLE")
    doc = None
    facts = {"schema": "echo-lineage-transfer-report/v1", "operation": op}
    if op == "issue":
        _require(not p["sealed"], "SOURCE_EPOCH_SEALED")
        legacy, artifacts = _source_parts(state)
        facts["source"] = _migration_report(legacy, state["policy"], artifacts)
        doc = _issue_document(state, body)
        _require(len(canon_json_bytes(state)) + len(canon_json_bytes(body)) + METADATA_RESERVE < MAX_ENVELOPE,
            "PROFILE_SIZE_LIMIT")
    elif op == "export_authorize":
        _require(p["issue"] is not None and p["export_authorized"] is None, "EXPORT_NOT_AVAILABLE")
        facts.update(issue_digest=p["issue"]["document_hash"], source_prefix_digest=snapshot_digest(_source_prefix(state)))
    elif op == "export_confirm":
        envelope = _make_envelope(state)
        raw = canon_json_bytes(envelope) + b"\n"
        _require(inp["envelope_digest"] == auth.digest("envelope", envelope)
            and inp["raw_sha256"] == sha256_hex(raw) and type(inp["byte_length"]) is int
            and inp["byte_length"] == len(raw), "EXPORT_BYTES_MISMATCH")
        _require(p["export_confirmed"] is None, "EXPORT_ALREADY_CONFIRMED")
        facts.update(inp)
    elif op == "receive":
        _require(p["receive"] is None, "TRANSFER_ALREADY_RECEIVED")
        _id(inp["recipient_runtime_session_id"], "runtime-session")
        typed = _verify_envelope(inp["envelope"], state["policy"], body["verification_time"])
        facts.update(typed)
        handoff = inp["envelope"]["issue"]["packet"]["payload"]["document"]
        legacy, _ = _source_parts(inp["envelope"]["source_prefix"])
        root = legacy["root"]
        tid = body["transfer_id"]
        continuation = finalize_document({"protocol": "echo-lineage/v1", "document_type": "trajectory_root",
            "body": {"trajectory_id": root["body"]["trajectory_id"],
                "genesis_root_document_hash": root["document_hash"]["value"],
                "installation_id": body["installation_id"],
                "created_by_runtime_session_id": inp["recipient_runtime_session_id"], "origin_kind": "continuation",
                "lineage_parents": [{"relation": "predecessor", "parent_trajectory_id": root["body"]["trajectory_id"],
                    "parent_genesis_root_document_hash": root["document_hash"]["value"],
                    "parent_installation_id": root["body"]["installation_id"],
                    "handoff_document_hash": handoff["document_hash"]["value"],
                    "parent_responsibility_head": handoff["resulting_head"]}],
                "inheritance_sources": root["body"]["inheritance_sources"], "fork_policy": "explicit_only",
                "acceptance_required": True, "signature_policy": "optional", "created_at": body["verification_time"]},
            "responsibility": {"chain_id": _typed("responsibility-chain", tid, "recipient-chain"),
                "event_index": 0, "previous_head": ZERO_HASH}, "proofs": []})
        validate_document(continuation, expected_type="trajectory_root")
        validate_root_graph([root, continuation], related_handoffs=[handoff],
            related_acceptances=[r["document"] for r in legacy["records"]],
            require_parent_evidence=True, verification_time=body["verification_time"])
        facts["continuation_root"] = continuation
    elif op == "decide":
        _require(p["receive"] is not None and p["decision"] is None, "DECISION_NOT_AVAILABLE")
        _require(inp["decision"] in DECISIONS, "INVALID_DECISION")
        verification = _acceptance_verification(state)
        doc = _acceptance_document(state, body, verification)
        facts.update(verification=verification, decision=inp["decision"],
            lineage_acceptance_available=doc is not None)
    elif op == "import":
        decision = p["decision"]
        _require(decision is not None and decision["decision"] in ACCEPTING
            and decision["acceptance_hash"] is not None and not p["integrity_blocked"], "IMPORT_NOT_ACCEPTED")
        _require(p["import"] is None, "CONTEXT_ALREADY_IMPORTED")
        data = _import_data(state, inp["artifact_ids"])
        facts.update(acceptance_hash=decision["acceptance_hash"], artifact_ids=inp["artifact_ids"],
            import_digest=auth.digest("import", {"acceptance_hash": decision["acceptance_hash"],
                "artifact_ids": inp["artifact_ids"], "artifacts": data}))
    elif op == "activate":
        _require(p["import"] is not None and not p["integrity_blocked"], "CONTEXT_NOT_IMPORTED")
        _uuid(inp["activation_id"])
        _require(inp["activation_id"] not in p["activations"], "ACTIVATION_ID_REUSED")
        _require(not any(not a["revoked"] for a in p["activations"].values()), "ACTIVATION_ALREADY_AUTHORIZED")
        _artifact_ids(inp["artifact_ids"])
        _require(inp["artifact_ids"] == p["import"]["artifact_ids"] and inp["artifact_ids"], "ACTIVATION_READ_SET_MISMATCH")
        data = _import_data(state, inp["artifact_ids"])
        for item in data:
            _b64(item["bytes_b64"]).decode("utf-8")
        probe = inp["probe"]
        _closed(probe, {"artifact_id", "offset", "length", "nonce"})
        _require(probe["artifact_id"] in inp["artifact_ids"] and type(probe["offset"]) is int
            and 0 <= probe["offset"] <= MAX_PAYLOAD and type(probe["length"]) is int
            and 1 <= probe["length"] <= 256, "INVALID_PROBE")
        probe_text = next(_b64(d["bytes_b64"]).decode("utf-8") for d in data if d["artifact_id"] == probe["artifact_id"])
        _require(probe["offset"] + probe["length"] <= len(probe_text), "INVALID_PROBE")
        _hex(probe["nonce"])
        _require(not any(a["probe_nonce"] == probe["nonce"] for a in p["activations"].values()), "PROBE_NONCE_REUSED")
        facts.update(import_digest=p["import"]["import_digest"], acceptance_hash=p["decision"]["acceptance_hash"],
            consumer=state["policy"]["consumer"], artifact_ids=inp["artifact_ids"], probe=probe)
    elif op == "activation_start":
        view = _grant_view(state, inp["activation_id"])
        _require(view["launch"] is None, "ACTIVATION_LAUNCH_ALREADY_ATTEMPTED")
        _uuid(inp["instance_id"])
        _hex(inp["launch_nonce"])
        _require(inp["code_digest"] == view["consumer"]["code_digest"], "CONSUMER_CODE_PIN_MISMATCH")
        facts.update(grant_digest=view["grant_digest"], import_digest=view["import_digest"], durable_launch_intent=True)
    elif op == "activation_loaded":
        view = _grant_view(state, inp["activation_id"])
        _require(view["status"] == "launch_intent", "CONSUMER_LOAD_ALREADY_RECORDED")
        facts["loaded"] = _loaded_receipt(state, inp)
        _require(_time(facts["loaded"]["observed_at"]) <= _time(body["verification_time"]), "INVALID_RECEIPT_TIME")
    elif op == "deactivate":
        view = _grant_view(state, inp["activation_id"])
        facts.update(grant_digest=view["grant_digest"], revocation_permanent=True)
    elif op == "receipt_ingest":
        receipt = _receipt(state, inp["receipt"])
        _require(receipt["kind"] not in p["remote_receipts"], "REMOTE_RECEIPT_ALREADY_RECORDED")
        facts["receipt"] = receipt
    if doc is not None:
        validate_document(doc)
        if signed:
            actual = body["document"]
            _require(isinstance(actual, dict), "PROTOCOL_DOCUMENT_MISSING")
            unsigned = _copy(actual)
            unsigned["proofs"] = []
            _require(_same(unsigned, doc), "PROTOCOL_DOCUMENT_BINDING_MISMATCH")
            auth.verify_protocol_document(actual, state["policy"],
                purpose="handoff_issue" if op == "issue" else "lineage_acceptance",
                actor_id=body["actor_id"], installation_id=body["installation_id"])
            doc = actual
        if op == "issue":
            legacy, _ = _source_parts(state)
            _validate_handoff_evidence(doc, related_roots=[legacy["root"]],
                related_acceptances=[r["document"] for r in legacy["records"]],
                related_handoffs=[], verification_time=body["verification_time"])
        elif op == "decide":
            legacy, _, _ = _receiver_facts(state)
            handoff = _received(state)["issue"]["packet"]["payload"]["document"]
            _validate_acceptance_evidence(doc, related_roots=[legacy["root"], _continuation(state)],
                related_acceptances=[r["document"] for r in legacy["records"]],
                related_handoffs=[handoff], verification_time=body["verification_time"])
        facts["document_artifact_hash"] = _hash(doc)
        facts["document_hash"] = doc["document_hash"]["value"]
    else:
        _require(body["document"] is None, "UNEXPECTED_PROTOCOL_DOCUMENT")
    return facts, doc


def _check_body(state, body, *, signed):
    _body_common(state, body, state["policy"])
    _require(body["operation"] in OPERATION_FIELDS, "INVALID_OPERATION")
    facts, doc = _derive(state, body, signed=signed)
    _require(_same(body["report"], facts) and _same(body["document"], doc), "REPORT_MISMATCH")


@_public
def prepare_action(state, operation, inputs, *, actor_id, request_id,
                   verification_time, expected_state_digest):
    state, _ = _replay(_copy(state))
    _require(operation in OPERATION_FIELDS, "INVALID_OPERATION")
    _request(request_id)
    _time(verification_time)
    _hex(expected_state_digest)
    _require(snapshot_digest(state) == expected_state_digest, "STALE_STATE")
    _require(request_id not in state["requests"], "REQUEST_CONFLICT")
    _require(len(state["records"]) < MAX_RECORDS, "PROFILE_SIZE_LIMIT")
    body = _body(state, operation, _copy(inputs), actor_id, request_id, verification_time)
    facts, doc = _derive(state, body)
    body.update(report=facts, document=doc)
    return _copy({"schema": CANDIDATE_SCHEMA, "policy": state["policy"], "body": body})


@_public
def sign_candidate(state_or_legacy, candidate, key_file, *, expected_policy_digest=None):
    candidate = _copy(candidate)
    _closed(candidate, {"schema", "policy", "body"}, "INVALID_CANDIDATE_FIELDS")
    _require(candidate["schema"] == CANDIDATE_SCHEMA, "INVALID_CANDIDATE_SCHEMA")
    policy = _policy(candidate["policy"])
    body = candidate["body"]
    if body["operation"] == "migrate":
        _require(expected_policy_digest is not None, "POLICY_PIN_REQUIRED")
        _policy(policy, expected_policy_digest)
        legacy = _copy(state_or_legacy, MAX_PROOF)
        _verify_migration(legacy, body, policy)
    else:
        state, _ = _replay(_copy(state_or_legacy))
        _require(_same(state["policy"], policy), "POLICY_PIN_MISMATCH")
        _check_body(state, body, signed=False)
        # Validate every generated report before the key reader is reached.
        if body["document"] is not None:
            body["document"] = auth.sign_protocol_document(body["document"], policy, key_file,
                purpose="handoff_issue" if body["operation"] == "issue" else "lineage_acceptance",
                actor_id=body["actor_id"], installation_id=body["installation_id"])
            facts, doc = _derive(state, body, signed=True)
            body.update(report=facts, document=doc)
    return auth.sign_packet(body, policy, key_file, purpose=PURPOSES[body["operation"]],
        actor_id=body["actor_id"], installation_id=body["installation_id"], role=body["role"])


def _initial_source(policy, packet, applied_at):
    body = _packet_body(packet, policy, operation="migrate")
    legacy = body["inputs"]["legacy_state"]
    _verify_migration(legacy, body, policy)
    _require(_time(body["verification_time"]) <= _time(applied_at), "VERIFICATION_TIME_AFTER_COMMIT")
    state = _initial("source", policy, {"kind": "source_migration", "migration": packet, "applied_at": applied_at})
    state["requests"][body["request_id"]] = {"generation": 0, "packet_digest": auth.digest("action", packet)}
    state["nonces"][body["nonce"]] = body["request_id"]
    state["nonces"][body["action_id"]] = body["request_id"]
    return state


@_public
def apply_migration(legacy_state, signed_candidate, *, expected_state_digest, applied_at, expected_policy_digest=None):
    _require(expected_policy_digest is not None, "POLICY_PIN_REQUIRED")
    if isinstance(legacy_state, dict) and legacy_state.get("schema") == SCHEMA:
        state, _ = _replay(_copy(legacy_state))
        _policy(state["policy"], expected_policy_digest)
        _require(state["role"] == "source" and _same(state["initial"]["migration"], signed_candidate), "REQUEST_CONFLICT")
        return state, _result(state, True)
    legacy = _copy(legacy_state, MAX_PROOF)
    # Policy is signed as part of the migration payload and must also match
    # the independently supplied local pin at this separate trust entry.
    body = signed_candidate.get("payload", {})
    _require(isinstance(body, dict) and body.get("operation") == "migrate", "INVALID_MIGRATION")
    # The signed packet carries policy alongside its inputs to support standalone apply.
    policy = body.get("inputs", {}).get("transfer_policy")
    _require(policy is not None, "MIGRATION_POLICY_MISSING")
    policy = _policy(policy, expected_policy_digest)
    _hex(expected_state_digest)
    _require(snapshot_digest(legacy) == expected_state_digest, "STALE_STATE")
    _time(applied_at)
    state = _initial_source(policy, signed_candidate, applied_at)
    _require(_same(_source_parts(state)[0], legacy), "SOURCE_PIN_MISMATCH")
    return _copy(state), _result(state, False)


def _result(state, duplicate):
    return {"status": "idempotent_replay" if duplicate else "applied_in_memory", "idempotent": duplicate,
        "store_id": state["store_id"], "generation": state["generation"],
        "journal_head": state["journal_head"], "snapshot_digest": snapshot_digest(state),
        "runtime_activation": False, "source_epoch_sealed": state["projections"]["sealed"]}


def _append(state, record):
    body = record["packet"]["payload"]
    op, inp, facts, p = body["operation"], body["inputs"], body["report"], state["projections"]
    generation = record["generation"]
    if op == "issue":
        p["sealed"] = True
        p["issue"] = {"generation": generation, "document_hash": body["document"]["document_hash"]["value"]}
    elif op == "export_authorize":
        p["export_authorized"] = {"generation": generation}
    elif op == "export_confirm":
        p["export_confirmed"] = {"generation": generation, **inp}
    elif op == "receive":
        p["receive"] = {"generation": generation, "envelope_digest": facts["envelope_digest"],
            "root": facts["continuation_root"]}
    elif op == "decide":
        p["decision"] = {"generation": generation, "decision": inp["decision"],
            "acceptance_hash": None if body["document"] is None else body["document"]["document_hash"]["value"]}
        if inp["decision"] == "quarantined_integrity_failure":
            p["integrity_blocked"] = True
    elif op == "import":
        p["import"] = {"generation": generation, "artifact_ids": inp["artifact_ids"], "import_digest": facts["import_digest"]}
    elif op == "activate":
        p["activations"][inp["activation_id"]] = {"generation": generation, "revoked": False,
            "launch": None, "status": "authorized", "probe_nonce": inp["probe"]["nonce"], "loaded_generation": None}
    elif op == "activation_start":
        activation = p["activations"][inp["activation_id"]]
        activation.update(launch=inp, status="launch_intent")
    elif op == "activation_loaded":
        p["activations"][inp["activation_id"]].update(status="loaded", loaded_generation=generation)
    elif op == "deactivate":
        p["activations"][inp["activation_id"]].update(revoked=True, status="revoked")
    elif op == "receipt_ingest":
        p["remote_receipts"][facts["receipt"]["kind"]] = facts["receipt"]
    state["records"].append(record)
    state["generation"] = generation
    state["journal_head"] = record["event_hash"]
    state["requests"][body["request_id"]] = {"generation": generation, "packet_digest": auth.digest("action", record["packet"])}
    state["nonces"][body["nonce"]] = body["request_id"]
    state["nonces"][body["action_id"]] = body["request_id"]


def _commit_time(body, applied_at):
    stamp = _time(applied_at)
    _require(_time(body["verification_time"]) <= stamp, "VERIFICATION_TIME_AFTER_COMMIT")
    if body["operation"] == "issue":
        _require(stamp < _time(body["inputs"]["expires_at"]), "HANDOFF_EXPIRED_OR_NOT_YET_VALID")
    elif body["operation"] == "receive":
        handoff = body["inputs"]["envelope"]["issue"]["packet"]["payload"]["document"]
        _require(stamp < _time(handoff["body"]["expires_at"]), "HANDOFF_EXPIRED_OR_NOT_YET_VALID")


def _record_hash(record):
    return auth.digest("event", {k: v for k, v in record.items() if k != "event_hash"})


def _replay_record(state, record):
    _closed(record, RECORD_FIELDS, "INVALID_RECORD_FIELDS")
    _require(type(record["generation"]) is int and record["generation"] == state["generation"] + 1,
        "RECORD_GENERATION_MISMATCH")
    _require(record["previous_journal_head"] == state["journal_head"] and record["event_hash"] == _record_hash(record),
        "BROKEN_JOURNAL_CHAIN")
    _time(record["applied_at"])
    body = _packet_body(record["packet"], state["policy"])
    _commit_time(body, record["applied_at"])
    _require(body["request_id"] not in state["requests"], "REQUEST_CONFLICT")
    _require(body["nonce"] not in state["nonces"] and body["action_id"] not in state["nonces"], "NONCE_CONFLICT")
    _check_body(state, body, signed=True)
    _append(state, record)


def _replay(state):
    _closed(state, STATE_FIELDS, "INVALID_STATE_FIELDS")
    _require(state["schema"] == SCHEMA and state["profile"] == PROFILE and state["role"] in {"source", "receiver"},
        "UNSUPPORTED_STATE_PROFILE")
    policy = _policy(state["policy"])
    _require(isinstance(state["records"], list) and len(state["records"]) <= MAX_RECORDS, "PROFILE_SIZE_LIMIT")
    if state["role"] == "source":
        _closed(state["initial"], {"kind", "migration", "applied_at"})
        _require(state["initial"]["kind"] == "source_migration", "INVALID_INITIAL_STATE")
        replay = _initial_source(policy, state["initial"]["migration"], state["initial"]["applied_at"])
    else:
        _require(state["initial"] == {"kind": "receiver_policy_only"}, "INVALID_INITIAL_STATE")
        replay = _initial("receiver", policy, state["initial"])
    genesis = replay["journal_head"]
    for record in state["records"]:
        _replay_record(replay, record)
    _require(_same(state, replay), "SNAPSHOT_REPLAY_MISMATCH")
    return replay, genesis


@_public
def apply_action(state, signed_candidate, *, expected_state_digest, applied_at):
    state, _ = _replay(_copy(state))
    packet = _copy(signed_candidate)
    body = _packet_body(packet, state["policy"])
    request = body["request_id"]
    # Exact replay is checked before CAS and all action-specific freshness checks.
    if request in state["requests"]:
        _require(state["requests"][request]["packet_digest"] == auth.digest("action", packet), "REQUEST_CONFLICT")
        return state, _result(state, True)
    _require(body["nonce"] not in state["nonces"] and body["action_id"] not in state["nonces"], "NONCE_CONFLICT")
    _require(len(state["records"]) < MAX_RECORDS, "PROFILE_SIZE_LIMIT")
    _hex(expected_state_digest)
    _require(snapshot_digest(state) == expected_state_digest, "STALE_STATE")
    _check_body(state, body, signed=True)
    _commit_time(body, applied_at)
    record = {"generation": state["generation"] + 1, "previous_journal_head": state["journal_head"],
        "packet": packet, "applied_at": applied_at}
    record["event_hash"] = _record_hash(record)
    _append(state, record)
    return _copy(state), _result(state, False)


def _make_envelope(state):
    p = state["projections"]
    _require(state["role"] == "source" and p["issue"] is not None and p["export_authorized"] is not None,
        "EXPORT_NOT_AUTHORIZED")
    envelope = {"schema": ENVELOPE_SCHEMA, "profile": PROFILE,
        "transfer_id": state["policy"]["transfer_id"], "policy_digest": auth.policy_digest(state["policy"]),
        "source_prefix": _source_prefix(state), "issue": state["records"][p["issue"]["generation"] - 1],
        "export_authorization": state["records"][p["export_authorized"]["generation"] - 1]}
    return _copy(envelope, MAX_ENVELOPE)


@_public
def make_envelope(source_state):
    state, _ = _replay(_copy(source_state))
    return _make_envelope(state)


def _verify_envelope(envelope, policy, stamp):
    envelope = _copy(envelope, MAX_ENVELOPE)
    _time(stamp)
    _closed(envelope, {"schema", "profile", "transfer_id", "policy_digest", "source_prefix", "issue", "export_authorization"},
        "INVALID_ENVELOPE_FIELDS")
    _require(envelope["schema"] == ENVELOPE_SCHEMA and envelope["profile"] == PROFILE
        and envelope["transfer_id"] == policy["transfer_id"] and envelope["policy_digest"] == auth.policy_digest(policy),
        "ENVELOPE_POLICY_MISMATCH")
    prefix, _ = _replay(envelope["source_prefix"])
    _require(prefix["role"] == "source" and _same(prefix["policy"], policy)
        and not prefix["projections"]["sealed"], "INVALID_SOURCE_PREFIX")
    _require(envelope["issue"]["packet"]["payload"]["operation"] == "issue"
        and envelope["export_authorization"]["packet"]["payload"]["operation"] == "export_authorize",
        "INVALID_ENVELOPE_RECORDS")
    _replay_record(prefix, envelope["issue"])
    _replay_record(prefix, envelope["export_authorization"])
    handoff = envelope["issue"]["packet"]["payload"]["document"]
    _require(_time(handoff["body"]["issued_at"]) <= _time(stamp) < _time(handoff["body"]["expires_at"]), "HANDOFF_EXPIRED_OR_NOT_YET_VALID")
    legacy, artifacts = _source_parts(prefix)
    latest = _legacy(legacy, policy)
    _require(handoff["body"]["lineage_root_ref"]["sha256"] == _hash(legacy["root"])
        and handoff["body"]["latest_acceptance_ref"]["sha256"] == _hash(latest["document"]), "SOURCE_CLOSURE_MISMATCH")
    facts = _capture(legacy, artifacts)
    return {"envelope_digest": auth.digest("envelope", envelope), "source_proof_verified": True,
        "source_store_id": legacy["store_id"], "source_acceptance_hash": latest["document"]["document_hash"]["value"],
        "handoff_document_hash": handoff["document_hash"]["value"], "artifacts": facts,
        "root_author_authenticated": False}


@_public
def verify_envelope(envelope, policy, *, verification_time):
    return _copy(_verify_envelope(envelope, _policy(policy), verification_time))


@_public
def consumer_view(state, activation_id):
    state, _ = _replay(_copy(state))
    return _copy(_grant_view(state, activation_id))


@_public
def inspect_state(state, checkpoint=None):
    state, genesis = _replay(_copy(state))
    satisfied = None
    if checkpoint is not None:
        _closed(checkpoint, {"store_id", "generation", "journal_head"}, "INVALID_CHECKPOINT_FIELDS")
        n = checkpoint["generation"]
        _require(type(n) is int and 0 <= n <= state["generation"] and checkpoint["store_id"] == state["store_id"],
            "CHECKPOINT_NOT_IN_HISTORY")
        head = genesis if n == 0 else state["records"][n - 1]["event_hash"]
        _require(head == checkpoint["journal_head"], "CHECKPOINT_NOT_IN_HISTORY")
        satisfied = True
    p = state["projections"]
    return {"schema": "echo-lineage-transfer-status/v1", "profile": PROFILE, "role": state["role"],
        **_prestate(state), "local_chain_valid": True, "external_checkpoint_satisfied": satisfied,
        "rollback_protection": "checkpoint_ancestor_checked" if satisfied else "not_externally_anchored",
        "source_epoch_sealed": p["sealed"], "export_authorized": p["export_authorized"] is not None,
        "export_confirmed": p["export_confirmed"] is not None, "received": p["receive"] is not None,
        "decision": p["decision"], "imported": p["import"] is not None,
        "activations": p["activations"], "integrity_blocked": p["integrity_blocked"],
        "remote_milestones": {k: "RECEIPT_VERIFIED" if k in p["remote_receipts"] else "UNKNOWN"
            for k in ("received", "decided", "imported", "loaded")},
        "current_process_liveness": "UNKNOWN", "loaded_receipts_are_historical": True,
        "root_author_authenticated": False, "runtime_activation": False}


@_public
def make_receipt(state, *, kind, actor_id, key_file, verification_time):
    state, _ = _replay(_copy(state))
    _require(state["role"] == "receiver", "WRONG_STORE_ROLE")
    _time(verification_time)
    p = state["projections"]
    _require(kind in {"received", "decided", "imported", "loaded"}, "INVALID_RECEIPT_KIND")
    milestone = p[{"received": "receive", "decided": "decision", "imported": "import"}.get(kind, "receive")]
    if kind == "loaded":
        loaded = [a for a in p["activations"].values() if a["loaded_generation"] is not None]
        _require(loaded, "MILESTONE_NOT_COMMITTED")
        generation = max(a["loaded_generation"] for a in loaded)
    else:
        _require(milestone is not None, "MILESTONE_NOT_COMMITTED")
        generation = milestone["generation"]
    record = state["records"][generation - 1]
    payload = {"schema": RECEIPT_SCHEMA, "kind": kind, "transfer_id": state["policy"]["transfer_id"],
        "envelope_digest": p["receive"]["envelope_digest"], "recipient_store_id": state["store_id"],
        "recipient_installation_id": state["policy"]["recipient"]["installation_id"],
        "policy_digest": auth.policy_digest(state["policy"]), "generation": state["generation"],
        "journal_head": state["journal_head"], "snapshot_digest": snapshot_digest(state),
        "milestone_digest": auth.digest("event", record), "observed_at": verification_time}
    return auth.sign_packet(payload, state["policy"], key_file, purpose="transfer_receipt", actor_id=actor_id,
        installation_id=payload["recipient_installation_id"], role="human_operator")
