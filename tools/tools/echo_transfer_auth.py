"""Closed, explicitly scoped Ed25519 authentication for 2C-h1-bound.

An authenticated key holder is neither a model identity nor an independent
witness. Packet payload semantics and independently supplied policy pins belong
to the transfer model. Existing v1 protocol documents retain their original
proof domain; a control signature never grants lineage-acceptance authority.
Cryptography remains an optional, lazily loaded capability.
"""
from __future__ import annotations

import base64
import binascii
import functools
import re
from pathlib import Path
from uuid import UUID

try:
    from .echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from .echo_lineage import (_validate_typed_id, build_proof_payload,
                               proof_message_bytes, validate_document)
    from .echo_lineage_auth import (
        AUTH_SCOPE, CryptoUnavailable, StateAuthError, _crypto,
        _public_key_bytes, _read_private_key, _require_pkcs8_pem,
        validate_policy as validate_lineage_policy,
    )
except ImportError:  # direct script imports
    from echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from echo_lineage import (_validate_typed_id, build_proof_payload,
                             proof_message_bytes, validate_document)
    from echo_lineage_auth import (
        AUTH_SCOPE, CryptoUnavailable, StateAuthError, _crypto,
        _public_key_bytes, _read_private_key, _require_pkcs8_pem,
        validate_policy as validate_lineage_policy,
    )


POLICY_SCHEMA = "echo-lineage-transfer-trust/v1"
SIGNED_SCHEMA = "echo-lineage-transfer-signed/v1"
PROFILE = "2C-h1-bound"
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_KEYS = 256
PREFIX = b"ECHO|TRANSFER|v1|"
SOURCE_PURPOSES = frozenset({"state_migration", "handoff_issue", "transfer_export",
                             "remote_receipt_ingest"})
RECIPIENT_PURPOSES = frozenset({"transfer_receive", "transfer_receipt",
    "receiver_decision", "context_import_authorize", "context_activation_authorize",
    "context_consumption_receipt", "context_deactivate"})
PURPOSES = SOURCE_PURPOSES | RECIPIENT_PURPOSES
ROLES = frozenset({"human_operator", "local_context_consumer"})
HEX = re.compile(r"[0-9a-f]{64}\Z")
DOMAIN = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
POLICY_FIELDS = {"schema", "profile", "transfer_id", "source_pin", "recipient",
                 "keys", "consumer"}
KEY_FIELDS = {"key_id", "public_key", "actor_id", "installation_id", "role", "purposes"}
PACKET_FIELDS = {"schema", "policy_digest", "purpose", "actor_id", "installation_id",
                 "role", "payload", "proof"}


class TransferAuthError(ValueError):
    """Path-free authentication refusal code; no key material is included."""


def _public(function):
    @functools.wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except TransferAuthError:
            raise
        except CryptoUnavailable:
            raise TransferAuthError("AUTHENTICATION_UNAVAILABLE") from None
        except StateAuthError:
            raise TransferAuthError("INVALID_AUTH_INPUT") from None
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError,
                RecursionError, OSError):
            raise TransferAuthError("INVALID_AUTH_INPUT") from None
    return checked


def _require(condition, code):
    if not condition:
        raise TransferAuthError(code)


def _closed(value, fields, code):
    _require(type(value) is dict and set(value) == fields, code)


def _copy(value):
    # Check before recursive canonicalization, including cycles, foreign Python
    # values, and stringification of non-string object keys.
    pending = [(value, 0)]
    nodes = 0
    minimum_bytes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _require(depth <= MAX_DEPTH and nodes <= MAX_BYTES, "AUTH_SIZE_LIMIT")
        if type(item) is dict:
            _require(all(type(k) is str for k in item), "INVALID_JSON_VALUE")
            minimum_bytes += sum(len(k) + 3 for k in item) + 2
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            minimum_bytes += len(item) + 1 if item else 2
            pending.extend((v, depth + 1) for v in item)
        else:
            _require(type(item) in (str, int, float, bool, type(None)), "INVALID_JSON_VALUE")
            minimum_bytes += len(item) + 2 if type(item) is str else 1
        _require(minimum_bytes <= MAX_BYTES, "AUTH_SIZE_LIMIT")
    raw = canon_json_bytes(value)
    _require(len(raw) <= MAX_BYTES, "AUTH_SIZE_LIMIT")
    return loads_json_strict(raw)


def _typed(value, kind):
    _validate_typed_id(value, kind, "identity")


def _hex(value):
    _require(type(value) is str and HEX.fullmatch(value), "INVALID_DIGEST")


def _uuid(value):
    _require(type(value) is str, "INVALID_STORE_ID")
    parsed = UUID(value)
    _require(str(parsed) == value and parsed.version in range(1, 6), "INVALID_STORE_ID")


def _scope(purpose, actor_id, installation_id, role):
    _require(type(purpose) is str and purpose in PURPOSES, "INVALID_PURPOSE")
    _require(type(role) is str and role in ROLES, "INVALID_ROLE")
    _typed(actor_id, "artifact" if role == "local_context_consumer" else "decision-actor")
    _typed(installation_id, "installation")
    if role == "local_context_consumer":
        _require(purpose == "context_consumption_receipt", "CONSUMER_PURPOSE_DENIED")
    else:
        _require(purpose != "context_consumption_receipt", "CONSUMER_ROLE_REQUIRED")


def _key_scope(key, purpose, actor_id, installation_id, role):
    return (key["actor_id"] == actor_id and key["installation_id"] == installation_id
            and key["role"] == role and purpose in key["purposes"])


@_public
def validate_policy(policy: dict) -> dict:
    """Validate the complete closed policy and return a detached CJNFC copy."""
    result = _copy(policy)
    _closed(result, POLICY_FIELDS, "INVALID_POLICY_FIELDS")
    _require(result["schema"] == POLICY_SCHEMA and result["profile"] == PROFILE,
             "UNSUPPORTED_POLICY")
    _typed(result["transfer_id"], "handoff")
    source = result["source_pin"]
    _closed(source, {"store_id", "installation_id", "snapshot_digest", "acceptance_policy_digest"},
            "INVALID_SOURCE_PIN_FIELDS")
    _uuid(source["store_id"])
    _typed(source["installation_id"], "installation")
    _hex(source["snapshot_digest"])
    _hex(source["acceptance_policy_digest"])
    recipient = result["recipient"]
    _closed(recipient, {"store_id", "installation_id", "lineage_policy"},
            "INVALID_RECIPIENT_FIELDS")
    _uuid(recipient["store_id"])
    _typed(recipient["installation_id"], "installation")
    _require(source["store_id"] != recipient["store_id"] and
             source["installation_id"] != recipient["installation_id"],
             "RECIPIENT_NOT_INDEPENDENT_INSTALLATION")
    recipient["lineage_policy"] = validate_lineage_policy(recipient["lineage_policy"])
    _require(all(k["installation_id"] == recipient["installation_id"]
                 for k in recipient["lineage_policy"]["keys"]),
             "LINEAGE_POLICY_INSTALLATION_MISMATCH")
    keys = result["keys"]
    _require(type(keys) is list and 1 <= len(keys) <= MAX_KEYS, "INVALID_KEY_COUNT")
    seen_ids, seen_public = set(), set()
    for key in keys:
        _closed(key, KEY_FIELDS, "INVALID_POLICY_KEY_FIELDS")
        _typed(key["key_id"], "key")
        _require(type(key["role"]) is str and key["role"] in ROLES, "INVALID_ROLE")
        role = key["role"]
        _typed(key["actor_id"], "artifact" if role == "local_context_consumer" else "decision-actor")
        _typed(key["installation_id"], "installation")
        public = _public_key_bytes(key["public_key"])
        _require(key["key_id"] not in seen_ids and public not in seen_public, "DUPLICATE_POLICY_KEY")
        seen_ids.add(key["key_id"])
        seen_public.add(public)
        purposes = key["purposes"]
        _require(type(purposes) is list and len(purposes) > 0 and
                 all(type(p) is str and p in PURPOSES for p in purposes) and
                 len(set(purposes)) == len(purposes), "INVALID_KEY_PURPOSES")
        for purpose in purposes:
            expected = source if purpose in SOURCE_PURPOSES else recipient
            _require(key["installation_id"] == expected["installation_id"], "KEY_INSTALLATION_MISMATCH")
        if role == "local_context_consumer":
            _require(purposes == ["context_consumption_receipt"], "CONSUMER_PURPOSE_DENIED")
        else:
            _require("context_consumption_receipt" not in purposes, "CONSUMER_ROLE_REQUIRED")
    consumer = result["consumer"]
    _closed(consumer, {"consumer_id", "key_id", "version", "code_digest", "capabilities"},
            "INVALID_CONSUMER_FIELDS")
    _typed(consumer["consumer_id"], "artifact")
    _typed(consumer["key_id"], "key")
    _hex(consumer["code_digest"])
    _require(consumer["version"] == "context-consumer-v1" and
             consumer["capabilities"] == ["read", "search"], "UNSUPPORTED_CONSUMER")
    consumers = [k for k in keys if k["role"] == "local_context_consumer"]
    _require(len(consumers) == 1 and consumers[0]["key_id"] == consumer["key_id"] and
             consumers[0]["actor_id"] == consumer["consumer_id"], "CONSUMER_KEY_MISMATCH")
    # A consumer key may not also be provisioned as a human v1 acceptance key.
    _require(all(k["public_key"] != consumers[0]["public_key"] and
                 k["key_id"] != consumers[0]["key_id"]
                 for k in recipient["lineage_policy"]["keys"]), "CONSUMER_IS_NOT_HUMAN_OPERATOR")
    return result


@_public
def digest(domain: str, value) -> str:
    """CJNFC digest with an unambiguous caller-selected transfer domain."""
    _require(type(domain) is str and DOMAIN.fullmatch(domain), "INVALID_DIGEST_DOMAIN")
    return sha256_hex(PREFIX + domain.encode("ascii") + b"|" + canon_json_bytes(_copy(value)))


@_public
def policy_digest(policy: dict) -> str:
    return digest("POLICY", validate_policy(policy))


def _packet_message(unsigned):
    return (PREFIX + b"SIGNED|" + unsigned["purpose"].encode("ascii") + b"|"
            + canon_json_bytes(unsigned))


def _sign(message, keys, key_file):
    _require(bool(keys), "KEY_SCOPE_DENIED")
    serialization, private_type, _, _, unsupported = _crypto()
    raw = _read_private_key(Path(key_file))
    _require_pkcs8_pem(raw)
    try:
        private = serialization.load_pem_private_key(raw, password=None)
        _require(isinstance(private, private_type), "SIGNING_KEY_NOT_ED25519")
        public = base64.b64encode(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        key = next((k for k in keys if k["public_key"] == public), None)
        _require(key is not None, "SIGNING_KEY_NOT_AUTHORIZED")
        return key, base64.b64encode(private.sign(message)).decode("ascii")
    except unsupported:
        raise TransferAuthError("AUTHENTICATION_UNAVAILABLE") from None


def _verify(message, signature, public_key):
    _require(type(signature) is str, "INVALID_SIGNATURE_ENCODING")
    try:
        raw = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error):
        raise TransferAuthError("INVALID_SIGNATURE_ENCODING") from None
    _require(len(raw) == 64 and base64.b64encode(raw).decode("ascii") == signature,
             "INVALID_SIGNATURE_ENCODING")
    public = _public_key_bytes(public_key)
    _, _, public_type, invalid, unsupported = _crypto()
    try:
        public_type.from_public_bytes(public).verify(raw, message)
    except unsupported:
        raise TransferAuthError("AUTHENTICATION_UNAVAILABLE") from None
    except (invalid, ValueError, TypeError):
        raise TransferAuthError("SIGNATURE_INVALID") from None


@_public
def sign_packet(payload: dict, policy: dict, key_file, *, purpose: str,
                actor_id: str, installation_id: str, role="human_operator") -> dict:
    policy = validate_policy(policy)
    _scope(purpose, actor_id, installation_id, role)
    payload = _copy(payload)
    _require(type(payload) is dict, "INVALID_PACKET_PAYLOAD")
    unsigned = {"schema": SIGNED_SCHEMA, "policy_digest": policy_digest(policy),
        "purpose": purpose, "actor_id": actor_id, "installation_id": installation_id,
        "role": role, "payload": payload}
    # Account for proof/identity overhead before accessing the private key.
    _copy({**unsigned, "proof": {"algorithm": "ed25519", "key_id": "x" * 128,
                                "signature": "x" * 88}})
    keys = [k for k in policy["keys"] if _key_scope(k, purpose, actor_id, installation_id, role)]
    key, signature = _sign(_packet_message(unsigned), keys, key_file)
    return {**unsigned, "proof": {"algorithm": "ed25519", "key_id": key["key_id"],
                                  "signature": signature}}


@_public
def verify_packet(packet: dict, policy: dict, *, purpose: str, actor_id=None,
                  installation_id=None, role="human_operator") -> dict:
    policy = validate_policy(policy)
    packet = _copy(packet)
    _closed(packet, PACKET_FIELDS, "INVALID_SIGNED_PACKET_FIELDS")
    _require(packet["schema"] == SIGNED_SCHEMA, "UNSUPPORTED_SIGNED_PACKET")
    _require(packet["policy_digest"] == policy_digest(policy), "POLICY_PIN_MISMATCH")
    _scope(packet["purpose"], packet["actor_id"], packet["installation_id"], packet["role"])
    _require(packet["purpose"] == purpose and packet["role"] == role, "PACKET_SCOPE_MISMATCH")
    if actor_id is not None:
        _require(packet["actor_id"] == actor_id, "ACTOR_MISMATCH")
    if installation_id is not None:
        _require(packet["installation_id"] == installation_id, "INSTALLATION_MISMATCH")
    _require(type(packet["payload"]) is dict, "INVALID_PACKET_PAYLOAD")
    proof = packet["proof"]
    _closed(proof, {"algorithm", "key_id", "signature"}, "INVALID_PACKET_PROOF_FIELDS")
    _require(proof["algorithm"] == "ed25519", "UNSUPPORTED_SIGNATURE_ALGORITHM")
    key = next((k for k in policy["keys"] if k["key_id"] == proof["key_id"]), None)
    _require(key is not None and _key_scope(key, purpose, packet["actor_id"],
                 packet["installation_id"], role), "KEY_SCOPE_DENIED")
    unsigned = {k: v for k, v in packet.items() if k != "proof"}
    _verify(_packet_message(unsigned), proof["signature"], key["public_key"])
    return packet["payload"]


def _protocol_scope(document, policy, purpose, actor_id, installation_id):
    _require(purpose in {"handoff_issue", "lineage_acceptance"}, "INVALID_PROTOCOL_PURPOSE")
    expected_type = "handoff" if purpose == "handoff_issue" else "lineage_acceptance"
    document = _copy(document)
    validate_document(document, expected_type=expected_type)
    body = document["body"]
    if purpose == "handoff_issue":
        actor, installation = body["recording_operator_id"], body["issuer_installation_id"]
        _require(body["handoff_id"] == policy["transfer_id"] and
                 installation == policy["source_pin"]["installation_id"] and
                 body["recipient_binding"] == {"mode": "bound", "recipient_installation_id":
                     policy["recipient"]["installation_id"]}, "HANDOFF_SCOPE_MISMATCH")
        keys = [k for k in policy["keys"] if _key_scope(k, purpose, actor, installation, "human_operator")]
    else:
        actor = body["decision_actor"]["decision_actor_id"]
        installation = body["installation_id"]
        _require(body["decision_actor"]["decision_mode"] == "human_operator" and
                 body["recording_operator"]["operator_actor_id"] == actor,
                 "ACCEPTANCE_HUMAN_SCOPE_REQUIRED")
        _require(installation == policy["recipient"]["installation_id"], "ACCEPTANCE_INSTALLATION_MISMATCH")
        keys = [k for k in policy["recipient"]["lineage_policy"]["keys"]
                if k["decision_actor_id"] == actor and k["installation_id"] == installation]
    if actor_id is not None:
        _require(actor == actor_id, "ACTOR_MISMATCH")
    if installation_id is not None:
        _require(installation == installation_id, "INSTALLATION_MISMATCH")
    _require(bool(keys), "KEY_SCOPE_DENIED")
    return document, keys, actor, installation


@_public
def sign_protocol_document(document: dict, policy: dict, key_file, *, purpose: str,
                           actor_id: str, installation_id: str) -> dict:
    policy = validate_policy(policy)
    # Explicit identities are required for signing, including if a caller passes None.
    _typed(actor_id, "decision-actor")
    _typed(installation_id, "installation")
    document, keys, _, _ = _protocol_scope(document, policy, purpose, actor_id, installation_id)
    _require(document["proofs"] == [], "PROTOCOL_DOCUMENT_ALREADY_SIGNED")
    key, signature = _sign(proof_message_bytes(document), keys, key_file)
    document["proofs"] = [{"proof_type": "responsibility_head", "algorithm": "ed25519",
        "key_id": key["key_id"], "signed_payload": build_proof_payload(document),
        "signature": signature}]
    return document


@_public
def verify_protocol_document(document: dict, policy: dict, *, purpose: str,
                             actor_id=None, installation_id=None) -> dict:
    policy = validate_policy(policy)
    document, keys, actor, installation = _protocol_scope(
        document, policy, purpose, actor_id, installation_id)
    _require(len(document["proofs"]) == 1, "PROTOCOL_REQUIRES_ONE_SIGNATURE")
    proof = document["proofs"][0]
    key = next((k for k in keys if k["key_id"] == proof["key_id"]), None)
    _require(key is not None, "KEY_SCOPE_DENIED")
    _verify(proof_message_bytes(document), proof["signature"], key["public_key"])
    return {"key_id": key["key_id"], "actor_id": actor, "installation_id": installation,
            "policy_digest": policy_digest(policy), "purpose": purpose,
            "role": "human_operator", "scope": AUTH_SCOPE}
