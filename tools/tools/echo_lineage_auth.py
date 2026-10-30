"""Scoped Ed25519 authentication for the private Stage 2B state profile.

This module authenticates possession of an explicitly authorized key.  It does
not establish biological/model identity, validate a report artifact, or change
the Stage 2A verifier's deliberately unauthenticated results.  Cryptography is
an optional capability, imported only when signing or verifying a signature.
"""

from __future__ import annotations

import base64
import binascii
import copy
import os
from pathlib import Path
import stat
from typing import Any

try:
    from .echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from .echo_lineage import (
        LineageError, _check_fields, _validate_typed_id, build_proof_payload,
        proof_message_bytes, validate_document,
    )
except ImportError:  # direct script execution
    from echo_canonical import canon_json_bytes, loads_json_strict, sha256_hex
    from echo_lineage import (
        LineageError, _check_fields, _validate_typed_id, build_proof_payload,
        proof_message_bytes, validate_document,
    )


POLICY_SCHEMA = "echo-lineage-trust/v1"
POLICY_DOMAIN = b"ECHO|STATE|v1|POLICY|"
MAX_POLICY_KEYS = 256
MAX_PRIVATE_KEY_BYTES = 16 * 1024
AUTH_SCOPE = "scoped_key_holder_not_biological_or_model_identity"
_ED25519_P = 2**255 - 19
_ED25519_D = -121665 * pow(121666, _ED25519_P - 2, _ED25519_P) % _ED25519_P
_ED25519_SQRT_M1 = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)
# The five sign-masked y coordinates in libsodium 1.0.20's published
# ge25519_has_small_order table cover all eight canonical torsion points.
# Its additional p/p+1 aliases are covered by the general y >= p rejection.
# https://github.com/jedisct1/libsodium/blob/1.0.20/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
_ED25519_SMALL_ORDER_Y = frozenset({
    0, 1, _ED25519_P - 1,
    2707385501144840649318225287225658788936804267575313519463743609750303402022,
    55188659117513257062467267217118295137698188065244968500265048394206261417927,
})


class StateAuthError(ValueError):
    """Authentication, policy, or private-key input was refused."""


class CryptoUnavailable(StateAuthError):
    """The optional Ed25519 capability is unavailable; no proof was verified."""


def _validate_public_point(raw: bytes) -> None:
    """Reject invalid/noncanonical encodings and pure torsion public keys.

    Public-input decoding follows RFC 8032 section 5.1.3; no private scalar or
    signature operation is implemented here.  Signature checks use cryptography.
    https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3
    """
    encoded = int.from_bytes(raw, "little")
    sign, y = encoded >> 255, encoded & ((1 << 255) - 1)
    if y >= _ED25519_P:
        raise StateAuthError("public_key has a noncanonical Ed25519 point encoding")
    y_squared = y * y % _ED25519_P
    x_squared = ((y_squared - 1)
                 * pow(_ED25519_D * y_squared + 1, _ED25519_P - 2, _ED25519_P)
                 % _ED25519_P)
    x = pow(x_squared, (_ED25519_P + 3) // 8, _ED25519_P)
    if x * x % _ED25519_P != x_squared:
        x = x * _ED25519_SQRT_M1 % _ED25519_P
    if x * x % _ED25519_P != x_squared or (x == 0 and sign == 1):
        raise StateAuthError("public_key is not a canonical Ed25519 curve point")
    if y in _ED25519_SMALL_ORDER_Y:
        raise StateAuthError("public_key is a small-order Ed25519 point")


def _public_key_bytes(value: Any) -> bytes:
    if not isinstance(value, str):
        raise StateAuthError("public_key must be canonical base64 for 32 bytes")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise StateAuthError("public_key must be canonical base64 for 32 bytes") from None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise StateAuthError("public_key must be canonical base64 for 32 bytes")
    _validate_public_point(raw)
    return raw


def validate_policy(value: dict) -> dict:
    """Validate a closed, explicitly scoped policy and return a detached copy."""
    try:
        if not isinstance(value, dict):
            raise StateAuthError("trust policy must be an object")
        _check_fields(value, required={"schema", "keys"}, context="trust policy")
        if value["schema"] != POLICY_SCHEMA:
            raise StateAuthError("unsupported trust policy schema")
        keys = value["keys"]
        if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_POLICY_KEYS:
            raise StateAuthError("trust policy requires 1 through 256 keys")
        seen_ids: set[str] = set()
        seen_public: set[bytes] = set()
        for key in keys:
            if not isinstance(key, dict):
                raise StateAuthError("trust policy key must be an object")
            _check_fields(
                key,
                required={"key_id", "public_key", "decision_actor_id",
                          "installation_id", "decision_mode", "purpose"},
                context="trust policy key",
            )
            for field, kind in (("key_id", "key"),
                                ("decision_actor_id", "decision-actor"),
                                ("installation_id", "installation")):
                _validate_typed_id(key[field], kind, f"trust policy key.{field}")
            if key["decision_mode"] != "human_operator":
                raise StateAuthError("trust policy supports only human_operator")
            if key["purpose"] != "lineage_acceptance":
                raise StateAuthError("trust policy key purpose must be lineage_acceptance")
            public = _public_key_bytes(key["public_key"])
            if key["key_id"] in seen_ids or public in seen_public:
                raise StateAuthError("trust policy contains duplicate key_id or public_key")
            seen_ids.add(key["key_id"])
            seen_public.add(public)
        return loads_json_strict(canon_json_bytes(value))
    except (LineageError, TypeError, KeyError, RecursionError):
        raise StateAuthError("invalid trust policy structure") from None


def policy_digest(policy: dict) -> str:
    """Hash the canonical validated policy with the Stage 2B domain separator."""
    return sha256_hex(POLICY_DOMAIN + canon_json_bytes(validate_policy(policy)))


def _acceptance(document: dict) -> dict:
    try:
        result = copy.deepcopy(document)
        validate_document(result, expected_type="lineage_acceptance")
    except (ValueError, TypeError, KeyError, RecursionError):
        raise StateAuthError("invalid finalized lineage_acceptance document") from None
    if result["body"]["decision_actor"]["decision_mode"] != "human_operator":
        raise StateAuthError("this profile authenticates only human_operator decisions")
    body = result["body"]
    if (body["decision_actor"]["decision_actor_id"]
            != body["recording_operator"]["operator_actor_id"]):
        raise StateAuthError("distinct recording operator requires authenticated delegation")
    return result


def _check_scope(key: dict, document: dict) -> None:
    body = document["body"]
    actor = body["decision_actor"]
    if (key["decision_actor_id"] != actor["decision_actor_id"]
            or key["installation_id"] != body["installation_id"]
            or key["decision_mode"] != actor["decision_mode"]
            or key["purpose"] != document["document_type"]):
        raise StateAuthError("signing key is not authorized for this decision scope")


def _crypto() -> tuple:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
    except (ImportError, OSError):
        raise CryptoUnavailable("optional cryptography Ed25519 capability is unavailable") from None
    return (serialization, Ed25519PrivateKey, Ed25519PublicKey,
            InvalidSignature, UnsupportedAlgorithm)


def verify_acceptance_signature(document: dict, policy: dict) -> dict:
    """Verify exactly one authorized proof; report artifact checks are external."""
    validated_policy = validate_policy(policy)
    acceptance = _acceptance(document)
    if len(acceptance["proofs"]) != 1:
        raise StateAuthError("exactly one acceptance signature is required")
    proof = acceptance["proofs"][0]
    key = next((item for item in validated_policy["keys"]
                if item["key_id"] == proof["key_id"]), None)
    if key is None:
        raise StateAuthError("acceptance signing key is not in the trust policy")
    _check_scope(key, acceptance)
    _, _, public_type, invalid_signature, unsupported = _crypto()
    try:
        public_type.from_public_bytes(_public_key_bytes(key["public_key"])).verify(
            base64.b64decode(proof["signature"], validate=True),
            proof_message_bytes(acceptance),
        )
    except unsupported:
        raise CryptoUnavailable("Ed25519 capability is unavailable") from None
    except (invalid_signature, ValueError, TypeError):
        raise StateAuthError("acceptance signature verification failed") from None
    return {
        "key_id": key["key_id"],
        "decision_actor_id": key["decision_actor_id"],
        "installation_id": key["installation_id"],
        "policy_digest": policy_digest(validated_policy),
        "scope": AUTH_SCOPE,
    }


def _private_metadata(info: os.stat_result) -> tuple:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 0 < info.st_size <= MAX_PRIVATE_KEY_BYTES):
        raise StateAuthError("private signing key must be a private owned regular file")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_private_key(path: Path) -> bytes:
    """Bounded read with descriptor/path checks; never expose OS error details."""
    descriptor = None
    try:
        initial = _private_metadata(os.lstat(path))
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        if _private_metadata(os.fstat(descriptor)) != initial:
            raise StateAuthError("private signing key changed while opening")
        chunks = []
        size = 0
        while size <= MAX_PRIVATE_KEY_BYTES:
            chunk = os.read(descriptor, MAX_PRIVATE_KEY_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_PRIVATE_KEY_BYTES:
            raise StateAuthError("private signing key exceeds the size limit")
        if (_private_metadata(os.fstat(descriptor)) != initial
                or _private_metadata(os.lstat(path)) != initial):
            raise StateAuthError("private signing key changed while reading")
        return b"".join(chunks)
    except (OSError, TypeError, ValueError, AttributeError):
        raise StateAuthError("cannot safely read private signing key") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise StateAuthError("cannot safely close private signing key") from None


def _require_pkcs8_pem(raw: bytes) -> None:
    lines = raw.strip().splitlines()
    if (len(lines) < 3 or lines[0] != b"-----BEGIN PRIVATE KEY-----"
            or lines[-1] != b"-----END PRIVATE KEY-----"):
        raise StateAuthError("private signing key must be unencrypted PKCS8 PEM")
    try:
        payload = b"".join(lines[1:-1])
        decoded = base64.b64decode(payload, validate=True)
        if base64.b64encode(decoded) != payload:
            raise ValueError
    except (ValueError, binascii.Error):
        raise StateAuthError("private signing key must be unencrypted PKCS8 PEM") from None


def sign_acceptance_document(
    document: dict, policy: dict, private_key_path: Path,
) -> dict:
    """Sign an already finalized unsigned decision, changing only its proofs."""
    validated_policy = validate_policy(policy)
    acceptance = _acceptance(document)
    if acceptance["proofs"]:
        raise StateAuthError("signing requires an unsigned acceptance document")
    serialization, private_type, _, _, unsupported = _crypto()
    raw = _read_private_key(private_key_path)
    _require_pkcs8_pem(raw)
    try:
        private = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(private, private_type):
            raise StateAuthError("private signing key must be Ed25519")
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        encoded_public = base64.b64encode(public).decode("ascii")
        key = next((item for item in validated_policy["keys"]
                    if item["public_key"] == encoded_public), None)
        if key is None:
            raise StateAuthError("private signing key is not in the trust policy")
        _check_scope(key, acceptance)
        signature = private.sign(proof_message_bytes(acceptance))
    except unsupported:
        raise CryptoUnavailable("Ed25519 capability is unavailable") from None
    except StateAuthError:
        raise
    except (ValueError, TypeError):
        raise StateAuthError("cannot load or use private Ed25519 signing key") from None
    acceptance["proofs"] = [{
        "proof_type": "responsibility_head",
        "algorithm": "ed25519",
        "key_id": key["key_id"],
        "signed_payload": build_proof_payload(acceptance),
        "signature": base64.b64encode(signature).decode("ascii"),
    }]
    return acceptance
