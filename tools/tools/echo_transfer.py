#!/usr/bin/env python3
"""Explicit local Stage 2C lifecycle; no network transport or automatic adoption.

Candidates, signatures, imported context, and private keys stay outside Git
checkouts. Each apply uses the existing store's stable lock and exact CAS.
"""
from __future__ import annotations

import argparse
from pathlib import Path

try:
    from .echo_canonical import canon_json_bytes, sha256_hex
    from .echo_state import CLIError, OutputUncertain, _outside_checkout, _read_object, _write_object
    from .echo_state_store import PrivateStateStore, CommitUncertain, snapshot_digest
    from .echo_lineage_auth import CryptoUnavailable
except ImportError:
    from echo_canonical import canon_json_bytes, sha256_hex
    from echo_state import CLIError, OutputUncertain, _outside_checkout, _read_object, _write_object
    from echo_state_store import PrivateStateStore, CommitUncertain, snapshot_digest
    from echo_lineage_auth import CryptoUnavailable


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise CLIError("INVALID_ARGUMENTS")


def _parser():
    parser = Parser(description=__doc__)
    groups = parser.add_subparsers(dest="group", required=True)
    for group, actions in {
            "state": ("status", "verify"),
            "receiver": ("init",),
            "migration": ("prepare", "apply"),
            "action": ("prepare", "apply"),
            "candidate": ("sign",),
            "handoff": ("export", "file-facts"),
            "receipt": ("sign",),
            "activation": ("request", "reconcile"),
            "consumer": ("query", "stop")}.items():
        sub = groups.add_parser(group).add_subparsers(dest="action", required=True)
        for action in actions:
            cmd = sub.add_parser(action)
            if (group, action) != ("handoff", "file-facts"):
                cmd.add_argument("--state-dir", required=True)
            cmd.add_argument("--json", action="store_true", help="Output is always strict JSON")
            if group == "state":
                cmd.add_argument("--checkpoint")
            if group == "receiver" or (group, action) == ("migration", "prepare"):
                cmd.add_argument("--policy", required=True)
                cmd.add_argument("--expected-policy-digest", required=True)
            if group in {"migration", "action"}:
                cmd.add_argument("--expected-state-digest", required=True)
                if group == "action":
                    cmd.add_argument("--observed-envelope",
                        help="Required actual durable export file for export_confirm")
                if action == "prepare":
                    for field in ("actor-id", "request-id", "verification-time", "out"):
                        cmd.add_argument("--" + field, required=True)
                    if group == "migration":
                        cmd.add_argument("--artifacts", required=True,
                            help="Private JSON object containing the exact artifacts list")
                    else:
                        cmd.add_argument("--operation", required=True)
                        cmd.add_argument("--inputs", required=True,
                            help="Private JSON object with closed operation inputs")
                else:
                    cmd.add_argument("--signed", required=True)
                    cmd.add_argument("--applied-at", required=True)
                    if group == "migration":
                        cmd.add_argument("--expected-policy-digest", required=True)
            if group == "candidate":
                for field in ("candidate", "key-file", "out"):
                    cmd.add_argument("--" + field, required=True)
                cmd.add_argument("--expected-policy-digest",
                    help="Required independent local policy pin when signing migration")
                cmd.add_argument("--observed-envelope",
                    help="Required actual durable export file when signing export_confirm")
            if (group, action) == ("handoff", "export"):
                cmd.add_argument("--out", required=True)
            if (group, action) == ("handoff", "file-facts"):
                cmd.add_argument("--file", required=True)
                cmd.add_argument("--out", required=True)
            if group == "receipt":
                for field in ("kind", "actor-id", "key-file", "verification-time", "out"):
                    cmd.add_argument("--" + field, required=True)
            if group in {"activation", "consumer"}:
                cmd.add_argument("--control-dir", required=True)
                if group == "activation":
                    cmd.add_argument("--activation-id", required=True)
                    if action == "request":
                        cmd.add_argument("--key-file", required=True,
                            help="Registered local consumer attestation key, never operator key")
                elif action == "query":
                    cmd.add_argument("--request", required=True)
    return parser


def _model():
    try:
        from . import echo_transfer_model as model
    except ImportError:
        import echo_transfer_model as model
    return model


def _runtime():
    try:
        from . import echo_transfer_runtime as runtime
    except ImportError:
        import echo_transfer_runtime as runtime
    return runtime


def _observe_export(operation, inputs, path):
    """Observed durable output is stronger than a caller-authored hash claim."""
    if operation != "export_confirm":
        return
    if path is None:
        raise CLIError("OBSERVED_EXPORT_REQUIRED")
    try:
        from .echo_transfer_io import read_envelope
        from .echo_transfer_auth import digest
    except ImportError:
        from echo_transfer_io import read_envelope
        from echo_transfer_auth import digest
    envelope, raw = read_envelope(path, sync=True)
    observed = {"envelope_digest": digest("envelope", envelope),
        "raw_sha256": sha256_hex(raw), "byte_length": len(raw)}
    if canon_json_bytes(observed) != canon_json_bytes(inputs):
        raise CLIError("OBSERVED_EXPORT_MISMATCH")


def _run(args):
    if args.group == "consumer":
        runtime = _runtime()
        control = _outside_checkout(args.control_dir)
        if args.action == "query":
            # Context text is returned only by an explicit, bounded read/search.
            return runtime.query_consumer(control, _read_object(_outside_checkout(args.request)),
                state_dir=_outside_checkout(args.state_dir))
        return runtime.stop_consumer(control, state_dir=_outside_checkout(args.state_dir))
    if args.group == "activation":
        runtime = _runtime()
        params = dict(activation_id=args.activation_id)
        if args.action == "request":
            params["key_file"] = _outside_checkout(args.key_file)
            return runtime.request_activation(_outside_checkout(args.state_dir),
                _outside_checkout(args.control_dir), **params)
        return runtime.reconcile_activation(_outside_checkout(args.state_dir),
            _outside_checkout(args.control_dir), **params)
    model = _model()
    if (args.group, args.action) == ("handoff", "file-facts"):
        path = _outside_checkout(args.file)
        try:
            from .echo_transfer_auth import digest
            from .echo_transfer_io import read_envelope
        except ImportError:
            from echo_transfer_auth import digest
            from echo_transfer_io import read_envelope
        envelope, raw = read_envelope(path)
        # Hash the bytes actually read, including transport whitespace. The
        # canonical envelope hash has a separate meaning and domain.
        facts = {"envelope_digest": digest("envelope", envelope),
            "raw_sha256": sha256_hex(raw), "byte_length": len(raw)}
        _write_object(args.out, facts)
        return {"status": "observed_file_facts_prepared", **facts,
            "export_confirmed": False, "commit_uncertain": False}
    store = PrivateStateStore(_outside_checkout(args.state_dir))
    if args.group == "receiver":
        state = model.create_receiver(_read_object(_outside_checkout(args.policy)),
            expected_policy_digest=args.expected_policy_digest)
        result = model.inspect_state(state)
        with store.locked(initialize=True) as tx:
            tx.write(state)
        return {**result, "status": "recipient_policy_provisioned", "commit_uncertain": False}
    output = None
    with store.locked() as tx:
        state = tx.read()
        if args.group == "state":
            checkpoint = _read_object(_outside_checkout(args.checkpoint)) if args.checkpoint else None
            return model.inspect_state(state, checkpoint=checkpoint)
        if args.group == "migration" and args.action == "prepare":
            captured = _read_object(_outside_checkout(args.artifacts))
            if set(captured) != {"artifacts"}:
                raise CLIError("INVALID_CAPTURE_FIELDS")
            output = model.prepare_migration(state,
                _read_object(_outside_checkout(args.policy)), artifacts=captured["artifacts"],
                actor_id=args.actor_id, request_id=args.request_id,
                verification_time=args.verification_time,
                expected_state_digest=args.expected_state_digest,
                expected_policy_digest=args.expected_policy_digest)
        elif args.group == "action" and args.action == "prepare":
            inputs = _read_object(_outside_checkout(args.inputs))
            _observe_export(args.operation, inputs, args.observed_envelope)
            output = model.prepare_action(state, args.operation, inputs, actor_id=args.actor_id,
                request_id=args.request_id, verification_time=args.verification_time,
                expected_state_digest=args.expected_state_digest)
        elif args.group == "candidate":
            candidate = _read_object(_outside_checkout(args.candidate))
            body = candidate.get("body", {})
            _observe_export(body.get("operation"), body.get("inputs"), args.observed_envelope)
            signing = {}
            if args.expected_policy_digest is not None:
                signing["expected_policy_digest"] = args.expected_policy_digest
            output = model.sign_candidate(state, candidate, _outside_checkout(args.key_file), **signing)
        elif args.group in {"migration", "action"}:
            function = model.apply_migration if args.group == "migration" else model.apply_action
            applying = dict(expected_state_digest=args.expected_state_digest, applied_at=args.applied_at)
            if args.group == "migration":
                applying["expected_policy_digest"] = args.expected_policy_digest
            signed = _read_object(_outside_checkout(args.signed))
            new_state, result = function(state, signed, **applying)
            if args.group == "action" and not result.get("idempotent"):
                body = signed.get("payload", {})
                _observe_export(body.get("operation"), body.get("inputs"), args.observed_envelope)
            if snapshot_digest(new_state) != snapshot_digest(state):
                tx.write(new_state)
            return {**result, "status": "already_recorded" if result.get("idempotent") else "committed",
                "commit_uncertain": False}
        elif args.group == "handoff":
            output = model.make_envelope(state)
        elif args.group == "receipt":
            output = model.make_receipt(state, kind=args.kind, actor_id=args.actor_id,
                key_file=_outside_checkout(args.key_file), verification_time=args.verification_time)
        else:
            raise CLIError("UNSUPPORTED_OPERATION")
    _write_object(args.out, output)
    # Candidate and export publication happens only after the read lock closes.
    # Successful local output never claims delivery or adoption by another party.
    return {"status": "output_written", "group": args.group, "operation": args.action,
        "state_mutated": False, "remote_delivery": "UNKNOWN", "commit_uncertain": False}


def main(argv=None):
    arguments = None
    try:
        arguments = _parser().parse_args(argv)
        result = _run(arguments)
        code = 0
        if isinstance(result, dict):
            if result.get("launch_outcome") in {"failed_no_respawn", "process_exited"}:
                code = 2
            elif result.get("current") in {"unknown", "unavailable"}:
                code = 10
            elif isinstance(result.get("result"), dict) and result["result"].get("grant_current") is False:
                code = 10
    except CommitUncertain:
        result = {"status": "commit_uncertain", "commit_uncertain": True,
            "next_action": "inspect_state_and_request_before_any_retry"}
        code = 2
    except OutputUncertain:
        result = {"status": "output_uncertain", "commit_uncertain": False,
            "output_uncertain": True, "next_action": "inspect_output_before_any_retry"}
        code = 2
    except CryptoUnavailable:
        result = {"status": "unavailable", "error": "AUTHENTICATION_UNAVAILABLE",
            "commit_uncertain": False}
        code = 10
    except (ValueError, OSError, TypeError, KeyError, RuntimeError) as exc:
        # Only our closed model/auth error codes may leave the process.
        allowed = exc.__class__.__name__ in {"TransferError", "TransferAuthError", "TransferRuntimeError", "CLIError"}
        message = str(exc) if allowed else "INVALID_OR_UNSAFE_INPUT"
        if not message or len(message) > 100 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in message):
            message = "INVALID_OR_UNSAFE_INPUT"
        unavailable = message in {"AUTHENTICATION_UNAVAILABLE", "UNSUPPORTED_PROFILE",
            "CONSUMER_UNAVAILABLE", "ACTIVATION_UNKNOWN"}
        result = {"status": "unavailable" if unavailable else "refused", "error": message,
            "commit_uncertain": False}
        if arguments is not None and arguments.group == "activation":
            result.update(activation_state_may_have_changed=True,
                next_action="inspect_activation_and_control_before_any_retry_no_respawn")
            if message == "CONTROL_COMMIT_UNCERTAIN":
                result.update(status="activation_unknown", control_commit_uncertain=True,
                    current="unknown")
        code = 10 if unavailable else 2
    print(canon_json_bytes(result).decode("utf-8"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
