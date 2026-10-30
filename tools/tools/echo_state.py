#!/usr/bin/env python3
"""Separate, local-only Stage 2B CLI. Never activates a runtime or a handoff."""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import os
from pathlib import Path
import stat

try:
    from .echo_canonical import canon_json_bytes, loads_json_strict
    from .echo_lineage import _bindings_from_args
    from .echo_lineage_auth import CryptoUnavailable, sign_acceptance_document
    from .echo_state_model import (ModelError, apply_decision, create_state,
        inspect_state, prepare_decision, validate_candidate)
    from .echo_state_store import (CommitUncertain, MAX_SNAPSHOT_BYTES,
        PrivateStateStore, StateStoreError, _Anchor)
except ImportError:  # support direct execution without installing the package
    from echo_canonical import canon_json_bytes, loads_json_strict
    from echo_lineage import _bindings_from_args
    from echo_lineage_auth import CryptoUnavailable, sign_acceptance_document
    from echo_state_model import (ModelError, apply_decision, create_state,
        inspect_state, prepare_decision, validate_candidate)
    from echo_state_store import (CommitUncertain, MAX_SNAPSHOT_BYTES,
        PrivateStateStore, StateStoreError, _Anchor)

CHECKOUT = Path(__file__).resolve().parents[2]
DECISIONS = ("accepted", "accepted_with_reservations", "declined",
    "quarantined_integrity_failure")


class CLIError(ValueError):
    """Path-free public refusal code."""


class OutputUncertain(CLIError):
    """A newly created candidate/signature output needs manual inspection."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # Do not echo untrusted arguments or filenames into logs.
        raise CLIError("INVALID_ARGUMENTS")


def _absolute(path) -> Path:
    result = Path(path)
    if ".." in result.parts:
        raise CLIError("PARENT_TRAVERSAL_FORBIDDEN")
    return result if result.is_absolute() else Path.cwd() / result


def _outside_checkout(path) -> Path:
    result = _absolute(path)
    resolved = result.resolve(strict=False)
    if resolved == CHECKOUT or CHECKOUT in resolved.parents:
        raise CLIError("PRIVATE_ARTIFACT_INSIDE_CHECKOUT")
    # Also refuse another Git checkout, including linked worktrees (.git file).
    if any((parent / ".git").exists() for parent in (resolved, *resolved.parents)):
        raise CLIError("PRIVATE_ARTIFACT_INSIDE_CHECKOUT")
    return result


def _metadata(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in (0, os.getuid())):
        raise CLIError("UNSAFE_INPUT_FILE")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_object(path) -> dict:
    path = _absolute(path)
    # Traverse directory entries explicitly: O_NOFOLLOW on just the leaf does
    # not reject a symlink in a parent. Inputs may live in a public checkout.
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory)
        before = _metadata(os.fstat(fd))
        if before[5] > MAX_SNAPSHOT_BYTES:
            raise CLIError("INPUT_SIZE_LIMIT")
        raw = bytearray()
        while len(raw) <= MAX_SNAPSHOT_BYTES:
            chunk = os.read(fd, min(65536, MAX_SNAPSHOT_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise CLIError("INPUT_SIZE_LIMIT")
        if (before != _metadata(os.fstat(fd)) or before != _metadata(
                os.stat(path.name, dir_fd=directory, follow_symlinks=False))):
            raise CLIError("INPUT_CHANGED")
        value = loads_json_strict(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise CLIError("INPUT_MUST_BE_OBJECT")
        return value
    finally:
        if fd is not None:
            try:
                os.close(fd)
            finally:
                os.close(directory)
        else:
            os.close(directory)


def _write_object(path, value):
    path = _outside_checkout(path)
    data = canon_json_bytes(value) + b"\n"
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise CLIError("OUTPUT_SIZE_LIMIT")
    anchor = _Anchor()
    fd = None
    created = False
    failure = None
    try:
        directory = anchor.open(path.parent, False)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        created = True
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise CLIError("OUTPUT_WRITE_FAILED")
            offset += written
        os.fsync(fd)
        anchor.validate()
        opened = os.fstat(fd)
        entry = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (_metadata(opened) != _metadata(entry)
                or stat.S_IMODE(opened.st_mode) != 0o600):
            raise CLIError("OUTPUT_CHANGED")
        os.fsync(directory)
    except BaseException as exc:
        failure = exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as exc:
                failure = failure or exc
        try:
            anchor.close()
        except BaseException as exc:
            failure = failure or exc
    if failure is not None:
        if created:
            # Outputs never replace files. An interrupted new output is left
            # for inspection; it is not evidence of a committed state change.
            raise OutputUncertain("OUTPUT_UNCERTAIN") from failure
        raise failure


def _add_bindings(parser):
    for flag in ("target", "target-root", "ledger", "ledger-root", "ledger-entry"):
        parser.add_argument("--" + flag, action="append", default=[], metavar="ID=VALUE")


def _parser():
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="group", required=True)
    states = commands.add_parser("state").add_subparsers(dest="action", required=True)
    init = states.add_parser("init")
    init.add_argument("--state-dir", required=True)
    init.add_argument("--root", required=True)
    init.add_argument("--trust-policy", required=True)
    init.add_argument("--expected-root-hash", required=True)
    init.add_argument("--root-artifact-id", required=True)
    for name in ("status", "verify"):
        child = states.add_parser(name)
        child.add_argument("--state-dir", required=True)
        child.add_argument("--json", action="store_true", help="JSON is the default output")
        if name == "verify":
            child.add_argument("--checkpoint")
    decisions = commands.add_parser("decision").add_subparsers(dest="action", required=True)
    prepare = decisions.add_parser("prepare")
    for flag in ("state-dir", "root", "actor-id", "operator-id", "request-id",
            "verification-time", "expected-state-digest", "out"):
        prepare.add_argument("--" + flag, required=True)
    prepare.add_argument("--decision", choices=DECISIONS, required=True)
    _add_bindings(prepare)
    sign = decisions.add_parser("sign")
    for flag in ("state-dir", "candidate", "key-file", "out"):
        sign.add_argument("--" + flag, required=True)
    apply = decisions.add_parser("apply")
    for flag in ("state-dir", "decision", "request-id", "expected-state-digest"):
        apply.add_argument("--" + flag, required=True)
    apply.add_argument("--report", help="Optional exact copy of the embedded report")
    _add_bindings(apply)
    return parser


def _run(args):
    store = PrivateStateStore(_outside_checkout(args.state_dir))
    if args.group == "state" and args.action == "init":
        root, policy = _read_object(args.root), _read_object(args.trust_policy)
        state = create_state(root, policy, args.root_artifact_id)
        if root["document_hash"]["value"] != args.expected_root_hash:
            raise CLIError("EXPECTED_ROOT_HASH_MISMATCH")
        result = inspect_state(state)
        with store.locked(initialize=True) as transaction:
            transaction.write(state)
        return {**result, "status": "initialized", "commit_uncertain": False}
    with store.locked() as transaction:
        state = transaction.read()
        if args.group == "state":
            checkpoint = _read_object(args.checkpoint) if getattr(args, "checkpoint", None) else None
            return inspect_state(state, checkpoint)
        if args.action == "prepare":
            root = _read_object(args.root)
            if canon_json_bytes(root) != canon_json_bytes(state.get("root")):
                raise CLIError("ROOT_DOES_NOT_MATCH_STORE")
            bundle = prepare_decision(state, decision=args.decision,
                actor_id=args.actor_id, operator_id=args.operator_id,
                request_id=args.request_id, verification_time=args.verification_time,
                expected_state_digest=args.expected_state_digest,
                bindings=_bindings_from_args(args))
            result = {"status": "prepared", "request_id": bundle["request_id"],
                "runtime_activation": False, "decision_recorded": False}
        elif args.action == "sign":
            bundle = validate_candidate(state, _read_object(_outside_checkout(args.candidate)))
            bundle["document"] = sign_acceptance_document(bundle["document"],
                state["policy"], _outside_checkout(args.key_file))
            result = {"status": "signed", "request_id": bundle["request_id"],
                "runtime_activation": False, "decision_recorded": False}
        else:
            bundle = _read_object(_outside_checkout(args.decision))
            if bundle.get("request_id") != args.request_id:
                raise CLIError("REQUEST_ID_MISMATCH")
            if args.report and canon_json_bytes(_read_object(args.report)) != canon_json_bytes(bundle.get("report")):
                raise CLIError("REPORT_COPY_MISMATCH")
            new_state, result = apply_decision(state, bundle, bindings=_bindings_from_args(args),
                expected_state_digest=args.expected_state_digest)
            if not result["idempotent"]:
                transaction.write(new_state)
            return {**result, "status": "already_recorded" if result["idempotent"] else "committed",
                "decision_recorded": True, "commit_uncertain": False}
    # Candidate/signature outputs are published after the read transaction has
    # closed successfully. A store cleanup failure cannot hide a completed output.
    _write_object(args.out, bundle)
    return result


def main(argv=None):
    try:
        result = _run(_parser().parse_args(argv))
        code = 0
    except CommitUncertain:
        result = {"status": "commit_uncertain", "commit_uncertain": True,
            "next_action": "inspect_state_and_request_before_any_retry", "runtime_activation": False}
        code = 2
    except OutputUncertain:
        result = {"status": "output_uncertain", "output_uncertain": True,
            "commit_uncertain": False, "next_action": "inspect_output_before_any_retry",
            "runtime_activation": False}
        code = 2
    except CryptoUnavailable:
        result = {"status": "unavailable", "error": "AUTHENTICATION_UNAVAILABLE",
            "commit_uncertain": False, "runtime_activation": False}
        code = 10
    except ModelError as exc:
        unavailable = str(exc) in {"AUTHENTICATION_UNAVAILABLE", "UNSUPPORTED_ROOT_PROFILE",
            "UNSUPPORTED_STATE_PROFILE"}
        result = {"status": "unavailable" if unavailable else "refused", "error": str(exc),
            "commit_uncertain": False, "runtime_activation": False}
        code = 10 if unavailable else 2
    except (ValueError, OSError, TypeError, KeyError, RuntimeError):
        # Do not expose arbitrary parser/crypto/filesystem error strings.
        result = {"status": "refused", "error": "INVALID_OR_UNSAFE_INPUT",
            "commit_uncertain": False, "runtime_activation": False}
        code = 2
    print(canon_json_bytes(result).decode("utf-8"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
