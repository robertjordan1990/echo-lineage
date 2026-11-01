#!/usr/bin/env python3
"""Offline synthetic 2B/2C walkthrough using the public command-line tools.

This creates demonstration keys and records fictional operator decisions. It
does not authorize a real installation, contact a model, or alter the release.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
T = "2032-01-02T03:04:06Z"
LATER = "2032-01-02T03:05:06Z"
EXPIRY = "2032-01-03T03:04:06Z"


class DemoError(ValueError):
    """A safe diagnostic code, never an arbitrary input or secret."""


def eid(kind, number):
    return f"urn:echo:{kind}:00000000-0000-4000-8000-{number:012d}"


SOURCE_ACTOR, RECIPIENT_ACTOR = eid("decision-actor", 1), eid("decision-actor", 2)
PAYLOAD, LEDGER, CONSUMER = eid("artifact", 20), eid("artifact", 520), eid("artifact", 901)
ACTIVATION = "00000000-0000-4000-8000-000000000401"


def output_path(value):
    path = Path(value)
    if ".." in path.parts:
        raise DemoError("PARENT_TRAVERSAL_FORBIDDEN")
    path = path if path.is_absolute() else Path.cwd() / path
    resolved = path.resolve(strict=False)
    if resolved == REPO or REPO in resolved.parents:
        raise DemoError("OUTPUT_INSIDE_CHECKOUT")
    for parent in [*reversed(path.parents), path]:
        if parent.is_symlink():
            raise DemoError("SYMLINK_FORBIDDEN")
        if (parent / ".git").exists() or (parent / ".git").is_symlink():
            raise DemoError("OUTPUT_INSIDE_GIT")
    if path.exists():
        raise DemoError("OUTPUT_ALREADY_EXISTS")
    if not path.parent.is_dir():
        raise DemoError("OUTPUT_PARENT_MISSING")
    for parent in path.parents:
        info = parent.stat()
        if info.st_uid not in (0, os.getuid()) or (
                info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
            raise DemoError("UNSAFE_OUTPUT_PARENT")
    return path


def dependencies():
    """Only pure input-producer/hash helpers; state transitions use the CLI."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sys.path.insert(0, str(REPO))
        from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
        from tools.tools.echo_lineage import finalize_document
        from tools.tools.echo_lineage_auth import policy_digest as legacy_digest
        from tools.tools.echo_transfer_auth import policy_digest
        from tools.tools.echo_transfer_runtime import consumer_code_digest
    except ImportError:
        raise DemoError("DEPENDENCIES_UNAVAILABLE") from None
    return dict(serialization=serialization, key_class=Ed25519PrivateKey,
        canonical=canon_json_bytes, hash=sha256_hex, finalize=finalize_document,
        legacy_digest=legacy_digest, policy_digest=policy_digest,
        code_digest=consumer_code_digest())


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


class Demo:
    def __init__(self, directory, helpers, *, quiet=False):
        self.directory, self.helpers, self.quiet = directory, helpers, quiet
        self.checks, self.scenarios, self.command_count = [], [], 0
        self.sequence = 0
        self.launch_possible = False
        self.consumer_scenario = None
        self.cleanup_result = {"attempted": False, "stopped_confirmed": True}
        self.transcript = (directory / "commands.txt").open("x", encoding="utf-8")
        self.progress = (directory / "progress.jsonl").open("x", encoding="utf-8")
        os.chmod(self.transcript.name, 0o600)
        os.chmod(self.progress.name, 0o600)

    def event(self, event, **fields):
        self.progress.write(json.dumps({"event": event, **fields}, ensure_ascii=False) + "\n")
        self.progress.flush()
        os.fsync(self.progress.fileno())

    def step(self, text):
        if not self.quiet:
            print(text, flush=True)
        self.event("step", message=text)

    def check(self, name, passed, detail=None):
        self.checks.append({"name": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise DemoError("DEMONSTRATION_CHECK_FAILED")

    def write(self, directory, name, value):
        return write_new(directory / name, self.helpers["canonical"](value) + b"\n")

    def invoke(self, cli, *arguments, expected=0, error=None):
        command = [sys.executable, "-B", str(REPO / "tools" / "tools" / (cli + ".py")),
                   *map(str, arguments)]
        self.command_count += 1
        self.transcript.write("$ " + shlex.join(command) + "\n")
        self.transcript.flush()
        os.fsync(self.transcript.fileno())
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        try:
            result = subprocess.run(command, cwd=self.directory, env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            self.event("command_uncertain", command_number=self.command_count)
            raise DemoError("COMMAND_TIMEOUT_INSPECT_BEFORE_RETRY") from None
        # CLI output contains safe result metadata; no key-generating command
        # or private-key bytes are ever written to this transcript.
        self.transcript.write(result.stdout)
        self.transcript.write(f"# exit {result.returncode}\n")
        self.transcript.flush()
        os.fsync(self.transcript.fileno())
        try:
            response = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise DemoError("INVALID_CLI_RESPONSE") from None
        if response.get("commit_uncertain") or response.get("output_uncertain"):
            raise DemoError("UNCERTAIN_OUTCOME_INSPECT_BEFORE_RETRY")
        if result.returncode != expected or (error and response.get("error") != error):
            self.event("unexpected_cli_result", command_number=self.command_count,
                exit_code=result.returncode, expected_exit=expected,
                error=response.get("error"))
            raise DemoError("UNEXPECTED_CLI_RESULT")
        return response

    def status(self, scenario, *, source=False, legacy=False):
        return self.invoke("echo_state" if legacy else "echo_transfer", "state", "status",
            "--state-dir", scenario["source" if source else "recipient"])

    def prepare(self, scenario, operation, inputs, *, source=False, request=None):
        self.sequence += 1
        name = f"{self.sequence:03d}-{operation}"
        state_dir = scenario["source" if source else "recipient"]
        digest = self.status(scenario, source=source)["snapshot_digest"]
        input_file = self.write(scenario["directory"], name + "-inputs.json", inputs)
        candidate = scenario["directory"] / (name + "-candidate.json")
        extra = ["--observed-envelope", scenario["envelope"]] if operation == "export_confirm" else []
        self.invoke("echo_transfer", "action", "prepare", "--state-dir", state_dir,
            "--operation", operation, "--inputs", input_file,
            "--actor-id", SOURCE_ACTOR if source else RECIPIENT_ACTOR,
            "--request-id", request or name, "--verification-time", LATER,
            "--expected-state-digest", digest, "--out", candidate, *extra)
        return candidate, digest, extra

    def sign(self, scenario, candidate, *, source=False, extra=()):
        signed = candidate.with_name(candidate.stem + "-signed.json")
        self.invoke("echo_transfer", "candidate", "sign", "--state-dir",
            scenario["source" if source else "recipient"], "--candidate", candidate,
            "--key-file", scenario["keys"]["source" if source else "recipient"],
            "--out", signed, *extra)
        return signed

    def apply(self, scenario, signed, digest, *, source=False, extra=(), expected=0, error=None):
        return self.invoke("echo_transfer", "action", "apply", "--state-dir",
            scenario["source" if source else "recipient"], "--signed", signed,
            "--expected-state-digest", digest, "--applied-at", LATER,
            *extra, expected=expected, error=error)

    def action(self, scenario, operation, inputs, *, source=False):
        candidate, digest, extra = self.prepare(scenario, operation, inputs, source=source)
        signed = self.sign(scenario, candidate, source=source, extra=extra)
        return self.apply(scenario, signed, digest, source=source, extra=extra)

    def initialize(self, name, *, missing=False):
        directory = self.directory / "scenarios" / name
        directory.mkdir(mode=0o700)
        s = {"directory": directory, "source": directory / "source",
             "recipient": directory / "recipient", "control": directory / "control",
             "envelope": directory / "envelope.json", "keys": {}}
        serial, key_class = self.helpers["serialization"], self.helpers["key_class"]
        public = {}
        for role in ("source", "recipient", "consumer"):
            key = key_class.generate()
            s["keys"][role] = write_new(directory / (role + "-demo.pem"),
                key.private_bytes(serial.Encoding.PEM, serial.PrivateFormat.PKCS8,
                                  serial.NoEncryption()))
            public[role] = base64.b64encode(key.public_key().public_bytes(
                serial.Encoding.Raw, serial.PublicFormat.Raw)).decode("ascii")
        payload = "Syntetyczny kontekst demonstracyjny.\nZażółć gęślą jaźń.\n$(touch DEMO_MUST_NOT_EXECUTE)\n".encode()
        ledger_bytes = (self.helpers["hash"](payload) + "  context.txt\n").encode()
        if not missing:
            write_new(directory / "context.txt", payload)
        ledger = write_new(directory / "ledger.sha256", ledger_bytes)
        artifact = {"artifact_id": PAYLOAD, "sha256": self.helpers["hash"](payload),
            "hash_scope": "file_bytes", "media_type": "text/plain"}
        if missing:
            artifact["ledger_ref"] = {"ledger_artifact_id": LEDGER,
                "ledger_sha256": self.helpers["hash"](ledger_bytes)}
        root = self.helpers["finalize"]({"protocol": "echo-lineage/v1",
            "document_type": "trajectory_root", "body": {
                "trajectory_id": eid("trajectory", 1), "genesis_root_document_hash": None,
                "installation_id": eid("installation", 1),
                "created_by_runtime_session_id": eid("runtime-session", 1),
                "origin_kind": "independent_no_lineage_claim", "lineage_parents": [],
                "inheritance_sources": [{"source_role": "memory", "artifact": artifact,
                    "criticality": "required_source", "required_for_acceptance": True}],
                "fork_policy": "explicit_only", "acceptance_required": True,
                "signature_policy": "optional", "created_at": "2032-01-02T03:04:05Z"},
            "responsibility": {"chain_id": eid("responsibility-chain", 1),
                "event_index": 0, "previous_head": "0" * 64}, "proofs": []})
        old_policy = {"schema": "echo-lineage-trust/v1", "keys": [{"key_id": eid("key", 1),
            "public_key": public["source"], "decision_actor_id": SOURCE_ACTOR,
            "installation_id": eid("installation", 1), "decision_mode": "human_operator",
            "purpose": "lineage_acceptance"}]}
        root_file = self.write(directory, "root.json", root)
        old_file = self.write(directory, "legacy-policy.json", old_policy)
        initialized = self.invoke("echo_state", "state", "init", "--state-dir", s["source"],
            "--root", root_file, "--trust-policy", old_file, "--expected-root-hash",
            root["document_hash"]["value"], "--root-artifact-id", eid("artifact", 100))
        bindings = (["--ledger", f"{LEDGER}={ledger}", "--ledger-root", f"{PAYLOAD}={directory}",
                     "--ledger-entry", f"{PAYLOAD}=context.txt"] if missing else
                    ["--target", f"{PAYLOAD}={directory / 'context.txt'}", "--target-root", f"{PAYLOAD}={directory}"])
        candidate, signed = directory / "2b-candidate.json", directory / "2b-signed.json"
        self.invoke("echo_state", "decision", "prepare", "--state-dir", s["source"],
            "--root", root_file, "--decision", "accepted_with_reservations" if missing else "accepted",
            "--actor-id", SOURCE_ACTOR, "--operator-id", SOURCE_ACTOR,
            "--request-id", "synthetic-legacy-accept", "--verification-time", T,
            "--expected-state-digest", initialized["snapshot_digest"], "--out", candidate, *bindings)
        self.invoke("echo_state", "decision", "sign", "--state-dir", s["source"],
            "--candidate", candidate, "--key-file", s["keys"]["source"], "--out", signed)
        self.invoke("echo_state", "decision", "apply", "--state-dir", s["source"],
            "--decision", signed, "--request-id", "synthetic-legacy-accept",
            "--expected-state-digest", initialized["snapshot_digest"], *bindings)
        legacy = self.status(s, source=True, legacy=True)
        lineage_policy = {"schema": "echo-lineage-trust/v1", "keys": [{"key_id": eid("key", 2),
            "public_key": public["recipient"], "decision_actor_id": RECIPIENT_ACTOR,
            "installation_id": eid("installation", 2), "decision_mode": "human_operator",
            "purpose": "lineage_acceptance"}]}
        purposes = {"source": ["state_migration", "handoff_issue", "transfer_export", "remote_receipt_ingest"],
            "recipient": ["transfer_receive", "transfer_receipt", "receiver_decision", "context_import_authorize",
                          "context_activation_authorize", "context_deactivate"],
            "consumer": ["context_consumption_receipt"]}
        policy = {"schema": "echo-lineage-transfer-trust/v1", "profile": "2C-h1-bound",
            "transfer_id": eid("handoff", 201), "source_pin": {"store_id": legacy["store_id"],
                "installation_id": eid("installation", 1), "snapshot_digest": legacy["snapshot_digest"],
                "acceptance_policy_digest": self.helpers["legacy_digest"](old_policy)},
            "recipient": {"store_id": str(uuid.uuid4()), "installation_id": eid("installation", 2),
                          "lineage_policy": lineage_policy},
            "keys": [{"key_id": eid("key", index), "public_key": public[role],
                "actor_id": CONSUMER if role == "consumer" else SOURCE_ACTOR if role == "source" else RECIPIENT_ACTOR,
                "installation_id": eid("installation", 1 if role == "source" else 2),
                "role": "local_context_consumer" if role == "consumer" else "human_operator",
                "purposes": purposes[role]} for index, role in enumerate(("source", "recipient", "consumer"), 1)],
            "consumer": {"consumer_id": CONSUMER, "key_id": eid("key", 3),
                "version": "context-consumer-v1", "code_digest": self.helpers["code_digest"],
                "capabilities": ["read", "search"]}}
        s["policy"] = self.write(directory, "transfer-policy.json", policy)
        s["pin"] = self.helpers["policy_digest"](policy)
        artifacts = ([{"artifact_id": PAYLOAD, "status": "missing",
            "ledger_b64": base64.b64encode(ledger_bytes).decode(), "ledger_entry": "context.txt"}]
            if missing else [{"artifact_id": PAYLOAD, "status": "present", "data_b64": base64.b64encode(payload).decode()}])
        capture = self.write(directory, "captured.json", {"artifacts": artifacts})
        candidate, signed = directory / "migration.json", directory / "migration-signed.json"
        self.invoke("echo_transfer", "migration", "prepare", "--state-dir", s["source"],
            "--policy", s["policy"], "--expected-policy-digest", s["pin"], "--artifacts", capture,
            "--actor-id", SOURCE_ACTOR, "--request-id", "synthetic-migrate", "--verification-time", T,
            "--expected-state-digest", legacy["snapshot_digest"], "--out", candidate)
        self.invoke("echo_transfer", "candidate", "sign", "--state-dir", s["source"],
            "--candidate", candidate, "--key-file", s["keys"]["source"],
            "--expected-policy-digest", s["pin"], "--out", signed)
        self.invoke("echo_transfer", "migration", "apply", "--state-dir", s["source"],
            "--signed", signed, "--expected-state-digest", legacy["snapshot_digest"],
            "--expected-policy-digest", s["pin"], "--applied-at", T)
        self.action(s, "issue", {"producer_runtime_session_id": eid("runtime-session", 1),
            "expires_at": EXPIRY}, source=True)
        self.action(s, "export_authorize", {}, source=True)
        self.invoke("echo_transfer", "handoff", "export", "--state-dir", s["source"], "--out", s["envelope"])
        facts = directory / "file-facts.json"
        self.invoke("echo_transfer", "handoff", "file-facts", "--file", s["envelope"], "--out", facts)
        self.action(s, "export_confirm", json.loads(facts.read_text()), source=True)
        self.invoke("echo_transfer", "receiver", "init", "--state-dir", s["recipient"],
            "--policy", s["policy"], "--expected-policy-digest", s["pin"])
        self.action(s, "receive", {"envelope": json.loads(s["envelope"].read_text()),
            "recipient_runtime_session_id": eid("runtime-session", 2)})
        return s

    def query(self, scenario, operation, **fields):
        self.sequence += 1
        request = self.write(scenario["directory"], f"query-{self.sequence}.json",
            {"operation": operation, "nonce": secrets.token_hex(32), **fields})
        return self.invoke("echo_transfer", "consumer", "query", "--state-dir", scenario["recipient"],
            "--control-dir", scenario["control"], "--request", request)

    def accepted(self):
        self.step("1. Pełny obieg: syntetyczny stan 2B, podpis, przekazanie i odbiór.")
        s = self.initialize("accepted")
        self.consumer_scenario = s
        receipt = s["directory"] / "received-receipt.json"
        self.invoke("echo_transfer", "receipt", "sign", "--state-dir", s["recipient"],
            "--kind", "received", "--actor-id", RECIPIENT_ACTOR, "--key-file", s["keys"]["recipient"],
            "--verification-time", LATER, "--out", receipt)
        self.action(s, "receipt_ingest", {"receipt": json.loads(receipt.read_text())}, source=True)
        status = self.status(s, source=True)
        self.check("accepted.receipt_verified", status["remote_milestones"]["received"] == "RECEIPT_VERIFIED"
            and status["remote_milestones"]["imported"] == "UNKNOWN")
        self.step("2. Osobna demonstracyjna decyzja, import danych i zgoda na konsumenta.")
        self.action(s, "decide", {"decision": "accepted"})
        self.action(s, "import", {"artifact_ids": [PAYLOAD]})
        self.check("accepted.import_without_activation", not s["control"].exists())
        self.action(s, "activate", {"activation_id": ACTIVATION, "artifact_ids": [PAYLOAD],
            "probe": {"artifact_id": PAYLOAD, "offset": 0, "length": 11, "nonce": secrets.token_hex(32)}})
        self.step("3. Własny lokalny proces: świeży probe, odczyt i wyszukiwanie w RAM.")
        self.launch_possible = True  # before the call: a failed/uncertain call can leave a child
        launched = self.invoke("echo_transfer", "activation", "request", "--state-dir", s["recipient"],
            "--control-dir", s["control"], "--activation-id", ACTIVATION, "--key-file", s["keys"]["consumer"])
        self.check("accepted.actual_consumer", launched.get("current") == "available")
        self.event("consumer_started", scenario="accepted")
        fresh = self.query(s, "status")
        self.check("accepted.fresh_probe", fresh["result"]["loaded"] and fresh["result"]["grant_current"]
            and len(fresh["result"]["probe_result_sha256"]) == 64)
        read = self.query(s, "read", artifact_id=PAYLOAD, offset=0, limit=4096)
        self.check("accepted.read", "Zażółć" in read["result"]["text"]
            and "$(touch DEMO_MUST_NOT_EXECUTE)" in read["result"]["text"]
            and not (self.directory / "DEMO_MUST_NOT_EXECUTE").exists())
        search = self.query(s, "search", query="Zażółć", limit=5)
        self.check("accepted.search", bool(search["result"].get("matches")))
        self.step("4. Odwołanie zgody: kolejny odczyt odrzucony; dawny receipt jest historyczny.")
        self.action(s, "deactivate", {"activation_id": ACTIVATION})
        self.sequence += 1
        request = self.write(s["directory"], f"denied-{self.sequence}.json", {
            "operation": "read", "nonce": secrets.token_hex(32), "artifact_id": PAYLOAD, "offset": 0, "limit": 100})
        denied = self.invoke("echo_transfer", "consumer", "query", "--state-dir", s["recipient"],
            "--control-dir", s["control"], "--request", request, expected=10)
        self.check("accepted.revoked_read_denied", denied["result"]["grant_current"] is False)
        historical = self.invoke("echo_transfer", "state", "verify", "--state-dir", s["recipient"])
        self.check("accepted.historical_receipt", historical["loaded_receipts_are_historical"]
            and historical["current_process_liveness"] == "UNKNOWN")
        self.cleanup()
        self.check("accepted.stopped", self.cleanup_result["stopped_confirmed"])
        self.scenarios.append({"name": "accepted", "status": "PASS", "decision": "accepted"})

    def refusal_scenario(self, name, decision, *, missing=False):
        self.step(f"5. Osobny scenariusz {name}: decyzja {decision}, bez importu niedozwolonych danych.")
        s = self.initialize(name, missing=missing)
        self.action(s, "decide", {"decision": decision})
        before = self.status(s)["snapshot_digest"]
        self.sequence += 1
        inputs = self.write(s["directory"], "refused-import-inputs.json", {"artifact_ids": [PAYLOAD]})
        code = "IMPORT_SCOPE_NOT_ACCEPTED" if missing else "IMPORT_NOT_ACCEPTED"
        self.invoke("echo_transfer", "action", "prepare", "--state-dir", s["recipient"],
            "--operation", "import", "--inputs", inputs, "--actor-id", RECIPIENT_ACTOR,
            "--request-id", "refused-import", "--verification-time", LATER,
            "--expected-state-digest", before, "--out", s["directory"] / "must-not-exist.json",
            expected=2, error=code)
        self.check(name + ".import_refused", self.status(s)["snapshot_digest"] == before
            and not (s["directory"] / "must-not-exist.json").exists())
        self.scenarios.append({"name": name, "status": "PASS", "decision": decision})

    def guards(self):
        self.step("6. Osobny scenariusz ochrony: zmiana podpisu, CAS, konflikty i dokładny replay.")
        s = self.initialize("guards")
        first, digest, _ = self.prepare(s, "decide", {"decision": "accepted"}, request="guard-decision")
        second, _, _ = self.prepare(s, "decide", {"decision": "declined"}, request="guard-decision")
        signed = self.sign(s, first)
        conflict = self.sign(s, second)
        changed = json.loads(signed.read_text())
        changed["payload"]["nonce"] = "f" * 64
        tampered = self.write(s["directory"], "tampered-signature.json", changed)
        self.apply(s, tampered, digest, expected=2)
        self.check("guards.tamper_rejected", self.status(s)["snapshot_digest"] == digest)
        self.apply(s, signed, "0" * 64, expected=2, error="STALE_STATE")
        self.check("guards.stale_cas_rejected", self.status(s)["snapshot_digest"] == digest)
        committed = self.apply(s, signed, digest)
        replay = self.apply(s, signed, digest)
        self.check("guards.exact_replay", replay.get("idempotent") is True
            and replay["snapshot_digest"] == committed["snapshot_digest"])
        self.apply(s, conflict, committed["snapshot_digest"], expected=2, error="REQUEST_CONFLICT")
        self.check("guards.request_conflict_rejected", self.status(s)["snapshot_digest"] == committed["snapshot_digest"])
        candidate, digest, _ = self.prepare(s, "import", {"artifact_ids": [PAYLOAD]})
        reused = json.loads(candidate.read_text())
        reused["body"]["nonce"] = json.loads(signed.read_text())["payload"]["nonce"]
        nonce_candidate = self.write(s["directory"], "reused-nonce-candidate.json", reused)
        nonce_signed = self.sign(s, nonce_candidate)
        self.apply(s, nonce_signed, digest, expected=2, error="NONCE_CONFLICT")
        self.check("guards.nonce_conflict_rejected", self.status(s)["snapshot_digest"] == digest)
        self.scenarios.append({"name": "guards", "status": "PASS", "decision": "accepted"})

    def cleanup(self):
        if not self.launch_possible:
            return
        s = self.consumer_scenario
        self.cleanup_result = {"attempted": True, "stop_ack_received": False, "stopped_confirmed": False}
        self.event("consumer_cleanup_started")
        try:
            # Cleanup is an exit request, never a retry of activation or apply.
            stopped = self.invoke("echo_transfer", "consumer", "stop", "--state-dir", s["recipient"],
                "--control-dir", s["control"])
            self.cleanup_result["stop_ack_received"] = stopped.get("current") == "stopping"
        except (DemoError, OSError):
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                status = self.invoke("echo_transfer", "activation", "reconcile", "--state-dir", s["recipient"],
                    "--control-dir", s["control"], "--activation-id", ACTIVATION, expected=10)
                outcome = ((status.get("inspection") or {}).get("observation") or {}).get("outcome")
                # not_running is produced only after public reconciliation
                # obtains the original consumer's exclusive instance lock.
                if status.get("current") == "unavailable" and outcome == "not_running":
                    self.cleanup_result["stopped_confirmed"] = True
                    self.launch_possible = False
                    break
            except (DemoError, OSError):
                pass
            time.sleep(0.05)
        self.event("consumer_cleanup_finished", **self.cleanup_result)

    def run(self):
        (self.directory / "scenarios").mkdir(mode=0o700)
        self.step("Demo lokalne: wyłącznie fikcyjne dane i świeże klucze demonstracyjne.\n"
                  "Decyzje operatorów są symulowane; nie są zgodą rzeczywistego operatora ani modelu.")
        self.accepted()
        self.refusal_scenario("reservations", "accepted_with_reservations", missing=True)
        self.refusal_scenario("declined", "declined")
        self.refusal_scenario("quarantine", "quarantined_integrity_failure")
        self.guards()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="Nowy, nieistniejący katalog poza Git")
    parser.add_argument("--json", action="store_true", help="Tylko końcowy raport JSON na stdout")
    args = parser.parse_args(argv)
    demo = None
    created = False
    result = {"schema": "echo-lineage-demo/v1", "status": "FAILED", "synthetic_only": True,
        "cloud_model_integrated": False, "production_keys_used": False,
        "operator_decisions": "automatic_synthetic_demonstration_not_real_consent",
        "checks": [], "scenarios": [], "commands_count": 0,
        "cleanup": {"attempted": False, "stopped_confirmed": True}}
    previous_handlers = {}

    def interrupted(signum, frame):
        raise DemoError("INTERRUPTED")

    try:
        directory = output_path(args.output_dir)
        helpers = dependencies()
        directory.mkdir(mode=0o700)
        created = True
        os.chmod(directory, 0o700)
        demo = Demo(directory, helpers, quiet=args.json)
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.signal(sig, interrupted)
        demo.run()
        result["status"] = "PASS"
    except (DemoError, OSError, ValueError, KeyboardInterrupt) as exc:
        result["error"] = str(exc) if isinstance(exc, DemoError) else "DEMO_FAILED"
    finally:
        if demo is not None:
            for sig in previous_handlers:
                signal.signal(sig, signal.SIG_IGN)
            try:
                demo.cleanup()
            except (DemoError, OSError, ValueError):
                result["error"] = "CLEANUP_FAILED"
                result["status"] = "FAILED"
            if not demo.cleanup_result["stopped_confirmed"]:
                result["status"], result["error"] = "FAILED", "CONSUMER_STOP_NOT_CONFIRMED"
            result.update(checks=demo.checks, scenarios=demo.scenarios,
                          commands_count=demo.command_count, cleanup=demo.cleanup_result)
            demo.transcript.close()
            demo.progress.close()
        if created:
            try:
                write_new(directory / "report.json", (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode())
            except OSError:
                result["status"], result["error"] = "FAILED", "REPORT_WRITE_FAILED"
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    print(json.dumps(result, ensure_ascii=False) if args.json else
          ("PASS: lokalne demo zakończone; raport: " + str(directory / "report.json")
           if result["status"] == "PASS" else "Odmowa lub błąd demo: " + result.get("error", "UNKNOWN")))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
