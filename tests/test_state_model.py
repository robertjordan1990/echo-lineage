from __future__ import annotations

import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage_test_helpers import root_document, source, artifact, eid
from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
from tools.tools.echo_lineage import finalize_document, validate_document, VerificationBindings
from tools.tools.echo_lineage_auth import sign_acceptance_document, CryptoUnavailable
from tools.tools.echo_state_store import snapshot_digest
from tools.tools import echo_state_model as model
from tools.tools.echo_state_model import (ModelError, create_state, inspect_state,
    prepare_decision, apply_decision)

T = "2032-01-02T03:04:06Z"
APPLIED = "2032-01-02T03:05:06Z"
STORE = "00000000-0000-4000-8000-000000000099"
ACTOR = OPERATOR = eid("decision-actor", 1)
ROOT_ARTIFACT = eid("artifact", 100)


class StateModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        # Published synthetic seed, never real user key material.
        key = Ed25519PrivateKey.from_private_bytes(bytes([71]) * 32)
        self.keyfile = self.directory / "synthetic.pem"
        self.keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.keyfile.chmod(0o600)
        self.policy = {"schema": "echo-lineage-trust/v1", "keys": [{
            "key_id": eid("key", 1), "public_key": base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            "decision_actor_id": ACTOR, "installation_id": eid("installation", 1),
            "decision_mode": "human_operator", "purpose": "lineage_acceptance"}]}
        self.root = root_document()
        self.state = create_state(self.root, self.policy, ROOT_ARTIFACT, store_id=STORE)

    def prepare(self, state=None, decision="accepted", request_id="request-1", bindings=None, **kw):
        state = self.state if state is None else state
        params = dict(decision=decision, actor_id=ACTOR, operator_id=OPERATOR,
            request_id=request_id, verification_time=T, bindings=bindings,
            expected_state_digest=snapshot_digest(state))
        params.update(kw)
        return prepare_decision(state, **params)

    def sign(self, bundle):
        result = copy.deepcopy(bundle)
        result["document"] = sign_acceptance_document(result["document"], self.policy, self.keyfile)
        return result

    def apply(self, bundle, state=None, bindings=None, **kw):
        state = self.state if state is None else state
        params = dict(bindings=bindings, expected_state_digest=snapshot_digest(state), applied_at=APPLIED)
        params.update(kw)
        return apply_decision(state, bundle, **params)

    def setup_source(self, *, criticality="required_source", ledger=False):
        payload = b"synthetic immutable target\n"
        self.target = self.directory / "payload.bin"
        self.target.write_bytes(payload)
        wanted = sha256_hex(payload)
        ledger_file = self.directory / "ledger.sha256"
        ledger_bytes = (wanted + "  payload.bin\n").encode()
        ledger_file.write_bytes(ledger_bytes)
        src = source(2, sha256=wanted, criticality=criticality,
            ledger_sha256=sha256_hex(ledger_bytes) if ledger else None)
        self.root = root_document(sources=[src])
        self.state = create_state(self.root, self.policy, ROOT_ARTIFACT, store_id=STORE)
        bindings = VerificationBindings(target_paths={eid("artifact", 2): self.target},
            target_roots={eid("artifact", 2): self.directory})
        if ledger:
            bindings.ledger_paths[eid("artifact", 502)] = ledger_file
            bindings.ledger_roots[eid("artifact", 2)] = self.directory
            bindings.ledger_entries[eid("artifact", 2)] = "payload.bin"
        return bindings

    def resign(self, bundle):
        b = copy.deepcopy(bundle)
        b["document"]["body"]["verification_report_hash"] = sha256_hex(canon_json_bytes(b["report"]))
        b["document"]["proofs"] = []
        b["document"] = finalize_document(b["document"])
        return self.sign(b)

    def test_bootstrap_is_detached_unaccepted_and_no_current_read(self):
        with mock.patch.object(model, "verify_document_read_only", side_effect=AssertionError("no read")):
            status = inspect_state(self.state)
        self.assertIsNone(status["active"])
        self.assertEqual(status["bootstrap_status"], "UNACCEPTED")
        self.assertFalse(status["root_author_authenticated"])
        self.assertFalse(status["integrity_blocked"])
        self.assertFalse(status["local_acceptance_active"])
        self.assertFalse(status["current_targets_rechecked"])
        self.assertEqual(status["rollback_protection"], "not_externally_anchored")
        self.root["body"]["created_at"] = "modified"
        self.policy["keys"][0]["purpose"] = "modified"
        self.assertNotEqual(self.state["root"], self.root)
        self.assertNotEqual(self.state["policy"], self.policy)

    def test_genesis_and_root_slot_are_domain_bound(self):
        value = {k: self.state[k] for k in ("store_id", "root", "root_artifact_id", "policy")}
        self.assertEqual(self.state["journal_head"], sha256_hex(model.GENESIS_DOMAIN + canon_json_bytes(value)))
        self.assertEqual(list(self.state["slots"].values()), [self.root["document_hash"]["value"]])
        self.assertEqual(len(self.state["edges"]), 1)

    def test_random_store_uuid_is_valid_and_unique(self):
        first = create_state(self.root, self.policy, ROOT_ARTIFACT)
        second = create_state(self.root, self.policy, ROOT_ARTIFACT)
        self.assertNotEqual(first["store_id"], second["store_id"])
        inspect_state(first)

    def test_reject_unsupported_root_profiles_and_artifact_collision(self):
        for field, value in (("origin_kind", "continuation"), ("signature_policy", "required")):
            root = copy.deepcopy(self.root)
            root["body"][field] = value
            root = finalize_document(root)
            with self.subTest(field=field), self.assertRaises(ModelError):
                create_state(root, self.policy, ROOT_ARTIFACT)
        self.setup_source()
        with self.assertRaisesRegex(ModelError, "COLLISION"):
            create_state(self.root, self.policy, eid("artifact", 2))

    def test_reject_other_installation_policy(self):
        self.policy["keys"][0]["installation_id"] = eid("installation", 9)
        with self.assertRaisesRegex(ModelError, "INSTALLATION"):
            create_state(self.root, self.policy, ROOT_ARTIFACT)

    def test_root_artifact_id_cannot_alias_source_ledger_id(self):
        self.setup_source(ledger=True)
        with self.assertRaisesRegex(ModelError, "COLLISION"):
            create_state(self.root, self.policy, eid("artifact", 502))

    def test_prepare_unsigned_has_separate_report_without_state_change(self):
        before = copy.deepcopy(self.state)
        b = self.prepare()
        self.assertEqual(self.state, before)
        self.assertEqual(b["document"]["proofs"], [])
        validate_document(b["document"])
        self.assertEqual(b["report"]["schema"], model.REPORT_SCHEMA)
        self.assertEqual(b["report"]["pre_state"]["snapshot_digest"], snapshot_digest(before))
        self.assertEqual(b["document"]["body"]["verification_report_hash"], sha256_hex(canon_json_bytes(b["report"])))
        self.assertEqual(b["document"]["responsibility"]["previous_head"], self.root["resulting_head"])

    def test_prepare_rejects_wrong_actor_or_malformed_inputs(self):
        for kw in ({"actor_id": eid("decision-actor", 99)}, {"operator_id": "not-an-id"},
                   {"operator_id": eid("decision-actor", 2)},
                   {"verification_time": "2032-02-30T00:00:00Z"}, {"verification_time": "2032-01-02T03:04:06+01:00"},
                   {"request_id": "../private"}, {"expected_state_digest": "a" * 64}):
            with self.subTest(kw=kw), self.assertRaises(ModelError):
                self.prepare(**kw)

    def test_unsigned_decision_cannot_apply_and_preserves_input(self):
        before = copy.deepcopy(self.state)
        with self.assertRaises(ModelError):
            self.apply(self.prepare())
        self.assertEqual(self.state, before)

    def test_signed_acceptance_is_replayable_and_not_runtime_activation(self):
        b = self.sign(self.prepare())
        state, result = self.apply(b)
        status = inspect_state(state)
        self.assertEqual(state["generation"], 1)
        self.assertEqual(result["status"], "applied_in_memory")
        self.assertTrue(result["current_targets_rechecked"])
        self.assertFalse(result["runtime_activation"])
        self.assertEqual(status["active"]["accepted_artifact_ids"], [ROOT_ARTIFACT])
        self.assertEqual(status["latest_decision"]["decision"], "accepted")
        self.assertEqual(state["records"][0]["applied_at"], APPLIED)
        self.assertEqual(state["records"][0]["report"]["verification_time"], T)
        self.assertEqual(self.state["generation"], 0)

    def test_decline_preserves_previous_active_acceptance(self):
        first, _ = self.apply(self.sign(self.prepare()))
        second, _ = self.apply(self.sign(self.prepare(first, "declined", "request-2")), first)
        self.assertEqual(second["active"], first["active"])
        self.assertEqual(inspect_state(second)["latest_decision"]["decision"], "declined")
        self.assertEqual(second["records"][1]["document"]["body"]["previous_acceptance_hash"],
            first["records"][0]["document"]["document_hash"]["value"])
        self.assertEqual(second["generation"], 2)

    def test_quarantine_requires_real_critical_mismatch_and_preserves_active(self):
        bindings = self.setup_source()
        first, _ = self.apply(self.sign(self.prepare(bindings=bindings)), bindings=bindings)
        self.target.write_bytes(b"changed")
        for decision in ("accepted", "accepted_with_reservations"):
            with self.assertRaisesRegex(ModelError, "NOT_PERMITTED"):
                self.prepare(first, decision, "bad-" + decision, bindings)
        b = self.sign(self.prepare(first, "quarantined_integrity_failure", "request-2", bindings))
        state, _ = self.apply(b, first, bindings)
        self.assertEqual(state["active"], first["active"])
        self.assertEqual(inspect_state(state)["latest_decision"]["decision"], "quarantined_integrity_failure")
        with self.assertRaises(ModelError):
            self.prepare(self.state, "quarantined_integrity_failure", bindings=None)

    def test_quarantine_then_valid_decline_remains_blocked_until_new_acceptance(self):
        bindings = self.setup_source()
        original_bytes = self.target.read_bytes()
        first, _ = self.apply(self.sign(self.prepare(bindings=bindings)), bindings=bindings)
        self.assertTrue(inspect_state(first)["local_acceptance_active"])
        self.target.write_bytes(b"corrupted after acceptance")
        quarantined, receipt = self.apply(self.sign(self.prepare(first,
            "quarantined_integrity_failure", "quarantine", bindings)), first, bindings)
        self.assertTrue(receipt["integrity_blocked"])
        self.assertFalse(receipt["local_acceptance_active"])
        self.target.write_bytes(original_bytes)
        declined, _ = self.apply(self.sign(self.prepare(quarantined,
            "declined", "decline-repaired", bindings)), quarantined, bindings)
        status = inspect_state(declined)
        self.assertTrue(status["integrity_blocked"])
        self.assertFalse(status["local_acceptance_active"])
        self.assertEqual(status["active"], first["active"])
        accepted, receipt = self.apply(self.sign(self.prepare(declined,
            "accepted", "accept-repaired", bindings)), declined, bindings)
        self.assertFalse(inspect_state(accepted)["integrity_blocked"])
        self.assertTrue(receipt["local_acceptance_active"])
        self.assertNotEqual(accepted["active"]["acceptance_id"], first["active"]["acceptance_id"])

    def test_decline_on_integrity_failure_also_sets_persistent_block(self):
        bindings = self.setup_source()
        original_bytes = self.target.read_bytes()
        first, _ = self.apply(self.sign(self.prepare(bindings=bindings)), bindings=bindings)
        self.target.write_bytes(b"corrupted")
        blocked, _ = self.apply(self.sign(self.prepare(first, "declined", "bad-decline", bindings)), first, bindings)
        self.assertTrue(inspect_state(blocked)["integrity_blocked"])
        self.target.write_bytes(original_bytes)
        still_blocked, _ = self.apply(self.sign(self.prepare(blocked, "declined", "good-decline", bindings)), blocked, bindings)
        self.assertTrue(inspect_state(still_blocked)["integrity_blocked"])

    def test_allowed_reservations_clear_block_and_replace_scope_without_bad_artifact(self):
        bindings = self.setup_source(criticality="optional")
        first, _ = self.apply(self.sign(self.prepare(bindings=bindings)), bindings=bindings)
        self.target.write_bytes(b"noncritical corruption")
        blocked, _ = self.apply(self.sign(self.prepare(first,
            "quarantined_integrity_failure", "quarantine", bindings)), first, bindings)
        reserved, receipt = self.apply(self.sign(self.prepare(blocked,
            "accepted_with_reservations", "reserve", bindings)), blocked, bindings)
        self.assertEqual(reserved["records"][-1]["report"]["root_verification"]["status"], "integrity_failure")
        self.assertFalse(reserved["integrity_blocked"])
        self.assertTrue(receipt["local_acceptance_active"])
        self.assertEqual(reserved["active"]["accepted_artifact_ids"], [ROOT_ARTIFACT])
        inspect_state(reserved)

    def test_integrity_block_is_rebuilt_not_trusted_from_snapshot(self):
        first, _ = self.apply(self.sign(self.prepare()))
        for state, value in ((self.state, True), (first, True), (first, 0)):
            tampered = copy.deepcopy(state)
            tampered["integrity_blocked"] = value
            with self.subTest(value=value), self.assertRaises(ModelError):
                inspect_state(tampered)
        bindings = self.setup_source()
        self.target.write_bytes(b"bad")
        blocked, _ = self.apply(self.sign(self.prepare(decision="quarantined_integrity_failure", bindings=bindings)), bindings=bindings)
        blocked["integrity_blocked"] = False
        with self.assertRaisesRegex(ModelError, "REPLAY_MISMATCH"):
            inspect_state(blocked)

    def test_root_artifact_and_domain_document_hash_are_distinct_and_bound(self):
        b = self.prepare()
        artifact_hash = sha256_hex(canon_json_bytes(self.root))
        document_hash = self.root["document_hash"]["value"]
        self.assertNotEqual(artifact_hash, document_hash)
        self.assertEqual(b["report"]["root_artifact_hash"], artifact_hash)
        self.assertEqual(b["report"]["root_document_hash"], document_hash)
        self.assertEqual(b["document"]["body"]["target_results"][0]["expected_sha256"], document_hash)
        for field, wrong_hash in (("root_artifact_hash", document_hash), ("root_document_hash", artifact_hash)):
            wrong = copy.deepcopy(b)
            wrong["report"][field] = wrong_hash
            with self.subTest(field=field), self.assertRaisesRegex(ModelError, "REPORT_BINDING_MISMATCH"):
                self.apply(self.resign(wrong))
        state, _ = self.apply(self.sign(b))
        state["records"][0]["report"]["root_artifact_hash"] = document_hash
        state["records"][0]["event_hash"] = model._event_hash(state["records"][0])
        state["journal_head"] = state["records"][0]["event_hash"]
        with self.assertRaisesRegex(ModelError, "REPORT_BINDING_MISMATCH"):
            inspect_state(state)

    def test_missing_ledger_known_source_allows_reservations(self):
        bindings = self.setup_source(criticality="optional", ledger=True)
        self.target.unlink()
        b = self.sign(self.prepare(decision="accepted_with_reservations", bindings=bindings))
        state, _ = self.apply(b, bindings=bindings)
        self.assertEqual(state["active"]["accepted_artifact_ids"], [ROOT_ARTIFACT])
        self.assertEqual(b["document"]["body"]["reservations"], [{
            "artifact_id": eid("artifact", 2), "code": "ledger_known_target_missing"}])
        self.assertFalse(any("message" in r or "observed_sha256" in r
            for r in b["document"]["body"]["target_results"]))

    def test_reservation_replaces_entire_scope_not_union(self):
        bindings = self.setup_source(criticality="optional", ledger=True)
        first, _ = self.apply(self.sign(self.prepare(bindings=bindings)), bindings=bindings)
        self.target.unlink()
        second, _ = self.apply(self.sign(self.prepare(first, "accepted_with_reservations", "request-2", bindings)), first, bindings)
        self.assertIn(eid("artifact", 2), first["active"]["accepted_artifact_ids"])
        self.assertNotIn(eid("artifact", 2), second["active"]["accepted_artifact_ids"])
        inspect_state(second)

    def test_noncritical_mismatch_has_explicit_exclusion(self):
        bindings = self.setup_source(criticality="optional")
        self.target.write_bytes(b"wrong")
        for decision in ("accepted_with_reservations", "declined", "quarantined_integrity_failure"):
            with self.subTest(decision=decision):
                b = self.sign(self.prepare(decision=decision, bindings=bindings))
                self.assertTrue(b["document"]["body"]["target_results"][1]["excluded_from_active_inheritance"])
                state, _ = self.apply(b, bindings=bindings)
                inspect_state(state)

    def test_unbound_or_missing_unanchored_target_blocks_accepting(self):
        bindings = self.setup_source(criticality="optional")
        self.target.unlink()
        for binding in (None, bindings):
            for decision in ("accepted", "accepted_with_reservations"):
                with self.subTest(binding=binding, decision=decision), self.assertRaises(ModelError):
                    self.prepare(decision=decision, bindings=binding)
        self.apply(self.sign(self.prepare(decision="declined", bindings=bindings)), bindings=bindings)

    def test_current_target_change_rejects_signed_stale_report(self):
        bindings = self.setup_source()
        b = self.sign(self.prepare(bindings=bindings))
        before = copy.deepcopy(self.state)
        self.target.write_bytes(b"changed after sign")
        with self.assertRaisesRegex(ModelError, "FRESH_REPORT"):
            self.apply(b, bindings=bindings)
        self.assertEqual(self.state, before)

    def test_historical_inspection_never_reads_current_targets(self):
        bindings = self.setup_source()
        state, _ = self.apply(self.sign(self.prepare(bindings=bindings)), bindings=bindings)
        self.target.unlink()
        with mock.patch.object(model, "verify_document_read_only", side_effect=AssertionError("no external reads")):
            self.assertFalse(inspect_state(state)["current_targets_rechecked"])

    def test_report_never_copies_private_paths_or_raw_errors(self):
        bindings = self.setup_source()
        self.target.write_bytes(b"mismatch")
        code, old_report = model.verify_document_read_only(self.root, bindings=bindings)
        old_report["target_results"][0]["message"] = "private path: " + str(self.directory)
        with mock.patch.object(model, "verify_document_read_only", return_value=(code, old_report)):
            b = self.prepare(decision="declined", bindings=bindings)
        raw = canon_json_bytes(b["report"])
        self.assertNotIn(str(self.directory).encode(), raw)
        self.assertNotIn(b'"message"', raw)
        self.assertNotIn(b'"errors"', raw)
        self.assertNotIn(b"target root was not declared", raw)

    def test_invalid_bindings_are_technical_refusal_not_quarantine(self):
        bindings = self.setup_source()
        bindings.target_roots.clear()
        with self.assertRaisesRegex(ModelError, "ROOT_VERIFICATION_INVALID"):
            self.prepare(decision="quarantined_integrity_failure", bindings=bindings)

    def test_bindings_cache_and_inputs_remain_unchanged(self):
        bindings = self.setup_source(ledger=True)
        before = copy.deepcopy(bindings.__dict__)
        bundle = self.sign(self.prepare(bindings=bindings))
        bundle_before = copy.deepcopy(bundle)
        self.apply(bundle, bindings=bindings)
        self.assertEqual(bindings.__dict__, before)
        self.assertEqual(bundle, bundle_before)

    def test_fabricated_pass_even_signed_and_correct_hash_is_refused(self):
        bindings = self.setup_source()
        b = self.prepare(bindings=bindings)
        self.target.write_bytes(b"now wrong")
        # Valid signature over an older/fabricated PASS does not bypass reread.
        with self.assertRaisesRegex(ModelError, "FRESH_REPORT"):
            self.apply(self.sign(b), bindings=bindings)

    def test_report_hash_request_time_and_unknown_fields_are_bound(self):
        original = self.sign(self.prepare())
        for edit in (lambda b: b["report"].update(verification_time="2032-01-02T03:04:07Z"),
                     lambda b: b.update(request_id="another-request"),
                     lambda b: b["report"].update(authenticated=True),
                     lambda b: b["document"]["body"].update(verification_report_hash="a" * 64)):
            b = copy.deepcopy(original)
            edit(b)
            with self.subTest(edit=edit), self.assertRaises(ModelError):
                self.apply(b)

    def test_signed_false_root_facts_and_target_coverage_are_refused(self):
        b = self.prepare()
        for mutate in (lambda x: x["report"]["root_verification"].update(exit_code=10),
                       lambda x: x["report"]["target_observations"].clear(),
                       lambda x: x["report"]["target_observations"][0].update(observed_sha256="a" * 64)):
            edited = copy.deepcopy(b)
            mutate(edited)
            with self.subTest(mutate=mutate), self.assertRaises(ModelError):
                self.apply(self.resign(edited))

    def test_identical_retry_wins_before_stale_cas_without_target_reread(self):
        b = self.sign(self.prepare())
        state, first = self.apply(b)
        with mock.patch.object(model, "verify_document_read_only", side_effect=AssertionError("no read")):
            retried, receipt = self.apply(b, state, expected_state_digest=snapshot_digest(self.state))
        self.assertEqual(retried, state)
        self.assertTrue(receipt["idempotent"])
        self.assertFalse(receipt["current_targets_rechecked"])
        self.assertEqual(receipt["event_hash"], first["event_hash"])

    def test_retry_conflicting_signed_bundle_is_refused(self):
        b = self.sign(self.prepare())
        state, _ = self.apply(b)
        conflict = self.sign(self.prepare(decision="declined"))
        with self.assertRaisesRegex(ModelError, "REQUEST_CONFLICT"):
            self.apply(conflict, state)

    def test_stale_cas_refuses_other_request(self):
        b = self.sign(self.prepare())
        other = self.sign(self.prepare(request_id="request-2"))
        state, _ = self.apply(b)
        with self.assertRaisesRegex(ModelError, "STALE_STATE"):
            self.apply(other, state, expected_state_digest=snapshot_digest(self.state))

    def test_new_request_cannot_reuse_old_signed_prestate_with_current_cas(self):
        first = self.sign(self.prepare())
        old = self.sign(self.prepare(request_id="request-2"))
        state, _ = self.apply(first)
        with self.assertRaisesRegex(ModelError, "REPORT_BINDING_MISMATCH"):
            self.apply(old, state)

    def test_request_alias_requires_report_binding_and_still_rejects_replayed_id(self):
        b = self.sign(self.prepare())
        state, _ = self.apply(b)
        aliased = copy.deepcopy(b)
        aliased["request_id"] = "alias"
        with self.assertRaises(ModelError):
            self.apply(aliased, state)

    def test_same_decision_nonce_or_acceptance_id_cannot_alias_new_request(self):
        first_bundle = self.sign(self.prepare())
        state, _ = self.apply(first_bundle)
        for key in ("decision_nonce", "acceptance_id"):
            b = self.prepare(state, "declined", "request-2")
            b["document"]["body"][key] = first_bundle["document"]["body"][key]
            with self.subTest(key=key), self.assertRaisesRegex(ModelError, "REPLAY_CONFLICT"):
                self.apply(self.resign(b), state)

    def test_tampered_snapshot_projection_is_not_hidden_by_valid_hash_chain(self):
        state, _ = self.apply(self.sign(self.prepare()))
        for field, value in (("generation", 0), ("active", None), ("requests", {}),
                             ("decision_ids", {}), ("nonces", {}), ("slots", {}), ("edges", {}),
                             ("journal_head", "a" * 64), ("generation", True)):
            wrong = copy.deepcopy(state)
            wrong[field] = value
            with self.subTest(field=field), self.assertRaises(ModelError):
                inspect_state(wrong)

    def test_closed_state_record_bundle_and_checkpoint_fields(self):
        state, _ = self.apply(self.sign(self.prepare()))
        for target in (state, state["records"][0]):
            target["surprise"] = True
            with self.assertRaises(ModelError):
                inspect_state(state)
            del target["surprise"]
        b = self.sign(self.prepare())
        b["surprise"] = True
        with self.assertRaises(ModelError):
            self.apply(b)
        with self.assertRaises(ModelError):
            inspect_state(state, {"store_id": STORE, "generation": 0,
                "journal_head": self.state["journal_head"], "trusted": True})

    def test_rehashed_record_cannot_hide_bad_prestate_or_responsibility(self):
        state, _ = self.apply(self.sign(self.prepare()))
        for edit in (lambda r: r["report"]["pre_state"].update(snapshot_digest="a" * 64),
                     lambda r: r["document"]["responsibility"].update(event_index=2),
                     lambda r: r.update(generation=2),
                     lambda r: r.update(previous_journal_head="a" * 64)):
            wrong = copy.deepcopy(state)
            edit(wrong["records"][0])
            wrong["records"][0]["event_hash"] = model._event_hash(wrong["records"][0])
            wrong["journal_head"] = wrong["records"][0]["event_hash"]
            with self.subTest(edit=edit), self.assertRaises(ModelError):
                inspect_state(wrong)

    def test_invalid_signature_never_becomes_quarantine(self):
        b = self.sign(self.prepare())
        b["document"]["proofs"][0]["signature"] = base64.b64encode(bytes(64)).decode()
        with self.assertRaises(ModelError):
            self.apply(b)

    def test_structurally_valid_other_actor_modes_are_not_adopted(self):
        actors = [
            {"decision_mode": "model_session", "runtime_session_id": eid("runtime-session", 1),
                "decision_evidence_ref": artifact(90)},
            {"decision_mode": "joint_human_model", "runtime_session_id": eid("runtime-session", 1),
                "human_actor_id": eid("decision-actor", 2), "decision_evidence_ref": artifact(90)},
            {"decision_mode": "system_policy", "policy_artifact_ref": artifact(90)},
            {"decision_mode": "imported_historical_claim", "historical_claim_artifact_ref": artifact(90)},
        ]
        for actor in actors:
            b = self.prepare(decision="declined")
            b["document"]["body"]["decision_actor"] = {"decision_actor_id": ACTOR, **actor}
            b["document"] = finalize_document(b["document"])
            validate_document(b["document"])
            with self.subTest(mode=actor["decision_mode"]), self.assertRaisesRegex(ModelError, "BINDING_MISMATCH"):
                self.apply(b)

    def test_signed_external_evidence_error_blocks_acceptance(self):
        b = self.prepare()
        facts = b["report"]["root_verification"]
        facts.update(evidence_status="incomplete", evidence_error_count=1,
            status="verified_with_unavailable_targets", exit_code=10)
        with self.assertRaisesRegex(ModelError, "DECISION_NOT_PERMITTED"):
            self.apply(self.resign(b))

    def test_checkpoint_matches_exact_historical_ancestor(self):
        first, _ = self.apply(self.sign(self.prepare()))
        second, _ = self.apply(self.sign(self.prepare(first, "declined", "request-2")), first)
        for saved in (self.state, first, second):
            checkpoint = {k: saved[k] for k in ("store_id", "generation", "journal_head")}
            self.assertTrue(inspect_state(second, checkpoint)["external_checkpoint_satisfied"])
        checkpoint = {k: first[k] for k in ("store_id", "generation", "journal_head")}
        for key, value in (("store_id", "00000000-0000-4000-8000-000000000090"),
                           ("generation", 3), ("journal_head", "a" * 64), ("generation", True)):
            bad = dict(checkpoint, **{key: value})
            with self.subTest(key=key), self.assertRaises(ModelError):
                inspect_state(second, bad)

    def test_whole_store_rollback_requires_later_external_checkpoint(self):
        first, _ = self.apply(self.sign(self.prepare()))
        checkpoint = {k: first[k] for k in ("store_id", "generation", "journal_head")}
        self.assertTrue(inspect_state(self.state)["local_chain_valid"])
        self.assertEqual(inspect_state(self.state)["rollback_protection"], "not_externally_anchored")
        with self.assertRaisesRegex(ModelError, "CHECKPOINT"):
            inspect_state(self.state, checkpoint)

    def test_prepare_and_apply_enforce_bound_and_crypto_capability(self):
        b = self.sign(self.prepare())
        with mock.patch.object(model, "MAX_RECORDS", 0):
            with self.assertRaisesRegex(ModelError, "RECORD_LIMIT"):
                self.prepare()
            with self.assertRaisesRegex(ModelError, "RECORD_LIMIT"):
                self.apply(b)
        with mock.patch.object(model, "verify_acceptance_signature", side_effect=CryptoUnavailable("unavailable")):
            with self.assertRaisesRegex(ModelError, "AUTHENTICATION_UNAVAILABLE"):
                self.apply(b)

    def test_failure_errors_do_not_leak_private_input_values(self):
        b = self.prepare()
        b["report"]["secret_path"] = str(self.directory)
        with self.assertRaises(ModelError) as error:
            self.apply(b)
        self.assertNotIn(str(self.directory), str(error.exception))


if __name__ == "__main__":
    unittest.main()
