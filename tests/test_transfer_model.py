from __future__ import annotations
import base64
import copy
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from lineage_test_helpers import eid
from transfer_test_helpers import (TransferFixture, T, LATER, EXPIRY, SOURCE_ACTOR,
    RECIPIENT_ACTOR, CONSUMER, PAYLOAD_ID, ACTIVATION, INSTANCE)
from tools.tools import echo_transfer_model as model
from tools.tools import echo_transfer_auth as auth
from tools.tools.echo_state_store import snapshot_digest
from tools.tools.echo_canonical import canon_json_bytes, sha256_hex
from tools.tools.echo_lineage import validate_document
from tools.tools.echo_lineage_auth import sign_acceptance_document
from tools.tools.echo_state_model import prepare_decision, apply_decision


class TransferModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.f = TransferFixture(cls.temp.name)
        cls.source, cls.receiver = cls.f.received()
        cls.envelope = model.make_envelope(cls.source)
        cls.initial_receiver = model.create_receiver(cls.f.policy, expected_policy_digest=auth.policy_digest(cls.f.policy))
        cls.accepted = cls.f.action(cls.receiver, 'decide', {'decision': 'accepted'})
        cls.imported = cls.f.action(cls.accepted, 'import', {'artifact_ids': [PAYLOAD_ID]})
        cls.authorized = cls.f.action(cls.imported, 'activate', {'activation_id': ACTIVATION,
            'artifact_ids': [PAYLOAD_ID], 'probe': {'artifact_id': PAYLOAD_ID, 'offset': 0, 'length': 9, 'nonce': 'a'*64}})
        cls.loaded_source, cls.loaded = cls.f.loaded()
        cls.missing_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.missing_dir.cleanup)
        cls.missing_fixture = TransferFixture(cls.missing_dir.name, missing=True)
        cls.missing_source, cls.missing_receiver = cls.missing_fixture.received()

    def prepare(self, state, operation, inputs, request='new-request', actor=None):
        actor = actor or (SOURCE_ACTOR if state['role'] == 'source' else RECIPIENT_ACTOR)
        return model.prepare_action(state, operation, inputs, actor_id=actor, request_id=request,
            verification_time=LATER, expected_state_digest=snapshot_digest(state))

    def sign(self, state, candidate, role=None):
        role = role or ('source' if state['role'] == 'source' else 'recipient')
        return model.sign_candidate(state, candidate, self.f.keys[role])

    def apply(self, state, packet, **overrides):
        kw = dict(expected_state_digest=snapshot_digest(state), applied_at=LATER)
        kw.update(overrides)
        return model.apply_action(state, packet, **kw)

    def migration_candidate(self, policy=None):
        policy = self.f.policy if policy is None else policy
        return model.prepare_migration(self.f.legacy, policy, artifacts=self.f.artifacts,
            actor_id=SOURCE_ACTOR, request_id='migration-new', verification_time=T,
            expected_state_digest=snapshot_digest(self.f.legacy), expected_policy_digest=auth.policy_digest(policy))

    def test_receiver_initialization_has_no_lineage_or_runtime_adoption(self):
        status = model.inspect_state(self.initial_receiver)
        self.assertFalse(status['received'])
        self.assertIsNone(status['decision'])
        self.assertFalse(status['imported'])
        self.assertFalse(status['runtime_activation'])
        self.assertEqual(status['current_process_liveness'], 'UNKNOWN')
        self.assertEqual(status['rollback_protection'], 'not_externally_anchored')

    def test_migration_preserves_exact_full_legacy_and_does_not_consume_slot(self):
        source = self.f.migrate()
        self.assertEqual(source['generation'], 0)
        self.assertEqual(source['initial']['applied_at'], T)
        legacy = source['initial']['migration']['payload']['inputs']['legacy_state']
        self.assertEqual(legacy, self.f.legacy)
        self.assertEqual(legacy['slots'], self.f.legacy['slots'])
        self.assertFalse(source['projections']['sealed'])
        with self.assertRaises(ValueError):
            from tools.tools.echo_state_model import inspect_state
            inspect_state(source)

    def test_migration_requires_independent_pin_at_every_trust_entry(self):
        c = self.migration_candidate()
        with mock.patch.object(auth, 'sign_packet', side_effect=AssertionError('key reached')):
            with self.assertRaisesRegex(model.TransferError, 'POLICY_PIN_REQUIRED'):
                model.sign_candidate(self.f.legacy, c, self.f.keys['source'])
            with self.assertRaisesRegex(model.TransferError, 'POLICY_PIN_MISMATCH'):
                model.sign_candidate(self.f.legacy, c, self.f.keys['source'], expected_policy_digest='f'*64)
        packet = model.sign_candidate(self.f.legacy, c, self.f.keys['source'], expected_policy_digest=auth.policy_digest(self.f.policy))
        with self.assertRaisesRegex(model.TransferError, 'POLICY_PIN_REQUIRED'):
            model.apply_migration(self.f.legacy, packet, expected_state_digest=snapshot_digest(self.f.legacy), applied_at=T)
        with self.assertRaisesRegex(model.TransferError, 'POLICY_PIN_MISMATCH'):
            model.apply_migration(self.f.legacy, packet, expected_state_digest=snapshot_digest(self.f.legacy), applied_at=T,
                expected_policy_digest='f'*64)

    def test_substituted_self_signed_policy_cannot_cross_independent_migration_pin(self):
        policy = copy.deepcopy(self.f.policy)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key = Ed25519PrivateKey.from_private_bytes(bytes([84])*32)
        keyfile = Path(self.temp.name) / 'attacker-synthetic.pem'
        keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        keyfile.chmod(0o600)
        policy['keys'][0]['public_key'] = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        c = self.migration_candidate(policy)
        attacker = model.sign_candidate(self.f.legacy, c, keyfile, expected_policy_digest=auth.policy_digest(policy))
        with self.assertRaisesRegex(model.TransferError, 'POLICY_PIN_MISMATCH'):
            model.apply_migration(self.f.legacy, attacker, expected_state_digest=snapshot_digest(self.f.legacy), applied_at=T,
                expected_policy_digest=auth.policy_digest(self.f.policy))

    def test_migration_exact_replay_before_stale_cas_and_request_reserved(self):
        state = self.f.migrate()
        packet = state['initial']['migration']
        replay, result = model.apply_migration(state, packet, expected_state_digest='0'*64, applied_at=LATER,
            expected_policy_digest=auth.policy_digest(self.f.policy))
        self.assertEqual(replay, state)
        self.assertTrue(result['idempotent'])
        with self.assertRaisesRegex(model.TransferError, 'REQUEST_CONFLICT'):
            self.prepare(state, 'issue', {'producer_runtime_session_id': eid('runtime-session', 1), 'expires_at': EXPIRY}, request='migration')

    def test_source_latest_decline_cannot_migrate_even_if_previous_active_preserved(self):
        legacy = self.f.legacy
        bundle = prepare_decision(legacy, decision='declined', actor_id=SOURCE_ACTOR, operator_id=SOURCE_ACTOR,
            request_id='later-decline', verification_time=T, expected_state_digest=snapshot_digest(legacy))
        bundle['document'] = sign_acceptance_document(bundle['document'], legacy['policy'], self.f.keys['source'])
        new, _ = apply_decision(legacy, bundle, expected_state_digest=snapshot_digest(legacy), applied_at=T)
        policy = copy.deepcopy(self.f.policy)
        policy['source_pin']['snapshot_digest'] = snapshot_digest(new)
        with self.assertRaisesRegex(model.TransferError, 'SOURCE_LATEST_NOT_ACTIVE_ACCEPTANCE'):
            model.prepare_migration(new, policy, artifacts=self.f.artifacts, actor_id=SOURCE_ACTOR, request_id='m',
                verification_time=T, expected_state_digest=snapshot_digest(new), expected_policy_digest=auth.policy_digest(policy))

    def test_prepare_and_sign_leave_source_unsealed_until_atomic_apply(self):
        state = self.f.migrate()
        before = copy.deepcopy(state)
        c = self.prepare(state, 'issue', {'producer_runtime_session_id': eid('runtime-session', 1), 'expires_at': EXPIRY})
        packet = self.sign(state, c)
        self.assertEqual(state, before)
        self.assertFalse(state['projections']['sealed'])
        issued, _ = self.apply(state, packet)
        self.assertTrue(issued['projections']['sealed'])
        doc = packet['payload']['document']
        validate_document(doc, expected_type='handoff')
        self.assertEqual(doc['body']['sequence'], 0)
        self.assertEqual(doc['body']['fork_intent'], 'none')
        self.assertEqual(doc['responsibility']['event_index'], self.f.legacy['records'][-1]['document']['responsibility']['event_index'] + 1)
        self.assertTrue(doc['proofs'])

    def test_alternative_issue_rejected_and_exact_replay_precedes_cas(self):
        packet = self.source['records'][0]['packet']
        replay, result = self.apply(self.source, packet, expected_state_digest='0'*64)
        self.assertEqual(replay, self.source)
        self.assertTrue(result['idempotent'])
        with self.assertRaisesRegex(model.TransferError, 'SOURCE_EPOCH_SEALED'):
            self.prepare(self.source, 'issue', {'producer_runtime_session_id': eid('runtime-session', 1), 'expires_at': EXPIRY})

    def test_generated_report_fabrication_rejected_before_any_key_read(self):
        c = self.prepare(self.receiver, 'decide', {'decision': 'accepted'})
        c['body']['report']['verification']['source_proof_verified'] = False
        with mock.patch.object(auth, 'sign_protocol_document', side_effect=AssertionError('key read')):
            with self.assertRaisesRegex(model.TransferError, 'REPORT_MISMATCH'):
                self.sign(self.receiver, c)

    def test_signatures_bind_signed_artifact_hash_after_protocol_signature(self):
        c = self.prepare(self.receiver, 'decide', {'decision': 'accepted'})
        unsigned_hash = c['body']['report']['document_artifact_hash']
        packet = self.sign(self.receiver, c)
        body = packet['payload']
        self.assertNotEqual(unsigned_hash, body['report']['document_artifact_hash'])
        self.assertEqual(body['report']['document_artifact_hash'], sha256_hex(canon_json_bytes(body['document'])))
        self.assertEqual(body['document']['body']['verification_report_hash'], sha256_hex(canon_json_bytes(body['report']['verification'])))
        self.apply(self.receiver, packet)

    def test_tampered_outer_signature_payload_fails(self):
        packet = copy.deepcopy(self.source['records'][0]['packet'])
        packet['payload']['inputs']['expires_at'] = '2033-01-01T00:00:00Z'
        with self.assertRaises(model.TransferError):
            self.apply(self.f.migrate(), packet)

    def test_full_envelope_replay_and_payload_transport_domains(self):
        facts = model.verify_envelope(self.envelope, self.f.policy, verification_time=LATER)
        self.assertTrue(facts['source_proof_verified'])
        item = facts['artifacts'][0]
        self.assertEqual(item['raw_sha256'], item['expected_sha256'])
        self.assertNotEqual(auth.digest('envelope', self.envelope), sha256_hex(canon_json_bytes(self.envelope)))
        bad = copy.deepcopy(self.envelope)
        bad['source_prefix']['projections']['sealed'] = True
        with self.assertRaisesRegex(model.TransferError, 'SNAPSHOT_REPLAY_MISMATCH'):
            model.verify_envelope(bad, self.f.policy, verification_time=LATER)

    def test_envelope_tampering_source_payload_and_extra_fields_refuse(self):
        for mutation in ('payload', 'extra', 'policy'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(self.envelope)
                if mutation == 'payload':
                    bad['source_prefix']['initial']['migration']['payload']['inputs']['artifacts'][0]['data_b64'] = base64.b64encode(b'evil').decode()
                elif mutation == 'extra':
                    bad['pretend_authenticated'] = True
                else:
                    bad['policy_digest'] = 'a'*64
                with self.assertRaises(model.TransferError):
                    model.verify_envelope(bad, self.f.policy, verification_time=LATER)

    def test_export_authorization_and_actual_confirm_are_separate(self):
        status = model.inspect_state(self.source)
        self.assertTrue(status['export_authorized'])
        self.assertFalse(status['export_confirmed'])
        raw = canon_json_bytes(self.envelope) + b'\n'
        inputs = {'envelope_digest': auth.digest('envelope', self.envelope), 'raw_sha256': sha256_hex(raw), 'byte_length': len(raw)}
        state = self.f.action(self.source, 'export_confirm', inputs)
        self.assertTrue(model.inspect_state(state)['export_confirmed'])
        inputs['raw_sha256'] = '0'*64
        with self.assertRaisesRegex(model.TransferError, 'EXPORT_BYTES_MISMATCH'):
            self.prepare(self.source, 'export_confirm', inputs)

    def test_actual_continuation_has_new_installation_chain_same_trajectory_genesis(self):
        root = self.receiver['projections']['receive']['root']
        old = self.f.legacy['root']
        self.assertEqual(root['body']['trajectory_id'], old['body']['trajectory_id'])
        self.assertEqual(root['body']['genesis_root_document_hash'], old['document_hash']['value'])
        self.assertNotEqual(root['body']['installation_id'], old['body']['installation_id'])
        self.assertNotEqual(root['responsibility']['chain_id'], old['responsibility']['chain_id'])
        self.assertEqual(len(root['body']['lineage_parents']), 1)
        self.assertEqual(root['proofs'], [])
        self.assertFalse(model.inspect_state(self.receiver)['root_author_authenticated'])

    def test_duplicate_receive_to_wrong_installation_and_same_store_refuse(self):
        with self.assertRaisesRegex(model.TransferError, 'TRANSFER_ALREADY_RECEIVED'):
            self.prepare(self.receiver, 'receive', {'envelope': self.envelope, 'recipient_runtime_session_id': eid('runtime-session', 2)})
        policy = copy.deepcopy(self.f.policy)
        policy['recipient']['store_id'] = policy['source_pin']['store_id']
        with self.assertRaises(model.TransferError):
            model.create_receiver(policy, expected_policy_digest='a'*64)

    def test_all_four_recipient_controls_and_separate_real_acceptance(self):
        for decision in ('accepted', 'declined', 'quarantined_integrity_failure'):
            with self.subTest(decision=decision):
                state = self.f.action(self.receiver, 'decide', {'decision': decision})
                doc = state['records'][-1]['packet']['payload']['document']
                self.assertEqual(state['projections']['decision']['decision'], decision)
                if decision == 'quarantined_integrity_failure':
                    self.assertIsNone(doc)  # No fabricated valid v1 acceptance.
                    self.assertTrue(state['projections']['integrity_blocked'])
                else:
                    validate_document(doc, expected_type='lineage_acceptance')
                    self.assertTrue(doc['proofs'])
        f = self.missing_fixture
        reserved = f.action(self.missing_receiver, 'decide', {'decision': 'accepted_with_reservations'})
        body = reserved['records'][-1]['packet']['payload']['document']['body']
        self.assertEqual(body['reservations'], [{'artifact_id': PAYLOAD_ID, 'code': 'ledger_known_target_missing'}])

    def test_accepted_requires_complete_valid_targets(self):
        with self.assertRaisesRegex(model.TransferError, 'DECISION_NOT_PERMITTED'):
            self.prepare(self.missing_receiver, 'decide', {'decision': 'accepted'})
        with self.assertRaisesRegex(model.TransferError, 'DECISION_NOT_PERMITTED'):
            self.prepare(self.receiver, 'decide', {'decision': 'accepted_with_reservations'})

    def test_import_only_verified_accepted_bytes_and_missing_scope_excluded(self):
        self.assertEqual(self.imported['projections']['import']['artifact_ids'], [PAYLOAD_ID])
        f = self.missing_fixture
        reserved = f.action(self.missing_receiver, 'decide', {'decision': 'accepted_with_reservations'})
        with self.assertRaisesRegex(model.TransferError, 'IMPORT_SCOPE_NOT_ACCEPTED'):
            self.prepare(reserved, 'import', {'artifact_ids': [PAYLOAD_ID]})
        declined = self.f.action(self.receiver, 'decide', {'decision': 'declined'})
        with self.assertRaisesRegex(model.TransferError, 'IMPORT_NOT_ACCEPTED'):
            self.prepare(declined, 'import', {'artifact_ids': [PAYLOAD_ID]})

    def test_received_decided_imported_do_not_authorize_consumer(self):
        for state in (self.receiver, self.accepted, self.imported):
            with self.assertRaisesRegex(model.TransferError, 'ACTIVATION_NOT_AUTHORIZED'):
                model.consumer_view(state, ACTIVATION)

    def test_grant_exact_read_set_pinned_consumer_and_fresh_probe(self):
        view = model.consumer_view(self.authorized, ACTIVATION)
        self.assertEqual(view['consumer'], self.f.policy['consumer'])
        self.assertEqual(view['read_set'], [{'artifact_id': PAYLOAD_ID, 'sha256': sha256_hex(base64.b64decode(view['artifacts'][0]['bytes_b64']))}])
        bad = {'activation_id': ACTIVATION, 'artifact_ids': [PAYLOAD_ID],
            'probe': {'artifact_id': PAYLOAD_ID, 'offset': 1000, 'length': 9, 'nonce': 'a'*64}}
        with self.assertRaisesRegex(model.TransferError, 'INVALID_PROBE'):
            self.prepare(self.imported, 'activate', bad)

    def test_human_operator_cannot_sign_consumer_launch_as_human(self):
        with self.assertRaises(model.TransferError):
            self.prepare(self.authorized, 'activation_start', {'activation_id': ACTIVATION,
                'instance_id': INSTANCE, 'launch_nonce': 'b'*64, 'code_digest': 'c'*64})
        c = self.prepare(self.authorized, 'activation_start', {'activation_id': ACTIVATION,
            'instance_id': INSTANCE, 'launch_nonce': 'b'*64, 'code_digest': 'c'*64}, actor=CONSUMER)
        self.assertEqual(c['body']['role'], 'local_context_consumer')

    def test_single_launch_attempt_and_loaded_receipt_from_exact_ram_probe(self):
        view = model.consumer_view(self.loaded, ACTIVATION)
        self.assertEqual(view['status'], 'loaded')
        self.assertEqual(view['launch']['instance_id'], INSTANCE)
        with self.assertRaisesRegex(model.TransferError, 'ACTIVATION_LAUNCH_ALREADY_ATTEMPTED'):
            self.prepare(self.loaded, 'activation_start', {'activation_id': ACTIVATION,
                'instance_id': INSTANCE, 'launch_nonce': 'd'*64, 'code_digest': 'c'*64}, actor=CONSUMER)
        self.assertEqual(model.inspect_state(self.loaded)['current_process_liveness'], 'UNKNOWN')

    def test_revoke_is_permanent_reauthorization_requires_new_grant_and_probe(self):
        revoked = self.f.action(self.loaded, 'deactivate', {'activation_id': ACTIVATION})
        with self.assertRaisesRegex(model.TransferError, 'ACTIVATION_REVOKED'):
            model.consumer_view(revoked, ACTIVATION)
        status = model.inspect_state(revoked)
        self.assertIsNotNone(status['activations'][ACTIVATION]['loaded_generation'])
        reused = {'activation_id': ACTIVATION, 'artifact_ids': [PAYLOAD_ID],
            'probe': {'artifact_id': PAYLOAD_ID, 'offset': 0, 'length': 9, 'nonce': 'd'*64}}
        with self.assertRaisesRegex(model.TransferError, 'ACTIVATION_ID_REUSED'):
            self.prepare(revoked, 'activate', reused)
        reused['activation_id'] = '00000000-0000-4000-8000-000000000402'
        reused['probe']['nonce'] = 'a'*64
        with self.assertRaisesRegex(model.TransferError, 'PROBE_NONCE_REUSED'):
            self.prepare(revoked, 'activate', reused)
        reused['probe']['nonce'] = 'd'*64
        new = self.f.action(revoked, 'activate', reused)
        self.assertEqual(model.consumer_view(new, reused['activation_id'])['status'], 'authorized')

    def test_postcommit_return_receipt_and_source_unknown_until_ingest(self):
        self.assertEqual(model.inspect_state(self.source)['remote_milestones']['received'], 'UNKNOWN')
        with self.assertRaisesRegex(model.TransferError, 'MILESTONE_NOT_COMMITTED'):
            model.make_receipt(self.initial_receiver, kind='received', actor_id=RECIPIENT_ACTOR,
                key_file=self.f.keys['recipient'], verification_time=LATER)
        receipt = model.make_receipt(self.loaded, kind='loaded', actor_id=RECIPIENT_ACTOR,
            key_file=self.f.keys['recipient'], verification_time=LATER)
        learned = self.f.action(self.loaded_source, 'receipt_ingest', {'receipt': receipt})
        status = model.inspect_state(learned)['remote_milestones']
        self.assertEqual(status['loaded'], 'RECEIPT_VERIFIED')
        self.assertEqual(status['received'], 'UNKNOWN')

    def test_wrong_return_receipt_envelope_fails_even_with_authorized_signature(self):
        packet = model.make_receipt(self.receiver, kind='received', actor_id=RECIPIENT_ACTOR,
            key_file=self.f.keys['recipient'], verification_time=LATER)
        payload = packet['payload']
        payload['envelope_digest'] = 'a'*64
        altered = auth.sign_packet(payload, self.f.policy, self.f.keys['recipient'], purpose='transfer_receipt',
            actor_id=RECIPIENT_ACTOR, installation_id=eid('installation', 2))
        with self.assertRaisesRegex(model.TransferError, 'RECEIPT_ENVELOPE_MISMATCH'):
            self.prepare(self.source, 'receipt_ingest', {'receipt': altered})

    def test_request_nonce_conflict_and_stale_cas(self):
        c = self.prepare(self.receiver, 'decide', {'decision': 'declined'})
        packet = self.sign(self.receiver, c)
        with self.assertRaisesRegex(model.TransferError, 'STALE_STATE'):
            self.apply(self.receiver, packet, expected_state_digest='0'*64)
        c = self.prepare(self.accepted, 'import', {'artifact_ids': [PAYLOAD_ID]})
        c['body']['nonce'] = self.accepted['records'][0]['packet']['payload']['nonce']
        packet = self.sign(self.accepted, c)
        with self.assertRaisesRegex(model.TransferError, 'NONCE_CONFLICT'):
            self.apply(self.accepted, packet)
        packet = copy.deepcopy(self.accepted['records'][-1]['packet'])
        packet['payload']['nonce'] = 'e'*64
        packet = auth.sign_packet(packet['payload'], self.f.policy, self.f.keys['recipient'], purpose='receiver_decision',
            actor_id=RECIPIENT_ACTOR, installation_id=eid('installation', 2))
        with self.assertRaisesRegex(model.TransferError, 'REQUEST_CONFLICT'):
            self.apply(self.accepted, packet, expected_state_digest='0'*64)

    def test_entire_state_replay_rejects_projection_record_and_history_changes(self):
        for mutate in ('projection', 'record', 'missing'):
            bad = copy.deepcopy(self.loaded)
            if mutate == 'projection':
                bad['projections']['activations'][ACTIVATION]['revoked'] = True
            elif mutate == 'record':
                bad['records'][0]['event_hash'] = '0'*64
            else:
                bad['records'].pop()
            with self.subTest(mutate=mutate), self.assertRaises(model.TransferError):
                model.inspect_state(bad)

    def test_checkpoint_requires_exact_ancestor_membership(self):
        point = {'store_id': self.loaded['store_id'], 'generation': 1, 'journal_head': self.loaded['records'][0]['event_hash']}
        self.assertTrue(model.inspect_state(self.loaded, checkpoint=point)['external_checkpoint_satisfied'])
        point['journal_head'] = '0'*64
        with self.assertRaisesRegex(model.TransferError, 'CHECKPOINT_NOT_IN_HISTORY'):
            model.inspect_state(self.loaded, checkpoint=point)
        # Complete rollback remains locally valid without an external checkpoint.
        self.assertTrue(model.inspect_state(self.receiver)['local_chain_valid'])

    def test_bounds_and_unsupported_artifact_scope_before_mutation(self):
        before = copy.deepcopy(self.f.legacy)
        artifacts = copy.deepcopy(self.f.artifacts)
        artifacts[0]['data_b64'] = base64.b64encode(b'x' * (model.MAX_PAYLOAD + 1)).decode()
        with self.assertRaises(model.TransferError):
            model.prepare_migration(before, self.f.policy, artifacts=artifacts, actor_id=SOURCE_ACTOR,
                request_id='huge', verification_time=T, expected_state_digest=snapshot_digest(before),
                expected_policy_digest=auth.policy_digest(self.f.policy))
        self.assertEqual(before, self.f.legacy)
        value = []
        for _ in range(66):
            value = [value]
        with self.assertRaisesRegex(model.TransferError, 'PROFILE_SIZE_LIMIT'):
            model.verify_envelope(value, self.f.policy, verification_time=LATER)

    def test_expiry_at_receive_and_commit_refuses_without_unsealing_source(self):
        with self.assertRaisesRegex(model.TransferError, 'HANDOFF_EXPIRED_OR_NOT_YET_VALID'):
            model.verify_envelope(self.envelope, self.f.policy, verification_time=EXPIRY)
        c = self.prepare(self.initial_receiver, 'receive', {'envelope': self.envelope, 'recipient_runtime_session_id': eid('runtime-session', 2)})
        packet = self.sign(self.initial_receiver, c)
        with self.assertRaisesRegex(model.TransferError, 'HANDOFF_EXPIRED_OR_NOT_YET_VALID'):
            self.apply(self.initial_receiver, packet, applied_at=EXPIRY)
        self.assertTrue(model.inspect_state(self.source)['source_epoch_sealed'])

    def test_ledger_missing_anchored_fact_keeps_exact_full_ledger(self):
        facts = model.verify_envelope(model.make_envelope(self.missing_source), self.missing_fixture.policy, verification_time=LATER)
        self.assertEqual(facts['artifacts'][0]['status'], 'ledger_known_target_missing')
        self.assertIsNone(facts['artifacts'][0]['raw_sha256'])

    def test_canonical_document_preserves_distinct_raw_and_semantic_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            f = TransferFixture(directory, payload=b'{ "context" : "synthetic" }\n', canonical=True)
            source_state, receiver = f.received()
            facts = model.verify_envelope(model.make_envelope(source_state), f.policy, verification_time=LATER)
            self.assertNotEqual(facts['artifacts'][0]['raw_sha256'], facts['artifacts'][0]['expected_sha256'])
            accepted = f.action(receiver, 'decide', {'decision': 'accepted'})
            imported = f.action(accepted, 'import', {'artifact_ids': [PAYLOAD_ID]})
            record = imported['records'][-1]['packet']['payload']
            self.assertTrue(record['report']['import_digest'])

    def test_noncritical_integrity_exclusion_supports_actual_signed_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            f = TransferFixture(directory, excluded=True)
            _, receiver = f.received()
            quarantined = f.action(receiver, 'decide', {'decision': 'quarantined_integrity_failure'})
            doc = quarantined['records'][-1]['packet']['payload']['document']
            self.assertIsNotNone(doc)
            validate_document(doc, expected_type='lineage_acceptance')
            self.assertTrue(doc['proofs'])
            reserved = f.action(receiver, 'decide', {'decision': 'accepted_with_reservations'})
            with self.assertRaisesRegex(model.TransferError, 'IMPORT_SCOPE_NOT_ACCEPTED'):
                f.action(reserved, 'import', {'artifact_ids': [PAYLOAD_ID]})

    def test_loaded_probe_hash_binds_exact_decomposed_unicode_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            f = TransferFixture(directory, payload='e\u0301context\n'.encode('utf-8'))
            _, state = f.activated()
            state = f.action(state, 'activation_start', {'activation_id': ACTIVATION,
                'instance_id': INSTANCE, 'launch_nonce': 'b'*64, 'code_digest': f.policy['consumer']['code_digest']})
            view = model.consumer_view(state, ACTIVATION)
            exact = 'e\u0301context'
            payload = {'kind': 'loaded', 'activation_id': ACTIVATION, 'instance_id': INSTANCE,
                'launch_nonce': 'b'*64, 'grant_digest': view['grant_digest'], 'import_digest': view['import_digest'],
                'read_set': view['read_set'], 'store_id': view['store_id'], 'installation_id': view['installation_id'],
                'consumer_id': CONSUMER, 'code_digest': f.policy['consumer']['code_digest'], 'probe': view['probe'],
                'probe_result': exact, 'probe_result_sha256': sha256_hex(exact.encode('utf-8')), 'observed_at': LATER}
            signed = auth.sign_packet(payload, f.policy, f.keys['consumer'], purpose='context_consumption_receipt',
                actor_id=CONSUMER, installation_id=eid('installation', 2), role='local_context_consumer')
            self.assertNotEqual(signed['payload']['probe_result'].encode('utf-8'), exact.encode('utf-8'))
            loaded = f.action(state, 'activation_loaded', {'activation_id': ACTIVATION, 'instance_id': INSTANCE, 'receipt': signed})
            self.assertEqual(model.consumer_view(loaded, ACTIVATION)['status'], 'loaded')
            payload['probe_result_sha256'] = sha256_hex(signed['payload']['probe_result'].encode('utf-8'))
            wrong = auth.sign_packet(payload, f.policy, f.keys['consumer'], purpose='context_consumption_receipt',
                actor_id=CONSUMER, installation_id=eid('installation', 2), role='local_context_consumer')
            with self.assertRaisesRegex(model.TransferError, 'LOADED_RECEIPT_BINDING_MISMATCH'):
                f.action(state, 'activation_loaded', {'activation_id': ACTIVATION, 'instance_id': INSTANCE, 'receipt': wrong})

    def test_full_lifecycle_capacity_refuses_max_policy_large_metadata_before_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            f = TransferFixture(directory, payload=b'x'*1000000, descriptor_bytes=900000, large_policy=True)
            self.assertEqual(len(f.policy['keys']), 256)
            self.assertEqual(len(f.policy['recipient']['lineage_policy']['keys']), 256)
            self.assertLess(len(canon_json_bytes(f.legacy)), model.MAX_PROOF)
            before = copy.deepcopy(f.legacy)
            with self.assertRaisesRegex(model.TransferError, 'PROFILE_SIZE_LIMIT'):
                f.migrate()
            self.assertEqual(f.legacy, before)
            self.assertEqual(f.legacy['schema'], 'echo-lineage-state/v1')

    def test_unavailable_crypto_preserves_closed_capability_code_only_from_trusted_types(self):
        from tools.tools import echo_state_model as old_model
        for failure, expected in ((auth.TransferAuthError('AUTHENTICATION_UNAVAILABLE'), 'AUTHENTICATION_UNAVAILABLE'),
                (ValueError('AUTHENTICATION_UNAVAILABLE'), 'INVALID_TRANSFER_INPUT'),
                (auth.TransferAuthError('other private diagnostic'), 'INVALID_TRANSFER_INPUT')):
            with self.subTest(type=type(failure).__name__, expected=expected):
                with mock.patch.object(auth, 'verify_packet', side_effect=failure):
                    with self.assertRaisesRegex(model.TransferError, '^' + expected + '$'):
                        model.inspect_state(self.source)
        with mock.patch.object(old_model, 'inspect_state', side_effect=old_model.ModelError('AUTHENTICATION_UNAVAILABLE')):
            with self.assertRaisesRegex(model.TransferError, '^AUTHENTICATION_UNAVAILABLE$'):
                self.migration_candidate()

    def test_closed_operation_inputs_reject_unknown_or_missing_fields(self):
        for inputs in ({'decision': 'accepted', 'authenticated': True}, {}, {'decision': 'invented'}):
            with self.subTest(inputs=inputs), self.assertRaises(model.TransferError):
                self.prepare(self.receiver, 'decide', inputs)

    def test_all_public_functions_detach_input_and_never_execute_payload(self):
        original = copy.deepcopy(self.authorized)
        view = model.consumer_view(self.authorized, ACTIVATION)
        self.assertIn('$(touch /never-execute)', base64.b64decode(view['artifacts'][0]['bytes_b64']).decode())
        view['artifacts'][0]['bytes_b64'] = ''
        view['policy']['consumer']['code_digest'] = 'f'*64
        self.assertEqual(self.authorized, original)
        self.assertFalse(Path('/never-execute').exists())


if __name__ == '__main__':
    unittest.main()
