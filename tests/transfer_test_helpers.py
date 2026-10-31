"""Published synthetic fixtures for the bounded transfer lifecycle."""
from __future__ import annotations
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from lineage_test_helpers import eid, root_document, source
from tools.tools.echo_canonical import sha256_hex, canon_json_bytes
from tools.tools.echo_lineage import VerificationBindings, finalize_document
from tools.tools.echo_lineage_auth import sign_acceptance_document, policy_digest as old_policy_digest
from tools.tools.echo_state_model import create_state, prepare_decision, apply_decision
from tools.tools.echo_state_store import snapshot_digest
from tools.tools import echo_transfer_auth as auth
from tools.tools import echo_transfer_model as model

T = '2032-01-02T03:04:06Z'
LATER = '2032-01-02T03:05:06Z'
EXPIRY = '2032-01-03T03:04:06Z'
SOURCE_ACTOR = eid('decision-actor', 1)
RECIPIENT_ACTOR = eid('decision-actor', 2)
CONSUMER = eid('artifact', 901)
PAYLOAD_ID = eid('artifact', 20)
SOURCE_STORE = '00000000-0000-4000-8000-000000000101'
RECIPIENT_STORE = '00000000-0000-4000-8000-000000000102'
TRANSFER = eid('handoff', 201)
ACTIVATION = '00000000-0000-4000-8000-000000000401'
INSTANCE = '00000000-0000-4000-8000-000000000501'


class TransferFixture:
    def __init__(self, directory, *, payload=b'Synthetic context.\n$(touch /never-execute)\n',
                 missing=False, excluded=False, canonical=False, descriptor_bytes=0, large_policy=False,
                 source_chain_id=None, root_artifact_id=None, payload_artifact_id=None, ledger_artifact_id=None, code_digest='c' * 64):
        self.directory = Path(directory)
        payload_id = PAYLOAD_ID if payload_artifact_id is None else payload_artifact_id
        ledger_id = eid('artifact', 520) if ledger_artifact_id is None else ledger_artifact_id
        root_artifact_id = eid('artifact', 100) if root_artifact_id is None else root_artifact_id
        self.keys, self.public = {}, {}
        for role, seed in [('source', 81), ('recipient', 82), ('consumer', 83)]:
            key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
            path = self.directory / (role + '.pem')
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            path.chmod(0o600)
            self.keys[role] = path
            self.public[role] = base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        old_policy = {'schema': 'echo-lineage-trust/v1', 'keys': [{
            'key_id': eid('key', 1), 'public_key': self.public['source'],
            'decision_actor_id': SOURCE_ACTOR, 'installation_id': eid('installation', 1),
            'decision_mode': 'human_operator', 'purpose': 'lineage_acceptance'}]}
        target = self.directory / 'context.txt'
        target.write_bytes(payload)
        ledger_data = (sha256_hex(payload) + '  context.txt\n').encode()
        ledger = self.directory / 'ledger.sha256'
        ledger.write_bytes(ledger_data)
        semantic = sha256_hex(canon_json_bytes(json.loads(payload))) if canonical else sha256_hex(payload)
        src = source(20, sha256=semantic, criticality='optional' if excluded else 'required_source', ledger_sha256=sha256_hex(ledger_data) if missing else None)
        if descriptor_bytes:
            src['artifact']['media_type'] = 'x' * descriptor_bytes
        if canonical:
            src['artifact']['hash_scope'] = 'canonical_document'
        if excluded:
            target.write_bytes(b'changed optional artifact')
        src['artifact']['artifact_id'] = payload_id
        if missing:
            src['artifact']['ledger_ref']['ledger_artifact_id'] = ledger_id
        root = root_document(sources=[src])
        if source_chain_id is not None:
            root['responsibility']['chain_id'] = source_chain_id
            root = finalize_document(root)
        legacy = create_state(root, old_policy, root_artifact_id, store_id=SOURCE_STORE)
        bindings = VerificationBindings(target_paths={payload_id: target}, target_roots={payload_id: self.directory})
        if missing:
            target.unlink()
            bindings.ledger_paths[ledger_id] = ledger
            bindings.ledger_roots[payload_id] = self.directory
            bindings.ledger_entries[payload_id] = 'context.txt'
        bundle = prepare_decision(legacy, decision='accepted_with_reservations' if missing or excluded else 'accepted',
            actor_id=SOURCE_ACTOR, operator_id=SOURCE_ACTOR, request_id='legacy-accept', verification_time=T,
            bindings=bindings, expected_state_digest=snapshot_digest(legacy))
        bundle['document'] = sign_acceptance_document(bundle['document'], old_policy, self.keys['source'])
        self.legacy, _ = apply_decision(legacy, bundle, bindings=bindings,
            expected_state_digest=snapshot_digest(legacy), applied_at=T)
        lineage_policy = {'schema': 'echo-lineage-trust/v1', 'keys': [{
            'key_id': eid('key', 2), 'public_key': self.public['recipient'],
            'decision_actor_id': RECIPIENT_ACTOR, 'installation_id': eid('installation', 2),
            'decision_mode': 'human_operator', 'purpose': 'lineage_acceptance'}]}
        self.policy = {'schema': 'echo-lineage-transfer-trust/v1', 'profile': model.PROFILE,
            'transfer_id': TRANSFER, 'source_pin': {'store_id': SOURCE_STORE,
                'installation_id': eid('installation', 1), 'snapshot_digest': snapshot_digest(self.legacy),
                'acceptance_policy_digest': old_policy_digest(old_policy)},
            'recipient': {'store_id': RECIPIENT_STORE, 'installation_id': eid('installation', 2),
                'lineage_policy': lineage_policy},
            'keys': [{'key_id': eid('key', n), 'public_key': self.public[role],
                'actor_id': actor, 'installation_id': eid('installation', install),
                'role': 'local_context_consumer' if role == 'consumer' else 'human_operator',
                'purposes': purposes} for role, n, actor, install, purposes in [
                    ('source', 1, SOURCE_ACTOR, 1, ['state_migration', 'handoff_issue', 'transfer_export', 'remote_receipt_ingest']),
                    ('recipient', 2, RECIPIENT_ACTOR, 2, ['transfer_receive', 'transfer_receipt', 'receiver_decision',
                        'context_import_authorize', 'context_activation_authorize', 'context_deactivate']),
                    ('consumer', 3, CONSUMER, 2, ['context_consumption_receipt'])]],
            'consumer': {'consumer_id': CONSUMER, 'key_id': eid('key', 3), 'version': 'context-consumer-v1',
                'code_digest': code_digest, 'capabilities': ['read', 'search']}}
        if large_policy:
            # Published integer seeds exercise the exact 256 + 256 policy bounds.
            for number in range(253):
                key = Ed25519PrivateKey.from_private_bytes((number + 1000).to_bytes(32, 'big'))
                public = base64.b64encode(key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
                self.policy['keys'].append({'key_id': eid('key', number + 1000), 'public_key': public,
                    'actor_id': RECIPIENT_ACTOR, 'installation_id': eid('installation', 2),
                    'role': 'human_operator', 'purposes': ['transfer_receive', 'transfer_receipt',
                    'receiver_decision', 'context_import_authorize', 'context_activation_authorize', 'context_deactivate']})
            for number in range(255):
                key = Ed25519PrivateKey.from_private_bytes((number + 2000).to_bytes(32, 'big'))
                public = base64.b64encode(key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
                self.policy['recipient']['lineage_policy']['keys'].append({
                    'key_id': eid('key', number + 2000), 'public_key': public,
                    'decision_actor_id': RECIPIENT_ACTOR, 'installation_id': eid('installation', 2),
                    'decision_mode': 'human_operator', 'purpose': 'lineage_acceptance'})
        self.artifacts = [{'artifact_id': payload_id, 'status': 'missing',
            'ledger_b64': base64.b64encode(ledger_data).decode(), 'ledger_entry': 'context.txt'}] if missing else [
            {'artifact_id': payload_id, 'status': 'present', 'data_b64': base64.b64encode(payload).decode()}]
        if excluded:
            self.artifacts = [{'artifact_id': payload_id, 'status': 'excluded'}]
        self.counter = 0

    def migrate(self):
        c = model.prepare_migration(self.legacy, self.policy, artifacts=self.artifacts,
            actor_id=SOURCE_ACTOR, request_id='migration', verification_time=T,
            expected_state_digest=snapshot_digest(self.legacy), expected_policy_digest=auth.policy_digest(self.policy))
        packet = model.sign_candidate(self.legacy, c, self.keys['source'], expected_policy_digest=auth.policy_digest(self.policy))
        state, _ = model.apply_migration(self.legacy, packet,
            expected_state_digest=snapshot_digest(self.legacy), applied_at=T, expected_policy_digest=auth.policy_digest(self.policy))
        return state

    def action(self, state, operation, inputs, *, role=None, request=None, return_packet=False):
        role = role or ('consumer' if operation in {'activation_start', 'activation_loaded'}
            else 'source' if state['role'] == 'source' else 'recipient')
        actor = {'source': SOURCE_ACTOR, 'recipient': RECIPIENT_ACTOR, 'consumer': CONSUMER}[role]
        self.counter += 1
        candidate = model.prepare_action(state, operation, inputs, actor_id=actor,
            request_id=request or ('action-' + str(self.counter)), verification_time=LATER,
            expected_state_digest=snapshot_digest(state))
        packet = model.sign_candidate(state, candidate, self.keys[role])
        new, result = model.apply_action(state, packet, expected_state_digest=snapshot_digest(state), applied_at=LATER)
        return (new, packet) if return_packet else new

    def exported(self):
        state = self.migrate()
        state = self.action(state, 'issue', {'producer_runtime_session_id': eid('runtime-session', 1), 'expires_at': EXPIRY})
        state = self.action(state, 'export_authorize', {})
        return state, model.make_envelope(state)

    def received(self):
        source_state, envelope = self.exported()
        state = model.create_receiver(self.policy, expected_policy_digest=auth.policy_digest(self.policy))
        state = self.action(state, 'receive', {'envelope': envelope, 'recipient_runtime_session_id': eid('runtime-session', 2)})
        return source_state, state

    def imported(self):
        source_state, state = self.received()
        state = self.action(state, 'decide', {'decision': 'accepted'})
        state = self.action(state, 'import', {'artifact_ids': [PAYLOAD_ID]})
        return source_state, state

    def activated(self):
        source_state, state = self.imported()
        state = self.action(state, 'activate', {'activation_id': ACTIVATION, 'artifact_ids': [PAYLOAD_ID],
            'probe': {'artifact_id': PAYLOAD_ID, 'offset': 0, 'length': 9, 'nonce': 'a' * 64}})
        return source_state, state

    def loaded(self):
        source_state, state = self.activated()
        state = self.action(state, 'activation_start', {'activation_id': ACTIVATION,
            'instance_id': INSTANCE, 'launch_nonce': 'b' * 64, 'code_digest': self.policy['consumer']['code_digest']})
        view = model.consumer_view(state, ACTIVATION)
        receipt_payload = {'kind': 'loaded', 'activation_id': ACTIVATION, 'instance_id': INSTANCE,
            'launch_nonce': 'b' * 64, 'grant_digest': view['grant_digest'], 'import_digest': view['import_digest'],
            'read_set': view['read_set'], 'store_id': view['store_id'], 'installation_id': view['installation_id'],
            'consumer_id': CONSUMER, 'code_digest': self.policy['consumer']['code_digest'],
            'probe': view['probe'], 'probe_result': 'Synthetic', 'probe_result_sha256': sha256_hex(b'Synthetic'), 'observed_at': LATER}
        receipt = auth.sign_packet(receipt_payload, self.policy, self.keys['consumer'],
            purpose='context_consumption_receipt', actor_id=CONSUMER,
            installation_id=eid('installation', 2), role='local_context_consumer')
        state = self.action(state, 'activation_loaded', {'activation_id': ACTIVATION, 'instance_id': INSTANCE, 'receipt': receipt})
        return source_state, state
