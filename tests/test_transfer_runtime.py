"""Real ephemeral local processes; only published synthetic context and keys."""
from __future__ import annotations

import base64
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from transfer_test_helpers import TransferFixture, ACTIVATION, PAYLOAD_ID
from tools.tools.echo_canonical import canon_json_bytes
from tools.tools.echo_state_store import PrivateStateStore, StateStoreError
from tools.tools import echo_transfer_runtime as runtime
from tools.tools import echo_context_consumer as consumer
from tools.tools import echo_transfer_model as model


class ConsumerPrimitiveTests(unittest.TestCase):
    def test_literal_inert_utf8_bytes_loaded_to_ram_and_bounded_queries(self):
        raw = 'żółć\n$(touch /never-execute)\n雪\n'.encode()
        view = {'artifacts': [{'artifact_id': 'synthetic',
            'bytes_b64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()}],
            'read_set': [{'artifact_id': 'synthetic', 'sha256': hashlib.sha256(raw).hexdigest()}]}
        documents = consumer._load(view)
        self.assertEqual(documents['synthetic']['bytes'], raw)
        self.assertEqual(consumer._answer(documents,
            {'operation': 'read', 'artifact_id': 'synthetic', 'offset': 0, 'limit': 4})['text'], 'żółć')
        found = consumer._answer(documents, {'operation': 'search', 'query': '$(touch', 'limit': 1})
        self.assertEqual(found['matches'][0]['offset'], 5)
        self.assertTrue(found['literal'])
        raw = b'not valid utf8 \xff'
        view['artifacts'][0].update(bytes_b64=base64.b64encode(raw).decode(), sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(UnicodeError):
            consumer._load(view)

    def test_corrupt_bytes_and_duplicate_ids_fail_closed(self):
        raw = b'Synthetic'
        row = {'artifact_id': 'synthetic', 'bytes_b64': base64.b64encode(raw).decode(), 'sha256': '0' * 64}
        with self.assertRaisesRegex(runtime.TransferRuntimeError, 'CONTEXT_BYTES_MISMATCH'):
            consumer._load({'artifacts': [row], 'read_set': []})
        row['sha256'] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(runtime.TransferRuntimeError, 'CONTEXT_DUPLICATE'):
            consumer._load({'artifacts': [row, row], 'read_set': []})

    def test_query_is_closed_and_every_literal_bound_checked(self):
        valid = {'operation': 'read', 'nonce': 'a' * 64, 'artifact_id': 'synthetic', 'offset': 0, 'limit': 4096}
        self.assertEqual(runtime._validate_request(valid), valid)
        for change in ({'limit': 4097}, {'offset': -1}, {'offset': True}, {'nonce': 'a' * 63},
                       {'command': 'never'}, {'operation': 'execute'}):
            with self.subTest(change=change), self.assertRaises(runtime.TransferRuntimeError):
                runtime._validate_request(dict(valid, **change))
        for needle in ('', 'x' * 257):
            with self.assertRaises(runtime.TransferRuntimeError):
                runtime._validate_request({'operation': 'search', 'nonce': 'a' * 64, 'query': needle, 'limit': 1})

    def test_canonical_json_preserves_exact_literal_search_and_read_bytes(self):
        # The two spellings have the same CJNFC form but different RAM bytes.
        raw = 'decomposed e\u0301; composed é'.encode('utf-8')
        digest = hashlib.sha256(raw).hexdigest()
        documents = consumer._load({'artifacts': [{'artifact_id': 'synthetic',
            'bytes_b64': base64.b64encode(raw).decode(), 'sha256': digest}],
            'read_set': [{'artifact_id': 'synthetic', 'sha256': digest}]})
        request = runtime._wire_request(runtime._validate_request({
            'operation': 'search', 'nonce': 'a' * 64, 'query': 'e\u0301', 'limit': 16}))
        # Transport canonicalization cannot normalize the literal byte field.
        from tools.tools.echo_canonical import loads_json_strict
        wire = loads_json_strict(canon_json_bytes(request))
        wire = runtime._validate_request(wire, wire=True)
        result = consumer._answer(documents, wire)
        self.assertEqual([row['offset'] for row in result['matches']], [11])
        returned = consumer._answer(documents,
            {'operation': 'read', 'artifact_id': 'synthetic', 'offset': 11, 'limit': 2})
        transported = loads_json_strict(canon_json_bytes(returned))
        self.assertEqual(base64.b64decode(transported['text_utf8_b64']), 'e\u0301'.encode())
        self.assertEqual(transported['total_characters'], len(raw.decode('utf-8')))

    def test_digest_pins_all_product_dependencies_and_no_private_path(self):
        digest = runtime.consumer_code_digest()
        self.assertEqual(len(digest), 64)
        self.assertIn('echo_transfer_auth.py', runtime._CODE_MODULES)
        self.assertIn('echo_transfer_model.py', runtime._CODE_MODULES)
        self.assertIn('echo_context_consumer.py', runtime._CODE_MODULES)
        with mock.patch.object(runtime, '_CODE_MODULES', ('no-such-product-module.py',)):
            with self.assertRaisesRegex(runtime.TransferRuntimeError, '^CONSUMER_CODE_UNAVAILABLE$'):
                runtime.consumer_code_digest()


class RuntimeProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='echo-consumer-test-', dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.fixture = TransferFixture(self.base, code_digest=runtime.consumer_code_digest(),
            payload=b'Synthetic context.\n$(touch /never-execute)\n' + 'e\u0301 distinct é\n'.encode())
        _source, state = self.fixture.activated()
        self.state_dir = self.base / 'state'
        self.control_dir = self.base / 'control'
        with PrivateStateStore(self.state_dir).locked(initialize=True) as transaction:
            transaction.write(state)
        self.processes = []
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        try:
            runtime.stop_consumer(self.control_dir, state_dir=self.state_dir)
        except ValueError:
            pass
        deadline = time.monotonic() + 3
        for process in self.processes:
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def read(self):
        with PrivateStateStore(self.state_dir).locked() as transaction:
            return transaction.read()

    def action(self, operation, inputs):
        with PrivateStateStore(self.state_dir).locked() as transaction:
            state = self.fixture.action(transaction.read(), operation, inputs)
            transaction.write(state)
        return state

    def launch(self, *, popen=None, activation_id=ACTIVATION):
        actual = subprocess.Popen
        def capture(*args, **kwargs):
            process = (popen or actual)(*args, **kwargs)
            self.processes.append(process)
            return process
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=capture):
            return runtime.request_activation(self.state_dir, self.control_dir,
                activation_id=activation_id, key_file=self.fixture.keys['consumer'])

    def query(self, operation, **kwargs):
        return runtime.query_consumer(self.control_dir,
            dict(operation=operation, nonce=secrets.token_hex(32), **kwargs), state_dir=self.state_dir)

    def test_actual_process_durable_intent_signed_loaded_ram_read_search_and_probe(self):
        actual = subprocess.Popen
        def inspect_before_spawn(*args, **kwargs):
            state = self.read()
            view = model.consumer_view(state, ACTIVATION)
            self.assertEqual(view['status'], 'launch_intent')
            self.assertEqual(state['records'][-1]['packet']['payload']['operation'], 'activation_start')
            self.assertTrue((self.control_dir / runtime.LAUNCH_NAME).is_file())
            self.assertFalse(kwargs.get('shell', False))
            self.assertIn('-I', args[0])
            self.assertEqual(len(kwargs['pass_fds']), 1)
            return actual(*args, **kwargs)
        result = self.launch(popen=inspect_before_spawn)
        self.assertEqual(result['current'], 'available', result)
        self.assertNotEqual(self.processes[0].pid, os.getpid())
        state = self.read()
        self.assertEqual(model.consumer_view(state, ACTIVATION)['status'], 'loaded')
        receipt = state['records'][-1]['packet']['payload']['inputs']['receipt']
        self.assertEqual(receipt['payload']['probe_result'], 'Synthetic')
        self.assertNotIn(str(self.base), canon_json_bytes(receipt).decode())
        self.assertEqual(self.query('read', artifact_id=PAYLOAD_ID, offset=0, limit=17)['result']['text'], 'Synthetic context')
        search = self.query('search', query='$(touch', limit=2)
        self.assertEqual(len(search['result']['matches']), 1)
        first, second = self.query('status'), self.query('status')
        self.assertNotEqual(first['response']['payload']['nonce'], second['response']['payload']['nonce'])
        self.assertEqual(second['result']['probe_result_sha256'], hashlib.sha256(b'Synthetic').hexdigest())
        exact = self.query('search', query='e\u0301', limit=16)
        self.assertEqual(len(exact['result']['matches']), 1)
        exact_offset = exact['result']['matches'][0]['offset']
        exact_read = self.query('read', artifact_id=PAYLOAD_ID, offset=exact_offset, limit=2)
        self.assertEqual(base64.b64decode(exact_read['result']['text_utf8_b64']), 'e\u0301'.encode())
        self.assertEqual(self.control_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.control_dir / runtime.SOCKET_NAME).stat().st_mode & 0o777, 0o600)

    def test_actual_decomposed_probe_receipt_and_fresh_probe_bind_exact_utf8(self):
        self.action('deactivate', {'activation_id': ACTIVATION})
        activation = '00000000-0000-4000-8000-000000000402'
        text = (self.base / 'context.txt').read_text()
        self.action('activate', {'activation_id': activation, 'artifact_ids': [PAYLOAD_ID],
            'probe': {'artifact_id': PAYLOAD_ID, 'offset': text.index('e\u0301'), 'length': 2, 'nonce': 'f' * 64}})
        result = self.launch(activation_id=activation)
        self.assertEqual(result['current'], 'available', result)
        state = self.read()
        receipt = state['records'][-1]['packet']['payload']['inputs']['receipt']
        expected = hashlib.sha256('e\u0301'.encode('utf-8')).hexdigest()
        self.assertEqual(receipt['payload']['probe_result_sha256'], expected)
        self.assertNotEqual(expected, hashlib.sha256('é'.encode('utf-8')).hexdigest())
        self.assertEqual(self.query('status')['result']['probe_result_sha256'], expected)

    def test_duplicate_request_never_spawns_and_other_control_dir_cannot_start(self):
        result = self.launch()
        self.assertEqual(result['current'], 'available', result)
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=AssertionError('duplicate spawn')):
            replay = runtime.request_activation(self.state_dir, self.control_dir,
                activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])
            self.assertEqual(replay['current'], 'available')
            with self.assertRaises(runtime.TransferRuntimeError):
                runtime.request_activation(self.state_dir, self.base / 'second-control',
                    activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])

    def test_revocation_denies_future_reads_and_preserves_historical_loaded_receipt(self):
        result = self.launch()
        self.assertEqual(result['current'], 'available', result)
        state = self.action('deactivate', {'activation_id': ACTIVATION})
        self.assertEqual(model.inspect_state(state)['activations'][ACTIVATION]['status'], 'revoked')
        denied = self.query('read', artifact_id=PAYLOAD_ID, offset=0, limit=4096)
        self.assertFalse(denied['result']['grant_current'])
        self.assertEqual(denied['result']['error'], 'ACTIVATION_REVOKED')
        self.assertNotIn('text', denied['result'])
        status = runtime.reconcile_activation(self.state_dir, self.control_dir, activation_id=ACTIVATION)
        self.assertEqual(status['current'], 'unavailable')
        self.assertTrue(status['historical_loaded'])

    def test_death_after_receipt_is_unavailable_and_never_respawns(self):
        result = self.launch()
        self.assertEqual(result['current'], 'available', result)
        self.processes[0].kill()
        self.processes[0].wait(timeout=3)
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=AssertionError('death respawn')):
            result = runtime.reconcile_activation(self.state_dir, self.control_dir, activation_id=ACTIVATION)
            self.assertTrue(result['historical_loaded'])
            self.assertEqual(result['current'], 'unavailable')
            runtime.request_activation(self.state_dir, self.control_dir,
                activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])

    def test_failure_before_process_start_is_durable_and_launch_is_consumed(self):
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=OSError('synthetic failure')):
            result = runtime.request_activation(self.state_dir, self.control_dir,
                activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])
        self.assertEqual(result['launch_outcome'], 'failed_no_respawn')
        self.assertEqual(model.consumer_view(self.read(), ACTIVATION)['status'], 'launch_intent')
        with runtime._Control(self.control_dir) as control:
            record = control.read(runtime.OUTCOME_NAME)
            self.assertEqual(record['observation']['phase'], 'before_process')
            self.assertIsNotNone(record['signed_observation'])
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=AssertionError('failure respawn')):
            result = runtime.request_activation(self.state_dir, self.control_dir,
                activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])
            self.assertEqual(result['launch_outcome'], 'existing_intent_no_respawn')

    def test_revocation_wins_before_load_and_no_loaded_publication(self):
        actual = subprocess.Popen
        def revoke_before_spawn(*args, **kwargs):
            self.action('deactivate', {'activation_id': ACTIVATION})
            return actual(*args, **kwargs)
        result = self.launch(popen=revoke_before_spawn)
        self.assertEqual(result['current'], 'unavailable', result)
        state = self.read()
        history = model.inspect_state(state)['activations'][ACTIVATION]
        self.assertIsNone(history['loaded_generation'])
        self.assertFalse((self.control_dir / runtime.SOCKET_NAME).exists())

    def test_actual_load_before_receipt_failure_has_durable_inspection(self):
        actual = subprocess.Popen
        def invalidate_adapter_key_after_intent(*args, **kwargs):
            # This trusted local fault occurs after the signed state intent,
            # before the separately launched process reads the signing key.
            self.fixture.keys['consumer'].write_bytes(b'synthetic invalid key')
            return actual(*args, **kwargs)
        result = self.launch(popen=invalidate_adapter_key_after_intent)
        self.assertEqual(result['current'], 'unavailable', result)
        history = model.inspect_state(self.read())['activations'][ACTIVATION]
        self.assertIsNone(history['loaded_generation'])
        self.assertEqual(history['status'], 'launch_intent')
        with runtime._Control(self.control_dir) as control:
            outcome = control.read(runtime.OUTCOME_NAME)
        self.assertEqual(outcome['observation']['phase'], 'loaded_unreceipted')
        self.assertIsNone(outcome['signed_observation'])
        self.assertFalse((self.control_dir / runtime.SOCKET_NAME).exists())

    def test_crash_after_state_intent_before_control_metadata_never_respawns(self):
        actual_write = runtime._Control.write
        def fail_launch_record(control, name, value):
            if name == runtime.LAUNCH_NAME:
                raise runtime.TransferRuntimeError('SYNTHETIC_CRASH')
            return actual_write(control, name, value)
        with mock.patch.object(runtime._Control, 'write', new=fail_launch_record), mock.patch.object(
                runtime.subprocess, 'Popen', side_effect=AssertionError('uncertain spawn')):
            with self.assertRaisesRegex(runtime.TransferRuntimeError, 'SYNTHETIC_CRASH'):
                runtime.request_activation(self.state_dir, self.control_dir,
                    activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])
        self.assertEqual(model.consumer_view(self.read(), ACTIVATION)['status'], 'launch_intent')
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=AssertionError('crash respawn')):
            observation = runtime.reconcile_activation(self.state_dir, self.control_dir, activation_id=ACTIVATION)
        self.assertEqual(observation['current'], 'unknown')
        self.assertEqual(observation['inspection']['observation']['outcome'], 'unknown_no_respawn')

    def test_loaded_receipt_prepared_from_ram_cannot_commit_after_revoke(self):
        started = self.action('activation_start', {'activation_id': ACTIVATION,
            'instance_id': '00000000-0000-4000-8000-000000000501',
            'launch_nonce': 'b' * 64, 'code_digest': self.fixture.policy['consumer']['code_digest']})
        view = model.consumer_view(started, ACTIVATION)
        documents = consumer._load(view)
        receipt = consumer._receipt(view, documents, view['launch']['instance_id'], self.fixture.keys['consumer'])
        self.action('deactivate', {'activation_id': ACTIVATION})
        with self.assertRaisesRegex(ValueError, 'ACTIVATION_REVOKED'):
            runtime._commit_action(self.state_dir, 'activation_loaded',
                {'activation_id': ACTIVATION, 'instance_id': view['launch']['instance_id'], 'receipt': receipt},
                self.fixture.keys['consumer'])
        history = model.inspect_state(self.read())['activations'][ACTIVATION]
        self.assertIsNone(history['loaded_generation'])

    def test_code_pin_mismatch_refuses_before_launch_intent_or_process(self):
        with mock.patch.object(runtime, 'consumer_code_digest', return_value='f' * 64), mock.patch.object(
                runtime.subprocess, 'Popen', side_effect=AssertionError('bad code spawned')):
            with self.assertRaisesRegex(runtime.TransferRuntimeError, 'CONSUMER_CODE_MISMATCH'):
                runtime.request_activation(self.state_dir, self.control_dir,
                    activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])
        self.assertIsNone(model.consumer_view(self.read(), ACTIVATION)['launch'])

    def test_private_anchor_symlink_and_replaced_lock_refused(self):
        self.control_dir.mkdir(mode=0o700)
        linked = self.base / 'linked'
        linked.symlink_to(self.control_dir, target_is_directory=True)
        with self.assertRaises(runtime.TransferRuntimeError):
            runtime.request_activation(self.state_dir, linked,
                activation_id=ACTIVATION, key_file=self.fixture.keys['consumer'])
        control = runtime._Control(self.base / 'safe', initialize=True, exclusive=True)
        try:
            (self.base / 'safe' / runtime.LOCK_NAME).unlink()
            replacement = self.base / 'safe' / runtime.LOCK_NAME
            replacement.write_bytes(b'')
            replacement.chmod(0o600)
            with self.assertRaises(ValueError):
                control.validate()
        finally:
            control.close()


if __name__ == '__main__':
    unittest.main()
