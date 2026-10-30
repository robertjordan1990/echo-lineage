"""Pinned, local-only UTF-8 context consumer control.

A committed activation_start is a single-use launch intent.  Nothing in this
module retries it or interprets context as code.  Historical load receipts and
fresh process availability are deliberately separate observations.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import base64
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import subprocess
import time
import uuid

try:
    from .echo_canonical import canon_json_bytes, loads_json_strict
    from .echo_state_store import (PrivateStateStore, StateStoreError,
                                   CommitUncertain, _Anchor, _private_file,
                                   _inode, _version, snapshot_digest)
    from . import echo_transfer_auth as auth
    from . import echo_transfer_model as model
except ImportError:
    from echo_canonical import canon_json_bytes, loads_json_strict
    from echo_state_store import (PrivateStateStore, StateStoreError,
                                  CommitUncertain, _Anchor, _private_file,
                                  _inode, _version, snapshot_digest)
    import echo_transfer_auth as auth
    import echo_transfer_model as model

MAX_MESSAGE_BYTES = 128 * 1024
MAX_CONTROL_BYTES = 4 * 1024 * 1024
SOCKET_NAME = 'consumer.sock'
LOCK_NAME = 'consumer.lock'
LAUNCH_NAME = 'launch.json'
OUTCOME_NAME = 'inspection.json'
# The complete fixed product dependency closure.  Paths and packet payloads
# cannot add modules to this set or choose an executable.
_CODE_MODULES = (
    'echo_canonical.py', 'echo_context_consumer.py', 'echo_ledger.py',
    'echo_lineage.py', 'echo_lineage_auth.py', 'echo_state_model.py',
    'echo_state_store.py', 'echo_transfer_auth.py', 'echo_transfer_model.py',
    'echo_transfer_runtime.py',
)


class TransferRuntimeError(ValueError):
    """Path-free local consumer failure."""


def _require(condition, code):
    if not condition:
        raise TransferRuntimeError(code)


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _hex(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4
    except (ValueError, TypeError, AttributeError):
        return False


def consumer_code_digest() -> str:
    """Hash names and raw bytes of the fixed transitive product modules."""
    hasher = hashlib.sha256(b'ECHO|TRANSFER|v1|CONSUMER_CODE|')
    base = Path(__file__).resolve().parent
    try:
        for name in _CODE_MODULES:
            data = (base / name).read_bytes()
            hasher.update(name.encode('ascii') + b'\0')
            hasher.update(len(data).to_bytes(8, 'big'))
            hasher.update(data)
    except OSError:
        raise TransferRuntimeError('CONSUMER_CODE_UNAVAILABLE') from None
    return hasher.hexdigest()


class _Control:
    """Private anchored directory and an unreplaceable instance-lock inode.

    The child inherits the locked open-file description.  Closing the parent's
    descriptor therefore never releases a live child's instance lock.
    """
    def __init__(self, path, *, initialize=False, exclusive=False, inherited_fd=None):
        self.anchor = _Anchor()
        self.fd = None
        self.lock_fd = None
        try:
            self.fd = self.anchor.open(Path(path), initialize)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if initialize:
                flags |= os.O_CREAT | os.O_EXCL
            if inherited_fd is None:
                self.lock_fd = os.open(LOCK_NAME, flags, 0o600, dir_fd=self.fd)
            else:
                self.lock_fd = os.dup(inherited_fd)
            if initialize:
                os.fchmod(self.lock_fd, 0o600)
            self.validate()
            if exclusive:
                try:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise TransferRuntimeError('CONSUMER_INSTANCE_BUSY') from None
            if initialize:
                os.fsync(self.lock_fd)
                os.fsync(self.fd)
        except BaseException:
            self.close()
            raise

    def validate(self):
        self.anchor.validate()
        opened = os.fstat(self.lock_fd)
        entry = os.stat(LOCK_NAME, dir_fd=self.fd, follow_symlinks=False)
        _private_file(opened)
        _private_file(entry)
        _require(_inode(opened) == _inode(entry), 'CONTROL_LOCK_CHANGED')

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        self.anchor.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def read(self, name, *, optional=False):
        self.validate()
        fd = None
        try:
            try:
                expected = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                if optional:
                    return None
                raise TransferRuntimeError('CONTROL_RECORD_MISSING') from None
            _private_file(expected)
            _require(expected.st_size <= MAX_CONTROL_BYTES, 'CONTROL_RECORD_SIZE')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            before = os.fstat(fd)
            _require(_version(before) == _version(expected), 'CONTROL_RECORD_CHANGED')
            data = bytearray()
            while len(data) <= MAX_CONTROL_BYTES:
                chunk = os.read(fd, min(65536, MAX_CONTROL_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            _require(len(data) <= MAX_CONTROL_BYTES, 'CONTROL_RECORD_SIZE')
            _require(_version(before) == _version(os.fstat(fd)), 'CONTROL_RECORD_CHANGED')
            current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            _require(_version(before) == _version(current), 'CONTROL_RECORD_CHANGED')
            value = loads_json_strict(bytes(data).decode('utf-8'))
            _require(isinstance(value, dict), 'CONTROL_RECORD_INVALID')
            self.validate()
            return value
        finally:
            if fd is not None:
                os.close(fd)

    def write(self, name, value):
        self.validate()
        data = canon_json_bytes(value) + b'\n'
        _require(len(data) <= MAX_CONTROL_BYTES, 'CONTROL_RECORD_SIZE')
        temporary = '.consumer-' + secrets.token_hex(16) + '.tmp'
        fd = None
        published = False
        attempted = False
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(data):
                count = os.write(fd, data[offset:])
                _require(count > 0, 'CONTROL_WRITE_FAILED')
                offset += count
            os.fsync(fd)
            self.validate()
            opened = os.fstat(fd)
            entry = os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)
            _private_file(opened)
            _private_file(entry)
            _require(_inode(opened) == _inode(entry), 'CONTROL_RECORD_CHANGED')
            # Existing metadata may only ever be another private regular file.
            try:
                _private_file(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
            except FileNotFoundError:
                pass
            attempted = True
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            published = True
            os.fsync(self.fd)
            self.validate()
        except BaseException:
            if attempted:
                # Once publication was attempted, callers must inspect and may
                # never convert uncertainty into another launch attempt.
                raise TransferRuntimeError('CONTROL_COMMIT_UNCERTAIN') from None
            raise
        finally:
            if fd is not None:
                if not published:
                    try:
                        entry = os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)
                        if _inode(entry) == _inode(os.fstat(fd)):
                            os.unlink(temporary, dir_fd=self.fd)
                    except FileNotFoundError:
                        pass
                os.close(fd)

    def socket_path(self):
        self.validate()
        # Linux /proc binds/connects relative to a pinned directory descriptor.
        return '/proc/self/fd/' + str(self.fd) + '/' + SOCKET_NAME

    def check_socket(self):
        self.validate()
        info = os.stat(SOCKET_NAME, dir_fd=self.fd, follow_symlinks=False)
        _require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                 'CONTROL_SOCKET_UNSAFE')
        return _version(info)


def _peer(connection):
    _require(hasattr(socket, 'SO_PEERCRED'), 'LOCAL_PEER_CHECK_UNAVAILABLE')
    pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    _require(uid == os.getuid(), 'LOCAL_PEER_REFUSED')
    return pid


def _send(connection, value):
    data = canon_json_bytes(value) + b'\n'
    _require(len(data) <= MAX_MESSAGE_BYTES, 'CONSUMER_MESSAGE_SIZE')
    connection.sendall(data)


def _receive(connection):
    data = bytearray()
    while len(data) <= MAX_MESSAGE_BYTES:
        chunk = connection.recv(min(4096, MAX_MESSAGE_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b'\n' in data:
            break
    _require(len(data) <= MAX_MESSAGE_BYTES and data.endswith(b'\n')
             and data.count(b'\n') == 1, 'CONSUMER_MESSAGE_INVALID')
    value = loads_json_strict(bytes(data[:-1]).decode('utf-8'))
    _require(isinstance(value, dict), 'CONSUMER_MESSAGE_INVALID')
    return value


def _sign(view, payload, key_file):
    return auth.sign_packet(payload, view['policy'], key_file,
                            purpose='context_consumption_receipt',
                            actor_id=view['consumer']['consumer_id'],
                            installation_id=view['installation_id'],
                            role='local_context_consumer')


def _verify(view, packet):
    return auth.verify_packet(packet, view['policy'],
                              purpose='context_consumption_receipt',
                              actor_id=view['consumer']['consumer_id'],
                              installation_id=view['installation_id'],
                              role='local_context_consumer')


def _read_view(state_dir, activation_id):
    with PrivateStateStore(Path(state_dir)).locked() as transaction:
        return model.consumer_view(transaction.read(), activation_id)


def _commit_action(state_dir, operation, inputs, key_file):
    with PrivateStateStore(Path(state_dir)).locked() as transaction:
        state = transaction.read()
        view = model.consumer_view(state, inputs['activation_id'])
        candidate = model.prepare_action(state, operation, inputs,
            actor_id=view['consumer']['consumer_id'],
            request_id='runtime:' + str(uuid.uuid4()), verification_time=_now(),
            expected_state_digest=snapshot_digest(state))
        signed = model.sign_candidate(state, candidate, key_file)
        updated, result = model.apply_action(state, signed,
            expected_state_digest=snapshot_digest(state), applied_at=_now())
        transaction.write(updated)
        return result


def _launch_record(control):
    record = control.read(LAUNCH_NAME)
    _require(set(record) == {'schema', 'policy', 'intent'}, 'CONTROL_RECORD_INVALID')
    _require(record['schema'] == 'echo-context-control/v1', 'CONTROL_RECORD_INVALID')
    policy = auth.validate_policy(record['policy'])
    consumer = policy['consumer']
    installation = policy['recipient']['installation_id']
    payload = auth.verify_packet(record['intent'], policy,
        purpose='context_consumption_receipt', actor_id=consumer['consumer_id'],
        installation_id=installation, role='local_context_consumer')
    fields = {'kind', 'activation_id', 'instance_id', 'launch_nonce', 'code_digest',
              'grant_digest', 'import_digest', 'store_id', 'installation_id',
              'consumer_id', 'observed_at'}
    _require(set(payload) == fields and payload['kind'] == 'launch_intent', 'CONTROL_RECORD_INVALID')
    _require(_uuid(payload['activation_id']) and _uuid(payload['instance_id'])
             and _hex(payload['launch_nonce']) and _hex(payload['grant_digest'])
             and _hex(payload['import_digest']) and _hex(payload['code_digest'])
             and payload['installation_id'] == installation
             and payload['consumer_id'] == consumer['consumer_id']
             and payload['code_digest'] == consumer['code_digest'], 'CONTROL_RECORD_INVALID')
    return record, payload


def _local_outcome(control, view, intent, *, outcome, phase, key_file=None, code=None):
    """Persist inspection even if a post-load signature cannot be produced."""
    payload = {'kind': 'runtime_outcome', 'activation_id': intent['activation_id'],
               'instance_id': intent['instance_id'], 'launch_nonce': intent['launch_nonce'],
               'outcome': outcome, 'phase': phase, 'observed_at': _now()}
    if code is not None:
        payload['code'] = code
    record = {'schema': 'echo-context-inspection/v1', 'observation': payload,
              'signed_observation': None}
    if key_file is not None and view is not None:
        try:
            record['signed_observation'] = _sign(view, payload, key_file)
        except (ValueError, OSError):
            pass
    control.write(OUTCOME_NAME, record)


def _safe_call(function):
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (TransferRuntimeError, CommitUncertain):
            raise
        except (OSError, StateStoreError, ValueError, TypeError, KeyError,
                RecursionError, UnicodeError):
            raise TransferRuntimeError('LOCAL_CONSUMER_REFUSED') from None
    checked.__name__ = function.__name__
    checked.__doc__ = function.__doc__
    return checked


@_safe_call
def request_activation(state_dir, control_dir, *, activation_id, key_file) -> dict:
    """Persist the one launch intent, then start exactly one fixed process.

    A previous intent, including a dead or uncertain process, is never retried.
    Re-authorization requires a new activation and a fresh explicit control dir.
    """
    _require(_uuid(activation_id), 'ACTIVATION_ID_INVALID')
    # _Anchor, not Path.mkdir(parents=True), owns and verifies every parent.
    try:
        control = _Control(control_dir, initialize=True, exclusive=True)
    except FileExistsError:
        try:
            control = _Control(control_dir, exclusive=True)
        except TransferRuntimeError as exc:
            if str(exc) == 'CONSUMER_INSTANCE_BUSY':
                return reconcile_activation(state_dir, control_dir, activation_id=activation_id)
            raise
    with control:
        previous = control.read(LAUNCH_NAME, optional=True)
        if previous is not None:
            _record, intent = _launch_record(control)
            _require(intent['activation_id'] == activation_id, 'CONTROL_ACTIVATION_CONFLICT')
            return {'activation_id': activation_id, 'instance_id': intent['instance_id'],
                    'launch_outcome': 'existing_intent_no_respawn', 'current': 'unavailable',
                    'inspection': control.read(OUTCOME_NAME, optional=True)}
        view = _read_view(state_dir, activation_id)
        _require(view['status'] == 'authorized' and view['launch'] is None,
                 'ACTIVATION_LAUNCH_ALREADY_CONSUMED')
        code_digest = consumer_code_digest()
        _require(view['consumer']['code_digest'] == code_digest, 'CONSUMER_CODE_MISMATCH')
        instance_id = str(uuid.uuid4())
        launch_nonce = secrets.token_hex(32)
        inputs = {'activation_id': activation_id, 'instance_id': instance_id,
                  'launch_nonce': launch_nonce, 'code_digest': code_digest}
        intent = dict(inputs, kind='launch_intent', grant_digest=view['grant_digest'],
                      import_digest=view['import_digest'], store_id=view['store_id'],
                      installation_id=view['installation_id'],
                      consumer_id=view['consumer']['consumer_id'], observed_at=_now())
        # Sign before touching the model.  The state action itself is separately
        # signed and durably committed under its original stable store lock.
        signed_intent = _sign(view, intent, key_file)
        _commit_action(state_dir, 'activation_start', inputs, key_file)
        control.write(LAUNCH_NAME, {'schema': 'echo-context-control/v1',
                                   'policy': view['policy'], 'intent': signed_intent})
        _local_outcome(control, view, intent, outcome='launch_pending', phase='before_process', key_file=key_file)
        script = Path(__file__).resolve().with_name('echo_context_consumer.py')
        # No shell, command from a packet, environment-controlled import path,
        # cwd-selected module, or context text can select executed code.
        command = [sys.executable, '-I', '-B', str(script),
                   '--state-dir', str(Path(state_dir).absolute()),
                   '--control-dir', str(Path(control_dir).absolute()),
                   '--key-file', str(Path(key_file).absolute()),
                   '--instance-id', instance_id, '--lock-fd', str(control.lock_fd)]
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=(control.lock_fd,), start_new_session=True)
        except (OSError, ValueError):
            _local_outcome(control, view, intent, outcome='process_creation_failed',
                           phase='before_process', key_file=key_file,
                           code='PROCESS_CREATION_FAILED')
            return {'activation_id': activation_id, 'instance_id': instance_id,
                    'launch_outcome': 'failed_no_respawn', 'current': 'unavailable'}
        # Popen success is not load evidence.  The child's signed fresh response
        # is the only observation of a currently answering consumer.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return {'activation_id': activation_id, 'instance_id': instance_id,
                        'launch_outcome': 'process_exited', 'current': 'unavailable',
                        'inspection': control.read(OUTCOME_NAME, optional=True)}
            try:
                observation = query_consumer(control_dir,
                    {'operation': 'status', 'nonce': secrets.token_hex(32)}, state_dir=state_dir)
                return {'activation_id': activation_id, 'instance_id': instance_id,
                        'launch_outcome': 'started', 'current': ('available' if observation['result'].get('grant_current') is True and observation['result'].get('loaded') is True else 'unavailable'),
                        'observation': observation}
            except TransferRuntimeError:
                time.sleep(0.025)
        return {'activation_id': activation_id, 'instance_id': instance_id,
                'launch_outcome': 'unknown_no_respawn', 'current': 'unknown'}


def _validate_request(request, *, wire=False):
    _require(isinstance(request, dict), 'QUERY_INVALID')
    operation = request.get('operation')
    fields = {
        'status': {'operation', 'nonce'}, 'stop': {'operation', 'nonce'},
        'read': {'operation', 'nonce', 'artifact_id', 'offset', 'limit'},
        'search': {'operation', 'nonce', 'query_utf8_b64' if wire else 'query', 'limit'},
    }
    _require(operation in fields and set(request) == fields[operation]
             and _hex(request.get('nonce')), 'QUERY_INVALID')
    if operation == 'read':
        _require(isinstance(request['artifact_id'], str)
                 and isinstance(request['offset'], int) and not isinstance(request['offset'], bool)
                 and 0 <= request['offset'] <= 1048576
                 and isinstance(request['limit'], int) and not isinstance(request['limit'], bool)
                 and 0 <= request['limit'] <= 4096, 'QUERY_BOUNDS')
    elif operation == 'search':
        needle = _search_text(request) if wire else request['query']
        _require(isinstance(needle, str) and 1 <= len(needle) <= 256
                 and isinstance(request['limit'], int) and not isinstance(request['limit'], bool)
                 and 1 <= request['limit'] <= 16, 'QUERY_BOUNDS')
    return copy.deepcopy(request)


def _search_text(request):
    value = request.get('query_utf8_b64')
    _require(isinstance(value, str) and len(value) <= 1368, 'QUERY_BOUNDS')
    try:
        raw = base64.b64decode(value, validate=True)
        _require(base64.b64encode(raw).decode('ascii') == value, 'QUERY_INVALID')
        return raw.decode('utf-8', errors='strict')
    except (ValueError, UnicodeError):
        raise TransferRuntimeError('QUERY_INVALID') from None


def _wire_request(request):
    request = copy.deepcopy(request)
    if request['operation'] == 'search':
        # CJNFC signatures normalize JSON strings.  Encoding literal search
        # text as bytes keeps canonically equivalent Unicode sequences distinct.
        needle = request.pop('query')
        request['query_utf8_b64'] = base64.b64encode(needle.encode('utf-8')).decode('ascii')
    return request


def _trusted_control_view(state_dir, record, intent):
    """Resolve IPC authority from an explicit, separately trusted state store."""
    with PrivateStateStore(Path(state_dir)).locked() as transaction:
        state = transaction.read()
        status = model.inspect_state(state)
        policy = state['policy']
        _require(record['policy'] == policy, 'CONTROL_POLICY_PIN_MISMATCH')
        history = status['activations'].get(intent['activation_id'])
        _require(history is not None and history['launch'] is not None, 'CONTROL_ACTIVATION_CONFLICT')
        grant = state['records'][history['generation'] - 1]['packet']
        launch = {field: intent[field] for field in ('activation_id', 'instance_id', 'launch_nonce', 'code_digest')}
        _require(history['launch'] == launch
                 and intent['grant_digest'] == auth.digest('grant', grant)
                 and intent['import_digest'] == state['projections']['import']['import_digest']
                 and intent['store_id'] == state['store_id']
                 and intent['installation_id'] == policy['recipient']['installation_id']
                 and intent['consumer_id'] == policy['consumer']['consumer_id']
                 and intent['code_digest'] == policy['consumer']['code_digest'], 'CONTROL_STATE_CONFLICT')
        return {'policy': policy, 'consumer': policy['consumer'],
                'installation_id': policy['recipient']['installation_id']}


def _expected_probe_digest(view):
    probe = view['probe']
    items = {item['artifact_id']: item for item in view['artifacts']}
    _require(probe['artifact_id'] in items, 'CONSUMER_PROBE_INVALID')
    item = items[probe['artifact_id']]
    raw = base64.b64decode(item['bytes_b64'], validate=True)
    _require(hashlib.sha256(raw).hexdigest() == item['sha256'], 'CONSUMER_PROBE_INVALID')
    text = raw.decode('utf-8', errors='strict')
    selected = text[probe['offset']:probe['offset'] + probe['length']]
    return hashlib.sha256(selected.encode('utf-8')).hexdigest()


@_safe_call
def query_consumer(control_dir, request, *, state_dir) -> dict:
    """Obtain and verify a nonce-bound signed response over private local IPC."""
    request = _wire_request(_validate_request(request))
    with _Control(control_dir) as control:
        record, intent = _launch_record(control)
        # Do not take the state lock while a just-launched adapter is still
        # loading/committing.  Socket existence alone is never trusted evidence;
        # policy is still independently checked before any IPC connection.
        before = control.check_socket()
        view = _trusted_control_view(state_dir, record, intent)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3.0)
            connection.connect(control.socket_path())
            _peer(connection)
            _require(control.check_socket() == before, 'CONTROL_SOCKET_CHANGED')
            _send(connection, request)
            packet = _receive(connection)
        payload = _verify(view, packet)
        _require(set(payload) == {'kind', 'activation_id', 'instance_id', 'launch_nonce',
                 'grant_digest', 'import_digest', 'store_id', 'installation_id', 'consumer_id',
                 'code_digest', 'request_digest', 'nonce', 'observed_at', 'result'},
                 'CONSUMER_RESPONSE_INVALID')
        for field in ('activation_id', 'instance_id', 'launch_nonce', 'grant_digest',
                      'import_digest', 'store_id', 'installation_id', 'consumer_id', 'code_digest'):
            _require(payload[field] == intent[field], 'CONSUMER_RESPONSE_BINDING')
        _require(payload['kind'] == request['operation']
                 and payload['nonce'] == request['nonce']
                 and payload['request_digest'] == auth.digest('consumer-query', request),
                 'CONSUMER_RESPONSE_BINDING')
        _require(isinstance(payload['result'], dict), 'CONSUMER_RESPONSE_INVALID')
        result = payload['result']
        _require(type(result.get('grant_current')) is bool, 'CONSUMER_RESPONSE_INVALID')
        if request['operation'] != 'stop':
            if result['grant_current']:
                # A valid consumer key cannot turn a revoked operator grant
                # into current read permission at the requesting endpoint.
                current = _read_view(state_dir, intent['activation_id'])
                _require(current['status'] == 'loaded'
                         and current['policy'] == view['policy']
                         and current['grant_digest'] == intent['grant_digest']
                         and current['import_digest'] == intent['import_digest'], 'CONSUMER_GRANT_CHANGED')
                if request['operation'] == 'status':
                    _require(set(result) == {'grant_current', 'loaded', 'read_set', 'probe_result_sha256'}
                             and result['loaded'] is True
                             and result['read_set'] == current['read_set']
                             and result['probe_result_sha256'] == _expected_probe_digest(current),
                             'CONSUMER_STATUS_PROOF_INVALID')
            else:
                _require(set(result) == {'error', 'grant_current', 'loaded'}
                         and result['loaded'] is False and isinstance(result['error'], str)
                         and 1 <= len(result['error']) <= 96
                         and result['error'][0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                         and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in result['error']),
                         'CONSUMER_RESPONSE_INVALID')
        return {'current': 'available', 'response': packet, 'result': payload['result']}


@_safe_call
def reconcile_activation(state_dir, control_dir, *, activation_id) -> dict:
    """Inspect verified history and fresh liveness; never launch a process."""
    _require(_uuid(activation_id), 'ACTIVATION_ID_INVALID')
    state_code = None
    view = None
    historical_loaded = False
    historical_receipt_digest = None
    with PrivateStateStore(Path(state_dir)).locked() as transaction:
        state = transaction.read()
        status = model.inspect_state(state)
        history = status['activations'].get(activation_id)
        _require(history is not None, 'ACTIVATION_NOT_AUTHORIZED')
        historical_loaded = history.get('loaded_generation') is not None
        if historical_loaded:
            loaded = state['records'][history['loaded_generation'] - 1]['packet']['payload']['inputs']['receipt']
            historical_receipt_digest = auth.digest('consumption-receipt', loaded)
        try:
            view = model.consumer_view(state, activation_id)
        except ValueError as exc:
            state_code = str(exc) if str(exc).isupper() and len(str(exc)) <= 96 else 'GRANT_UNAVAILABLE'
    with _Control(control_dir) as control:
        try:
            _record, intent = _launch_record(control)
        except TransferRuntimeError as exc:
            if str(exc) != 'CONTROL_RECORD_MISSING':
                raise
            # State commit can precede local metadata publication.  Its signed
            # single-use launch remains consumed; reconciliation cannot start
            # or reconstruct an authenticated adapter instance.
            launch = history.get('launch')
            _require(launch is not None, 'CONTROL_RECORD_MISSING')
            intent = dict(launch)
            _local_outcome(control, view, intent, outcome='unknown_no_respawn',
                           phase='intent_committed_metadata_missing')
            return {'activation_id': activation_id, 'instance_id': launch['instance_id'],
                    'historical_loaded': historical_loaded,
                    'historical_receipt_digest': historical_receipt_digest,
                    'current': 'unknown', 'grant_current': view is not None,
                    'inspection': control.read(OUTCOME_NAME)}
        _require(intent['activation_id'] == activation_id, 'CONTROL_ACTIVATION_CONFLICT')
        _require(_record['policy'] == state['policy'], 'CONTROL_POLICY_PIN_MISMATCH')
        _trusted_control_view(state_dir, _record, intent)
        if view is not None:
            _require(view['grant_digest'] == intent['grant_digest']
                     and view['import_digest'] == intent['import_digest']
                     and view['store_id'] == intent['store_id'], 'CONTROL_STATE_CONFLICT')
        result = {'activation_id': activation_id, 'instance_id': intent['instance_id'],
                  'historical_loaded': historical_loaded,
                  'historical_receipt_digest': historical_receipt_digest,
                  'current': 'unknown', 'grant_current': view is not None,
                  'inspection': control.read(OUTCOME_NAME, optional=True)}
        if state_code is not None:
            result['state_code'] = state_code
        try:
            observation = query_consumer(control_dir, {'operation': 'status', 'nonce': secrets.token_hex(32)}, state_dir=state_dir)
            result['observation'] = observation
            result['current'] = ('available' if observation['result'].get('grant_current') is True
                                 and observation['result'].get('loaded') is True else 'unavailable')
        except TransferRuntimeError:
            # An exclusive lock proves no cooperating holder currently owns the
            # original inode; a busy lock with no answer remains UNKNOWN.
            try:
                fcntl.flock(control.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result['current'] = 'unavailable'
                _local_outcome(control, view, intent, outcome='not_running', phase='inspection')
                result['inspection'] = control.read(OUTCOME_NAME)
            except BlockingIOError:
                result['current'] = 'unknown'
        return result


@_safe_call
def stop_consumer(control_dir, *, state_dir) -> dict:
    """Request local process exit; this does not revoke a historical grant."""
    observation = query_consumer(control_dir, {'operation': 'stop', 'nonce': secrets.token_hex(32)}, state_dir=state_dir)
    return {'current': 'stopping', 'observation': observation}
