#!/usr/bin/env python3
"""Fixed separately launched literal UTF-8 consumer. Context is inert data."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

# -I deliberately removes script/cwd import paths.  Only this fixed product
# directory is restored; packet data can never change the module search path.
from pathlib import Path
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import argparse
import base64
import hashlib
import os
import secrets
import socket
import stat

try:
    from . import echo_transfer_runtime as runtime
except ImportError:
    import echo_transfer_runtime as runtime


def _load(view):
    """Decode exact granted bytes once into RAM, plus a literal text index."""
    documents = {}
    total = 0
    for artifact in view['artifacts']:
        raw = base64.b64decode(artifact['bytes_b64'], validate=True)
        runtime._require(base64.b64encode(raw).decode('ascii') == artifact['bytes_b64'], 'CONTEXT_BASE64_INVALID')
        total += len(raw)
        runtime._require(total <= 1048576 and len(documents) < 16, 'CONTEXT_SIZE_LIMIT')
        runtime._require(hashlib.sha256(raw).hexdigest() == artifact['sha256'], 'CONTEXT_BYTES_MISMATCH')
        text = raw.decode('utf-8', errors='strict')
        runtime._require(artifact['artifact_id'] not in documents, 'CONTEXT_DUPLICATE')
        # Keep both bytes and text: raw hashes remain distinct from character
        # offsets; no JSON/code/template interpretation is performed.
        documents[artifact['artifact_id']] = {'bytes': raw, 'text': text}
    runtime._require(sorted(documents) == sorted(row['artifact_id'] for row in view['read_set']), 'CONTEXT_READ_SET_MISMATCH')
    return documents


def _probe(documents, probe):
    return documents[probe['artifact_id']]['text'][probe['offset']:probe['offset'] + probe['length']]


def _answer(documents, request):
    operation = request['operation']
    if operation == 'read':
        runtime._require(request['artifact_id'] in documents, 'ARTIFACT_NOT_AUTHORIZED')
        text = documents[request['artifact_id']]['text']
        offset, limit = request['offset'], request['limit']
        selected = text[offset:offset + limit]
        return {'artifact_id': request['artifact_id'], 'offset': offset,
                'text': selected, 'text_utf8_b64': base64.b64encode(selected.encode('utf-8')).decode('ascii'),
                'total_characters': len(text)}
    if operation == 'search':
        matches = []
        needle = runtime._search_text(request) if 'query_utf8_b64' in request else request['query']
        for artifact_id in sorted(documents):
            text = documents[artifact_id]['text']
            offset = 0
            while len(matches) < request['limit']:
                found = text.find(needle, offset)
                if found < 0:
                    break
                snippet = text[max(0, found - 32):found + min(len(needle) + 32, 288)]
                matches.append({'artifact_id': artifact_id, 'offset': found, 'text': snippet,
                                'text_utf8_b64': base64.b64encode(snippet.encode('utf-8')).decode('ascii')})
                offset = found + max(1, len(needle))
            if len(matches) >= request['limit']:
                break
        return {'matches': matches, 'literal': True}
    return {}


def _same_current(initial, current):
    for field in ('activation_id', 'grant_digest', 'import_digest', 'store_id',
                  'installation_id', 'consumer', 'read_set', 'probe', 'launch'):
        runtime._require(initial[field] == current[field], 'CONSUMER_GRANT_CHANGED')
    runtime._require(current['status'] == 'loaded', 'CONSUMER_NOT_LOADED')


def _receipt(view, documents, instance_id, key_file):
    payload = {'kind': 'loaded', 'activation_id': view['activation_id'],
        'instance_id': instance_id, 'launch_nonce': view['launch']['launch_nonce'],
        'grant_digest': view['grant_digest'], 'import_digest': view['import_digest'],
        'read_set': view['read_set'], 'store_id': view['store_id'],
        'installation_id': view['installation_id'],
        'consumer_id': view['consumer']['consumer_id'],
        'code_digest': view['consumer']['code_digest'], 'probe': view['probe'],
        'probe_result': _probe(documents, view['probe']),
        'probe_result_sha256': hashlib.sha256(_probe(documents, view['probe']).encode('utf-8')).hexdigest(),
        'observed_at': runtime._now()}
    return runtime._sign(view, payload, key_file)


def _serve(state_dir, control, view, documents, intent, key_file):
    # Never replace a stale/existing socket: a failed prior incarnation needs
    # explicit inspection and a newly authorized activation/control directory.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound = False
    socket_version = None
    try:
        try:
            os.stat(runtime.SOCKET_NAME, dir_fd=control.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise runtime.TransferRuntimeError('CONTROL_SOCKET_ALREADY_EXISTS')
        control.validate()
        old_umask = os.umask(0o177)
        try:
            server.bind(control.socket_path())
            bound = True
        finally:
            os.umask(old_umask)
        os.chmod(runtime.SOCKET_NAME, 0o600, dir_fd=control.fd, follow_symlinks=False)
        socket_version = control.check_socket()
        server.listen(4)
        server.settimeout(0.5)
        while True:
            control.validate()
            runtime._require(control.check_socket() == socket_version, 'CONTROL_SOCKET_CHANGED')
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(3.0)
                try:
                    runtime._peer(connection)
                    request = runtime._validate_request(runtime._receive(connection), wire=True)
                    current = None
                    denial = None
                    try:
                        current = runtime._read_view(state_dir, view['activation_id'])
                        _same_current(view, current)
                        runtime._require(runtime.consumer_code_digest() == view['consumer']['code_digest'], 'CONSUMER_CODE_MISMATCH')
                    except (ValueError, OSError) as exc:
                        code = str(exc)
                        denial = code if code.isupper() and len(code) <= 96 else 'GRANT_UNAVAILABLE'
                    operation = request['operation']
                    if operation == 'stop':
                        result = {'stopping': True, 'grant_current': denial is None}
                    elif denial is not None:
                        result = {'error': denial, 'grant_current': False, 'loaded': False}
                    elif operation == 'status':
                        # A fresh result derives from the actual retained RAM,
                        # independent of the historical loaded receipt.
                        result = {'grant_current': True, 'loaded': True,
                                  'read_set': view['read_set'],
                                  'probe_result_sha256': hashlib.sha256(_probe(documents, view['probe']).encode('utf-8')).hexdigest()}
                    else:
                        result = _answer(documents, request)
                        result['grant_current'] = True
                    payload = {field: intent[field] for field in (
                        'activation_id', 'instance_id', 'launch_nonce', 'grant_digest',
                        'import_digest', 'store_id', 'installation_id', 'consumer_id', 'code_digest')}
                    payload.update(kind=operation,
                        request_digest=runtime.auth.digest('consumer-query', request),
                        nonce=request['nonce'], observed_at=runtime._now(), result=result)
                    packet = runtime._sign(view, payload, key_file)
                    # Recheck grant immediately before publishing a context
                    # response, under the same original state lock as revoke.
                    if operation in ('read', 'search', 'status') and denial is None:
                        with runtime.PrivateStateStore(Path(state_dir)).locked() as transaction:
                            latest = runtime.model.consumer_view(transaction.read(), view['activation_id'])
                            _same_current(view, latest)
                            runtime._send(connection, packet)
                    else:
                        runtime._send(connection, packet)
                    if operation == 'stop':
                        return
                except (ValueError, OSError, KeyError, TypeError, UnicodeError):
                    # Invalid/failed requests close locally; no unsigned error
                    # can be mistaken for a successful authenticated response.
                    continue
    finally:
        server.close()
        if bound:
            try:
                if control.check_socket() == socket_version:
                    os.unlink(runtime.SOCKET_NAME, dir_fd=control.fd)
                    os.fsync(control.fd)
            except (ValueError, OSError):
                pass


def run_consumer(state_dir, control_dir, *, key_file, instance_id, lock_fd):
    runtime._require(runtime._uuid(instance_id), 'INSTANCE_ID_INVALID')
    with runtime._Control(control_dir, inherited_fd=lock_fd, exclusive=True) as control:
        # Verify inherited fd names the original private inode; never open or
        # acquire a second lock that could silently create another instance.
        record, intent = runtime._launch_record(control)
        runtime._require(intent['instance_id'] == instance_id, 'INSTANCE_BINDING_MISMATCH')
        phase = 'before_validation'
        view = None
        try:
            view = runtime._read_view(state_dir, intent['activation_id'])
            runtime._require(view['status'] == 'launch_intent' and view['launch'] == {
                'activation_id': intent['activation_id'], 'instance_id': instance_id,
                'launch_nonce': intent['launch_nonce'], 'code_digest': intent['code_digest']},
                'LAUNCH_INTENT_MISMATCH')
            runtime._require(view['policy'] == record['policy']
                and view['grant_digest'] == intent['grant_digest']
                and view['import_digest'] == intent['import_digest']
                and view['store_id'] == intent['store_id']
                and runtime.consumer_code_digest() == intent['code_digest'], 'CONSUMER_BINDING_MISMATCH')
            phase = 'validated'
            documents = _load(view)
            phase = 'loaded_unreceipted'
            runtime._local_outcome(control, view, intent, outcome='loaded_unreceipted', phase=phase, key_file=key_file)
            receipt = _receipt(view, documents, instance_id, key_file)
            runtime._commit_action(state_dir, 'activation_loaded',
                {'activation_id': intent['activation_id'], 'instance_id': instance_id,
                 'receipt': receipt}, key_file)
            phase = 'loaded_committed'
            view = runtime._read_view(state_dir, intent['activation_id'])
            runtime._local_outcome(control, view, intent, outcome='loaded_committed', phase=phase, key_file=key_file)
            _serve(state_dir, control, view, documents, intent, key_file)
            runtime._local_outcome(control, view, intent, outcome='stopped', phase='stopped', key_file=key_file)
        except BaseException as exc:
            code = str(exc)
            code = code if code.isupper() and len(code) <= 96 else 'CONSUMER_FAILED'
            try:
                runtime._local_outcome(control, view, intent, outcome='failed', phase=phase, key_file=key_file, code=code)
            except BaseException:
                pass
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description='Fixed local context consumer')
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--control-dir', required=True)
    parser.add_argument('--key-file', required=True)
    parser.add_argument('--instance-id', required=True)
    parser.add_argument('--lock-fd', required=True, type=int)
    arguments = parser.parse_args(argv)
    try:
        run_consumer(arguments.state_dir, arguments.control_dir,
            key_file=arguments.key_file, instance_id=arguments.instance_id,
            lock_fd=arguments.lock_fd)
        return 0
    except BaseException:
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
