from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.tools import echo_state_store as store
from tools.tools.echo_state_store import (
    CommitUncertain,
    MAX_SNAPSHOT_BYTES,
    PrivateStateStore,
    StateStoreError,
    snapshot_digest,
)


class PrivateStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        # An owned private child of root-owned sticky /tmp is supported;
        # the test suite never uses a real state directory or private payload.
        self.temporary = tempfile.TemporaryDirectory(prefix="echo-state-test-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.path = self.base / "private"
        self.store = PrivateStateStore(self.path)

    def initialize(self, payload: dict | None = None) -> None:
        with self.store.locked(initialize=True) as session:
            session.write({"generation": 0} if payload is None else payload)

    def read(self) -> dict:
        with self.store.locked() as session:
            return session.read()

    def test_unicode_digest_uses_frozen_canonical_domain_and_no_newline(self) -> None:
        expected = hashlib.sha256(
            b"ECHO|STATE|v1|SNAPSHOT|" + '{"a":"é","z":"雪"}'.encode()
        ).hexdigest()
        self.assertEqual(snapshot_digest({"z": "雪", "a": "e\u0301"}), expected)
        self.initialize({"z": "雪", "a": "e\u0301"})
        self.assertEqual((self.path / "state.json").read_bytes(),
                         '{"a":"é","z":"雪"}\n'.encode())
        with self.store.locked() as session:
            self.assertEqual(session.write({"a": "é", "z": "雪"}), expected)

    def test_private_modes_stable_lock_and_repeated_full_snapshots(self) -> None:
        self.initialize({"old": [1, 2]})
        lock_inode = (self.path / "state.lock").stat().st_ino
        for number in range(3):
            with self.store.locked() as session:
                self.assertFalse(session.initialize)
                session.write({"generation": number})
            self.assertEqual(self.read(), {"generation": number})
            self.assertEqual((self.path / "state.lock").stat().st_ino, lock_inode)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
        self.assertEqual(set(p.name for p in self.path.iterdir()), {"state.lock", "state.json"})
        for name in ("state.lock", "state.json"):
            info = (self.path / name).stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_nlink, 1)

    def test_missing_read_never_creates_anything(self) -> None:
        with self.assertRaises(StateStoreError):
            with self.store.locked():
                self.fail("missing store opened")
        self.assertEqual(list(self.base.iterdir()), [])
        self.path.mkdir(mode=0o700)
        with self.assertRaises(StateStoreError):
            with self.store.locked():
                self.fail("missing lock created")
        self.assertEqual(list(self.path.iterdir()), [])

    def test_partial_initialization_is_preserved_and_cannot_be_repaired_or_reset(self) -> None:
        with self.store.locked(initialize=True) as session:
            self.assertTrue(session.initialize)
            with self.assertRaises(StateStoreError):
                session.read()
        inode = (self.path / "state.lock").stat().st_ino
        for initialize in (False, True):
            with self.assertRaises(StateStoreError):
                with self.store.locked(initialize=initialize):
                    self.fail("partial state reopened")
        self.assertEqual((self.path / "state.lock").stat().st_ino, inode)
        self.assertEqual(set(p.name for p in self.path.iterdir()), {"state.lock"})

    def test_reinitialization_refuses_even_existing_empty_directory(self) -> None:
        self.path.mkdir(mode=0o700)
        with self.assertRaises(StateStoreError):
            with self.store.locked(initialize=True):
                self.fail("existing directory accepted")
        self.assertEqual(list(self.path.iterdir()), [])

    def test_reinitialization_preserves_existing_snapshot(self) -> None:
        self.initialize({"original": True})
        original = (self.path / "state.json").read_bytes()
        with self.assertRaises(StateStoreError):
            with self.store.locked(initialize=True):
                self.fail("reinitialization accepted")
        self.assertEqual((self.path / "state.json").read_bytes(), original)

    def test_initial_first_write_refuses_unexpected_existing_file(self) -> None:
        with self.store.locked(initialize=True) as session:
            target = self.path / "state.json"
            target.write_bytes(b'{"unexpected":true}\n')
            target.chmod(0o600)
            with self.assertRaises(StateStoreError):
                session.write({"replacement": True})
            self.assertEqual(target.read_bytes(), b'{"unexpected":true}\n')

    def test_closed_transaction_cannot_be_reused(self) -> None:
        with self.store.locked(initialize=True) as session:
            session.write({"generation": 0})
        with self.assertRaisesRegex(StateStoreError, "closed"):
            session.read()
        with self.assertRaisesRegex(StateStoreError, "closed"):
            session.write({"generation": 1})

    def test_strict_malformed_json_rejected(self) -> None:
        self.initialize()
        for payload in (b'{', b'[]', b'{"a":1,"a":2}', b'{"n":NaN}',
                        b'{"n":1e400}', b'{"x":"\xff"}', b'{} {}',
                        b'{"e\\u0301":1,"\\u00e9":2}', b'{"x":"\\ud800"}'):
            with self.subTest(payload=payload):
                (self.path / "state.json").write_bytes(payload)
                with self.assertRaises(StateStoreError):
                    self.read()

    def test_invalid_payload_refused_before_snapshot_changes(self) -> None:
        self.initialize()
        original = (self.path / "state.json").read_bytes()
        for payload in ([], {"bad": float("nan")}, {"bad": {1, 2}},
                        {"é": 1, "e\u0301": 2}):
            with self.subTest(payload=repr(payload)):
                with self.store.locked() as session:
                    with self.assertRaises(StateStoreError):
                        session.write(payload)
                self.assertEqual((self.path / "state.json").read_bytes(), original)

    def test_oversized_read_is_bounded_and_oversized_write_preserves_old_state(self) -> None:
        self.initialize()
        original = (self.path / "state.json").read_bytes()
        with self.store.locked() as session:
            with self.assertRaisesRegex(StateStoreError, "size limit"):
                session.write({"too_large": "x" * MAX_SNAPSHOT_BYTES})
        self.assertEqual((self.path / "state.json").read_bytes(), original)
        with (self.path / "state.json").open("r+b") as stream:
            stream.truncate(MAX_SNAPSHOT_BYTES + 1)
        with self.assertRaisesRegex(StateStoreError, "size limit"):
            self.read()

    def test_size_limit_includes_newline(self) -> None:
        self.initialize()
        # {"x":""} is eight bytes; one disk newline consumes the ninth.
        with mock.patch.object(store, "MAX_SNAPSHOT_BYTES", 9):
            with self.store.locked() as session:
                session.write({"x": ""})
            self.assertEqual(self.read(), {"x": ""})
            with self.store.locked() as session:
                with self.assertRaisesRegex(StateStoreError, "size limit"):
                    session.write({"x": "a"})

    def test_unsafe_root_mode_is_rejected_without_chmod(self) -> None:
        self.initialize()
        self.path.chmod(0o755)
        with self.assertRaises(StateStoreError):
            self.read()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o755)

    def test_untrusted_writable_ancestor_is_rejected(self) -> None:
        self.base.chmod(0o770)
        with self.assertRaisesRegex(StateStoreError, "ancestor"):
            self.initialize()
        self.assertFalse(self.path.exists())

    def test_symlink_ancestor_and_state_root_are_rejected(self) -> None:
        real = self.base / "real"
        real.mkdir(mode=0o700)
        (self.base / "alias").symlink_to(real, target_is_directory=True)
        for path in (self.base / "alias" / "state", self.base / "alias"):
            with self.subTest(path=path):
                with self.assertRaises(StateStoreError):
                    with PrivateStateStore(path).locked(initialize=path.name == "state"):
                        self.fail("symlink directory accepted")
        self.assertEqual(list(real.iterdir()), [])

    def test_parent_traversal_is_rejected(self) -> None:
        with self.assertRaises(StateStoreError):
            with PrivateStateStore(self.base / ".." / "unwanted").locked(initialize=True):
                self.fail("parent traversal accepted")

    def test_state_symlink_never_reads_or_writes_outside_store(self) -> None:
        self.initialize()
        outside = self.base / "outside.json"
        outside.write_bytes(b'{"outside":true}')
        outside.chmod(0o600)
        (self.path / "state.json").unlink()
        (self.path / "state.json").symlink_to(outside)
        with self.assertRaises(StateStoreError):
            self.read()
        self.assertEqual(outside.read_bytes(), b'{"outside":true}')

    def test_unsafe_state_and_lock_objects_are_rejected_without_blocking(self) -> None:
        self.initialize()
        for name in ("state.json", "state.lock"):
            for kind in ("mode", "hardlink", "fifo", "symlink", "directory"):
                with self.subTest(name=name, kind=kind):
                    target = self.path / name
                    backup = self.path / (name + ".saved")
                    target.rename(backup)
                    if kind == "mode":
                        target.write_bytes(b'{}')
                        target.chmod(0o640)
                    elif kind == "hardlink":
                        os.link(backup, target)
                    elif kind == "fifo":
                        os.mkfifo(target, 0o600)
                    elif kind == "symlink":
                        target.symlink_to(backup)
                    else:
                        target.mkdir(mode=0o700)
                    with self.assertRaises(StateStoreError):
                        self.read()
                    if kind == "directory":
                        target.rmdir()
                    else:
                        target.unlink()
                    backup.rename(target)

    def test_wrong_owner_is_rejected(self) -> None:
        self.initialize()
        with mock.patch.object(store.os, "getuid", return_value=os.getuid() + 50000):
            with self.assertRaises(StateStoreError):
                self.read()

    def test_same_process_competing_transaction_reports_busy(self) -> None:
        self.initialize()
        with self.store.locked():
            with self.assertRaisesRegex(StateStoreError, "busy"):
                with self.store.locked():
                    self.fail("second lock acquired")

    def test_other_process_cannot_apply_while_transaction_is_locked(self) -> None:
        self.initialize()
        script = """
import sys
from pathlib import Path
from tools.tools.echo_state_store import PrivateStateStore, StateStoreError
try:
    with PrivateStateStore(Path(sys.argv[1])).locked() as state:
        state.write({'generation': 999})
except StateStoreError as error:
    print(str(error))
    sys.exit(3)
sys.exit(0)
"""
        with self.store.locked():
            result = subprocess.run([sys.executable, "-B", "-c", script, str(self.path)],
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("busy", result.stdout)
        self.assertEqual(self.read(), {"generation": 0})

    def test_two_initializers_cannot_both_claim_directory(self) -> None:
        script = """
import sys
from pathlib import Path
from tools.tools.echo_state_store import PrivateStateStore, StateStoreError
print('ready', flush=True)
sys.stdin.readline()
try:
    with PrivateStateStore(Path(sys.argv[1])).locked(initialize=True) as state:
        state.write({'winner': sys.argv[2]})
    print('created', flush=True)
except StateStoreError:
    print('refused', flush=True)
"""
        processes = [subprocess.Popen(
            [sys.executable, "-B", "-c", script, str(self.path), str(index)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ) for index in range(2)]
        try:
            for process in processes:
                self.assertEqual(process.stdout.readline().strip(), "ready")
            for process in processes:
                process.stdin.write("go\n")
                process.stdin.flush()
            results = [process.communicate(timeout=10) for process in processes]
            self.assertEqual(sorted(out.strip() for out, _ in results), ["created", "refused"])
            self.assertIn(self.read()["winner"], ("0", "1"))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_pre_rename_file_fsync_failure_preserves_old_snapshot_and_allows_explicit_retry(self) -> None:
        self.initialize()
        original = (self.path / "state.json").read_bytes()
        with self.store.locked() as session:
            with mock.patch.object(store.os, "fsync", side_effect=OSError("synthetic file failure")):
                with self.assertRaises(StateStoreError) as caught:
                    session.write({"generation": 1})
            self.assertNotIsInstance(caught.exception, CommitUncertain)
            self.assertEqual((self.path / "state.json").read_bytes(), original)
            self.assertEqual(set(p.name for p in self.path.iterdir()), {"state.lock", "state.json"})
            session.write({"generation": 1})
        self.assertEqual(self.read(), {"generation": 1})

    def test_pre_rename_failure_preserves_old_snapshot(self) -> None:
        self.initialize()
        original = (self.path / "state.json").read_bytes()
        with self.store.locked() as session:
            with mock.patch.object(store.os, "replace", side_effect=OSError("synthetic rename failure")):
                with self.assertRaises(StateStoreError) as caught:
                    session.write({"generation": 1})
            self.assertNotIsInstance(caught.exception, CommitUncertain)
        self.assertEqual((self.path / "state.json").read_bytes(), original)
        self.assertEqual(set(p.name for p in self.path.iterdir()), {"state.lock", "state.json"})

    def test_post_rename_directory_fsync_failure_is_uncertain_and_never_rolled_back(self) -> None:
        self.initialize()
        real_fsync = os.fsync
        lock_inode = (self.path / "state.lock").stat().st_ino

        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory failure")
            return real_fsync(fd)

        with self.store.locked() as session:
            with mock.patch.object(store.os, "fsync", side_effect=fail_directory):
                with self.assertRaisesRegex(CommitUncertain, "commit_uncertain"):
                    session.write({"generation": 1})
            with self.assertRaisesRegex(StateStoreError, "closed"):
                session.write({"generation": 2})
        self.assertEqual(self.read(), {"generation": 1})
        self.assertEqual((self.path / "state.lock").stat().st_ino, lock_inode)

    def test_exception_immediately_after_rename_is_uncertain(self) -> None:
        self.initialize()
        real_replace = os.replace

        def interrupted_replace(*args, **kwargs):
            real_replace(*args, **kwargs)
            raise OSError("synthetic interruption after publication")

        with self.store.locked() as session:
            with mock.patch.object(store.os, "replace", side_effect=interrupted_replace):
                with self.assertRaises(CommitUncertain):
                    session.write({"generation": 1})
        self.assertEqual(self.read(), {"generation": 1})

    def test_post_rename_interrupt_is_also_uncertain(self) -> None:
        self.initialize()
        real_fsync = os.fsync

        def interrupt_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise KeyboardInterrupt()
            return real_fsync(fd)

        with self.store.locked() as session:
            with mock.patch.object(store.os, "fsync", side_effect=interrupt_directory):
                with self.assertRaises(CommitUncertain):
                    session.write({"generation": 1})
        self.assertEqual(self.read(), {"generation": 1})

    def test_post_rename_close_failure_is_uncertain(self) -> None:
        self.initialize()
        real_close = os.close

        def close_snapshot_then_fail(fd):
            info = os.fstat(fd)
            real_close(fd)
            if stat.S_ISREG(info.st_mode) and info.st_size > 0:
                raise OSError("synthetic close failure after publication")

        with self.store.locked() as session:
            with mock.patch.object(store.os, "close", side_effect=close_snapshot_then_fail):
                with self.assertRaises(CommitUncertain):
                    session.write({"generation": 1})
        self.assertEqual(self.read(), {"generation": 1})

    def test_lock_close_failure_after_publication_is_uncertain_and_closes_directories(self) -> None:
        self.initialize()
        real_close = os.close
        lock_inode = (self.path / "state.lock").stat().st_ino
        directory_fds = []

        def close_lock_then_fail(fd):
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode):
                directory_fds.append(fd)
            real_close(fd)
            if info.st_ino == lock_inode:
                raise OSError("synthetic lock close failure")

        with mock.patch.object(store.os, "close", side_effect=close_lock_then_fail):
            with self.assertRaisesRegex(CommitUncertain, "transaction cleanup"):
                with self.store.locked() as session:
                    session.write({"generation": 1})
        self.assertGreaterEqual(len(directory_fds), 3)
        for fd in directory_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual(self.read(), {"generation": 1})

    def test_directory_close_failure_after_publication_is_uncertain_and_closes_rest(self) -> None:
        self.initialize()
        real_close = os.close
        root_inode = self.path.stat().st_ino
        directory_fds = []

        def close_directory_then_fail(fd):
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode):
                directory_fds.append(fd)
            real_close(fd)
            if info.st_ino == root_inode:
                raise OSError("synthetic directory close failure")

        with mock.patch.object(store.os, "close", side_effect=close_directory_then_fail):
            with self.assertRaisesRegex(CommitUncertain, "transaction cleanup"):
                with self.store.locked() as session:
                    session.write({"generation": 1})
        self.assertGreaterEqual(len(directory_fds), 3)
        for fd in directory_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual(self.read(), {"generation": 1})

    def test_cleanup_failure_preserves_existing_commit_uncertain(self) -> None:
        self.initialize()
        real_close, real_fsync = os.close, os.fsync
        lock_inode = (self.path / "state.lock").stat().st_ino

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("first publication uncertainty")
            real_fsync(fd)

        def close_lock_then_fail(fd):
            info = os.fstat(fd)
            real_close(fd)
            if info.st_ino == lock_inode:
                raise OSError("later cleanup failure")

        original = None
        with mock.patch.object(store.os, "close", side_effect=close_lock_then_fail):
            with self.assertRaises(CommitUncertain) as caught:
                with self.store.locked() as session:
                    with mock.patch.object(store.os, "fsync", side_effect=fail_directory_fsync):
                        try:
                            session.write({"generation": 1})
                        except CommitUncertain as exc:
                            original = exc
                            raise
        self.assertIs(caught.exception, original)
        self.assertEqual(str(caught.exception.__cause__), "first publication uncertainty")
        self.assertEqual(self.read(), {"generation": 1})

    def test_cleanup_failure_before_publication_is_normal_store_error(self) -> None:
        self.initialize()
        real_close = os.close
        lock_inode = (self.path / "state.lock").stat().st_ino

        def close_lock_then_fail(fd):
            info = os.fstat(fd)
            real_close(fd)
            if info.st_ino == lock_inode:
                raise OSError("synthetic prepublication close failure")

        with mock.patch.object(store.os, "close", side_effect=close_lock_then_fail):
            with self.assertRaises(StateStoreError) as caught:
                with self.store.locked() as session:
                    self.assertEqual(session.read(), {"generation": 0})
        self.assertNotIsInstance(caught.exception, CommitUncertain)
        self.assertEqual(self.read(), {"generation": 0})

    def test_snapshot_close_failure_cannot_mask_publication_uncertainty(self) -> None:
        self.initialize()
        real_close, real_fsync = os.close, os.fsync

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("original publication failure")
            real_fsync(fd)

        def close_snapshot_then_fail(fd):
            info = os.fstat(fd)
            real_close(fd)
            if stat.S_ISREG(info.st_mode) and info.st_size > 0:
                raise OSError("later snapshot close failure")

        with self.assertRaises(CommitUncertain) as caught:
            with self.store.locked() as session:
                with mock.patch.object(store.os, "fsync", side_effect=fail_directory_fsync):
                    with mock.patch.object(store.os, "close", side_effect=close_snapshot_then_fail):
                        session.write({"generation": 1})
        self.assertEqual(str(caught.exception.__cause__), "original publication failure")
        self.assertEqual(self.read(), {"generation": 1})

    def test_snapshot_modification_between_read_and_write_is_rejected(self) -> None:
        self.initialize()
        with self.store.locked() as session:
            self.assertEqual(session.read(), {"generation": 0})
            (self.path / "state.json").write_bytes(b'{"external":true}\n')
            with self.assertRaisesRegex(StateStoreError, "changed"):
                session.write({"generation": 1})
        self.assertEqual(self.read(), {"external": True})

    def test_lock_substitution_before_publication_is_rejected(self) -> None:
        self.initialize()
        real_fsync = os.fsync
        outside = self.base / "outside"
        outside.write_bytes(b"unchanged")

        def swap_lock(fd):
            real_fsync(fd)
            (self.path / "state.lock").unlink()
            (self.path / "state.lock").symlink_to(outside)

        with self.store.locked() as session:
            with mock.patch.object(store.os, "fsync", side_effect=swap_lock):
                with self.assertRaises(StateStoreError) as caught:
                    session.write({"generation": 1})
            self.assertNotIsInstance(caught.exception, CommitUncertain)
        self.assertEqual(outside.read_bytes(), b"unchanged")
        self.assertEqual((self.path / "state.json").read_bytes(), b'{"generation":0}\n')

    def test_directory_substitution_before_publication_never_writes_outside(self) -> None:
        self.initialize()
        real_fsync = os.fsync
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        moved = self.base / "original"

        def swap_directory(fd):
            real_fsync(fd)
            self.path.rename(moved)
            self.path.symlink_to(outside, target_is_directory=True)

        with self.store.locked() as session:
            with mock.patch.object(store.os, "fsync", side_effect=swap_directory):
                with self.assertRaises(StateStoreError):
                    session.write({"generation": 1})
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual((moved / "state.json").read_bytes(), b'{"generation":0}\n')
        self.assertEqual(set(p.name for p in moved.iterdir()), {"state.lock", "state.json"})

    def test_snapshot_substitution_before_publication_is_rejected(self) -> None:
        self.initialize()
        real_fsync = os.fsync

        def swap_snapshot(fd):
            real_fsync(fd)
            target = self.path / "state.json"
            target.unlink()
            target.write_bytes(b'{"external":true}\n')
            target.chmod(0o600)

        with self.store.locked() as session:
            with mock.patch.object(store.os, "fsync", side_effect=swap_snapshot):
                with self.assertRaises(StateStoreError):
                    session.write({"generation": 1})
        self.assertEqual(self.read(), {"external": True})

    def test_temporary_symlink_substitution_never_writes_outside(self) -> None:
        self.initialize()
        outside = self.base / "outside"
        outside.write_bytes(b"unchanged")
        real_fsync = os.fsync

        def swap_temporary(fd):
            real_fsync(fd)
            temporary, = self.path.glob(".state-*.tmp")
            temporary.unlink()
            temporary.symlink_to(outside)

        with self.store.locked() as session:
            with mock.patch.object(store.os, "fsync", side_effect=swap_temporary):
                with self.assertRaises(StateStoreError):
                    session.write({"generation": 1})
        self.assertEqual(outside.read_bytes(), b"unchanged")
        self.assertEqual(self.read(), {"generation": 0})

    def test_mutation_during_read_is_rejected(self) -> None:
        self.initialize()
        real_read = os.read
        changed = False

        def mutate_during_read(fd, count):
            nonlocal changed
            result = real_read(fd, count)
            if not changed:
                changed = True
                (self.path / "state.json").write_bytes(b'{"external":true}\n')
            return result

        with self.store.locked() as session:
            with mock.patch.object(store.os, "read", side_effect=mutate_during_read):
                with self.assertRaisesRegex(StateStoreError, "changed"):
                    session.read()


if __name__ == "__main__":
    unittest.main()
