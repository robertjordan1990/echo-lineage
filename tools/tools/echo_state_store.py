#!/usr/bin/env python3
"""Bounded, private POSIX snapshot storage; no state semantics or key handling.

The owning account/root can replace the whole store. This module provides
cooperating-process exclusion and durable atomic snapshots, not that boundary.
An interrupted/failed initialization is deliberately left for explicit review.
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import fcntl
import hashlib
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    from .echo_canonical import CanonicalJSONError, canon_json_bytes, loads_json_strict
except ImportError:  # direct script/import from tools/tools
    from echo_canonical import CanonicalJSONError, canon_json_bytes, loads_json_strict


MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
_DOMAIN = b"ECHO|STATE|v1|SNAPSHOT|"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
_FILE_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK
_STATE = "state.json"
_LOCK = "state.lock"


class StateStoreError(ValueError):
    """Unsafe, missing, busy, malformed, or conflicting local store."""


class CommitUncertain(StateStoreError):
    """Publication occurred; durability is uncertain. Inspect, never auto-retry."""


def _canonical(payload: dict) -> bytes:
    if not isinstance(payload, dict):
        raise StateStoreError("snapshot must be a JSON object")
    try:
        return canon_json_bytes(payload)
    except (CanonicalJSONError, RecursionError) as exc:
        raise StateStoreError("invalid canonical snapshot") from exc


def snapshot_digest(payload: dict) -> str:
    """Domain-separated digest of canonical JSON, excluding the disk newline."""
    return hashlib.sha256(_DOMAIN + _canonical(payload)).hexdigest()


def _inode(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino


def _version(info: os.stat_result) -> tuple:
    return (_inode(info), info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private_file(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise StateStoreError("store file must be owned, regular, single-link mode 0600")


def _directory(info: os.stat_result, *, private: bool = False) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        raise StateStoreError("unsafe directory")
    if private:
        if info.st_uid != os.getuid() or mode != 0o700:
            raise StateStoreError("state directory must be owned mode 0700")
    elif info.st_uid not in (0, os.getuid()) or (
        mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX)
    ):
        raise StateStoreError("untrusted writable ancestor")


class _Anchor:
    """Keep every traversed directory pinned, and recheck each parent edge."""

    def __init__(self) -> None:
        self.fds: list[int] = []
        self.edges: list[tuple[int, str, int]] = []

    def open(self, path: Path, initialize: bool) -> int:
        if ".." in path.parts:
            raise StateStoreError("parent traversal is forbidden")
        absolute = path if path.is_absolute() else Path.cwd() / path
        parts = absolute.parts[1:]
        if not parts:
            raise StateStoreError("filesystem root cannot be a state directory")
        parent = os.open("/", _DIR_FLAGS)
        self.fds.append(parent)
        _directory(os.fstat(parent))
        for name in parts[:-1]:
            child = os.open(name, _DIR_FLAGS, dir_fd=parent)
            self.fds.append(child)
            self.edges.append((parent, name, child))
            _directory(os.fstat(child))
            parent = child
        if initialize:
            # mkdir itself is the atomic no-reinitialization claim.
            os.mkdir(parts[-1], 0o700, dir_fd=parent)
        child = os.open(parts[-1], _DIR_FLAGS, dir_fd=parent)
        self.fds.append(child)
        self.edges.append((parent, parts[-1], child))
        if initialize:
            os.fsync(parent)
        self.validate()
        return child

    def validate(self) -> None:
        for index, fd in enumerate(self.fds):
            _directory(os.fstat(fd), private=index == len(self.fds) - 1)
        for parent, name, child in self.edges:
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _inode(entry) != _inode(os.fstat(child)) or not stat.S_ISDIR(entry.st_mode):
                raise StateStoreError("directory identity changed")

    def close(self) -> None:
        failure = None
        fds, self.fds = self.fds, []
        for fd in reversed(fds):
            try:
                os.close(fd)
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure


class LockedState:
    """One live transaction; valid only inside PrivateStateStore.locked()."""

    def __init__(self, anchor: _Anchor, directory_fd: int, lock_fd: int,
                 initialize: bool) -> None:
        self.initialize = initialize
        self._anchor, self._dir, self._lock = anchor, directory_fd, lock_fd
        self._active = True
        self._published = False
        self._snapshot: tuple | None = None
        self._validate()
        existing = self._state_info()
        if initialize:
            if existing is not None:
                raise StateStoreError("initial state already exists")
        elif existing is None:
            raise StateStoreError("state snapshot is missing; partial store refused")
        if existing is not None:
            _private_file(existing)
            self._snapshot = _version(existing)

    def _validate(self) -> None:
        if not self._active:
            raise StateStoreError("transaction is closed")
        self._anchor.validate()
        opened = os.fstat(self._lock)
        entry = os.stat(_LOCK, dir_fd=self._dir, follow_symlinks=False)
        _private_file(opened)
        _private_file(entry)
        if _inode(opened) != _inode(entry):
            raise StateStoreError("lock identity changed")

    def _state_info(self) -> os.stat_result | None:
        try:
            return os.stat(_STATE, dir_fd=self._dir, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _check_snapshot(self) -> os.stat_result | None:
        info = self._state_info()
        if info is not None:
            _private_file(info)
        if (None if info is None else _version(info)) != self._snapshot:
            raise StateStoreError("snapshot identity or contents changed")
        return info

    def read(self) -> dict:
        fd = None
        try:
            self._validate()
            expected = self._check_snapshot()
            if expected is None:
                raise StateStoreError("state snapshot is missing")
            fd = os.open(_STATE, os.O_RDONLY | _FILE_FLAGS, dir_fd=self._dir)
            before = os.fstat(fd)
            _private_file(before)
            if _version(before) != _version(expected):
                raise StateStoreError("snapshot changed during open")
            if before.st_size > MAX_SNAPSHOT_BYTES:
                raise StateStoreError("snapshot exceeds size limit")
            data = bytearray()
            while len(data) <= MAX_SNAPSHOT_BYTES:
                chunk = os.read(fd, min(65536, MAX_SNAPSHOT_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > MAX_SNAPSHOT_BYTES:
                raise StateStoreError("snapshot exceeds size limit")
            after = os.fstat(fd)
            _private_file(after)
            if _version(before) != _version(after):
                raise StateStoreError("snapshot changed during read")
            self._check_snapshot()
            self._validate()
            value = loads_json_strict(data.decode("utf-8"))
            if not isinstance(value, dict):
                raise StateStoreError("snapshot must be a JSON object")
            return value
        except (OSError, UnicodeError, CanonicalJSONError, RecursionError) as exc:
            raise StateStoreError("cannot safely read snapshot") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def write(self, payload: dict) -> str:
        canonical = _canonical(payload)
        data = canonical + b"\n"
        if len(data) > MAX_SNAPSHOT_BYTES:
            raise StateStoreError("snapshot exceeds size limit")
        name = ".state-" + secrets.token_hex(16) + ".tmp"
        fd = None
        renamed = False
        rename_attempted = False
        primary_failure = None
        try:
            self._validate()
            self._check_snapshot()
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_FLAGS,
                         0o600, dir_fd=self._dir)
            os.fchmod(fd, 0o600)  # only the O_EXCL-created temporary file
            offset = 0
            while offset < len(data):
                count = os.write(fd, data[offset:])
                if count <= 0:
                    raise StateStoreError("snapshot write made no progress")
                offset += count
            os.fsync(fd)
            self._validate()
            self._check_snapshot()
            opened = os.fstat(fd)
            entry = os.stat(name, dir_fd=self._dir, follow_symlinks=False)
            _private_file(opened)
            _private_file(entry)
            if _inode(opened) != _inode(entry):
                raise StateStoreError("temporary snapshot identity changed")
            rename_attempted = True
            os.replace(name, _STATE, src_dir_fd=self._dir, dst_dir_fd=self._dir)
            renamed = True
            self._published = True
            os.fsync(self._dir)
            self._validate()
            published = self._state_info()
            if published is None or _version(published) != _version(os.fstat(fd)):
                raise StateStoreError("published snapshot identity changed")
            _private_file(published)
            self._snapshot = _version(published)
            return hashlib.sha256(_DOMAIN + canonical).hexdigest()
        except BaseException as exc:
            if rename_attempted and not renamed and fd is not None:
                # Even a wrapper interrupted immediately after rename must not
                # turn an already published snapshot into a retryable failure.
                try:
                    current = self._state_info()
                    renamed = current is not None and _inode(current) == _inode(os.fstat(fd))
                except OSError:
                    renamed = True
            if renamed:
                self._published = True
                self._active = False
                primary_failure = CommitUncertain("commit_uncertain: inspect existing request before retry")
                raise primary_failure from exc
            if isinstance(exc, OSError):
                primary_failure = StateStoreError("cannot safely write snapshot")
                raise primary_failure from exc
            primary_failure = exc
            raise
        finally:
            if fd is not None:
                try:
                    if not renamed:
                        entry = os.stat(name, dir_fd=self._dir, follow_symlinks=False)
                        if _inode(entry) == _inode(os.fstat(fd)):
                            os.unlink(name, dir_fd=self._dir)
                except OSError:
                    pass
                finally:
                    try:
                        os.close(fd)
                    except BaseException as exc:
                        if isinstance(primary_failure, CommitUncertain):
                            pass
                        elif renamed:
                            self._active = False
                            raise CommitUncertain("commit_uncertain: snapshot close failed") from exc
                        elif primary_failure is not None:
                            pass
                        elif isinstance(exc, OSError):
                            raise StateStoreError("cannot safely close temporary snapshot") from exc
                        else:
                            raise


class PrivateStateStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @contextmanager
    def locked(self, *, initialize: bool = False) -> Iterator[LockedState]:
        anchor = _Anchor()
        lock_fd = None
        session = None
        primary_failure = None
        try:
            directory_fd = anchor.open(self.path, initialize)
            flags = os.O_RDWR | _FILE_FLAGS
            if initialize:
                flags |= os.O_CREAT | os.O_EXCL
            lock_fd = os.open(_LOCK, flags, 0o600, dir_fd=directory_fd)
            if initialize:
                os.fchmod(lock_fd, 0o600)
            info = os.fstat(lock_fd)
            entry = os.stat(_LOCK, dir_fd=directory_fd, follow_symlinks=False)
            _private_file(info)
            _private_file(entry)
            if _inode(info) != _inode(entry):
                raise StateStoreError("lock identity changed")
            anchor.validate()
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise StateStoreError("state store is busy") from exc
            session = LockedState(anchor, directory_fd, lock_fd, initialize)
            if initialize:
                os.fsync(lock_fd)
                os.fsync(directory_fd)
            yield session
        except OSError as exc:
            primary_failure = StateStoreError("cannot safely open private state store")
            raise primary_failure from exc
        except BaseException as exc:
            primary_failure = exc
            raise
        finally:
            if session is not None:
                session._active = False
            cleanup_failure = None
            if lock_fd is not None:
                try:
                    os.close(lock_fd)  # releases flock on the unchanged inode
                except BaseException as exc:
                    cleanup_failure = exc
            try:
                anchor.close()
            except BaseException as exc:
                if cleanup_failure is None:
                    cleanup_failure = exc
            if cleanup_failure is not None and not isinstance(primary_failure, CommitUncertain):
                if session is not None and session._published:
                    raise CommitUncertain("commit_uncertain: transaction cleanup failed") from cleanup_failure
                if primary_failure is None:
                    raise StateStoreError("cannot safely close private state store") from cleanup_failure
