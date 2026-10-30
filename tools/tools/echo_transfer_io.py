"""Bounded anchored private transport reads; no packet-derived filesystem paths."""
from __future__ import annotations

import os
from pathlib import Path

try:
    from .echo_state import CLIError, _outside_checkout, _metadata
    from .echo_state_store import _Anchor
    from .echo_canonical import loads_json_strict
except ImportError:
    from echo_state import CLIError, _outside_checkout, _metadata
    from echo_state_store import _Anchor
    from echo_canonical import loads_json_strict

MAX_ENVELOPE_BYTES = 4 * 1024 * 1024


def read_private_bytes(path, *, limit=MAX_ENVELOPE_BYTES, sync=False):
    """Pin all parent edges and recheck the regular, single-link input file."""
    path = _outside_checkout(Path(path))
    anchor, fd = _Anchor(), None
    try:
        directory = anchor.open(path.parent, False)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory)
        before = _metadata(os.fstat(fd))
        if before[5] > limit:
            raise CLIError("INPUT_SIZE_LIMIT")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > limit:
            raise CLIError("INPUT_SIZE_LIMIT")
        anchor.validate()
        if before != _metadata(os.fstat(fd)) or before != _metadata(
                os.stat(path.name, dir_fd=directory, follow_symlinks=False)):
            raise CLIError("INPUT_CHANGED")
        if sync:
            os.fsync(fd)
            os.fsync(directory)
            anchor.validate()
            if before != _metadata(os.fstat(fd)) or before != _metadata(
                    os.stat(path.name, dir_fd=directory, follow_symlinks=False)):
                raise CLIError("INPUT_CHANGED")
        return bytes(raw)
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            anchor.close()


def read_envelope(path, *, sync=False):
    raw = read_private_bytes(path, sync=sync)
    envelope = loads_json_strict(raw.decode("utf-8"))
    if not isinstance(envelope, dict):
        raise CLIError("INPUT_MUST_BE_OBJECT")
    return envelope, raw
