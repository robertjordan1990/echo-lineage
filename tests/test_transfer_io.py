from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from tools.tools.echo_state import CLIError
from tools.tools.echo_state_store import StateStoreError
from tools.tools.echo_transfer_io import read_private_bytes, read_envelope


class TransferIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / "envelope.json"
        self.path.write_bytes(b'{ "fictional": "context" }\n')
        self.path.chmod(0o600)

    def test_preserves_actual_transport_bytes_separately_from_json(self):
        value, raw = read_envelope(self.path)
        self.assertEqual(value, {"fictional": "context"})
        self.assertEqual(raw, b'{ "fictional": "context" }\n')

    def test_rejects_limit_before_and_during_read(self):
        with self.assertRaises(CLIError):
            read_private_bytes(self.path, limit=3)

    def test_rejects_leaf_symlink(self):
        link = self.directory / "linked.json"
        link.symlink_to(self.path)
        with self.assertRaises((OSError, CLIError)):
            read_private_bytes(link)

    def test_rejects_directory_symlink(self):
        link = self.directory / "linked-parent"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises((OSError, StateStoreError)):
            read_private_bytes(link / self.path.name)

    def test_rejects_hardlink(self):
        second = self.directory / "another.json"
        os.link(self.path, second)
        with self.assertRaises(CLIError):
            read_private_bytes(self.path)

    def test_rejects_fifo_without_waiting_for_writer(self):
        fifo = self.directory / "pipe"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(CLIError):
            read_private_bytes(fifo)

    def test_rejects_nonprivate_parent(self):
        self.directory.chmod(0o750)
        with self.assertRaises(StateStoreError):
            read_private_bytes(self.path)

    def test_rejects_parent_traversal(self):
        with self.assertRaises(CLIError):
            read_private_bytes(self.directory / ".." / self.directory.name / self.path.name)

    def test_rejects_git_checkout_even_if_private(self):
        (self.directory / ".git").write_text("gitdir: fictional\n")
        with self.assertRaises(CLIError):
            read_private_bytes(self.path)

    def test_strict_duplicate_json_never_becomes_packet(self):
        self.path.write_bytes(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            read_envelope(self.path)

    def test_object_required(self):
        self.path.write_bytes(b'["not a packet"]')
        with self.assertRaises(CLIError):
            read_envelope(self.path)


if __name__ == "__main__":
    unittest.main()
