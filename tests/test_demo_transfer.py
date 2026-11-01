"""Exercise the published demo interface and its filesystem/process effects."""
from __future__ import annotations

import json
import fcntl
import os
from pathlib import Path
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "demo_transfer.py"


class TransferDemoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="echo-demo-test-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def invoke(self, *arguments, without_site=False, timeout=120):
        command = [sys.executable, "-B"]
        if without_site:
            command.append("-S")
        command += [str(SCRIPT), *map(str, arguments)]
        return subprocess.run(command, cwd=self.directory,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            text=True, capture_output=True, timeout=timeout, check=False)

    def refuse(self, output):
        result = self.invoke("--output-dir", output, "--json")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)

    def test_help_works_without_optional_crypto_or_filesystem_changes(self):
        before = sorted(self.directory.iterdir())
        result = self.invoke("--help", without_site=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--output-dir", result.stdout)
        self.assertEqual(sorted(self.directory.iterdir()), before)
        output = self.directory / "missing-dependencies"
        failure = self.invoke("--output-dir", output, "--json", without_site=True)
        self.assertEqual(failure.returncode, 2, failure.stdout + failure.stderr)
        self.assertEqual(json.loads(failure.stdout)["error"], "DEPENDENCIES_UNAVAILABLE")
        self.assertFalse(output.exists())

    def test_existing_files_directories_and_leaf_links_are_untouched(self):
        directory = self.directory / "existing-directory"
        directory.mkdir()
        sentinel = directory / "user-data.txt"
        sentinel.write_bytes(b"existing user data\x00\xff")
        regular = self.directory / "existing-file"
        regular.write_bytes(b"never overwrite this file")
        live_link = self.directory / "live-link"
        live_link.symlink_to(directory, target_is_directory=True)
        dangling = self.directory / "dangling-link"
        missing = self.directory / "must-stay-missing"
        dangling.symlink_to(missing, target_is_directory=True)
        for output in (directory, regular, live_link, dangling):
            with self.subTest(path=output.name):
                self.refuse(output)
        self.assertEqual(sentinel.read_bytes(), b"existing user data\x00\xff")
        self.assertEqual(regular.read_bytes(), b"never overwrite this file")
        self.assertEqual(list(directory.iterdir()), [sentinel])
        self.assertEqual(live_link.readlink(), directory)
        self.assertEqual(dangling.readlink(), missing)
        self.assertFalse(missing.exists())

    def test_parent_links_and_git_worktrees_are_refused_before_output(self):
        target = self.directory / "real-parent"
        target.mkdir()
        linked = self.directory / "linked-parent"
        linked.symlink_to(target, target_is_directory=True)
        checkout = self.directory / "other-worktree"
        checkout.mkdir()
        metadata = checkout / ".git"
        metadata.write_text("gitdir: /nonexistent/demo-test-metadata\n")
        own_checkout_output = ROOT / ("must-not-create-demo-" + self.directory.name)
        self.assertFalse(own_checkout_output.exists())
        self.addCleanup(shutil.rmtree, own_checkout_output, True)
        destinations = [linked / "output", checkout / "output", own_checkout_output]
        for output in destinations:
            with self.subTest(path=str(output)):
                self.refuse(output)
                self.assertFalse(output.exists())
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(list(checkout.iterdir()), [metadata])
        self.assertEqual(metadata.read_text(), "gitdir: /nonexistent/demo-test-metadata\n")
        # A downloaded source ZIP has no .git marker. It still must not receive
        # demo keys or state, and the refusal must precede dependency loading.
        unpacked = self.directory / "unpacked-source"
        (unpacked / "scripts").mkdir(parents=True)
        copied_script = unpacked / "scripts" / SCRIPT.name
        shutil.copyfile(SCRIPT, copied_script)
        result = subprocess.run([sys.executable, "-B", "-S", str(copied_script),
            "--output-dir", str(unpacked / "output"), "--json"],
            cwd=self.directory, text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["error"], "OUTPUT_INSIDE_CHECKOUT")
        self.assertFalse((unpacked / "output").exists())

    def verify_state(self, state_dir):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/tools/echo_transfer.py"),
            "state", "verify", "--state-dir", str(state_dir)], cwd=self.directory,
            text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        status = json.loads(result.stdout)
        self.assertIs(status["local_chain_valid"], True)
        return status

    def assert_consumer_stopped(self, output):
        locks = list(output.rglob("consumer.lock"))
        self.assertEqual(len(locks), 1, locks)
        for lock in locks:
            with lock.open("rb") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertFalse((lock.parent / "consumer.sock").exists())

    def stop_own_consumer_if_needed(self, output):
        # Cleanup is scoped to this test's fresh private directory, never a
        # global process search or an existing user's service.
        for lock in output.rglob("consumer.lock"):
            if not (lock.parent / "consumer.sock").exists():
                continue
            subprocess.run([sys.executable, "-B", str(ROOT / "tools/tools/echo_transfer.py"),
                "consumer", "stop", "--state-dir", str(lock.parent.parent / "recipient"),
                "--control-dir", str(lock.parent)], capture_output=True, timeout=15, check=False)

    def test_two_clean_runs_have_same_semantic_outcomes_and_no_live_consumer(self):
        summaries = []
        for name in ("first", "second"):
            output = self.directory / name
            self.addCleanup(self.stop_own_consumer_if_needed, output)
            result = self.invoke("--output-dir", output, "--json", timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(json.loads(result.stdout), report)
            self.assertEqual(report["schema"], "echo-lineage-demo/v1")
            self.assertEqual(report["status"], "PASS")
            self.assertIs(report["synthetic_only"], True)
            self.assertIs(report["cloud_model_integrated"], False)
            checks = {item["name"]: item["passed"] for item in report["checks"]}
            expected = {"accepted." + item for item in (
                "receipt_verified", "import_without_activation", "actual_consumer",
                "fresh_probe", "read", "search", "revoked_read_denied", "historical_receipt", "stopped")}
            expected |= {item + ".import_refused" for item in ("reservations", "declined", "quarantine")}
            expected |= {"guards." + item for item in ("tamper_rejected", "stale_cas_rejected",
                "request_conflict_rejected", "nonce_conflict_rejected", "exact_replay")}
            self.assertTrue(expected.issubset(checks), sorted(expected - checks.keys()))
            self.assertTrue(all(checks.values()), checks)
            scenarios = {item["name"]: item["status"] for item in report["scenarios"]}
            self.assertEqual(set(scenarios), {"accepted", "reservations", "declined", "quarantine", "guards"})
            self.assertTrue(all(value == "PASS" for value in scenarios.values()), scenarios)
            summaries.append((checks, scenarios))
            source = self.verify_state(output / "scenarios/accepted/source")
            self.assertEqual(source["remote_milestones"]["received"], "RECEIPT_VERIFIED")
            self.assertEqual(source["remote_milestones"]["imported"], "UNKNOWN")
            decisions = {"accepted": "accepted", "reservations": "accepted_with_reservations",
                "declined": "declined", "quarantine": "quarantined_integrity_failure", "guards": "accepted"}
            for scenario, decision in decisions.items():
                state = self.verify_state(output / "scenarios" / scenario / "recipient")
                self.assertEqual(state["decision"]["decision"], decision)
                self.assertIs(state["imported"], scenario == "accepted")
                if scenario == "accepted":
                    self.assertEqual(len(state["activations"]), 1)
                    activation = next(iter(state["activations"].values()))
                    self.assertIs(activation["revoked"], True)
                    self.assertIsNotNone(activation["loaded_generation"])
                    self.assertIs(state["loaded_receipts_are_historical"], True)
                    self.assertEqual(state["current_process_liveness"], "UNKNOWN")
                else:
                    self.assertEqual(state["activations"], {})
            self.assert_consumer_stopped(output)
            public_output = result.stdout + result.stderr + (output / "commands.txt").read_text()
            keys = list(output.rglob("*.pem"))
            self.assertTrue(keys)
            for path in [output, *output.rglob("*")]:
                if path.is_dir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, path)
            for key in keys:
                self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
                for line in key.read_text().splitlines():
                    if line and not line.startswith("---"):
                        self.assertNotIn(line, public_output)
            self.assertNotIn("BEGIN PRIVATE KEY", public_output)
        self.assertEqual(summaries[0], summaries[1])

    def test_sigterm_after_actual_launch_stops_only_own_consumer_and_reports_failure(self):
        output = self.directory / "interrupted"
        self.addCleanup(self.stop_own_consumer_if_needed, output)
        process = subprocess.Popen([sys.executable, "-B", str(SCRIPT),
            "--output-dir", str(output), "--json"], cwd=self.directory,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 100
            started = False
            while time.monotonic() < deadline and process.poll() is None:
                progress = output / "progress.jsonl"
                if progress.exists():
                    for line in progress.read_text().splitlines():
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue  # The writer may be appending its last line.
                        if item.get("event") == "consumer_started":
                            started = True
                            break
                if started:
                    break
                time.sleep(0.02)
            self.assertTrue(started, "demo never reported an actual consumer launch")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=45)
            self.assertEqual(process.returncode, 2, stdout + stderr)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(json.loads(stdout), report)
            self.assert_consumer_stopped(output)
            self.assertNotIn("Traceback", stderr)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
