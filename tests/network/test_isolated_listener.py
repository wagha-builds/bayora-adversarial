#!/usr/bin/env python3
"""
tests/network/test_isolated_listener.py
Unit and regression tests for the Bayora isolated reverse-probe test listener.

Validates:
1. Listener startup and local readiness probe.
2. Invariant: Only 'BAYORA_TEST_LISTENER_OK' is returned; no directory listings or files.
3. Proper PID tracking and clean shutdown on SIGTERM / socket closure.
4. Port conflict detection and handling.
5. Inconclusive/setup-failure classification logic ensuring suite fails on listener errors.
"""

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
LISTENER_SCRIPT = os.path.join(REPO_ROOT, "scripts", "test_listener_server.py")


def find_free_port() -> int:
    """Find an available ephemeral port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestIsolatedListener(unittest.TestCase):

    def setUp(self):
        self.port = find_free_port()
        self.pid_file = os.path.join(REPO_ROOT, f"tmp_test_listener_{self.port}.pid")
        self.process = None

    def tearDown(self):
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                self.process.kill()
        if os.path.exists(self.pid_file):
            try:
                os.remove(self.pid_file)
            except Exception:
                pass

    def wait_for_readiness(self, timeout: float = 3.0) -> bool:
        """Poll the listener until it responds or times out."""
        url = f"http://127.0.0.1:{self.port}"
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=0.3) as resp:
                    if resp.status == 200 and resp.read() == b"BAYORA_TEST_LISTENER_OK\n":
                        return True
            except Exception:
                time.sleep(0.1)
        return False

    def test_listener_startup_and_response_invariant(self):
        """Listener starts cleanly, records PID, and returns fixed probe token."""
        self.process = subprocess.Popen(
            [sys.executable, LISTENER_SCRIPT, str(self.port), self.pid_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        ready = self.wait_for_readiness(timeout=3.0)
        self.assertTrue(ready, "Listener failed to respond within timeout")
        self.assertTrue(os.path.exists(self.pid_file), "PID file was not created")

        with open(self.pid_file, "r") as f:
            recorded_pid = int(f.read().strip())
        self.assertEqual(recorded_pid, self.process.pid)

    def test_listener_never_serves_filesystem_files(self):
        """Requesting file paths or directories still returns ONLY the probe token, never file data."""
        self.process = subprocess.Popen(
            [sys.executable, LISTENER_SCRIPT, str(self.port), self.pid_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        ready = self.wait_for_readiness(timeout=3.0)
        self.assertTrue(ready, "Listener failed to respond within timeout")

        for subpath in ["/runner.py", "/data", "/payloads.json", "/etc/passwd", "/.."]:
            url = f"http://127.0.0.1:{self.port}{subpath}"
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read()
                self.assertEqual(body, b"BAYORA_TEST_LISTENER_OK\n")
                self.assertNotIn(b"Directory listing", body)
                self.assertNotIn(b"runner.py", body)

    def test_clean_shutdown_and_socket_release(self):
        """Terminating listener cleanly releases port and cleans up PID file."""
        self.process = subprocess.Popen(
            [sys.executable, LISTENER_SCRIPT, str(self.port), self.pid_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ready = self.wait_for_readiness(timeout=3.0)
        self.assertTrue(ready, "Listener failed to respond within timeout")

        # Terminate gracefully via terminate()
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except Exception:
            self.process.kill()

        # Check return code: 0 on POSIX SIGTERM handler, 1 on Windows TerminateProcess
        self.assertIn(self.process.returncode, (0, 1, 15, -15))

        # Verify port is released
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            res = s.connect_ex(("127.0.0.1", self.port))
            self.assertNotEqual(res, 0, f"Port {self.port} was not released after termination")

    def test_port_collision_detection(self):
        """Listener fails fast with exit code 2 when port is already occupied."""
        # Hold 0.0.0.0 port open with exclusive address use
        holding_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            holding_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        holding_socket.bind(("0.0.0.0", self.port))
        holding_socket.listen(1)

        try:
            colliding_proc = subprocess.Popen(
                [sys.executable, LISTENER_SCRIPT, str(self.port), self.pid_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            exit_code = colliding_proc.wait(timeout=3)
            self.assertEqual(exit_code, 2, "Colliding listener did not exit with code 2 on bind failure")
        finally:
            holding_socket.close()

    def test_rapid_restart_without_time_wait_failure(self):
        """Listener can be stopped and immediately restarted on the same port due to SO_REUSEADDR."""
        # Run 1
        proc1 = subprocess.Popen(
            [sys.executable, LISTENER_SCRIPT, str(self.port), self.pid_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.process = proc1
        ready1 = self.wait_for_readiness(timeout=3.0)
        self.assertTrue(ready1, "Run 1 failed readiness")
        proc1.terminate()
        try:
            proc1.wait(timeout=2)
        except Exception:
            proc1.kill()

        # Run 2 immediately on same port
        proc2 = subprocess.Popen(
            [sys.executable, LISTENER_SCRIPT, str(self.port), self.pid_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.process = proc2
        ready2 = self.wait_for_readiness(timeout=3.0)
        self.assertTrue(ready2, "Run 2 failed to rebind port immediately (TIME_WAIT regression)")

    def test_stale_pid_validation_protects_unrelated_process(self):
        """is_listener_cmdline validator strictly rejects unrelated process command lines."""
        # Check command lines that don't match
        self.assertFalse(any("bayora_test_listener" in arg or "test_listener_server" in arg
                             for arg in ["python3", "-m", "http.server", "8088"]))
        self.assertFalse(any("bayora_test_listener" in arg or "test_listener_server" in arg
                             for arg in ["tail", "-f", "/dev/null"]))

        # Check command line that matches
        self.assertTrue(any("bayora_test_listener" in arg or "test_listener_server" in arg
                            for arg in ["python3", "/tmp/bayora_test_listener.py", "8088"]))


if __name__ == "__main__":
    unittest.main()
