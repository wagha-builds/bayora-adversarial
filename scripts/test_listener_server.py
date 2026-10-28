#!/usr/bin/env python3
"""
scripts/test_listener_server.py
Isolated probe listener for Bayora reverse-isolation acceptance tests.

Security & Architectural Requirements:
1. Serves strictly a fixed probe response 'BAYORA_TEST_LISTENER_OK\\n' with HTTP 200.
2. Never serves files, directory listings, or the container working directory.
3. Binds exclusively to the specified host/port interface.
4. Writes its exact process ID (PID) to a tracked PID file for deterministic cleanup.
5. Handles SIGTERM and SIGINT gracefully, closing the listening socket cleanly.
6. Suppresses verbose request logging to prevent output pollution.
"""

import os
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PROBE_BODY = b"BAYORA_TEST_LISTENER_OK\n"
DEFAULT_PORT = 8088
DEFAULT_PID_FILE = "/tmp/bayora_test_listener.pid"


class IsolatedProbeHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler returning only the fixed probe token."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(PROBE_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(PROBE_BODY)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(PROBE_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress standard logging to keep container output clean
        pass


class ProbeServer(HTTPServer):
    """HTTPServer with SO_REUSEADDR enabled for clean rapid restarts without TIME_WAIT locking."""
    allow_reuse_address = True


def run_listener(port: int = DEFAULT_PORT, pid_file: str = DEFAULT_PID_FILE):
    """Run the probe server until terminated by signal."""
    try:
        server = ProbeServer(("0.0.0.0", port), IsolatedProbeHandler)
    except Exception as e:
        sys.stderr.write(f"[!] Failed to bind HTTP server on 0.0.0.0:{port}: {e}\n")
        sys.exit(2)

    # Record PID for reliable teardown only after successful bind
    try:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        sys.stderr.write(f"[!] Failed to write PID file {pid_file}: {e}\n")
        server.server_close()
        sys.exit(1)

    def shutdown_signal_handler(signum, frame):
        try:
            server.server_close()
        except Exception:
            pass
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_signal_handler)
    signal.signal(signal.SIGINT, shutdown_signal_handler)

    try:
        server.serve_forever()
    except Exception:
        pass
    finally:
        shutdown_signal_handler(None, None)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    pid_file = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PID_FILE
    run_listener(port, pid_file)
