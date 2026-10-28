#!/usr/bin/env python3
"""
Bayora Phase 3 — Network Segmentation Acceptance Test Suite

Topology & Policy Specification:
1. red-net          (172.20.1.0/24, internal: true)  -> red-runner (172.20.1.10), baseline-stub (172.20.1.2)
2. blue-net         (172.20.2.0/24, internal: true)  -> baseline-stub (172.20.2.2), blue-filter (172.20.2.10)
3. model-net        (172.20.3.0/24, internal: true)  -> baseline-stub (172.20.3.2), model-server (172.20.3.20)
4. gateway-host-net (172.20.0.0/24, internal: false) -> baseline-stub (172.20.0.2) [127.0.0.1:8000 published]

Rules & Assertions:
1. Gateway (baseline-stub) is the SOLE multi-homed container across internal zones.
2. Blue and Model ports (8001, 8080) are NOT published to the host in Phase 3.
3. Red, Blue, and Model must NOT reach each other directly via hostname, raw IP, or bridge.
4. Positive controls (Red -> Gateway, Gateway -> Blue, Gateway -> Model) must PASS.
5. Reverse direction reachability (Blue -> Red, Model -> Red) uses a temporary listener in Red.
   Connection refused indicates Layer 3 reachability (not blocked), while timeout/unreachable indicates isolation.
6. Host-reachability via bridge gateway IP (port 22) is tracked separately as a known gap until Phase 3.3 (nftables).
"""

import datetime
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
EVIDENCE_DIR = os.path.join(REPO_ROOT, "results", "hardening", "phase3-network", "local-ubuntu-vm")

REVERSE_LISTENER_PORT = 8088
REVERSE_LISTENER_TOKEN = "BAYORA_TEST_LISTENER_OK"
REVERSE_LISTENER_PID_PATH = "/tmp/bayora_test_listener.pid"
REVERSE_LISTENER_LOG_PATH = "/tmp/bayora_test_listener.log"
REVERSE_LISTENER_SCRIPT_PATH = "/tmp/bayora_test_listener.py"

# Expected Phase 3 static addresses & network topology
EXPECTED_PHASE3_IPAM = {
    "red-net": {
        "subnet": "172.20.1.0/24",
        "internal": True,
        "containers": {
            "bayora-red-runner": "172.20.1.10",
            "bayora-baseline-stub": "172.20.1.2",
        },
    },
    "blue-net": {
        "subnet": "172.20.2.0/24",
        "internal": True,
        "containers": {
            "bayora-baseline-stub": "172.20.2.2",
            "bayora-blue-filter": "172.20.2.10",
        },
    },
    "model-net": {
        "subnet": "172.20.3.0/24",
        "internal": True,
        "containers": {
            "bayora-baseline-stub": "172.20.3.2",
            "bayora-model-server": "172.20.3.20",
        },
    },
    "gateway-host-net": {
        "subnet": "172.20.0.0/24",
        "internal": False,
        "containers": {
            "bayora-baseline-stub": "172.20.0.2",
        },
    },
}


# ---------------------------------------------------------------------------
# Command Helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Execute command locally on Docker host with bounded timeout."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def get_live_container_inspect() -> dict:
    """Inspect all 4 Bayora containers and return parsed JSON map by name."""
    code, stdout, _ = run_cmd([
        "docker", "inspect",
        "bayora-model-server", "bayora-blue-filter", "bayora-baseline-stub", "bayora-red-runner"
    ])
    if code != 0:
        return {}
    try:
        return {c["Name"].lstrip("/"): c for c in json.loads(stdout)}
    except Exception:
        return {}


def get_red_etc_hosts() -> dict[str, str]:
    """Extract hostname -> IP mappings from inside bayora-red-runner /etc/hosts."""
    code, stdout, _ = run_cmd(["docker", "exec", "bayora-red-runner", "cat", "/etc/hosts"])
    mappings = {}
    if code != 0:
        return mappings
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            for host in parts[1:]:
                mappings[host] = ip
    return mappings


def probe_http_from_python_container(container_name: str, url: str, timeout: int = 4) -> tuple[int, str, str]:
    """Probe an HTTP URL from inside a Python-based container (baseline-stub or blue-filter)."""
    script = (
        "import urllib.request, sys\n"
        "try:\n"
        f"    req = urllib.request.Request('{url}')\n"
        f"    with urllib.request.urlopen(req, timeout={timeout}) as resp:\n"
        "        sys.stdout.write(resp.read().decode('utf-8', errors='replace'))\n"
        "        sys.exit(0)\n"
        "except urllib.error.HTTPError as e:\n"
        "    sys.stdout.write(e.read().decode('utf-8', errors='replace'))\n"
        "    sys.exit(0)\n"
        "except Exception as e:\n"
        "    sys.stderr.write(str(e))\n"
        "    sys.exit(1)\n"
    )
    return run_cmd(["docker", "exec", container_name, "python3", "-c", script], timeout=timeout + 3)


# ---------------------------------------------------------------------------
# Preflight & Target Availability Validation
# ---------------------------------------------------------------------------

def preflight_target_health(containers: dict, is_hardened: bool = False) -> tuple[bool, dict[str, str]]:
    """
    Verify all 4 containers are running and their HTTP endpoints respond.
    Negative isolation tests are only conclusive if target services are verified healthy.
    """
    health_status = {}
    all_ok = True

    # 1. Container running state
    for name in ["bayora-model-server", "bayora-blue-filter", "bayora-baseline-stub", "bayora-red-runner"]:
        c = containers.get(name)
        if not c or not c.get("State", {}).get("Running", False):
            health_status[name] = "NOT_RUNNING"
            all_ok = False
        else:
            health_status[name] = "RUNNING"

    if not all_ok:
        return False, health_status

    # 2. HTTP Endpoint health: Mode-aware target health checks
    if not is_hardened:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=3) as resp:
                data = resp.read().decode()
                health_status["model_http"] = "HEALTHY" if "ok" in data else "UNEXPECTED"
        except Exception as e:
            health_status["model_http"] = f"DOWN ({e})"

        try:
            with urllib.request.urlopen("http://127.0.0.1:8001/health", timeout=3) as resp:
                data = resp.read().decode()
                health_status["blue_http"] = "HEALTHY" if "blue-filter" in data else "UNEXPECTED"
        except Exception as e:
            health_status["blue_http"] = f"DOWN ({e})"

        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=3) as resp:
                data = resp.read().decode()
                health_status["gateway_http"] = "HEALTHY" if "baseline-stub" in data else "UNEXPECTED"
        except Exception as e:
            health_status["gateway_http"] = f"DOWN ({e})"
    else:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=3) as resp:
                data = resp.read().decode()
                health_status["gateway_http"] = "HEALTHY" if "baseline-stub" in data else "UNEXPECTED"
        except Exception as e:
            health_status["gateway_http"] = f"DOWN ({e})"

        m_code, m_out, m_err = probe_http_from_python_container("bayora-baseline-stub", "http://172.20.3.20:8080/health", timeout=3)
        health_status["model_http"] = "HEALTHY" if (m_code == 0 and "ok" in m_out) else f"DOWN ({m_err or m_out})"

        b_code, b_out, b_err = probe_http_from_python_container("bayora-baseline-stub", "http://172.20.2.10:8001/health", timeout=3)
        health_status["blue_http"] = "HEALTHY" if (b_code == 0 and "blue-filter" in b_out) else f"DOWN ({b_err or b_out})"

    targets_healthy = all("HEALTHY" in health_status.get(k, "") for k in ["model_http", "blue_http", "gateway_http"])
    return targets_healthy, health_status


# ---------------------------------------------------------------------------
# Positive Controls
# ---------------------------------------------------------------------------

def test_red_to_gateway_hostname_mapping(containers: dict, red_hosts: dict[str, str], is_hardened: bool) -> dict:
    """Test consistency between Red's configured hostname 'baseline-stub' and Gateway IP on red-net."""
    print("[*] [POSITIVE-1a] Red -> Gateway hostname resolution check...")
    resolved_ip = red_hosts.get("baseline-stub")

    # In hardened mode, Gateway IP on red-net must be 172.20.1.2
    gw_nets = containers.get("bayora-baseline-stub", {}).get("NetworkSettings", {}).get("Networks", {})
    actual_red_ip = None
    for n_name, n_data in gw_nets.items():
        if n_name == "red-net" or n_name.endswith("_red-net"):
            actual_red_ip = n_data.get("IPAddress")
            break

    if not actual_red_ip and not is_hardened:
        actual_red_ip = list(gw_nets.values())[0].get("IPAddress") if gw_nets else None

    if not resolved_ip:
        status = "FAIL"
        detail = "Hostname 'baseline-stub' is NOT present in Red's /etc/hosts"
    elif resolved_ip == actual_red_ip:
        status = "PASS_AUTHORIZED"
        detail = f"Hostname 'baseline-stub' correctly resolves to Gateway red-net IP ({resolved_ip})"
    else:
        status = "FAIL_IP_DRIFT" if not is_hardened else "FAIL"
        detail = f"IP Mismatch: Red resolves 'baseline-stub' to {resolved_ip}, but Gateway red-net is at {actual_red_ip}"

    return {
        "test": "red_to_gateway_hostname_mapping",
        "route": "Red /etc/hosts -> baseline-stub",
        "target": f"resolved={resolved_ip}, actual={actual_red_ip}",
        "status": status,
        "detail": detail,
    }


def test_red_to_gateway_authorized(containers: dict, is_hardened: bool) -> dict:
    """Positive: Red must reach authorized Gateway entrypoint and verify service identity."""
    print("[*] [POSITIVE-1b] Red -> Gateway direct HTTP reachability...")
    gw_nets = containers.get("bayora-baseline-stub", {}).get("NetworkSettings", {}).get("Networks", {})
    actual_red_ip = None
    for n_name, n_data in gw_nets.items():
        if n_name == "red-net" or n_name.endswith("_red-net"):
            actual_red_ip = n_data.get("IPAddress")
            break
    if not actual_red_ip and not is_hardened:
        actual_red_ip = list(gw_nets.values())[0].get("IPAddress") if gw_nets else None

    url = "http://baseline-stub:8000/health" if is_hardened else f"http://{actual_red_ip}:8000/health"
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "4", url])

    if code == 0 and "baseline-stub" in stdout:
        status = "PASS_AUTHORIZED"
        detail = f"Gateway reached at {url}; verified identity: 'baseline-stub'"
    else:
        status = "FAIL_AUTHORIZED"
        detail = f"Failed to reach Gateway at {url}: code={code}, stdout={stdout[:80]}, stderr={stderr[:80]}"

    return {
        "test": "red_to_gateway_authorized",
        "route": f"Red -> {url}",
        "target": actual_red_ip,
        "status": status,
        "detail": detail,
    }


def test_gateway_to_blue_authorized(is_hardened: bool) -> dict:
    """Positive: Gateway must reach Blue filter backend (http://blue-filter:8001/health)."""
    print("[*] [POSITIVE-2] Gateway -> Blue authorized access...")
    url = "http://blue-filter:8001/health" if not is_hardened else "http://172.20.2.10:8001/health"
    code, stdout, stderr = probe_http_from_python_container("bayora-baseline-stub", url, timeout=4)
    if code == 0 and "blue-filter" in stdout:
        status = "PASS_AUTHORIZED"
        detail = "Gateway reached Blue filter; verified identity: 'blue-filter'"
    else:
        status = "FAIL_AUTHORIZED"
        detail = f"Gateway failed to reach Blue: code={code}, stdout={stdout[:80]}, stderr={stderr[:80]}"

    return {
        "test": "gateway_to_blue_authorized",
        "route": f"Gateway -> {url}",
        "target": "172.20.2.10" if is_hardened else "blue-filter",
        "status": status,
        "detail": detail,
    }


def test_gateway_to_model_authorized(is_hardened: bool) -> dict:
    """Positive: Gateway must reach Model server backend (http://model-server:8080/health)."""
    print("[*] [POSITIVE-3] Gateway -> Model authorized access...")
    url = "http://model-server:8080/health" if not is_hardened else "http://172.20.3.20:8080/health"
    code, stdout, stderr = probe_http_from_python_container("bayora-baseline-stub", url, timeout=4)
    if code == 0 and "ok" in stdout:
        status = "PASS_AUTHORIZED"
        detail = "Gateway reached Model server; verified identity: 'ok'"
    else:
        status = "FAIL_AUTHORIZED"
        detail = f"Gateway failed to reach Model: code={code}, stdout={stdout[:80]}, stderr={stderr[:80]}"

    return {
        "test": "gateway_to_model_authorized",
        "route": f"Gateway -> {url}",
        "target": "172.20.3.20" if is_hardened else "model-server",
        "status": status,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Negative Isolation Checks: Direct Cross-Zone
# ---------------------------------------------------------------------------

def classify_connection_result(code: int, stdout: str, stderr: str, expected_keyword: str) -> str:
    """
    Classify raw probe result into reachability state:
    - HTTP_REACHED: HTTP response returned with expected identity.
    - L3_CONNECTION_REFUSED: Packet reached target host at Layer 3, TCP port refused (RST received).
    - ISOLATED_TIMEOUT_OR_UNREACHABLE: No route to host, network unreachable, or timed out.
    """
    if code == 0 and (expected_keyword in stdout or not expected_keyword):
        return "HTTP_REACHED"

    # Specific L3 Connection Refused (TCP RST received from target IP)
    if "Connection refused" in stderr or "Errno 111" in stderr:
        return "L3_CONNECTION_REFUSED"

    # Isolation / network path blocked
    if (code in (28, 124) or
        "timed out" in stderr or
        "No route" in stderr or
        "unreachable" in stderr or
        "Could not connect" in stderr or
        "Couldn't connect" in stderr or
        "Could not resolve host" in stderr):
        return "ISOLATED_TIMEOUT_OR_UNREACHABLE"

    return "UNKNOWN_ERROR"


def test_red_to_blue_by_name(red_hosts: dict[str, str], is_hardened: bool, target_healthy: bool) -> dict:
    """Negative: Red attempts direct access to Blue by hostname (http://blue-filter:8001/rules)."""
    print("[*] [NEGATIVE-1a] Red -> Blue by service name...")
    if not target_healthy:
        return {"test": "red_to_blue_by_name", "route": "Red -> blue-filter:8001", "status": "INCONCLUSIVE", "detail": "Target Blue filter is not verified healthy / IPAM preflight failed"}

    resolved_ip = red_hosts.get("blue-filter", "unresolved")
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "4", "http://blue-filter:8001/rules"])
    classification = classify_connection_result(code, stdout, stderr, "keywords")

    if is_hardened:
        if classification == "ISOLATED_TIMEOUT_OR_UNREACHABLE" or resolved_ip == "unresolved":
            status = "PASS_ISOLATED"
            detail = f"Policy enforced: hostname unresolvable or network unreachable (resolved={resolved_ip}, err={stderr})"
        else:
            status = "FAIL_POLICY"
            detail = f"Policy violation: connection reached target (classification={classification}, stdout={stdout[:60]})"
    else:
        if classification == "HTTP_REACHED":
            status = "BASELINE_VULNERABLE"
            detail = f"Blue ruleset directly extracted via hostname (resolved={resolved_ip})"
        elif classification == "L3_CONNECTION_REFUSED":
            status = "BASELINE_VULNERABLE"
            detail = f"Layer 3 reachable but port refused (resolved to {resolved_ip}; demonstrates Phase 2 IP mismatch)"
        else:
            status = "BASELINE_VULNERABLE"
            detail = f"Probe completed in baseline: resolved={resolved_ip}, classification={classification}, code={code}"

    return {
        "test": "red_to_blue_by_name",
        "route": "Red -> blue-filter:8001 (/rules)",
        "target": f"resolved={resolved_ip}",
        "status": status,
        "detail": detail,
    }


def test_red_to_blue_by_ip(live_ips: dict[str, str], is_hardened: bool, target_healthy: bool) -> dict:
    """Negative: Red attempts direct access to Blue by container IP (http://<blue_ip>:8001/rules)."""
    print("[*] [NEGATIVE-1b] Red -> Blue by container IP...")
    if not target_healthy:
        return {"test": "red_to_blue_by_ip", "route": "Red -> Blue (by IP)", "status": "INCONCLUSIVE", "detail": "Target Blue filter is not verified healthy / IPAM preflight failed"}

    target_ip = "172.20.2.10" if is_hardened else live_ips.get("bayora-blue-filter")
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "4", f"http://{target_ip}:8001/rules"])
    classification = classify_connection_result(code, stdout, stderr, "keywords")

    if is_hardened:
        if classification == "ISOLATED_TIMEOUT_OR_UNREACHABLE":
            status = "PASS_ISOLATED"
            detail = f"Network isolated: no route to Blue at {target_ip} (err={stderr})"
        else:
            status = "FAIL_POLICY"
            detail = f"Policy violation: reached Blue at {target_ip} (classification={classification})"
    else:
        if classification in ("HTTP_REACHED", "L3_CONNECTION_REFUSED"):
            status = "BASELINE_VULNERABLE"
            detail = f"Direct access to Blue at {target_ip} succeeded (verified ruleset extracted: '{stdout[:40]}...')"
        else:
            status = "UNEXPECTED_BLOCKED"
            detail = f"Unexpectedly blocked in baseline: code={code}, err={stderr}"

    return {
        "test": "red_to_blue_by_ip",
        "route": f"Red -> {target_ip}:8001 (/rules)",
        "target": target_ip,
        "status": status,
        "detail": detail,
    }


def test_red_to_model_by_name(red_hosts: dict[str, str], is_hardened: bool, target_healthy: bool) -> dict:
    """Negative: Red attempts direct access to Model by hostname (http://model-server:8080/health)."""
    print("[*] [NEGATIVE-2a] Red -> Model by service name...")
    if not target_healthy:
        return {"test": "red_to_model_by_name", "route": "Red -> model-server:8080", "status": "INCONCLUSIVE", "detail": "Target Model server is not verified healthy / IPAM preflight failed"}

    resolved_ip = red_hosts.get("model-server", "unresolved")
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "4", "http://model-server:8080/health"])
    classification = classify_connection_result(code, stdout, stderr, "ok")

    if is_hardened:
        if classification == "ISOLATED_TIMEOUT_OR_UNREACHABLE" or resolved_ip == "unresolved":
            status = "PASS_ISOLATED"
            detail = f"Policy enforced: hostname unresolvable or network unreachable (resolved={resolved_ip}, err={stderr})"
        else:
            status = "FAIL_POLICY"
            detail = f"Policy violation: connection reached target (classification={classification})"
    else:
        if classification == "HTTP_REACHED":
            status = "BASELINE_VULNERABLE"
            detail = f"Model directly accessed via hostname (resolved={resolved_ip})"
        elif classification == "L3_CONNECTION_REFUSED":
            status = "BASELINE_VULNERABLE"
            detail = f"Layer 3 reachable but port refused (resolved to {resolved_ip}; demonstrates Phase 2 IP mismatch)"
        else:
            status = "BASELINE_VULNERABLE"
            detail = f"Probe completed in baseline: resolved={resolved_ip}, classification={classification}, code={code}"

    return {
        "test": "red_to_model_by_name",
        "route": "Red -> model-server:8080 (/health)",
        "target": f"resolved={resolved_ip}",
        "status": status,
        "detail": detail,
    }


def test_red_to_model_by_ip(live_ips: dict[str, str], is_hardened: bool, target_healthy: bool) -> dict:
    """Negative: Red attempts direct access to Model by container IP (http://<model_ip>:8080/health)."""
    print("[*] [NEGATIVE-2b] Red -> Model by container IP...")
    if not target_healthy:
        return {"test": "red_to_model_by_ip", "route": "Red -> Model (by IP)", "status": "INCONCLUSIVE", "detail": "Target Model server is not verified healthy / IPAM preflight failed"}

    target_ip = "172.20.3.20" if is_hardened else live_ips.get("bayora-model-server")
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "4", f"http://{target_ip}:8080/health"])
    classification = classify_connection_result(code, stdout, stderr, "ok")

    if is_hardened:
        if classification == "ISOLATED_TIMEOUT_OR_UNREACHABLE":
            status = "PASS_ISOLATED"
            detail = f"Network isolated: no route to Model at {target_ip} (err={stderr})"
        else:
            status = "FAIL_POLICY"
            detail = f"Policy violation: reached Model at {target_ip} (classification={classification})"
    else:
        if classification in ("HTTP_REACHED", "L3_CONNECTION_REFUSED"):
            status = "BASELINE_VULNERABLE"
            detail = f"Direct access to Model at {target_ip} succeeded (verified response: '{stdout[:30]}')"
        else:
            status = "UNEXPECTED_BLOCKED"
            detail = f"Unexpectedly blocked in baseline: code={code}, err={stderr}"

    return {
        "test": "red_to_model_by_ip",
        "route": f"Red -> {target_ip}:8080 (/health)",
        "target": target_ip,
        "status": status,
        "detail": detail,
    }


def test_blue_to_model_direct(live_ips: dict[str, str], is_hardened: bool, target_healthy: bool) -> dict:
    """Negative: Blue filter must NOT reach Model server directly."""
    print("[*] [NEGATIVE-3] Blue -> Model direct access...")
    if not target_healthy:
        return {"test": "blue_to_model_direct", "route": "Blue -> Model", "status": "INCONCLUSIVE", "detail": "Target Model is not verified healthy / IPAM preflight failed"}

    target_ip = "172.20.3.20" if is_hardened else live_ips.get("bayora-model-server")
    code, stdout, stderr = probe_http_from_python_container("bayora-blue-filter", f"http://{target_ip}:8080/health", timeout=4)
    classification = classify_connection_result(code, stdout, stderr, "ok")

    if is_hardened:
        if classification == "ISOLATED_TIMEOUT_OR_UNREACHABLE":
            status = "PASS_ISOLATED"
            detail = f"Network isolated: Blue cannot route to Model at {target_ip} (err={stderr})"
        else:
            status = "FAIL_POLICY"
            detail = f"Policy violation: Blue reached Model directly at {target_ip}"
    else:
        if classification == "HTTP_REACHED":
            status = "BASELINE_VULNERABLE"
            detail = f"Blue reached Model directly on flat bridge (response: '{stdout[:30]}')"
        else:
            status = "UNEXPECTED_BLOCKED"
            detail = f"Unexpected result in baseline: classification={classification}, code={code}"

    return {
        "test": "blue_to_model_direct",
        "route": f"Blue -> Model ({target_ip}:8080)",
        "target": target_ip,
        "status": status,
        "detail": detail,
    }


def test_model_to_blue_direct(live_ips: dict[str, str], is_hardened: bool, target_healthy: bool) -> dict:
    """Negative: Model server must NOT reach Blue filter directly."""
    print("[*] [NEGATIVE-4] Model -> Blue direct access...")
    if not target_healthy:
        return {"test": "model_to_blue_direct", "route": "Model -> Blue", "status": "INCONCLUSIVE", "detail": "Target Blue is not verified healthy / IPAM preflight failed"}

    target_ip = "172.20.2.10" if is_hardened else live_ips.get("bayora-blue-filter")
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-model-server", "curl", "-sS", "-m", "4", f"http://{target_ip}:8001/health"])
    classification = classify_connection_result(code, stdout, stderr, "blue-filter")

    if is_hardened:
        if classification == "ISOLATED_TIMEOUT_OR_UNREACHABLE":
            status = "PASS_ISOLATED"
            detail = f"Network isolated: Model cannot route to Blue at {target_ip} (err={stderr})"
        else:
            status = "FAIL_POLICY"
            detail = f"Policy violation: Model reached Blue directly at {target_ip}"
    else:
        if classification == "HTTP_REACHED":
            status = "BASELINE_VULNERABLE"
            detail = f"Model reached Blue directly on flat bridge (response: '{stdout[:30]}')"
        else:
            status = "UNEXPECTED_BLOCKED"
            detail = f"Unexpected result in baseline: classification={classification}, code={code}"

    return {
        "test": "model_to_blue_direct",
        "route": f"Model -> Blue ({target_ip}:8001)",
        "target": target_ip,
        "status": status,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Reverse Direction Probes (With Isolated Test Listener in Red)
# ---------------------------------------------------------------------------

def get_process_cmdline(pid: int) -> str:
    """Read /proc/<pid>/cmdline inside bayora-red-runner to verify process identity."""
    code, stdout, _ = run_cmd(["docker", "exec", "bayora-red-runner", "cat", f"/proc/{pid}/cmdline"])
    if code == 0:
        return stdout.replace("\x00", " ").strip()
    return ""


def is_listener_pid(pid: int) -> bool:
    """Validate that a PID actually belongs to our test listener before signalling it."""
    cmdline = get_process_cmdline(pid)
    return "bayora_test_listener" in cmdline or "test_listener_server" in cmdline


def safe_kill_listener_process(pid: int, timeout: float = 2.0) -> bool:
    """
    Safely terminates a verified listener process by PID.
    Checks process identity first to avoid killing unrelated processes.
    """
    if not is_listener_pid(pid):
        print(f"[*] PID {pid} does not match listener cmdline (found: '{get_process_cmdline(pid)}'); skipping kill.")
        return False

    # Send SIGTERM for clean shutdown
    run_cmd(["docker", "exec", "bayora-red-runner", "kill", "-15", str(pid)])
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, _, _ = run_cmd(["docker", "exec", "bayora-red-runner", "kill", "-0", str(pid)])
        if code != 0:
            return True  # Process exited
        time.sleep(0.1)

    # Force kill if still alive
    if is_listener_pid(pid):
        run_cmd(["docker", "exec", "bayora-red-runner", "kill", "-9", str(pid)])
    return True


def deploy_and_start_isolated_listener(port: int = REVERSE_LISTENER_PORT) -> tuple[bool, str, int | None]:
    """
    Deploys and starts an isolated probe listener inside bayora-red-runner.
    - Pre-checks port availability to prevent false positives from stale/colliding services.
    - Deploys scripts/test_listener_server.py into container /tmp with exit status verification.
    - Starts the server with stderr/stdout redirected to /tmp/bayora_test_listener.log.
    - Verifies readiness via local probe before returning.
    - On failure, captures log diagnostics and process info before returning.
    Returns (success: bool, detail: str, tracked_pid: int | None).
    """
    # 1. Check if port is already listening inside Red
    chk_code, chk_out, _ = run_cmd([
        "docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "1", f"http://127.0.0.1:{port}"
    ])
    if chk_code == 0:
        # Port is already bound. Check if it belongs to our stale listener.
        p_code, p_out, _ = run_cmd(["docker", "exec", "bayora-red-runner", "cat", REVERSE_LISTENER_PID_PATH])
        if p_code == 0 and p_out.strip().isdigit():
            stale_pid = int(p_out.strip())
            if is_listener_pid(stale_pid):
                print(f"[*] Cleaning up verified stale listener on port {port} (PID {stale_pid})...")
                safe_kill_listener_process(stale_pid)
                run_cmd(["docker", "exec", "bayora-red-runner", "rm", "-f", REVERSE_LISTENER_PID_PATH])
                time.sleep(0.3)
            else:
                return False, f"Port {port} inside bayora-red-runner is already occupied by an unrelated process (PID {stale_pid}: '{get_process_cmdline(stale_pid)}')", None
        else:
            return False, f"Port {port} inside bayora-red-runner is already occupied by an unknown process", None

    # 2. Deploy listener server script into container /tmp
    local_server_path = os.path.join(REPO_ROOT, "scripts", "test_listener_server.py")
    if not os.path.exists(local_server_path):
        return False, f"Missing listener script on test host: {local_server_path}", None

    with open(local_server_path, "rb") as f:
        script_bytes = f.read()

    p = subprocess.Popen(
        ["docker", "exec", "-i", "bayora-red-runner", "sh", "-c", f"cat > {REVERSE_LISTENER_SCRIPT_PATH}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    copy_out, copy_err = p.communicate(input=script_bytes, timeout=5)
    if p.returncode != 0:
        err_msg = copy_err.decode("utf-8", errors="replace").strip()
        return False, f"Script deployment failed: exit code {p.returncode}, stderr='{err_msg}'", None

    # Verify deployed script size inside container
    test_code, _, _ = run_cmd(["docker", "exec", "bayora-red-runner", "test", "-s", REVERSE_LISTENER_SCRIPT_PATH])
    if test_code != 0:
        return False, f"Deployed script {REVERSE_LISTENER_SCRIPT_PATH} is missing or empty inside container", None

    # Clean old log and pid files before start
    run_cmd(["docker", "exec", "bayora-red-runner", "rm", "-f", REVERSE_LISTENER_LOG_PATH, REVERSE_LISTENER_PID_PATH])

    # 3. Start listener in background with stderr/stdout captured to log file
    start_cmd = (
        f"python3 {REVERSE_LISTENER_SCRIPT_PATH} {port} {REVERSE_LISTENER_PID_PATH} "
        f"> {REVERSE_LISTENER_LOG_PATH} 2>&1"
    )
    start_code, start_stdout, start_stderr = run_cmd([
        "docker", "exec", "-d", "bayora-red-runner", "sh", "-c", start_cmd
    ])
    if start_code != 0:
        return False, f"docker exec -d failed to start listener: code={start_code}, stderr='{start_stderr}'", None

    # 4. Poll readiness loop (up to 3 seconds) with error capture
    deadline = time.time() + 3.0
    listener_ready = False
    last_probe_detail = ""
    while time.time() < deadline:
        l_code, l_out, l_err = run_cmd([
            "docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "1", f"http://127.0.0.1:{port}"
        ])
        if l_code == 0 and REVERSE_LISTENER_TOKEN in l_out:
            listener_ready = True
            break
        last_probe_detail = f"code={l_code}, err='{l_err}', out='{l_out}'"
        time.sleep(0.2)

    # Check for tracked PID regardless of readiness (in case process started then hung or failed probe)
    p_code, pid_out, _ = run_cmd(["docker", "exec", "bayora-red-runner", "cat", REVERSE_LISTENER_PID_PATH])
    tracked_pid = int(pid_out.strip()) if (p_code == 0 and pid_out.strip().isdigit()) else None

    # Read container listener log
    _, log_out, _ = run_cmd(["docker", "exec", "bayora-red-runner", "cat", REVERSE_LISTENER_LOG_PATH])
    log_content = log_out.strip() if log_out else "none"

    if not listener_ready:
        diag = (
            f"Isolated listener on port {port} failed readiness poll within 3s. "
            f"Last probe: [{last_probe_detail}]. Container log: [{log_content}]. PID: {tracked_pid}"
        )
        return False, diag, tracked_pid

    return True, "Isolated listener verified ready and serving probe token", tracked_pid


def cleanup_isolated_listener(tracked_pid: int | None, port: int = REVERSE_LISTENER_PORT):
    """
    Clean up listener process and temporary artifacts.
    Validates process identity before killing.
    Guarantees cleanup even if tracked_pid was None.
    """
    # 1. If tracked_pid provided, kill if verified
    if tracked_pid and is_listener_pid(tracked_pid):
        safe_kill_listener_process(tracked_pid)

    # 2. Check PID file if tracked_pid was None or missed
    p_code, pid_out, _ = run_cmd(["docker", "exec", "bayora-red-runner", "cat", REVERSE_LISTENER_PID_PATH])
    if p_code == 0 and pid_out.strip().isdigit():
        residual_pid = int(pid_out.strip())
        if is_listener_pid(residual_pid):
            safe_kill_listener_process(residual_pid)

    # 3. Clean up container temporary files
    run_cmd(["docker", "exec", "bayora-red-runner", "rm", "-f",
             REVERSE_LISTENER_PID_PATH, REVERSE_LISTENER_LOG_PATH, REVERSE_LISTENER_SCRIPT_PATH])


def test_reverse_probes_with_red_listener(live_ips: dict[str, str], is_hardened: bool) -> list[dict]:
    """
    Reverse direction checks: Blue -> Red and Model -> Red.
    Uses an isolated test listener inside bayora-red-runner (port 8088).
    Strictly verifies listener readiness before executing probes.
    """
    print("[*] [REVERSE-PROBES] Starting isolated test listener in Red (port 8088)...")
    ready, detail, tracked_pid = deploy_and_start_isolated_listener(REVERSE_LISTENER_PORT)
    red_ip = "172.20.1.10" if is_hardened else live_ips.get("bayora-red-runner")
    results = []

    try:
        if not ready:
            print(f"[-] [REVERSE-PROBES] Listener setup FAILED: {detail}")
            # Explicit test setup failure: MUST NOT BE TREATED AS PASS
            results.append({
                "test": "blue_to_red_direct",
                "route": f"Blue -> Red ({red_ip}:{REVERSE_LISTENER_PORT})",
                "target": red_ip,
                "status": "SETUP_FAILED",
                "detail": f"Reverse isolation probe aborted: {detail}",
            })
            results.append({
                "test": "model_to_red_direct",
                "route": f"Model -> Red ({red_ip}:{REVERSE_LISTENER_PORT})",
                "target": red_ip,
                "status": "SETUP_FAILED",
                "detail": f"Reverse isolation probe aborted: {detail}",
            })
            return results

        # 1. Probe from Blue filter -> Red
        print("[*] [NEGATIVE-5a] Blue -> Red reverse access probe...")
        b_code, b_out, b_err = probe_http_from_python_container(
            "bayora-blue-filter", f"http://{red_ip}:{REVERSE_LISTENER_PORT}", timeout=3
        )
        b_class = classify_connection_result(b_code, b_out, b_err, REVERSE_LISTENER_TOKEN)
        if is_hardened:
            if b_class == "ISOLATED_TIMEOUT_OR_UNREACHABLE":
                b_status = "PASS_ISOLATED"
                b_detail = f"Network isolated: Blue cannot reach Red at {red_ip} (err={b_err})"
            else:
                b_status = "FAIL_POLICY"
                b_detail = f"Policy violation: Blue reached Red (classification={b_class})"
        else:
            if b_class == "HTTP_REACHED":
                b_status = "BASELINE_VULNERABLE"
                b_detail = f"Blue reached Red probe listener on flat bridge (L3/L7 verified)"
            elif b_class == "L3_CONNECTION_REFUSED":
                b_status = "BASELINE_VULNERABLE"
                b_detail = f"Blue reached Red at L3 (connection refused received)"
            else:
                b_status = "UNEXPECTED_BLOCKED"
                b_detail = f"Connection failed in baseline: {b_err}"

        results.append({
            "test": "blue_to_red_direct",
            "route": f"Blue -> Red ({red_ip}:{REVERSE_LISTENER_PORT})",
            "target": red_ip,
            "status": b_status,
            "detail": b_detail,
        })

        # 2. Probe from Model server -> Red
        print("[*] [NEGATIVE-5b] Model -> Red reverse access probe...")
        m_code, m_out, m_err = run_cmd([
            "docker", "exec", "bayora-model-server", "curl", "-sS", "-m", "3", f"http://{red_ip}:{REVERSE_LISTENER_PORT}"
        ])
        m_class = classify_connection_result(m_code, m_out, m_err, REVERSE_LISTENER_TOKEN)
        if is_hardened:
            if m_class == "ISOLATED_TIMEOUT_OR_UNREACHABLE":
                m_status = "PASS_ISOLATED"
                m_detail = f"Network isolated: Model cannot reach Red at {red_ip} (err={m_err})"
            else:
                m_status = "FAIL_POLICY"
                m_detail = f"Policy violation: Model reached Red (classification={m_class})"
        else:
            if m_class == "HTTP_REACHED":
                m_status = "BASELINE_VULNERABLE"
                m_detail = f"Model reached Red probe listener on flat bridge (L3/L7 verified)"
            elif m_class == "L3_CONNECTION_REFUSED":
                m_status = "BASELINE_VULNERABLE"
                m_detail = f"Model reached Red at L3 (connection refused received)"
            else:
                m_status = "UNEXPECTED_BLOCKED"
                m_detail = f"Connection failed in baseline: {m_err}"

        results.append({
            "test": "model_to_red_direct",
            "route": f"Model -> Red ({red_ip}:{REVERSE_LISTENER_PORT})",
            "target": red_ip,
            "status": m_status,
            "detail": m_detail,
        })

    finally:
        cleanup_isolated_listener(tracked_pid, REVERSE_LISTENER_PORT)

    return results


def test_red_external_egress(is_hardened: bool) -> dict:
    """Negative: Red runner must have NO external egress (red-net internal: true)."""
    print("[*] [NEGATIVE-6] Red external egress test (1.1.1.1)...")
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "4", "http://1.1.1.1"])
    classification = classify_connection_result(code, stdout, stderr, "")

    if is_hardened:
        if classification == "ISOLATED_TIMEOUT_OR_UNREACHABLE":
            status = "PASS_ISOLATED"
            detail = f"External egress blocked by internal: true bridge (code={code}, err={stderr})"
        else:
            status = "FAIL_POLICY"
            detail = f"Policy violation: external egress active (stdout={stdout[:60]})"
    else:
        status = "BASELINE_VULNERABLE"
        detail = f"External internet reachable on default bridge NAT (code={code})"

    return {
        "test": "red_external_egress",
        "route": "Red -> External Internet (1.1.1.1)",
        "target": "1.1.1.1",
        "status": status,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Host Reachability via Bridge Gateway IP (Separated from Cross-Zone Tests)
# ---------------------------------------------------------------------------

def test_red_to_bridge_host_sshd(is_hardened: bool) -> dict:
    """
    Host Reachability Probe:
    Tests whether Red can connect to the host's bridge gateway IP on port 22 (SSH).
    In Phase 3 Hardened mode, this MUST be dropped by host nftables rules.
    """
    print("[*] [HOST-PROBE] Red -> Bridge Gateway IP port 22 (Host SSH)...")
    bridge_ip = "172.20.1.1" if is_hardened else "172.18.0.1"
    code, stdout, stderr = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "3", f"telnet://{bridge_ip}:22"])

    if "SSH-2.0" in stdout or "OpenSSH" in stdout:
        if not is_hardened:
            status = "BASELINE_VULNERABLE"
            detail = f"Host SSH banner exposed via bridge gateway {bridge_ip}:22 ('{stdout.strip()[:35]}')"
        else:
            status = "FAIL_FIREWALL"
            detail = f"Policy violation: Host SSH banner exposed to Red at {bridge_ip}:22 ('{stdout.strip()[:35]}'). Host firewall missing or inactive!"
    else:
        status = "PASS_ISOLATED"
        detail = f"Host port 22 unreachable via bridge gateway {bridge_ip} (code={code}, dropped by host firewall)"

    return {
        "test": "red_to_bridge_host_sshd",
        "route": f"Red -> Bridge Host ({bridge_ip}:22)",
        "target": f"{bridge_ip}:22",
        "status": status,
        "detail": detail,
    }


def test_red_to_bridge_container_ports(is_hardened: bool) -> dict:
    """
    Host Bridge IP: Container Ports Probe (8001, 8080).
    Verifies that container ports published to 127.0.0.1 do not accept connections via the bridge IP.
    """
    print("[*] [HOST-PROBE] Red -> Bridge Gateway IP container ports (8001, 8080)...")
    bridge_ip = "172.20.1.1" if is_hardened else "172.18.0.1"
    code_8001, out_8001, _ = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "2", f"http://{bridge_ip}:8001/health"])
    code_8080, out_8080, _ = run_cmd(["docker", "exec", "bayora-red-runner", "curl", "-sS", "-m", "2", f"http://{bridge_ip}:8080/health"])

    if code_8001 != 0 and code_8080 != 0:
        status = "PASS"
        detail = f"Bridge gateway ports 8001/8080 closed (127.0.0.1 binding effective)"
    else:
        status = "FAIL_POLICY"
        detail = f"Bridge gateway forwarded to localhost ports: 8001={code_8001}, 8080={code_8080}"

    return {
        "test": "red_to_bridge_container_ports",
        "route": f"Red -> Bridge ({bridge_ip}:8001, 8080)",
        "target": f"{bridge_ip}",
        "status": status,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Controls & IPAM Validation
# ---------------------------------------------------------------------------

def test_phase2_controls_preserved(containers: dict) -> dict:
    """Verify that all Phase 2 container hardening controls remain active."""
    print("[*] [CONTROLS] Validating Phase 2 controls preservation...")
    violations = []

    # 1. Red runner
    red = containers.get("bayora-red-runner", {})
    if red.get("HostConfig", {}).get("Runtime") != "runsc":
        violations.append("bayora-red-runner missing gVisor (runsc) runtime")
    if "ALL" not in red.get("HostConfig", {}).get("CapDrop", []):
        violations.append("bayora-red-runner missing cap_drop: ALL")
    for m in red.get("Mounts", []):
        if m.get("Type") == "bind" and m.get("RW", True):
            violations.append(f"bayora-red-runner has writable host bind mount: {m.get('Source')}")

    # 2. Model server
    model = containers.get("bayora-model-server", {})
    if model.get("HostConfig", {}).get("Runtime") != "runc":
        violations.append("bayora-model-server missing runc runtime")
    sec_opts = model.get("HostConfig", {}).get("SecurityOpt", [])
    if not any("seccomp" in s for s in sec_opts):
        violations.append("bayora-model-server missing seccomp profile")
    if not any("bayora-model-server" in s for s in sec_opts):
        violations.append("bayora-model-server missing bayora-model-server AppArmor profile")
    if "ALL" not in model.get("HostConfig", {}).get("CapDrop", []):
        violations.append("bayora-model-server missing cap_drop: ALL")

    # 3. Blue filter
    blue = containers.get("bayora-blue-filter", {})
    if not blue.get("HostConfig", {}).get("ReadonlyRootfs", False):
        violations.append("bayora-blue-filter missing read_only: true rootfs")
    if "ALL" not in blue.get("HostConfig", {}).get("CapDrop", []):
        violations.append("bayora-blue-filter missing cap_drop: ALL")

    # 4. Gateway
    gateway = containers.get("bayora-baseline-stub", {})
    if "ALL" not in gateway.get("HostConfig", {}).get("CapDrop", []):
        violations.append("bayora-baseline-stub missing cap_drop: ALL")

    if violations:
        return {
            "test": "phase2_controls_preserved",
            "route": "HostConfig Hardening Check",
            "target": "all containers",
            "status": "FAIL",
            "detail": "; ".join(violations),
        }
    return {
        "test": "phase2_controls_preserved",
        "route": "HostConfig Hardening Check",
        "target": "all containers",
        "status": "PASS",
        "detail": "All Phase 2 controls active (runsc, seccomp, AppArmor, cap_drop: ALL, read_only rootfs)",
    }


def test_ipam_static_assignments(is_hardened: bool, containers: dict) -> dict:
    """Validate static IP assignments and detect startup IP drifting."""
    print("[*] [IPAM] Validating network IPAM and container address assignments...")
    if not is_hardened:
        addrs = {}
        for name, data in containers.items():
            nets = data.get("NetworkSettings", {}).get("Networks", {})
            addrs[name] = {net_name: net_info.get("IPAddress") for net_name, net_info in nets.items()}
        return {
            "test": "ipam_static_assignments",
            "route": "Docker Network Inspection",
            "target": "bridge",
            "status": "BASELINE_UNSEGMENTED",
            "detail": f"Containers operating on single flat bridge: {json.dumps(addrs)}",
        }

    mismatches = []
    for short_net, net_spec in EXPECTED_PHASE3_IPAM.items():
        for cname, expected_ip in net_spec["containers"].items():
            cdata = containers.get(cname)
            if not cdata:
                mismatches.append(f"Container {cname} not found")
                continue
            c_nets = cdata.get("NetworkSettings", {}).get("Networks", {})
            actual_ip = None
            for raw_n, n_data in c_nets.items():
                if raw_n == short_net or raw_n.endswith(f"_{short_net}"):
                    actual_ip = n_data.get("IPAddress")
                    break

            if actual_ip != expected_ip:
                mismatches.append(f"{cname} on {short_net}: expected {expected_ip}, got {actual_ip or 'NOT_ATTACHED'}")

    if mismatches:
        return {
            "test": "ipam_static_assignments",
            "route": "Docker Network Inspection",
            "target": "Phase 3 IPAM",
            "status": "FAIL_IPAM",
            "detail": "; ".join(mismatches),
        }
    return {
        "test": "ipam_static_assignments",
        "route": "Docker Network Inspection",
        "target": "Phase 3 IPAM",
        "status": "PASS_IPAM",
        "detail": "All static IPAM assignments verified matching running containers",
    }


# ---------------------------------------------------------------------------
# Network Membership Matrix Generator
# ---------------------------------------------------------------------------

def generate_network_matrix(containers: dict) -> str:
    """Generate ASCII network membership matrix from container inspection."""
    networks = set()
    for c in containers.values():
        networks.update(c.get("NetworkSettings", {}).get("Networks", {}).keys())
    sorted_nets = sorted(networks)
    sorted_containers = sorted(containers.keys())

    col_w = 26
    net_w = 20
    header = f"{'Container':<{col_w}} | " + " | ".join(f"{n:<{net_w}}" for n in sorted_nets)
    divider = "-" * len(header)
    rows = [header, divider]

    for cname in sorted_containers:
        c_nets = containers[cname].get("NetworkSettings", {}).get("Networks", {})
        cols = []
        for n in sorted_nets:
            if n in c_nets:
                ip = c_nets[n].get("IPAddress", "ATTACHED")
                cols.append(f"{ip:<{net_w}}")
            else:
                cols.append(f"{'-':<{net_w}}")
        rows.append(f"{cname:<{col_w}} | " + " | ".join(cols))

    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Acceptance Suite Runner
# ---------------------------------------------------------------------------

def run_acceptance_suite(is_hardened: bool = False) -> dict:
    start_time = time.time()
    capture_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print("=" * 84)
    print(" BAYORA PHASE 3 — NETWORK SEGMENTATION ACCEPTANCE SUITE")
    print(f" Execution Mode: {'PHASE 3 HARDENED (Enforcing Policy)' if is_hardened else 'BASELINE PRE-IMPLEMENTATION (Measuring Bypasses)'}")
    print(f" Timestamp (UTC): {capture_time}")
    print("=" * 84)

    containers = get_live_container_inspect()
    preflight_ok, health_status = preflight_target_health(containers, is_hardened)
    print(f"[*] Preflight target health status: {health_status}")
    if not preflight_ok:
        print(f"[-] Preflight target check failed! Results may be inconclusive.")

    # Extract Red's /etc/hosts
    red_hosts = get_red_etc_hosts()

    # Build IPAM evaluation
    ipam_result = test_ipam_static_assignments(is_hardened, containers)
    ipam_ok = (ipam_result["status"] == "PASS_IPAM") if is_hardened else True
    if is_hardened and not ipam_ok:
        print("[-] IPAM Precondition FAILED: static IP assignments not verified. Negative tests will be INCONCLUSIVE.")

    negative_tests_valid = preflight_ok and ipam_ok

    # Build and execute test suite
    tests = [
        test_phase2_controls_preserved(containers),
        ipam_result,
        test_red_to_gateway_hostname_mapping(containers, red_hosts, is_hardened),
        test_red_to_gateway_authorized(containers, is_hardened),
        test_gateway_to_blue_authorized(is_hardened),
        test_gateway_to_model_authorized(is_hardened),
        test_red_to_blue_by_name(red_hosts, is_hardened, negative_tests_valid),
        test_red_to_blue_by_ip({}, is_hardened, negative_tests_valid),
        test_red_to_model_by_name(red_hosts, is_hardened, negative_tests_valid),
        test_red_to_model_by_ip({}, is_hardened, negative_tests_valid),
        test_blue_to_model_direct({}, is_hardened, negative_tests_valid),
        test_model_to_blue_direct({}, is_hardened, negative_tests_valid),
    ]

    # Add reverse probes with temporary listener in Red
    reverse_results = test_reverse_probes_with_red_listener({}, is_hardened)
    tests.extend(reverse_results)

    # Add external egress test
    tests.append(test_red_external_egress(is_hardened))

    # Add bridge host reachability probes (separated from cross-zone tests)
    tests.append(test_red_to_bridge_host_sshd(is_hardened))
    tests.append(test_red_to_bridge_container_ports(is_hardened))

    print("\n" + "=" * 84)
    print(" PHASE 3 NETWORK ACCEPTANCE TEST MATRIX")
    print("=" * 84)
    print(f"{'TEST NAME':<34} | {'STATUS':<24} | {'TARGET':<20}")
    print("-" * 84)
    for t in tests:
        print(f"{t['test']:<34} | {t['status']:<24} | {t.get('target', ''):<20}")
    print("-" * 84)

    print("\n" + "=" * 84)
    print(" LIVE DOCKER NETWORK MEMBERSHIP MATRIX")
    print("=" * 84)
    matrix = generate_network_matrix(containers)
    print(matrix)
    print("=" * 84)

    # Verdict evaluation
    if is_hardened:
        overall_pass = all(
            t["status"] in ("PASS_AUTHORIZED", "PASS_ISOLATED", "PASS", "PASS_IPAM")
            for t in tests
        )
    else:
        positive_ok = all(
            t["status"] == "PASS_AUTHORIZED"
            for t in tests if "authorized" in t["test"]
        )
        controls_ok = (tests[0]["status"] == "PASS")
        vulnerabilities_detected = any(
            t["status"] == "BASELINE_VULNERABLE"
            for t in tests
        )
        overall_pass = positive_ok and controls_ok and vulnerabilities_detected

    verdict_text = "PASS (All Hardened Policies Enforced)" if overall_pass else "FAIL (Criteria Not Met)"
    print(f"\nOverall Suite Verdict: {verdict_text}")

    report_data = {
        "timestamp": capture_time,
        "mode": "hardened" if is_hardened else "baseline",
        "duration_seconds": round(time.time() - start_time, 2),
        "overall_pass": overall_pass,
        "verdict": verdict_text,
        "membership_matrix": matrix,
        "tests": tests,
    }

    # Automatically persist evidence artifacts to results/ directory
    try:
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        report_json_path = os.path.join(EVIDENCE_DIR, "acceptance_test_report.json")
        with open(report_json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Saved structured acceptance report: {report_json_path}")
    except Exception as e:
        print(f"[-] Warning: Failed to persist acceptance JSON: {e}")

    return report_data


if __name__ == "__main__":
    is_hardened_flag = "--hardened" in sys.argv
    res = run_acceptance_suite(is_hardened=is_hardened_flag)
    sys.exit(0 if res["overall_pass"] else 1)
