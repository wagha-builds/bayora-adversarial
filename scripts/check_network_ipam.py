#!/usr/bin/env python3
"""
Bayora Phase 3 — Network IPAM & Topology Preflight Auditor

Validates:
1. All four required networks exist with exact subnets and internal flags:
   - red-net          (172.20.1.0/24, internal: true)
   - blue-net         (172.20.2.0/24, internal: true)
   - model-net        (172.20.3.0/24, internal: true)
   - gateway-host-net (172.20.0.0/24, internal: false)
2. Every container has its designated static IPv4 address on every attached network.
3. Gateway (bayora-baseline-stub) is the SOLE multi-homed container across internal trust zones.
4. Tenant zones (Red, Blue, Model) have NO shared network memberships with each other.
5. Only the Gateway publishes a port, strictly bound to 127.0.0.1:8000.
6. Red runner's actual /etc/hosts resolves 'baseline-stub' to 172.20.1.2 and has no direct blue/model entries.
7. Emits live ASCII network membership matrix from docker inspect.

Exits 0 if and only if all assertions pass; exits nonzero on any violation.
"""

import datetime
import json
import subprocess
import sys

EXPECTED_NETWORKS = {
    "bayora_adversarial_red-net": {
        "short_name": "red-net",
        "subnet": "172.20.1.0/24",
        "internal": True,
    },
    "bayora_adversarial_blue-net": {
        "short_name": "blue-net",
        "subnet": "172.20.2.0/24",
        "internal": True,
    },
    "bayora_adversarial_model-net": {
        "short_name": "model-net",
        "subnet": "172.20.3.0/24",
        "internal": True,
    },
    "bayora_adversarial_gateway-host-net": {
        "short_name": "gateway-host-net",
        "subnet": "172.20.0.0/24",
        "internal": False,
    },
}

EXPECTED_CONTAINER_IPS = {
    "bayora-red-runner": {
        "red-net": "172.20.1.10",
    },
    "bayora-blue-filter": {
        "blue-net": "172.20.2.10",
    },
    "bayora-model-server": {
        "model-net": "172.20.3.20",
    },
    "bayora-baseline-stub": {
        "red-net": "172.20.1.2",
        "blue-net": "172.20.2.2",
        "model-net": "172.20.3.2",
        "gateway-host-net": "172.20.0.2",
    },
}


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def audit_ipam() -> bool:
    print("=" * 80)
    print(" BAYORA PHASE 3 — STATIC IPAM & NETWORK TOPOLOGY PREFLIGHT AUDIT")
    print(f" Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("=" * 80)

    violations = []
    checks_passed = []

    # 1. Inspect live Docker networks
    code, stdout, stderr = run_cmd(["docker", "network", "ls", "--format", "{{json .}}"])
    if code != 0:
        print(f"[-] FATAL: Failed to list Docker networks: {stderr}")
        return False

    raw_nets = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    live_net_names = {n["Name"]: n for n in raw_nets}

    for full_name, spec in EXPECTED_NETWORKS.items():
        # Match by full project name or suffix
        matching = [name for name in live_net_names if name == full_name or name.endswith(f"_{spec['short_name']}") or name == spec['short_name']]
        if not matching:
            violations.append(f"Network missing: {full_name} ({spec['short_name']})")
            continue

        actual_net_name = matching[0]
        # Inspect network details
        c_code, c_out, _ = run_cmd(["docker", "network", "inspect", actual_net_name])
        if c_code != 0:
            violations.append(f"Failed to inspect network: {actual_net_name}")
            continue

        net_info = json.loads(c_out)[0]
        is_internal = net_info.get("Internal", False)
        ipam_configs = net_info.get("IPAM", {}).get("Config", [])
        actual_subnet = ipam_configs[0].get("Subnet") if ipam_configs else None

        if is_internal != spec["internal"]:
            violations.append(f"{actual_net_name}: internal flag mismatch (expected {spec['internal']}, got {is_internal})")
        else:
            checks_passed.append(f"{actual_net_name}: internal={is_internal} verified")

        if actual_subnet != spec["subnet"]:
            violations.append(f"{actual_net_name}: subnet mismatch (expected {spec['subnet']}, got {actual_subnet})")
        else:
            checks_passed.append(f"{actual_net_name}: subnet={actual_subnet} verified")

    # 2. Inspect containers
    code, stdout, _ = run_cmd([
        "docker", "inspect",
        "bayora-red-runner", "bayora-blue-filter", "bayora-model-server", "bayora-baseline-stub"
    ])
    if code != 0:
        print(f"[-] FATAL: Failed to inspect containers: {code}")
        return False

    containers = {c["Name"].lstrip("/"): c for c in json.loads(stdout)}

    # Verify container IP assignments
    for cname, expected_nets in EXPECTED_CONTAINER_IPS.items():
        cdata = containers.get(cname)
        if not cdata:
            violations.append(f"Container missing: {cname}")
            continue

        c_networks = cdata.get("NetworkSettings", {}).get("Networks", {})
        # Normalize network names to short names
        attached_short_nets = {}
        for raw_net_name, net_data in c_networks.items():
            for full_n, spec in EXPECTED_NETWORKS.items():
                if raw_net_name == full_n or raw_net_name.endswith(f"_{spec['short_name']}") or raw_net_name == spec['short_name']:
                    attached_short_nets[spec["short_name"]] = net_data.get("IPAddress")

        # Verify expected networks and addresses
        for short_net, expected_ip in expected_nets.items():
            actual_ip = attached_short_nets.get(short_net)
            if actual_ip != expected_ip:
                violations.append(f"{cname} on {short_net}: expected {expected_ip}, got {actual_ip or 'NOT_ATTACHED'}")
            else:
                checks_passed.append(f"{cname} -> {short_net} ({actual_ip}) verified")

        # Verify no unauthorized extra networks
        for short_net in attached_short_nets:
            if short_net not in expected_nets:
                violations.append(f"{cname} attached to unauthorized extra network: {short_net}")

    # 3. Verify Multi-Homing Invariant: Gateway is the ONLY multi-homed container across internal zones
    for cname, cdata in containers.items():
        c_networks = cdata.get("NetworkSettings", {}).get("Networks", {})
        internal_count = 0
        for raw_n in c_networks:
            for full_n, spec in EXPECTED_NETWORKS.items():
                if (raw_n == full_n or raw_n.endswith(f"_{spec['short_name']}") or raw_n == spec['short_name']) and spec["internal"]:
                    internal_count += 1

        if cname == "bayora-baseline-stub":
            if internal_count != 3:
                violations.append(f"Gateway (bayora-baseline-stub) expected 3 internal networks, found {internal_count}")
            else:
                checks_passed.append("Gateway is correctly multi-homed across all 3 internal zones (red, blue, model)")
        else:
            if internal_count > 1:
                violations.append(f"Security invariant violated: Non-gateway container {cname} is multi-homed ({internal_count} internal networks)")
            elif internal_count == 1:
                checks_passed.append(f"Tenant isolation: {cname} is strictly single-homed (1 internal network)")

    # 4. Port Publishing Audit: Only Gateway published on 127.0.0.1:8000
    for cname, cdata in containers.items():
        port_bindings = cdata.get("HostConfig", {}).get("PortBindings", {}) or {}
        if cname == "bayora-baseline-stub":
            # Must publish 8000 strictly to 127.0.0.1
            bindings = port_bindings.get("8000/tcp", [])
            if not bindings or bindings[0].get("HostIp") != "127.0.0.1" or bindings[0].get("HostPort") != "8000":
                violations.append(f"Gateway port 8000 not properly bound to 127.0.0.1:8000: {bindings}")
            else:
                checks_passed.append("Gateway port 8000 correctly bound to 127.0.0.1:8000")
        else:
            if port_bindings:
                violations.append(f"Prohibited port exposure: {cname} publishes ports: {port_bindings}")
            else:
                checks_passed.append(f"{cname}: no ports published to host (verified)")

    # 5. Red /etc/hosts audit
    code, stdout, _ = run_cmd(["docker", "exec", "bayora-red-runner", "cat", "/etc/hosts"])
    if code != 0:
        violations.append("Failed to inspect bayora-red-runner /etc/hosts")
    else:
        hosts_lines = [l.strip() for l in stdout.splitlines() if l.strip() and not l.startswith("#")]
        host_map = {}
        for l in hosts_lines:
            parts = l.split()
            if len(parts) >= 2:
                for h in parts[1:]:
                    host_map[h] = parts[0]

        if host_map.get("baseline-stub") != "172.20.1.2":
            violations.append(f"Red /etc/hosts: baseline-stub expected 172.20.1.2, got {host_map.get('baseline-stub')}")
        else:
            checks_passed.append("Red /etc/hosts: baseline-stub -> 172.20.1.2 verified")

        if "blue-filter" in host_map:
            violations.append(f"Stale mapping: Red /etc/hosts contains direct blue-filter mapping ({host_map['blue-filter']})")
        else:
            checks_passed.append("Red /etc/hosts: blue-filter direct mapping absent (verified)")

        if "model-server" in host_map:
            violations.append(f"Stale mapping: Red /etc/hosts contains direct model-server mapping ({host_map['model-server']})")
        else:
            checks_passed.append("Red /etc/hosts: model-server direct mapping absent (verified)")

    # Generate and print Network Membership Matrix
    print("\n" + "=" * 80)
    print(" LIVE DOCKER NETWORK MEMBERSHIP MATRIX")
    print("=" * 80)
    nets = sorted(EXPECTED_NETWORKS.keys())
    short_header = [EXPECTED_NETWORKS[n]["short_name"] for n in nets]
    col_w = 26
    net_w = 16
    header = f"{'Container':<{col_w}} | " + " | ".join(f"{n:<{net_w}}" for n in short_header)
    divider = "-" * len(header)
    print(header)
    print(divider)

    for cname in sorted(containers.keys()):
        c_nets = containers[cname].get("NetworkSettings", {}).get("Networks", {})
        cols = []
        for n in nets:
            spec = EXPECTED_NETWORKS[n]
            # Match
            ip = "-"
            for actual_n, n_data in c_nets.items():
                if actual_n == n or actual_n.endswith(f"_{spec['short_name']}") or actual_n == spec['short_name']:
                    ip = n_data.get("IPAddress", "ATTACHED")
            cols.append(f"{ip:<{net_w}}")
        print(f"{cname:<{col_w}} | " + " | ".join(cols))
    print("=" * 80 + "\n")

    print(f"[*] Verified Checks Passed: {len(checks_passed)}")
    for c in checks_passed:
        print(f"  [+] {c}")

    if violations:
        print(f"\n[-] IPAM AUDIT FAILED with {len(violations)} violation(s):")
        for v in violations:
            print(f"  [!] VIOLATION: {v}")
        return False

    print("\n[+] SUCCESS: Static IPAM preflight passed with 100% compliance!")
    return True


if __name__ == "__main__":
    ok = audit_ipam()
    sys.exit(0 if ok else 1)
