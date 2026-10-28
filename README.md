# Bayora — Adversarial AI Evaluation Platform

> **A Hardened Five-Zone Defense-in-Depth Sandbox for Adversarial LLM Safety Evaluations**<br>
> *Current Status: Phase 3 (Five-Zone Network Segmentation, Static IPAM & Host Firewall) Implemented & Verified (17/17 Checks Passed); Systemd Firewall Persistence Active (Cold Reboot Verification Pending)*<br>
> *Active Tag: `phase2-final` | Active Branch: `phase3-network`*

---

## 1. Executive Summary

**Bayora** is an adversarial security evaluation harness and isolation platform designed to evaluate Large Language Models (LLMs) against jailbreaks, prompt injections, system prompt extractions, and microarchitectural side-channels—**without** introducing catastrophic security risks into evaluation infrastructure:

1. **Model Weight & Parameter Confidentiality:** Prevents unauthorized extraction of weights, embeddings, and architecture secrets.
2. **Evaluation State & Cache Isolation:** Eliminates cross-query prompt leakage, KV cache timing oracles, and shared filesystem/memory snooping.
3. **Defense Shielding & Uniform Refusals:** Prevents Red teams from probing or reverse-engineering Blue defense heuristics through strict mediation and indistinguishable rejection responses.
4. **Cryptographic Audit Immutability:** Records every query, response token count, latency metric, and policy verdict in an append-only, tamper-evident hash ledger anchored externally.

Bayora follows a scientifically rigorous **Before vs. After** methodology:
- **Unhardened Baseline (Phase 1 & Phase 2.0):** Empirically proves that conventional LLM deployment stacks are vulnerable across all attack vectors using automated attack scripts.
- **Hardened Sandbox (Phases 2.1–10):** Sequentially layers container isolation (gVisor `runsc`), system call filtering (`seccomp`), mandatory access control (AppArmor), five-zone network segmentation, identity/mTLS (`step-ca`), declarative policy enforcement (OPA), and tamper-evident audit chaining.

---

## 2. Core Security Invariants

All architectural phases in Bayora enforce four non-negotiable security invariants:

| Invariant | Title | Specification |
|---|---|---|
| **R1** | **Red Isolation** | The Red Team execution environment operates as an untrusted workload sandboxed via gVisor (`runsc`). Red has **zero** access to the host filesystem, internal networks, or the model server. Red communicates exclusively via authenticated HTTP requests to the Evaluation Gateway. |
| **R2** | **Blue Integrity** | Blue defenses execute as sealed input/output guardrails. Red receives no visibility into Blue filter code, models, token representations, or classification scores. Blocked queries return standardized, uniform refusals. |
| **R3** | **Model Confidentiality** | The model runtime (`llama.cpp`) operates in an isolated zone under standard `runc` (retained following empirical evaluation of gVisor's 9.26x CPU overhead) hardened by custom seccomp syscall filters and AppArmor confinement. KV prefix caching is scheduled for removal in Phase 6, and inference processes will be pinned to dedicated CPU cores (`cpuset`) in Phase 7 to mitigate timing-oracle side channels. |
| **R4** | **Audit Immutability** | Every prompt submission, token metric, latency trace, and policy decision is Ed25519-signed and SHA-256 chained in an append-only ledger anchored externally. |

---

## 3. Five-Zone Architecture & Network Topology

Workloads and services are strictly compartmentalized across five isolated security zones:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       HOST BOUNDARY (Linux Host / VM)                   │
│                                                                         │
│   ┌───────────────────┐                         ┌───────────────────┐   │
│   │      ZONE 1:      │      HTTP Requests      │      ZONE 4:      │   │
│   │     RED TEAM      │ ──────────────────────> │   CONTROL ZONE    │   │
│   │    (Untrusted)    │ <────────────────────── │   (Gateway+OPA)   │   │
│   │   [gVisor runsc]  │      Uniform Refusal    └───┬───────────┬───┘   │
│   │   (172.20.1.10)   │                             │           │       │
│   └───────────────────┘                             │           │ Audit │
│                                   Sanitized Prompt  │           │ Event │
│                                   ┌─────────────────┘           │       │
│                                   │                             ▼       │
│                                   ▼                     ┌───────────┐   │
│                           ┌───────────────┐             │  ZONE 5:  │   │
│                           │    ZONE 2:    │             │   AUDIT   │   │
│                           │   BLUE TEAM   │             │   ZONE    │   │
│                           │   (Defenses)  │             │  (Ledger) │   │
│                           │ (172.20.2.10) │             └───────────┘   │
│                           └───────┬───────┘                             │
│                                   │ Filtered Prompt                     │
│                                   ▼                                     │
│                           ┌───────────────┐                             │
│                           │    ZONE 3:    │                             │
│                           │  MODEL ZONE   │                             │
│                           │  (llama.cpp)  │                             │
│                           │ [172.20.3.20] │                             │
│                           └───────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Implemented Network Segmentation & IPAM Matrix (Phase 3)

| Network | Subnet CIDR | `internal` | Gateway IP (Host) | Attached Container | Static IPv4 | Published Ports |
|---|---|---|---|---|---|---|
| `red-net` | `172.20.1.0/24` | `true` | `172.20.1.1` | `bayora-red-runner`<br/>`bayora-baseline-stub` | `172.20.1.10`<br/>`172.20.1.2` | None |
| `blue-net` | `172.20.2.0/24` | `true` | `172.20.2.1` | `bayora-blue-filter`<br/>`bayora-baseline-stub` | `172.20.2.10`<br/>`172.20.2.2` | None (Port 8001 unmapped) |
| `model-net` | `172.20.3.0/24` | `true` | `172.20.3.1` | `bayora-model-server`<br/>`bayora-baseline-stub` | `172.20.3.20`<br/>`172.20.3.2` | None (Port 8080 unmapped) |
| `gateway-host-net` | `172.20.0.0/24` | `false` | `172.20.0.1` | `bayora-baseline-stub` | `172.20.0.2` | `127.0.0.1:8000:8000` |

### Zone Communication Matrix

| Zone | Component | Inbound Permitted From | Outbound Permitted To | Applied Now (Phase 3) | Planned Hardening (Phases 4–7) |
|---|---|---|---|---|---|
| **Zone 1: Red** | `red-runner` | None | Zone 4 (Gateway only) | gVisor `runsc`, `cap_drop: ALL`, `no-new-privileges: true`, payload-only `:ro` mount, in-memory `tmpfs` results volume, dedicated `red-net` (`172.20.1.10`, `internal: true`) | mTLS client authentication (`step-ca`, Phase 4) |
| **Zone 2: Blue** | `blue-filter` | Zone 4 (Gateway only) | Zone 4 (Verdict return) | `read_only: true` rootfs, non-root user (`65534:65534`), `tmpfs: /tmp`, `cap_drop: ALL`, custom seccomp profile, AppArmor profile (`bayora-python-service`), dedicated `blue-net` (`172.20.2.10`, `internal: true`), host port unmapped | mTLS certificates (`step-ca`, Phase 4) |
| **Zone 3: Model** | `model-server` | Zone 4 (Gateway only) | Zone 4 (Inference stream) | Hardened `runc` runtime, `cap_drop: ALL`, custom seccomp profile, AppArmor profile (`bayora-model-server`), read-only model mount, dedicated `model-net` (`172.20.3.20`, `internal: true`), host port unmapped | KV prompt caching disabled (Phase 6), `cpuset` core pinning (Phase 7) |
| **Zone 4: Control** | `baseline-stub` / Gateway | Zone 1 (Red), Host Evaluator | Zone 2 (Blue), Zone 3 (Model), Zone 5 (Audit) | Sole multi-homed container across zones (`172.20.0.2`, `1.2`, `2.2`, `3.2`), `read_only: true` rootfs, non-root user (`65534:65534`), `cap_drop: ALL`, localhost bound `127.0.0.1:8000:8000` | OPA ABAC engine, TLS termination, token bucket rate limiter (Phase 4) |
| **Zone 5: Audit** | Audit Daemon | Zone 4 (Gateway only) | External Trust Anchor | Container log verification script | Append-only SHA-256 chained hash ledger with Ed25519 signatures, external Git anchoring (Phase 5) |

---

## 4. Current Implementation Status & Test Results

### Phase 2 Summary: Runtimes, Profiles & Least Privilege
- **gVisor (`runsc`):** Red container isolated under Sentry user-space kernel virtualization. Model evaluated under gVisor; 9.26x overhead documented, retaining hardened `runc` for Model.
- **Seccomp & AppArmor:** Custom seccomp syscall filters unconditionally block 18 high-risk syscalls (`ptrace`, `bpf`, `mount`). Custom AppArmor profiles loaded in enforce mode.
- **Least Privilege & Storage:** `cap_drop: ALL` active across all 4 containers; shared volume unmounted (`SEC-001` mitigated).
- **Consolidated Tag:** `phase2-final` points to verified commit `02e2a1c` (VM and Windows identical tag object).

### Phase 3 Summary: Five-Zone Network Segmentation & IPAM Preflight
- **Static IPAM Audit (`scripts/check_network_ipam.py`):** **26 of 26 checks passed (100% compliance)**. Confirmed 4 isolated networks, subnets, internal flags, static IPs, Gateway multi-homing, and single-homed tenants.
- **Hardened Acceptance Suite (`tests/network/test_phase3_network_acceptance.py`):**
  - **Positive Controls:** Red $\rightarrow$ Gateway (`PASS_AUTHORIZED`), Gateway $\rightarrow$ Blue (`PASS_AUTHORIZED`), Gateway $\rightarrow$ Model (`PASS_AUTHORIZED`).
  - **Cross-Zone Denials:** Red $\rightarrow$ Blue direct (`PASS_ISOLATED`), Red $\rightarrow$ Model direct (`PASS_ISOLATED`), Blue $\leftrightarrow$ Model direct (`PASS_ISOLATED`).
  - **Reverse Probes:** Blue $\rightarrow$ Red and Model $\rightarrow$ Red fail with verified temporary test listener on port 8088 (`PASS_ISOLATED`), using dedicated probe server (`scripts/test_listener_server.py`).
  - **Egress:** Red external egress to `1.1.1.1` blocked by `internal: true` (`PASS_ISOLATED`).
  - **Bridge Host Reachability:** Red $\rightarrow$ `172.20.1.1:22` (Host SSH) blocked by host firewall rules (`PASS_ISOLATED`, packets dropped by `inet bayora_host_firewall`).
  - **Bridge Container Ports:** Red $\rightarrow$ `172.20.1.1:8001,8080` closed (`PASS`, localhost `127.0.0.1` binding effective).
  - **Suite Verdict:** **`PASS (All Hardened Policies Enforced)`** (17 of 17 checks passed across two consecutive runs).

### Phase 3 Hardened Leak Suite Status Flips

| Test Script | Target Vulnerability | Phase 2.3 Status | Phase 3 Status | Security Impact |
|---|---|---|---|---|
| `test_fs_blue_rules.py` | SEC-001 (Shared Volume) | MITIGATED | **MITIGATED** | Rule extraction via filesystem blocked (`/shared_data` unmounted). |
| `test_net_blue_direct.py` | SEC-008 (Direct Blue Bypass) | still_reproducible | **FLIPPED $\rightarrow$ MITIGATED** | Direct network access blocked by network segmentation (`network_segmented_and_blocked`). |
| `test_net_model_direct.py` | SEC-008 (Direct Model Bypass) | still_reproducible | **FLIPPED $\rightarrow$ MITIGATED** | Direct network access blocked by network segmentation (`network_segmented_and_blocked`). |
| `test_cache_timing.py` | LLM-001 (Cache Timing Oracle) | still_reproducible | **STILL_REPRODUCIBLE** | Rerouted via Gateway (`http://baseline-stub:8000/query`); prefix caching speedup detected ($+3,644.29\text{ ms}$; scheduled for Phase 6). |
| `test_log_exposure.py` | PRIV-001 (Daemon Log Exposure) | still_reproducible | **STILL_REPRODUCIBLE** | Prompts visible in stdout logs at operator boundary; scheduled for Phase 5. |

### Phase 3.3 Host Firewall Remediation (`nftables`) & Persistence Status
- **Finding:** Docker bridge gateways assign host kernel IP (`172.20.1.1` on `red-net`). Services bound to `0.0.0.0` (such as OpenSSH on port 22) are reachable from within tenant containers across the bridge gateway (`SSH-2.0-OpenSSH_9.6p1` banner exposed).
- **Remediation Implementation:** `scripts/apply_phase3_host_firewall.sh` applies dedicated table `inet bayora_host_firewall` hooking `input` at priority `filter - 1`. Packets from tenant subnets (`172.20.1.0/24`, `172.20.2.0/24`, `172.20.3.0/24`) destined to host ports are dropped, while established/related connections, loopback, and admin SSH on `enp0s3` are preserved.
- **Persistence Configuration:** Rules are stored in `/etc/nftables.d/bayora-host-firewall.nft` and managed by a dedicated systemd service (`/etc/systemd/system/bayora-host-firewall.service`), ordered `After=network.target docker.service`. The service does NOT touch `/etc/nftables.conf` and avoids `flush ruleset`.
- **Operational Verification:** Service status confirmed `enabled` and `active`; active ruleset verified with nonzero packet drop counters; test `red_to_bridge_host_sshd` verified `PASS_ISOLATED`.
- **Authoritative Caveat:** An independent post-reboot cold verification has **not** been performed; persistence is configured and operational in the running systemd state. Rollback is provided via `scripts/rollback_phase3_host_firewall.sh`.

---

## 5. Development Roadmap & Milestones

| Phase | Milestone | Scope & Deliverables | Status |
|---|---|---|---|
| **Phase 0** | Alignment & Threat Model | STRIDE threat model, Five-Zone DFD, Gateway API contract, 22-item risk register | ✅ Complete |
| **Phase 1** | Insecure Baseline (WSL2) | Naive Compose stack, 5 automated leak tests, provisional contention baseline | ✅ Complete (`phase1-baseline-v2`) |
| **Phase 2.0** | Native VM Re-Baselining | Ubuntu 24.04 VM, 18 evidence artifacts, verified leak suite, accepted waiver | ✅ Complete (`phase2.0-vm-baseline`) |
| **Phase 2.1** | Container Hardening (gVisor) | Apply gVisor `runsc` runtime to Red Team container; empirical Model evaluation | ✅ Complete (`phase2.1-gvisor-hardening`) |
| **Phase 2.2** | System Call & MAC Hardening | Custom `seccomp` syscall profiles and AppArmor enforcement per container | ✅ Complete (`phase2.2-seccomp-apparmor`) |
| **Phase 2.3** | Least Privilege & Storage | Drop capabilities (`cap_drop: ALL`), no-new-privileges, payloads-only mount, tmpfs results, non-root Blue/Gateway, localhost ports | ✅ Complete (`phase2.3-least-privilege`) |
| **Phase 2 Audit** | Git Hygiene & Consolidation | Reconcile tag history, static seccomp audit with self-tests, filesystem scan | ✅ Complete (`phase2-final` on `02e2a1c`) |
| **Phase 3** | Five-Zone Network Isolation | Strict Docker bridge network isolation (4 distinct networks), static IPAM preflight, hardened acceptance suite | ✅ Complete & Verified |
| **Phase 3.3** | Host Firewall Persistence | Dedicated `nftables` table `inet bayora_host_firewall` and systemd unit closing Docker bridge host service exposure | ✅ Implemented & Active (Reboot Verification Pending) |
| **Phase 4** | Identity, Secrets & Policy | OpenBao secrets engine, `step-ca` automated mTLS per zone, OPA ABAC engine (Evaluation Gateway architecture planned) | 🔄 **NEXT** |
| **Phase 5** | Cryptographic Audit Ledger | Append-only SHA-256 chained ledger with Ed25519 signatures, external Git anchoring, log redaction | 🔲 Planned |
| **Phase 6** | LLM Hardening | Stateless llama.cpp runtime, prompt caching disabled, uniform refusal responses | 🔲 Planned |
| **Phase 7** | Resource Governance & Suite | CPU pinning (`cpuset`), bounded contention rerun ($\le 2$ cores/quotas), full regression suite | 🔲 Planned |
| **Phase 8** | Telemetry & Observability | Falco eBPF runtime security auditing, Prometheus metrics, Grafana dashboards | 🔲 Planned |
| **Phase 9** | Stress Testing & Resilience | Network partition tests, credential expiration stress, high-concurrency fuzzing | 🔲 Planned |
| **Phase 10** | Single-Command Deployment | Production `Makefile`, turnkey deployment (`make up`), complete walkthrough report | 🔲 Planned |

---

## 6. Repository Layout

```text
bayora_adversarial/
├── data/
│   └── baseline/
│       ├── blue_rules.json                 # Proprietary keyword filter configuration
│       └── payloads.json                   # 10 synthetic evaluation prompts (5 benign, 5 jailbreak)
├── docs/
│   ├── api/
│   │   └── gateway-contract.md             # Evaluation Gateway OpenAPI / schema specification
│   ├── architecture/
│   │   ├── dfd.md                          # Five-Zone Data Flow Diagram & trust crossing matrix
│   │   └── zones.md                        # Zone definitions, trust boundaries & lifecycle state machine
│   ├── demo/                               # Prototype demonstration scripts, checklists, and pitch materials
│   │   ├── one_minute_elevator_pitch.md    # 60-second social pitch script
│   │   ├── prototype_demo_script.md        # Step-by-step terminal execution demo walkthrough
│   │   ├── slide_outline.md                # 10-slide presentation deck structure
│   │   └── submission_checklist.md         # Pre-submission verification checklist
│   ├── maintenance/
│   │   └── markdown-audit.md               # Repository-wide Markdown documentation inventory & audit
│   ├── risk/
│   │   └── risk-register.md                # Comprehensive risk register with mitigations & residual risk ratings
│   ├── threat-model/
│   │   └── stride.md                       # Complete 42-cell STRIDE threat model
│   └── roadmap.md                          # Phase-by-phase architectural roadmap & Definition of Done
├── models/
│   └── .gitkeep                            # Mount point for pinned GGUF model weights
├── policies/
│   ├── apparmor/
│   │   ├── bayora-model-server             # Custom AppArmor policy for model server
│   │   └── bayora-python-service           # Custom AppArmor policy for Python services
│   └── seccomp/
│       ├── model-server-seccomp.json       # Syscall filter denying 18 high-risk calls for model
│       └── python-service-seccomp.json     # Syscall filter denying 18 high-risk calls for Python
├── results/
│   ├── baseline/                           # Historical unhardened baseline evidence
│   └── hardening/
│       ├── phase2.1-gvisor/                # Phase 2.1 evidence artifacts
│       ├── phase2.2-seccomp-apparmor/      # Phase 2.2 evidence artifacts
│       ├── phase2.3-least-privilege/       # Phase 2.3 evidence artifacts
│       └── phase3-network/                 # Phase 3 network segmentation evidence
│           └── local-ubuntu-vm/
│               ├── acceptance_test_report.json # 17/17 passed hardened acceptance test report
│               ├── ipam_audit_output.txt   # 26/26 passed static IPAM audit report
│               └── leak_test_results.json  # 5-test leak suite outputs with status flips
├── scripts/
│   ├── apply_phase3_host_firewall.sh       # Phase 3.3 host firewall persistent installer (nftables + systemd)
│   ├── rollback_phase3_host_firewall.sh    # Phase 3.3 host firewall rollback script
│   ├── check_network_ipam.py               # 26-assertion static IPAM preflight auditor
│   ├── test_listener_server.py             # Dedicated reverse probe test listener (HTTP 200, no directory browse)
│   ├── download_model.py                   # Model downloader with SHA-256 verification
│   ├── download_model.sh                   # Automated curl/python downloader wrapper
│   └── provision-host.sh                   # Automated host provisioning script (Docker, runsc, AppArmor)
├── services/
│   ├── baseline-stub/                      # Evaluation Gateway (sole multi-homed bridge mediator)
│   ├── blue-filter/                        # Blue Team defense filter (single-homed on blue-net)
│   ├── model-server/                       # llama.cpp server configuration (single-homed on model-net)
│   └── red-runner/                         # Red Team adversary container (single-homed on red-net)
├── tests/
│   ├── baseline/                           # Historical baseline exploit scripts
│   ├── hardening/
│   │   ├── run_phase2_3_leak_tests.py      # Phase 2.3 leak suite runner
│   │   ├── run_phase3_leak_tests.py        # Phase 3 leak suite runner
│   │   └── test_negative_security.py       # Negative syscall/capability assertions
│   └── network/
│       └── test_phase3_network_acceptance.py # Mode-aware network acceptance test suite
├── docker-compose.yml                      # Segmented 4-network deployment stack
├── task.md                                 # Master project execution tracker & audit findings
└── README.md                               # This document
```

---

## 7. Quickstart & Local Reproduction Guide

### Prerequisites
- **Host OS:** Linux (Ubuntu 24.04 LTS recommended) or Linux VM under VirtualBox/VMware.
- **Hardware:** $\ge 6$ vCPUs, 8 GB RAM, 60 GB disk.
- **Dependencies:** Docker Engine 24+, Docker Compose v2, Python 3.10+, `cgroup v2`, gVisor `runsc`.

### Step 1: Launch the Phase 3 Hardened Stack
```bash
docker compose up -d
docker compose ps
```

### Step 2: Run Static IPAM Preflight Audit
Verify all 26 network and IPAM assertions:
```bash
python3 scripts/check_network_ipam.py
```
*Expected Output:* `[+] SUCCESS: Static IPAM preflight passed with 100% compliance! (26/26 checks passed)`.

### Step 3: Run the Hardened Network Acceptance Test Suite
```bash
python3 tests/network/test_phase3_network_acceptance.py --hardened
```
*Expected Output:* All positive controls pass (`PASS_AUTHORIZED`), all cross-zone probes pass with verified isolation (`PASS_ISOLATED`), reverse probes pass against dedicated probe server, bridge gateway SSH is dropped by host firewall (`PASS_ISOLATED`), and the suite achieves `Overall Suite Verdict: PASS (All Hardened Policies Enforced)` (17/17 passed).

### Step 4: Run the Phase 3 Hardened Leak Test Suite
```bash
python3 tests/hardening/run_phase3_leak_tests.py
```
*Expected Output:* SEC-001 MITIGATED, SEC-008 FLIPPED to MITIGATED (network segmented), LLM-001 STILL_REPRODUCIBLE via Gateway, PRIV-001 STILL_REPRODUCIBLE on daemon logs.

### Step 5 (Privileged): Verify or Apply Phase 3.3 Host Firewall
To inspect active persistent firewall rules:
```bash
sudo nft list table inet bayora_host_firewall
systemctl status bayora-host-firewall.service
```
To re-apply or install on a fresh system:
```bash
sudo bash scripts/apply_phase3_host_firewall.sh
```
*(Warning: `scripts/rollback_phase3_host_firewall.sh` disables `bayora-host-firewall.service` and removes the table, re-exposing host services across the Docker bridge. Use strictly for intentional rollback).*

---

## 8. Security & Responsible Disclosure

This repository contains intentional baseline vulnerabilities strictly confined within container boundaries for comparative evaluation purposes. **Never deploy the unhardened baseline stack on public-facing networks or production clusters.** All host-facing ports must remain strictly bound to `127.0.0.1`.

For questions, architecture reviews, or audit verifications, refer to [`docs/roadmap.md`](docs/roadmap.md) and [`task.md`](task.md).

---

## 9. Team & Contributions

This project is being developed by a 3-member team for the **Hack in the Hills 26 PS04 Bayora** hackathon:

- **Atharva (Project Owner & Lead Developer):** Leading the core architecture, threat modeling, and implementation. Responsible for Phase 0 (Alignment) and Phase 1 (Baseline), and actively executing Phase 2 (Hardening) and Phase 3 (Network Isolation) objectives.
- **Akshaya (Security Engineering & Evaluation Lead):** Leading security auditing, negative test harness verification, and evaluation pipelines across hardened container boundaries.
- **[Member 3 Name] (Contributing Developer & Documentation):** Focused on project documentation, ideation, and external presentation. Major responsibilities include creating the pitch deck (PPT), prototype demo videos, and driving project communication.
