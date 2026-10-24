# Bayora — Adversarial AI Evaluation Platform

> **A Hardened Five-Zone Defense-in-Depth Sandbox for Adversarial LLM Safety Evaluations**
> *Current Status: Phase 2 (Hardening: gVisor, Seccomp, AppArmor, Least Privilege & Storage Isolation) Verified & Tagged*
> *Active Tag: `phase2.3-least-privilege` | Active Branch: `phase2-hardening`*

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

## 3. Five-Zone Architecture

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
│   └───────────────────┘                             │           │       │
│                                   Sanitized Prompt  │           │ Audit │
│                                   ┌─────────────────┘           │ Event │
│                                   │                             ▼       │
│                                   ▼                     ┌───────────┐   │
│                           ┌───────────────┐             │  ZONE 5:  │   │
│                           │    ZONE 2:    │             │   AUDIT   │   │
│                           │   BLUE TEAM   │             │   ZONE    │   │
│                           │   (Defenses)  │             │  (Ledger) │   │
│                           └───────┬───────┘             └───────────┘   │
│                                   │ Filtered Prompt                     │
│                                   ▼                                     │
│                           ┌───────────────┐                             │
│                           │    ZONE 3:    │                             │
│                           │  MODEL ZONE   │                             │
│                           │  (llama.cpp)  │                             │
│                           │  [Stateless]  │                             │
│                           └───────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Zone Communication Matrix

| Zone | Component | Inbound Permitted From | Outbound Permitted To | Applied Now (Phase 2.3) | Planned Hardening (Phases 3–7) |
|---|---|---|---|---|---|
| **Zone 1: Red** | `red-runner` | None | Zone 4 (Gateway only) | gVisor `runsc`, `cap_drop: ALL`, `no-new-privileges: true`, payload-only `:ro` mount, in-memory `tmpfs` results volume (no host filesystem write access) | Strict bridge network isolation to Gateway only (Phase 3) |
| **Zone 2: Blue** | `blue-filter` | Zone 4 (Gateway only) | Zone 4 (Verdict return) | `read_only: true` rootfs, non-root user (`65534:65534`), `tmpfs: /tmp`, `cap_drop: ALL`, `no-new-privileges: true`, custom seccomp profile, AppArmor profile (`bayora-python-service`) | Strict bridge network isolation to Gateway only (Phase 3), mTLS certificates (`step-ca`, Phase 4) |
| **Zone 3: Model** | `model-server` | Zone 4 (Gateway only) | Zone 4 (Inference stream) | Hardened `runc` runtime (retained after 9.26x gVisor CPU overhead evaluation), `cap_drop: ALL`, `no-new-privileges: true`, custom seccomp profile, AppArmor profile (`bayora-model-server`), read-only model mount | Strict bridge network isolation to Gateway only (Phase 3), KV prompt caching disabled (Phase 6), `cpuset` core pinning (Phase 7) |
| **Zone 4: Control** | `baseline-stub` / Gateway | Zone 1 (Red) | Zone 2 (Blue), Zone 3 (Model), Zone 5 (Audit) | `read_only: true` rootfs, non-root user (`65534:65534`), `tmpfs: /tmp`, `cap_drop: ALL`, `no-new-privileges: true`, custom seccomp profile, AppArmor profile (`bayora-python-service`) | OPA ABAC engine, TLS termination, token bucket rate limiter (Phase 4) |
| **Zone 5: Audit** | Audit Daemon | Zone 4 (Gateway only) | External Trust Anchor | Container log verification script | Append-only SHA-256 chained hash ledger with Ed25519 signatures, external Git anchoring (Phase 5) |


---

## 4. Current Implementation Status & Test Results

### Phase 1: Insecure Baseline (Docker Desktop / WSL2) — Tag: `phase1-baseline-v2`
- Constructed unhardened baseline stack with single shared bridge network and shared Docker volume.
- Verified 5/5 baseline vulnerabilities via automated exploit scripts.
- Provisional reference latency: Unloaded $p50 = 3,237.08\text{ ms}$ (16-thread host).

### Phase 2.0: Native Linux VM Re-Baselining — Tag: `phase2.0-vm-baseline`
- **Target Environment:** Dedicated Ubuntu Server 24.04 LTS on VirtualBox (6 vCPUs, 8 GB RAM, `cgroup v2`, gVisor `runsc` installed, key-only SSH).
- **Security Checkpoints Passed:** Ports bound strictly to guest localhost; no published ports to LAN; zero containers running prior to test.
- **Evidence Collection:** All **18 native baseline evidence files** collected and preserved in [`results/baseline/local-ubuntu-vm/`](results/baseline/local-ubuntu-vm/).

#### Native Baseline Test Matrix Summary

| Test Script | Target | Insecure Behavior Demonstrated | Native VM Outcome | PRD Req |
|---|---|---|---|---|
| `test_net_blue_direct.py` | Blue Filter | Red connects directly to Blue port 8001 bypassing Gateway | ✅ **EXPLOIT SUCCEEDED** (HTTP 200) | SEC-008 |
| `test_net_model_direct.py` | Model Server | Red connects directly to llama.cpp port 8080 | ✅ **EXPLOIT SUCCEEDED** (HTTP 200) | SEC-008 |
| `test_fs_blue_rules.py` | Shared Volume | Red reads proprietary `blue_rules.json` directly from shared volume | ✅ **EXPLOIT SUCCEEDED** (Rules extracted) | SEC-001 |
| `test_cache_timing.py` | Model KV Cache | Identical prefix returns in 126 ms vs 2,565 ms (delta: 2,439 ms) | ✅ **EXPLOIT SUCCEEDED** (Oracle confirmed) | LLM-001 |
| `test_log_exposure.py` | Container Stdout | Unredacted raw user prompts readable from container logs | ✅ **EXPLOIT SUCCEEDED** (Prompts leaked) | PRIV-001 |
| `test_resource_contention.py` | Host CPU | Red stressor monopolizes CPU; causes severe latency spikes and 502 timeouts | ✅ **FAILURE MODE PROVEN** (Accepted with waiver) | PERF-004 |
| `test_unloaded_recovery.py` | Host Recovery | Clean post-contention recovery run (10/10 requests complete) | ✅ **RECOVERY VERIFIED** ($p50 = 7,790.57\text{ ms}$) | RES-004 |

#### Contention & Recovery Benchmark Findings
- **Contention Failure Mode:** Spawning 4 CPU stressor processes alongside 2 inference threads saturated all 6 vCPUs on the VM, inducing Linux kernel watchdog soft-lockup alarms, client timeouts (4 explicit timeouts at 45.0s threshold), and upstream gateway timeouts (5 HTTP 502s). 10 queries completed with latencies up to 442 seconds.
- **Post-Contention Recovery:** After stopping the stressor, an independent 10-request unloaded recovery check completed 10/10 requests with median latency $p50 = 7,790.57\text{ ms}$, confirming operational return to service.
- **Approved Waiver:** Owner waiver accepted on 2026-10-24 accepting the partial run as baseline failure-mode evidence; bounded contention testing with $\le 2$ stressor processes or CFS quotas is deferred to Phase 7.

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

| **Phase 3** | Five-Zone Network Isolation | Strict Docker bridge network isolation (5 distinct bridges), internal DNS, `nftables` | 🔄 **NEXT** |
| **Phase 4** | Identity, Secrets & Policy | OpenBao secrets engine, `step-ca` automated mTLS per zone, OPA ABAC engine | 🔲 Planned |
| **Phase 5** | Cryptographic Audit Ledger | Append-only SHA-256 chained ledger with Ed25519 signatures, external Git anchoring | 🔲 Planned |
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
│       ├── blue_rules.json                 # Naive keyword filter configuration
│       └── payloads.json                   # 10 synthetic evaluation prompts (5 benign, 5 jailbreak)
├── docs/
│   ├── api/
│   │   └── gateway-contract.md             # Evaluation Gateway OpenAPI / schema specification
│   ├── architecture/
│   │   ├── dfd.md                          # Five-Zone Data Flow Diagram & trust crossing matrix
│   │   └── zones.md                        # Zone definitions, trust boundaries & lifecycle state machine
│   ├── risk/
│   │   └── risk-register.md                # 22-item risk register with mitigations & residual risk ratings
│   ├── threat-model/
│   │   └── stride.md                       # Complete 42-cell STRIDE threat model
│   └── roadmap.md                          # Phase-by-phase architectural roadmap & Definition of Done
├── models/
│   └── .gitkeep                            # Mount point for pinned GGUF model weights
├── results/
│   └── baseline/
│       ├── contention_baseline_results.json# WSL2 provisional contention baseline
│       ├── leak_test_results.json          # WSL2 leak test results
│       └── local-ubuntu-vm/                # 18 Native VM baseline evidence files
│           ├── bayora-compose-config.txt   # Resolved docker compose configuration
│           ├── bayora-contention-4core-partial-run.log # 4-core contention log
│           ├── bayora-contention-interrupted-run.log   # 6-core stall evidence
│           ├── bayora-kernel-softlockup-evidence.png   # Console screenshot of soft lockup
│           ├── bayora-model-sha256.txt     # Verified SHA-256 digest
│           ├── host_fingerprint.json       # Host machine, OS, CPU & hypervisor details
│           ├── leak_test_results.json      # 5/5 Native VM automated leak test outputs
│           ├── unloaded_recovery_results.json # 10/10 post-contention recovery metrics
│           └── vm-baseline-run-001_results.json# Native 10-prompt baseline evaluation
├── scripts/
│   ├── download_model.py                   # Model downloader with SHA-256 verification
│   ├── download_model.sh                   # Automated curl/python downloader wrapper
│   └── provision-host.sh                   # Automated host provisioning script (Docker, runsc, AppArmor)
├── services/
│   ├── baseline-stub/                      # Naive routing stub / Evaluation Gateway
│   ├── blue-filter/                        # Keyword-based Blue Team defense filter
│   ├── model-server/                       # llama.cpp server configuration
│   └── red-runner/                         # Red Team adversary container
├── tests/
│   └── baseline/
│       ├── run_all_leak_tests.py           # Unified runner for all 5 leak tests
│       ├── test_cache_timing.py            # Prompt/prefix cache timing oracle exploit
│       ├── test_fs_blue_rules.py           # Cross-zone filesystem read exploit
│       ├── test_log_exposure.py            # Container log snooping exploit
│       ├── test_net_blue_direct.py         # Direct network bypass exploit to Blue
│       ├── test_net_model_direct.py        # Direct network bypass exploit to Model
│       ├── test_r19_timeout.py             # Defense timeout failure-open test
│       ├── test_resource_contention.py     # CPU stressor & contention benchmark
│       └── test_unloaded_recovery.py       # Post-contention unloaded recovery check
├── docker-compose.yml                      # Baseline unsegmented deployment stack
├── task.md                                 # Master project execution tracker & audit findings
└── README.md                               # This document
```

---

## 7. Quickstart & Local Reproduction Guide

### Prerequisites
- **Host OS:** Linux (Ubuntu 24.04 LTS recommended) or Linux VM under VirtualBox/VMware.
- **Hardware:** $\ge 6$ vCPUs, 8 GB RAM, 60 GB disk.
- **Dependencies:** Docker Engine 24+, Docker Compose v2, Python 3.10+, `cgroup v2`.

### Step 1: Provision the Host
```bash
chmod +x scripts/provision-host.sh
./scripts/provision-host.sh
```

### Step 2: Download & Verify Model Weights
Download the pinned `Qwen2.5-1.5B-Instruct-Q4_K_M.gguf` weights (verified SHA-256 digest: `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`):
```bash
chmod +x scripts/download_model.sh
./scripts/download_model.sh
```

### Step 3: Launch the Baseline Stack
```bash
docker compose up -d --build
docker compose ps
```

### Step 4: Run the Automated Leak Test Suite
Execute all 5 baseline leak tests from inside the Red runner container:
```bash
docker compose exec red-runner python /app/tests/run_all_leak_tests.py
```
*Expected Insecure Baseline Output:* All 5 tests **PASS** (confirming that every vulnerability is exploitable prior to hardening).

### Step 5: Run the Baseline Evaluation Pipeline
```bash
docker compose exec red-runner python /app/services/red-runner/main.py
```

### Step 6: Run Post-Contention Recovery Validation
```bash
docker compose exec red-runner python /app/tests/test_unloaded_recovery.py
```

---

## 8. Security & Responsible Disclosure

This repository contains intentional vulnerabilities strictly confined within container boundaries for comparative evaluation purposes. **Never deploy the unhardened Phase 1/Phase 2.0 baseline stack on public-facing networks or production clusters.** All ports must remain strictly bound to `127.0.0.1`.

For questions, architecture reviews, or audit verifications, refer to [`docs/roadmap.md`](docs/roadmap.md) and [`task.md`](task.md).

---

## 9. Team & Contributions

This project is being developed by a 3-member team for the **Hack in the Hills 26 PS04 Bayora** hackathon. The current roles and planned contributions are structured as follows:

- **Akshaya (Lead Developer):** Leading the core architecture, threat modeling, and current implementation. Responsible for Phase 0 (Alignment) and Phase 1 (Baseline), and actively executing the current Phase 2 (Hardening) and Phase 3 (Network Isolation) objectives.
- **[Member 2 Name] (Contributing Developer):** Assigned to implement upcoming critical security infrastructure. Will be taking ownership of future phases, specifically focusing on Phase 4 (Identity, Secrets & Policy via OpenBao/OPA) and Phase 5 (Audit Ledger & External Anchoring) once the foundational hardening is complete.
- **[Member 3 Name] (Developer & Evangelist):** Focused on project documentation, ideation, and external presentation. Major responsibilities include creating the pitch deck (PPT), prototype demo videos, and driving social pitching (LinkedIn, Instagram reels) to showcase the platform's capabilities to judges and the community.
