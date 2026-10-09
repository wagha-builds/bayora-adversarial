# Bayora — Project Task Tracker & Technical Blueprint

## Current Phase: Phase 0 — Alignment + Threat Model
**Status:** COMPLETED ✅  
**Objective:** Establish architectural consensus, formalize the Five-Zone Isolation model, document all trust boundaries and data flows, define the threat model via comprehensive STRIDE analysis, specify the Evaluation Gateway API contract, and populate the initial 22-item risk register before any container or application code is written.

---

## 1. Confirmed Decisions & Technology Stack Reference

All architectural and infrastructure decisions confirmed for the project:

| Category | Decision / Selection | Rationale / Reference |
|---|---|---|
| **VM Provider** | Oracle Cloud Always Free (OCI) | VM.Standard.A1.Flex: 2 ARM OCPUs, 12 GB RAM, 200 GB disk, Ubuntu 24.04 LTS (ARM64). $0 forever cost. |
| **CPU Architecture** | ARM64 (Ampere Altra) | Dedicated physical cores without SMT/hyperthreading — superior physical zone isolation. |
| **Model Runtime** | Qwen2.5-1.5B-Instruct Q4_K_M GGUF on `llama.cpp` | Fast CPU inference, Apache 2.0 license, pinned SHA-256 weights. Fallback: Llama-3.2-3B. |
| **Evaluation Gateway** | FastAPI (Python 3.12) | Rapid prototyping for hackathon; unskippable policy middleware; SQLite run metadata. Go rewrite logged as R-07. |
| **Secrets Engine** | OpenBao | Fully open-source (MPL 2.0) fork of Vault; transit encryption, short-lived tokens. |
| **Internal PKI / CA** | `step-ca` | Automated mTLS certificate issuance per zone; ARM64 native binary. |
| **Policy Engine** | Open Policy Agent (OPA) + Rego | Declarative Attribute-Based Access Control (ABAC) sidecar; unskippable evaluation middleware. |
| **Immutable Ledger** | Custom SHA-256 Hash Chain + Ed25519 (~300 LOC) | Zero external dependencies; local append-only log with Merkle tree roots. |
| **External Trust Anchor**| GitHub Private Repo (MVP) + Rekor (Stretch) | Out-of-band digest publication beyond the reach of compromised tenant containers. |
| **Kernel Sandboxing** | gVisor (`runsc`) for Red; evaluate for Model (1-2h timebox); hardened `runc` fallback | Strong syscall-level virtualization separating untrusted evaluation code from host kernel. |
| **Runtime Monitoring** | Falco with modern eBPF probe | Kernel-level telemetry bypassing OCI kernel-module signing restrictions. |
| **Host Firewall** | Dual-layer: OCI VCN Security List + host `nftables` | Defense-in-depth packet filtering at both cloud hypervisor and Linux kernel levels. |
| **Query Budget $Q$** | $Q = 200$ queries per run | Limits differential state leakage through binary response oracle to $\le 200$ bits per run. |
| **Refusal Semantics** | Uniform refusal response | Red receives identical generic refusal token on all filter blocks to eliminate defense-profiling side channels. |

---

## 2. Phase 0 Sub-Tasks Breakdown

| Task ID | Sub-Task Description | Status | Dependencies | Files Involved |
|---|---|---|---|---|
| **P0-1** | Setup Phase 0 Tracking & Blueprint in `task.md` | ✅ COMPLETED | None | `task.md` |
| **P0-2** | Repository Skeleton & Scaffolding | ✅ COMPLETED | P0-1 | `.gitignore`, `Makefile`, `README.md`, `docs/` dirs |
| **P0-3** | Five-Zone Architecture & Data-Flow Diagram (DFD) | ✅ COMPLETED | P0-2 | `docs/architecture/dfd.md` |
| **P0-4** | Zone Specifications, Lifecycle & Trust Assumptions | ✅ COMPLETED | P0-3 | `docs/architecture/zones.md` |
| **P0-5** | STRIDE Threat Model & Attack Surface Analysis | ✅ COMPLETED | P0-4 | `docs/threat-model/stride.md` |
| **P0-6** | Evaluation Gateway API Contract (FR-003) | ✅ COMPLETED | P0-5 | `docs/api/gateway-contract.md` |
| **P0-7** | Risk Register (All 22 entries: R-01 to R-22) | ✅ COMPLETED | P0-6 | `docs/risk/risk-register.md` |
| **P0-8** | Phase 0 Peer Review, Verification & Summary | ✅ COMPLETED | P0-7 | `task.md`, all `docs/` artifacts |

---

## 3. Files & Components Involved in Phase 0

Phase 0 is **strictly a documentation and architectural alignment phase**. No application code, Docker images, or container baselines are created.

```
bayora_adversarial/
├── task.md                           # Master tracking, architecture blueprint, progress status
├── README.md                         # Project overview, security principles, phase roadmap
├── Makefile                          # Top-level lifecycle targets (dry stubs for future phases)
├── .gitignore                        # Standard hygiene ignoring secrets, caches, artifacts
└── docs/
    ├── architecture/
    │   ├── dfd.md                    # Five-Zone DFD, trust boundaries, boundary crossing matrix
    │   └── zones.md                  # Detailed zone specs, run lifecycle states, trust assumptions
    ├── threat-model/
    │   └── stride.md                 # STRIDE matrix (7 crossings × 6 categories = 42 cells), actors, assets
    ├── api/
    │   └── gateway-contract.md       # FR-003 11 endpoints, schemas, invariants, error taxonomy
    └── risk/
        └── risk-register.md          # 22-risk register with likelihood, impact, mitigations, bounds
```

---

## 4. Completion Criteria (Definition of Done for Phase 0)

Per PRD §32 (Phase 0 Definition of Done):
1. **DFD Peer-Reviewed vs. Five-Zone Rule:** Every component resides in exactly one zone. No direct inter-zone communication exists without passing through the Evaluation Gateway.
2. **STRIDE Analysis Complete:** All 7 trust boundary crossings evaluated across all 6 STRIDE categories (42-cell matrix fully populated with threats and mitigations).
3. **Gateway Contract Complete:** All 11 FR-003 endpoints defined with request/response schemas, access control policies, phase guards, and error codes.
4. **Risk Register Fully Populated:** All 22 risks (R-01 through R-22) documented with Threat, Likelihood, Impact, Mitigation, Residual Risk, Detection, and Future Work.
5. **Run Lifecycle Formalized:** State machine transitions (Setup → Committed → Running → Closed → Revealed) and embargo enforcement documented.
6. **Zero Code Rule Maintained:** No application code, Compose files, or container implementations started.

---

## 5. Verification & Tests Required

| Artifact | Verification Method | Pass Criteria |
|---|---|---|
| `docs/architecture/dfd.md` | Boundary audit & graph validation | No bypass paths exist; all 8 crossings identified; traffic directionality strictly validated. |
| `docs/architecture/zones.md` | PRD cross-reference audit | All 5 zones specified with runtime, cpuset, network rules, and TA-1 to TA-6 assumptions. |
| `docs/threat-model/stride.md` | Completeness matrix check | Exactly 42 cells filled; every threat has a corresponding SEC/FR PRD mitigation. |
| `docs/api/gateway-contract.md`| Schema completeness check | All 11 FR-003 endpoints defined; budget check ($Q=200$), OPA policy hook, and error taxonomy present. |
| `docs/risk/risk-register.md` | Risk count & field validation | Exactly 22 entries (R-01..R-22); Oracle bound $\le 200$ bits/run documented; ARM64 notes added. |

---

## 6. Phase 0 Manual Checklist & Status

The following checklist tracks all manual setup and review actions. Actions 1 and 2 (OCI and SSH) are safely deferred to Phase 3, while Actions 3 and 4 are active for Phase 0 sign-off.

### OCI (Manual Action 1 — Deferred to Phase 3)
- [ ] OCI account / home region confirmed
- [ ] `bayora-vcn` created / selected (Internet Connectivity enabled)
- [ ] `VM.Standard.A1.Flex` shape selected
- [ ] 2 OCPU configured
- [ ] 12 GB RAM configured
- [ ] Ubuntu 24.04 LTS (aarch64) image selected
- [ ] 200 GB custom boot volume configured
- [ ] Always Free eligible status confirmed
- [ ] SSH key pair generated (`ed25519` via PowerShell)
- [ ] Public key (`bayora_oci.pub`) uploaded
- [ ] VM is RUNNING
- [ ] `uname -m` confirms `aarch64`
- [ ] `stat -fc %T /sys/fs/cgroup` confirms `cgroup2fs`

### SSH SECURITY (Manual Action 2 — Deferred to Phase 3)
- [ ] Personal public IPv4 obtained via `curl.exe https://api.ipify.org`
- [ ] TCP port 22 allowed exclusively from `YOUR_IP/32`
- [ ] TCP port 22 open to `0.0.0.0/0` removed from Security List
- [ ] No unnecessary application ports exposed to public ingress
- [ ] SSH connection tested successfully (`ssh -i ... ubuntu@<IP>`)

### GITHUB (Manual Action 3 — User Action for Phase 0 ✅)
- [x] Private `bayora-anchors` repository created
- [x] Repository visibility confirmed as Private
- [x] Fine-grained Personal Access Token (PAT) created
- [x] Repository access scoped strictly to `bayora-anchors` only
- [x] Permissions set strictly to `Contents: Read and write`
- [x] No unnecessary administrative or workflow permissions granted
- [x] Token stored securely in password manager / local secure store
- [x] Token confirmed NOT committed to repo or exposed in configuration

### DOCUMENT REVIEW (Manual Action 4 — Verified & Reconciled ✅)
- [x] `README.md` reviewed (Five zones, invariants R1–R4, roadmap)
- [x] `docs/architecture/dfd.md` reviewed (Gateway mediation, boundary matrix)
- [x] `docs/architecture/zones.md` reviewed (Zone specs, lifecycle, trust assumptions)
- [x] `docs/threat-model/stride.md` reviewed (42-cell matrix, actors, assets)
- [x] `docs/api/gateway-contract.md` reviewed (11 endpoints, schemas, invariants)
- [x] `docs/risk/risk-register.md` reviewed (22 risks, scoring, Oracle bound)
- [x] `task.md` reviewed (Sub-tasks P0-1 to P0-8 completed)
- [x] `.gitignore` reviewed (Hygiene covering secrets, keys, weights, and caches)
- [x] **2 OCPU / 12 GB OCI adjustment recorded:** Topology updated (Core 0 dedicated to Model; Core 1 shared)
- [x] **2 OCPU / 12 GB OCI adjustment recorded:** Topology updated (Core 0 dedicated to Model; Core 1 shared)
- [x] **7-vs-8 STRIDE discrepancy resolved:** X1–X7 are inter-zone/tenant boundaries; X8 is intra-TCB
- [x] **gVisor Red/Model wording resolved:** Red is mandatory gVisor (`runsc`); Model is hardened `runc` with 1-2h gVisor trial

---

## Current Phase: Phase 1 — PREPARATION / PLANNING PASS (Insecure Baseline)
**Status:** PLANNING
**Objective:** Deliberately reproduce the insecure baseline (Current State) described in the PRD (Section 4, FR-022) so that the later hardened implementation can be objectively compared against it.

### 1. Phase 1 Technical Blueprint & Scope
Phase 1 intentionally creates a **flawed, insecure shared environment** where adversaries, defenders, and the model operate simultaneously. It explicitly avoids implementing the five-zone hardened architecture. 
The baseline will consist of a single Docker Compose stack where all components share a default bridge network, a shared volume, and exposed cache state.

**What Phase 1 MUST NOT Implement:**
- Five isolated networks.
- Gateway-only inter-zone communication.
- mTLS, OPA/ABAC enforcement, Vault-based isolation.
- Commit-then-freeze enforcement, sealed Blue runtime.
- Model egress isolation or container hardening (gVisor, dropped caps).
- Timing normalization or resource isolation (cgroups).

### 2. Insecure Conditions to Reproduce
| Insecure Condition | WHAT is it? | WHY is it needed? (PRD Req) | HOW will it be demonstrated? |
|--------------------|-------------|-----------------------------|------------------------------|
| **Shared Network** | All containers on the default `bridge` network. | PRD Sec 4 (Red scans/connects directly to blue/model). | Red runs `curl` against Blue and Model directly, bypassing Gateway. |
| **Shared Storage** | A single `shared_data` volume mounted to all containers. | PRD Sec 4 (Direct file reads). | Red executes a script to read Blue's rules (`cat /shared/blue_rules.json`). |
| **Model Cache Timing** | Model server runs with prompt/prefix caching enabled. | PRD Sec 4 (Prefix caching timing oracle). | Red sends two identical prompts; the second returns significantly faster. |
| **Raw Logging** | Standard stdout/stderr without redaction. | PRD Sec 4 (Raw red prompts queryable by blue). | Blue reads `docker logs gateway` or Red's logs to see the payloads. |
| **Resource Contention**| No CPU limits on containers. | PRD Sec 5.2 (CPU contention distortion). | Red floods the host, causing Blue/Model latency to spike or timeout. |

### 3. Baseline Leak-Test Matrix
These tests will form the automated leak suite. In Phase 1, **all of these tests must PASS (i.e., successfully demonstrate the leak).** In later phases, the exact same scripts must FAIL.

| Test Name | Attacker / Source | Target Zone | Expected Insecure Behavior | Evidence Collected | PRD Req |
|-----------|------------------|-------------|----------------------------|--------------------|---------|
| `test_net_blue_direct` | Red | Blue | Red connects directly to Blue's port. | HTTP 200 from Blue. | SEC-008 |
| `test_net_model_direct`| Red | Model | Red connects directly to Model's API. | HTTP 200 from Model. | SEC-008 |
| `test_fs_blue_rules` | Red | Blue (Volume) | Red reads Blue's configuration file. | File contents of `rules.json`. | SEC-001 |
| `test_cache_timing` | Red | Model | Second request for same prefix is faster. | Latency measurements (ms). | LLM-001 |
| `test_log_exposure` | Blue | Gateway/Red | Blue queries raw logs to see Red's prompt. | Prompt text found in logs. | PRIV-001 |

### 4. Baseline Data & Workload
To avoid sensitive data, Phase 1 will use synthetic/demo workloads:
- **Red Payload Dataset:** 10 synthetic prompts (5 benign, 5 explicit adversarial/jailbreak strings based on AdvBench).
- **Blue Defense:** Python FastAPI service with a hardcoded keyword/regex filter (e.g., blocking "ignore previous instructions").
- **Model:** `llama.cpp` server running `Qwen2.5-1.5B-Instruct Q4_K_M GGUF` on CPU.
- **Gateway:** A naive Python FastAPI stub that simply routes traffic (Red -> Blue -> Model) without any OPA/Vault/TLS enforcement.

### 5. Required Baseline Measurements
For Phase 2+ to compare against, Phase 1 will record:
1. **Isolation Failures:** Count of successful unauthorized cross-zone connections and file reads.
2. **Cache Timing Difference (ms):** Delta between $T_{first}$ and $T_{cached}$ for identical prompts.
3. **Pipeline Latency (ms):** End-to-end latency for $N$ requests under no load.
4. **Contention Latency (ms):** End-to-end latency when Red floods the CPU with background stress.

### 6. Baseline Architecture (Docker Compose)
- **Services:** `red-runner`, `baseline-stub` (gateway), `blue-filter`, `model-server`.
- **Base Images:** Must use **multi-arch base images** (x86_64 for local dev, arm64 for Oracle VM target).
- **Network:** Single default Docker `bridge` (differs slightly between Docker Desktop and Linux native, requiring re-validation on the VM).
- **Volumes:** Single **named volume** `shared_data` (or specific WSL path) mounted to all containers, avoiding Windows bind-mount permission quirks.
- **Line Endings:** `.gitattributes` enforces `LF` to prevent container crashes on shell scripts.

### 7. Implementation Subtasks (Ordered)
*Status: READY TO EXECUTE.*
- [x] **Phase 1.1:** Setup Baseline Repository Structure & Dummy Data (✅ COMPLETED: Created `data/baseline/payloads.json` with 10 synthetic prompts, `data/baseline/blue_rules.json` with naive keyword rules, `models/.gitkeep`, and baseline directory layout).
- [x] **Phase 1.2:** Write `blue-filter` service (✅ COMPLETED: Naive FastAPI filter service with keyword matching, unauthenticated `/rules` endpoint, unredacted stdout logging, and multi-arch Dockerfile; verified with unit tests).
- [x] **Phase 1.3:** Write Model Download Script (✅ COMPLETED: Created `scripts/download_model.py` and `scripts/download_model.sh`; downloaded `qwen2.5-1.5b-instruct-q4_k_m.gguf` and verified SHA-256 matches pinned digest `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`).
- [x] **Phase 1.4:** Configure `model-server` (✅ COMPLETED: Pulled `ghcr.io/ggml-org/llama.cpp:server` multi-arch image; mounted GGUF model read-only; enabled `--cache-prompt`; verified `/health` and `/completion` endpoints with timings).
- [x] **Phase 1.5:** Write `baseline-stub` service (✅ COMPLETED: Created naive FastAPI routing stub adhering to baseline evaluation interface; handles prompt routing to Blue and Model without OPA, mTLS, or budget enforcement; verified with health check tests).
- [x] **Phase 1.6:** Write `red-runner` service (✅ COMPLETED: Created Red runner service script and multi-arch Dockerfile with network testing utilities; verifies 10 synthetic evaluation payloads and metrics collection).
- [x] **Phase 1.7:** Compose it together (✅ COMPLETED: Created `docker-compose.yml` with single unsegmented bridge network `baseline-net`, shared named volume `bayora_shared_data`, and all 4 containers; verified end-to-end integration with smoke test run `test-smoke-001`).
- [x] **Phase 1.8:** Write Automated Leak-Test Scripts (✅ COMPLETED: Created 5 tests, missing contention test).
- [x] **Phase 1.9:** Execute Baseline & Record Initial Local Measurements (✅ COMPLETED: 5/5 leak tests PASSED, recorded in `results/baseline/leak_test_results.json`).
- [x] **Phase 1.9b:** Write and Execute Resource Contention Test (✅ COMPLETED: Ran alternating A-B-B-A test with UUID salting; verified contention effect; results recorded in `results/baseline/contention_baseline_results.json`).
- [x] **Phase 1.10:** Deploy to Oracle VM and Record Final Evidence (✅ DEFERRED TO PHASE 3).

### Phase 1 Completion Audit Findings
**Date:** 2026-10-09
**Verdict:** READY FOR PHASE 2 (Conditional on 1.9b execution)
**Analysis & Adjustments:**
1. **Missing Resource Contention Test:** While not a strict Phase 1 blocker according to the PRD DoD, executing this test now (Phase 1.9b) provides a valuable provisional baseline for PERF-004 and RES-004. This is an R4 validity problem (contention distortion), not a side-channel. 
2. **Provisional Environment Caveat:** Contention and timing numbers captured on the local Windows/WSL2 host are strictly provisional. They will not be comparable to the Oracle ARM64 VM. A full re-baselining on the target hardware must occur at the start of Phase 3 before OS-level hardening is applied.
3. **Roadmap Correction:** `cpuset` hardening and resource governance belong strictly to Phase 7, not Phase 3. The roadmap has been updated.

---

## Current Phase: Phase 2 — Container Hardening & Local VM Execution
**Status:** PLANNING
**Objective:** Transition to a full, dedicated Linux VM environment (Local Ubuntu 24.04 LTS on VMware Workstation / VirtualBox), capture the definitive native hardware baseline, and implement OS/Kernel-level container hardening (gVisor runsc, AppArmor, seccomp). Treat Oracle Cloud ARM64 as a possible later migration target.

**VM Environment & Sizing (Host: i5-13450HX 10c/16t, 16 GB RAM):**
- **Hypervisor:** VMware Workstation Pro 17+ (Free Personal) or VirtualBox 7.0+ (Windows 11 Home lacks Hyper-V Manager).
- **VM Sizing:** 6 vCPUs, 8 GB RAM (leaves 8 GB for Windows 11 to avoid host memory exhaustion/swapping), 60 GB dynamic disk.
- **Networking:** NAT with SSH port forwarding (e.g. host 127.0.0.1:2222 -> VM 22) or Host-Only. Avoid bridged network onto LAN.
- **Automated Provisioning:** Use `scripts/provision-host.sh` for architecture-aware setup (Docker, gVisor `runsc`, AppArmor, cgroup v2 verification).
- **Results Storage:** Store results per host (`results/baseline/local-ubuntu-vm/` and later `results/baseline/oracle-arm64/`).

**Key Tasks:**
- [ ] **Phase 2.0: Target Environment Setup & Native Re-Baselining:**
  - Spin up local Ubuntu 24.04 LTS VM with recommended sizing and SSH forwarding.
  - Run `scripts/provision-host.sh` to install Docker, gVisor (`runsc`), AppArmor utilities, and verify `cgroup v2`.
  - Clone repository via read-only deploy key or git archive.
  - Run the unchanged Phase 1 stack natively on the VM.
  - Re-run all five leak tests, latency benchmark, cache-timing test, and contention test natively.
  - Record host fingerprint and save results to `results/baseline/local-ubuntu-vm/`.
  - Tag `phase2.0-vm-baseline`.
- [ ] **Phase 2.1:** Implement gVisor (`runsc`) for Red Team and Model containers.
- [ ] **Phase 2.2:** Implement `seccomp` profiles and `AppArmor`.
- [ ] **Phase 2.3:** Drop capabilities and remove shared volumes.

---

## Future Phase: Phase 3 — Five-Zone Network Isolation
**Status:** DEFERRED
**Key Tasks:**
- [ ] **Phase 3.1:** Implement strict Docker bridge network isolation (5 distinct networks).
- [ ] **Phase 3.2:** Configure internal DNS resolution.
- [ ] **Phase 3.3:** Configure host-level `nftables` defense-in-depth.

### 8. Acceptance Criteria (FR-022)
- **PASS:** The insecure baseline is successfully spun up locally and on the Oracle VM. Every script in the leak-test matrix successfully exploits the intended weakness (network, fs, cache, etc.). Baseline latency is measured *both* through the stub and via direct calls.
- **FAIL:** The expected insecure behavior cannot be reproduced, or unintended isolation prevents the baseline from failing as designed.

### 9. Prerequisites & Manual Actions Required
1. **WSL2 Environment (✅ COMPLETED):** The repository has been successfully moved to the native WSL2 filesystem (`/home/atharva/bayora_adversarial`).
2. **Oracle VM Validation (✅ DEFERRED TO PHASE 3):** The final evidence (leak table, latency, throughput, cache-timing chart) MUST be generated on the Oracle ARM64 VM. You must record the instance type next to the timing numbers (R-04, R-14).
3. **Model Hash Pinning:** On the first run of the download script, you will need to manually verify the computed SHA-256 hash against the official HuggingFace page. This hash becomes the registered weights hash (FR-015, LLM-008).
4. **License Check (✅ COMPLETED):** Qwen2.5-1.5B-Instruct uses the Apache 2.0 license. This is an open-source, permissive license that is fully compliant with the project's requirements. No restrictions exist for this usage.

