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
**Status:** COMPLETED ✅
**Objective:** Transition to a full, dedicated Linux VM environment (Local Ubuntu 24.04 LTS on VMware Workstation / VirtualBox), capture the definitive native hardware baseline, and implement OS/Kernel-level container hardening (gVisor runsc, AppArmor, seccomp). Treat Oracle Cloud ARM64 as a possible later migration target.

**VM Environment & Sizing (Host: i5-13450HX 10c/16t, 16 GB RAM):**
- **Hypervisor:** VMware Workstation Pro 17+ (Free Personal) or VirtualBox 7.0+ (Windows 11 Home lacks Hyper-V Manager).
- **VM Sizing:** 6 vCPUs, 8 GB RAM (leaves 8 GB for Windows 11 to avoid host memory exhaustion/swapping), 60 GB dynamic disk.
- **Limitation Note:** Windows dynamically schedules VM threads across P-cores (with hyperthreading) and E-cores. vCPUs are not pinned to physical P-cores, meaning timing results (especially contention) will have noise/variance and are considered provisional.
- **Networking:** NAT with SSH port forwarding (e.g. host 127.0.0.1:2222 -> VM 22) or Host-Only. Avoid bridged network onto LAN.
- **Automated Provisioning:** Use `scripts/provision-host.sh` for architecture-aware setup (Docker, gVisor `runsc`, AppArmor, cgroup v2 verification).
- **Results Storage:** Store results per host (`results/baseline/local-ubuntu-vm/` and later `results/baseline/oracle-arm64/`).

**Key Tasks:**
- [x] **Phase 2.0: Target Environment Setup & Native Re-Baselining:**
  - [x] Spin up local Ubuntu 24.04 LTS VM with recommended sizing and SSH forwarding.
  - [x] Run `scripts/provision-host.sh` to install Docker, gVisor (`runsc`), AppArmor utilities, and verify `cgroup v2`.
  - [x] Clone repository via read-only deploy key.
  - [x] Verify no ports are published beyond localhost (`ss -tlnp` and `docker ps`).
  - [x] Run the unchanged Phase 1 stack natively on the VM (`bayora-model-server`, `bayora-blue-filter`, `bayora-baseline-stub`, `bayora-red-runner`).
  - [x] Re-run evaluation pipeline (`vm-baseline-run-001`), all five leak tests (5/5 PASSED), and prefix cache-timing test.
  - [ ] Contention benchmark (PARTIAL / INTERRUPTED — WAIVED): Evaluated under unconstrained Phase 1 baseline conditions on the VirtualBox Ubuntu 24.04 VM (distinguished from the earlier WSL2 reference measurement of p50=3,237.08 ms). Both 6-core and 4-core stressors induced severe host contention, client timeouts, and kernel watchdog soft-lockup alarms under unthrottled CFS scheduling. Safely halted via cleanup guard; all stressor processes terminated. Server-side timestamped gateway logs verify that during Loaded Round 1, 15 queries were received, yielding 10 HTTP 200 responses and 5 HTTP 502 responses. The client log recorded 4 explicit timeout messages, but individual client outcomes cannot reliably be mapped to gateway requests from the available client-side evidence. One additional query was received at the gateway belonging to the interrupted Round 2, and the full 60-request A-B-B-A benchmark remains incomplete. A post-contention unloaded recovery check completed 10/10 requests with a median latency of 7,790.57 ms, compared to the initial unloaded baseline median of 5,577.94 ms (approximately 39.7% higher). Both unloaded runs used matching inference settings (prompt, salting, 64-token limit, temperature=0.7), and server logs confirmed zero residual inference work prior to the recovery check. Host-level thread scheduling across hybrid P/E-cores and thermal/power throttling are plausible explanations, but their exact cause was not independently verified. These figures represent two observations on an unpinned VM host rather than formal bounds.
  - [x] Record host fingerprint (including manual Windows tuning notes) and save all 18 baseline evidence files to `results/baseline/local-ubuntu-vm/`.
  - [x] Tag `phase2.0-vm-baseline` (authorized and tagged).
  - [x] Take Snapshot #3: Post-Baseline, Pre-Hardening (UUID: `d6048cf6-9209-4781-a457-094bdc0a596a` verified active on VirtualBox host).


### Phase 2.0 Baseline Audit Findings & Contention Notes
**Date:** 2026-10-24
**Environment:** Local Ubuntu 24.04 LTS on Oracle VirtualBox 7.2.20 (6 vCPUs, 8 GB RAM, unpinned host threads on Intel Core i5-13450HX)
**Status / Sign-off Readiness:** Phase 2.0 complete with waiver

1. **Distinction from WSL2 Reference Measurements:**
   - Earlier Phase 1 reference measurements on Windows/WSL2 recorded an unloaded median latency of $p50 = 3,237.08\text{ ms}$ across 16 host execution threads.
   - On the dedicated 6-vCPU VirtualBox Ubuntu 24.04 VM, the initial unloaded baseline (Round 1, $N=15$) measured a median latency of $p50 = 5,577.94\text{ ms}$. These environments are distinct and not directly comparable.

2. **Loaded Contention Benchmark Reconciliation (Step 15 — Partial / Interrupted):**
   - **Experimental Setup:** Both 6-core and 4-core stressor attempts induced severe host starvation, client timeouts, and Linux kernel watchdog soft-lockup alarms under unconstrained CFS scheduling. The benchmark was halted safely via the cleanup guard; all stressor processes terminated.
   - **Gateway Verification:** Server-side timestamped gateway logs verify that during Loaded Round 1, 15 queries were received, yielding:
     - **10 HTTP 200 responses** (latencies ranging from 7.5s to 442.4s).
     - **5 HTTP 502 responses** (upstream gateway timeouts to Blue filter / Model server).
   - **Client-Side Evidence:** The client log recorded 4 explicit timeout messages (`TimeoutError('timed out')` at 45.0s threshold). However, individual client outcomes cannot reliably be mapped to gateway requests from the available client-side evidence.
   - **Claims Strictly Excluded:** Unsupported claims that 8 requests definitely completed within the client's 45-second timeout or that two specific client-timed-out requests later completed on the server are removed and not asserted.
   - **Benchmark Incompleteness:** Exactly one additional query (`[Salt: d4543642...]`) was received at the gateway belonging to the interrupted Round 2. The full 60-request A-B-B-A benchmark remains incomplete.

3. **Post-Contention Unloaded Recovery Check:**
   - Following termination of all stressor processes and system stabilization, a dedicated post-contention recovery check (`test_unloaded_recovery.py`) completed 10/10 requests ($N=10$) with a median latency of $p50 = 7,790.57\text{ ms}$ (max: $8,862.45\text{ ms}$).
   - Compared to the initial unloaded baseline median ($5,577.94\text{ ms}$), recovery latency was approximately 39.7% higher.
   - Both unloaded runs used matching inference settings (identical base prompt, UUID salting, 64-token limit, temperature=0.7), and server logs confirmed zero residual inference work prior to the recovery check (>4 minutes idle).
   - Host-level thread scheduling across heterogeneous P/E-cores on Windows 11 and thermal/power throttling are plausible explanations, but their exact cause was not independently verified. These figures represent two discrete observations on an unpinned VM host rather than formal upper/lower bounds.

4. **Phase 2.0 Definition of Done Assessment & Waiver:**
   - Under a strict literal reading of `docs/roadmap.md` DoD criterion #4 ("contention test run successfully"), the partial run blocks unconditional sign-off because the 60-request scripted benchmark was halted before completion.
   - However, the empirical objective of PRD Sec 5.2 / RES-004 / PERF-004 (demonstrating that unconstrained CPU flood causes severe latency degradation and upstream timeouts) was conclusively demonstrated and documented.
   - **Waiver — accepted by Akshaya on 2026-10-24:** The partial/interrupted contention run is accepted as baseline failure-mode evidence for Phase 2.0. A bounded contention rerun is deferred to the start of Phase 7 (using ≤2 stressor processes or quota/nice limits, leaving at least 2 vCPUs free for the guest and inference), using the preserved pre-hardening VM snapshot, subject to the Phase 7 test plan.
   - Sign-off status: **Phase 2.0 complete with waiver**.

5. **Host Fingerprint Evidence Provenance:**
   - `power_mode, plugged_in, heavy_applications are operator-reported, not telemetry.` All 18 raw evidence artifacts in `results/baseline/local-ubuntu-vm/` remain preserved and unmodified.
- [x] **Phase 2.1:** Implement gVisor (`runsc`) for Red Team and Model containers.
  - [x] Verify gVisor (`runsc`) registration and availability in Docker Engine.
  - [x] Measure bounded baseline inference reference under native `runc` ($N=10$).
  - [x] Hardened `bayora-red-runner` using `runtime: runsc` with verified sandbox kernel isolation (`dmesg` confirms `Starting gVisor...`).
  - [x] Configured container hostname routing for Red container via `extra_hosts` in Docker Compose (with documented IPAM order-dependency limitation).
  - [x] Evaluated `bayora-model-server` under gVisor (`runsc`); recorded empirical evidence of 9.26x latency regression ($0.99\text{ tok/s}$).
  - [x] Empirically justified decision to retain `bayora-model-server` on `runc` while keeping Red on `runsc`.
  - [x] Measured bounded post-change performance ($N=10$, $p50 = 4,859.72\text{ ms}$, $14.98\text{ tok/s}$).
  - [x] Verified all 4 services `Up` and healthy; executed full 5-test leak suite inside Red gVisor sandbox.
  - [x] Stored all 10 evidence artifacts separately in `results/hardening/phase2.1-gvisor/local-ubuntu-vm/`.
- [x] **Phase 2.2:** Implement custom `seccomp` profiles and `AppArmor` policies.
- [x] **Phase 2.3:** Drop capabilities (`cap_drop: ALL`) and remove shared storage (`shared_data`).

### Phase 2.1 Container Hardening (gVisor) Audit Findings & Evidence Summary
**Date:** 2026-10-24
**Environment:** Local Ubuntu 24.04 LTS on VirtualBox (6 vCPUs, 8 GB RAM, kernel 6.8.0-146-generic)
**Status / Sign-off Readiness:** Pre-Commit Audit Verified (Pending Owner Sign-Off)

#### 1. Runtime Inventory & Isolation Verification
- **gVisor Binary & Specification:** `runsc version release-20261012.0`, `spec: 1.2.1` installed at `/usr/local/bin/runsc`.
- **Docker Daemon Registration:** `/etc/docker/daemon.json` registers `runsc` as an available OCI runtime; default runtime remains `runc`.
- **Effective Runtime per Service:**
  | Service Name | Container Name | Assigned Runtime | Effective Sandbox Status | Host Process Validation |
  |:---|:---|:---:|:---:|:---|
  | `red-runner` | `bayora-red-runner` | `runsc` | **Full gVisor Sentry Sandbox** | Verified `runsc-sandbox`, `runsc-gofer`, `runsc-fd-parking`; `dmesg` confirms `Starting gVisor...` |
  | `model-server` | `bayora-model-server` | `runc` | Standard Container (Native) | Reverted from `runsc` following empirical performance evaluation |
  | `blue-filter` | `bayora-blue-filter` | `runc` | Standard Container (Native) | Unchanged Phase 2.0 baseline state |
  | `baseline-stub` | `bayora-baseline-stub` | `runc` | Standard Container (Native) | Unchanged Phase 2.0 baseline state |

#### 2. Model Container gVisor Evaluation & Runtime Decision Rationale
- **Compatibility:** `llama.cpp:server` loaded the pinned GGUF weights (`6a1a2eb6...`) successfully under `runsc`, initialized threadpools, and passed container health checks (`/health` returned `{"status":"ok"}`).
- **Inference Latency & Throughput Comparison:**
  | Metric | Reference Baseline (`runc`) | gVisor Trial (`runsc`) | Final Hardened (`runc` Model / `runsc` Red) | Impact (Trial vs Reference) |
  |:---|:---:|:---:|:---:|:---:|
  | Requests Evaluated | 10 | 5 | 10 | Bounded, salted sequential requests |
  | Success / Timeout | 10/10 (0 timeouts) | 5/5 (0 timeouts at 120s) | 10/10 (0 timeouts) | Zero errors across all runs |
  | **Latency $p50$** | **$7,148.65\text{ ms}$** | **$66,213.42\text{ ms}$** | **$4,859.72\text{ ms}$** | **$+826.2\%$ (+9.26x slowdown)** |
  | Latency $p95$ | $9,371.66\text{ ms}$ | $75,769.48\text{ ms}$ | $7,347.51\text{ ms}$ | $+708.5\%$ |
  | **Generation Speed $p50$** | **$9.86\text{ tok/s}$** | **$0.99\text{ tok/s}$** | **$14.98\text{ tok/s}$** | **$-90.0\%$ throughput collapse** |
  | Token Latency $p50$ | $101.38\text{ ms/tok}$ | $1,007.79\text{ ms/tok}$ | $66.77\text{ ms/tok}$ | $+894.1\%$ |
  | Total Wall Duration | $76.41\text{ s}$ (10 reqs) | $314.14\text{ s}$ (5 reqs) | $49.10\text{ s}$ (10 reqs) | Exceeds acceptable evaluation budget |
- **Decision:** As specified in PRD Sec 5.2 and task guidelines, `model-server` is retained on `runc`. The observed slowdown (~66 seconds per 64-token completion) is prohibitive for interactive evaluation. Retaining `runc` for Model while isolating Red under `runsc` satisfies project performance and security objectives. Full empirical traces are preserved in `benchmark_gvisor_trial.json`.
- **Note on Root Cause:** Systrap virtualization overhead (frequent page-fault handling on mmap'd weights, futex serialization, guest-host context switches) is a plausible architectural hypothesis consistent with known gVisor CPU-bound workload behavior, but remains unconfirmed as low-level kernel profiling (`perf` or `runsc debug profile`) was not captured.
- **Benchmark Limitations:** Measurements are bounded sequential samples ($N=5$ for trial, $N=10$ for baseline/final) subject to host VirtualBox scheduling and unpinned CPU core variability.

#### 3. Red Workload & Leak-Test Suite Verification (inside gVisor)
All 5 automated baseline leak tests were executed with `bayora-red-runner` executing inside the active `runsc` sandbox:
| Test Script | Vulnerability ID | Execution Status | Security Outcome | Security Boundary Analysis |
|:---|:---|:---:|:---:|:---|
| `test_net_blue_direct.py` | SEC-008 | Clean (exit 0) | `still_reproducible` (PASS) | Flat bridge network intact; network segmentation scheduled for Phase 3. |
| `test_net_model_direct.py` | SEC-008 | Clean (exit 0) | `still_reproducible` (PASS) | Direct HTTP connection to model server succeeds across bridge; Phase 3 isolates zones. |
| `test_fs_blue_rules.py` | SEC-001 | Clean (exit 0) | `still_reproducible` (PASS) | Shared named volume `/shared_data` intact; volume removal scheduled for Phase 2.3. |
| `test_cache_timing.py` | LLM-001 | Clean (exit 0) | `still_reproducible` (PASS) | Prefix cache timing delta ($3,467.90\text{ ms}$) detected; cache hardening scheduled for Phase 6. |
| `test_log_exposure.py` | PRIV-001 | Clean (exit 0) | `still_reproducible` (PASS) | Unredacted prompts in stdout logs; audit ledger scheduled for Phase 5. |

*Semantic Clarification:* In this test harness, `raw_status: PASS` means the baseline vulnerability was successfully executed and reproduced (leak demonstrated), confirming that gVisor syscall isolation alone does NOT mitigate direct network access or shared-volume leakage. The execution status (clean exit code 0 under gVisor Sentry) confirms application and test compatibility.

#### 4. Evidence Artifacts Provenance (Phase 2.1)
All 10 newly generated evidence artifacts are stored separately from the immutable Phase 2.0 baseline under:
`results/hardening/phase2.1-gvisor/local-ubuntu-vm/`
1. `benchmark_reference_runc.json` — Pre-change reference benchmark on native `runc` ($N=10$).
2. `benchmark_gvisor_trial.json` — Empirical model evaluation under `runsc` ($N=5$) documenting the 9.26x slowdown.
3. `benchmark_final_hardened.json` — Post-change benchmark under final runtime configuration ($N=10$).
4. `leak_test_results.json` — Master leak test suite executed with Red sandboxed in gVisor.
5. `container_inspect.json` — Full Docker inspect metadata for all 4 services.
6. `docker_runtimes.json` — Docker daemon registered runtime configuration.
7. `docker_compose_ps.txt` — Running service inventory and port bindings.
8. `host_runsc_processes.txt` — Active `runsc-sandbox` and `runsc-gofer` host process table.
9. `red_runner_dmesg_gvisor.txt` — In-container `dmesg` buffer confirming gVisor kernel initialization.
10. `runsc_version.txt` — Verified installed gVisor binary version and OCI specification version.

#### 5. Rollback Procedure
If runtime regression or failure occurs:
1. Revert `docker-compose.yml`: remove `runtime: runsc` and `extra_hosts` from `red-runner`.
2. Execute `docker compose up -d red-runner` to restart Red on standard `runc`.
3. Verify via `docker inspect -f '{{.HostConfig.Runtime}}' bayora-red-runner` (returns empty / default `runc`).

#### 6. Residual Risks & Next Steps (Phase 2.2)
- **What Phase 2.1 Protects:** Strong syscall-level virtualization isolating untrusted Red Team evaluation code from the host Linux kernel, mitigating host kernel privilege escalation and escape vulnerabilities (STRIDE: Elevation of Privilege).
- **Residual Attack Surface:** Red can still issue all non-blocked Linux syscalls supported by gVisor, execute unconstrained file operations inside its container, traverse flat bridge networks, and read shared volumes.
- **Immediate Next Step (Phase 2.2):** Implement custom `seccomp` profiles and restrictive `AppArmor` policies to constrain syscalls and filesystem access for remaining services (COMPLETED ✅).

#### 7. Audit Limitations & Accepted Technical Debt
- **Hardcoded `extra_hosts` Mappings:** The mappings `model-server: 172.18.0.3`, `blue-filter: 172.18.0.2`, and `baseline-stub: 172.18.0.4` match running container IPs. However, Docker bridge IP assignment is sequential and depends on container startup order. Recreating containers out of order can cause IP reassignment, breaking Red's routing. This is accepted as an interim limitation, to be architecturally superseded in Phase 3 by dedicated subnets with explicit IPAM and DNS proxying.
- **Port Exposure (`0.0.0.0` vs Localhost-only):** Services in `docker-compose.yml` publish ports on `0.0.0.0:8000`, `0.0.0.0:8001`, and `0.0.0.0:8080`. This is a pre-existing configuration from Phase 1. Within the guest VM, the localhost-only requirement is UNMET. However, external host/LAN access is blocked at the VirtualBox NAT hypervisor boundary (only `127.0.0.1:2222 -> guest:22` is forwarded). Bound port lockdown (`127.0.0.1:PORT`) and zone isolation are deferred to Phase 3 to avoid disruptive Compose network recreations.

---

### Phase 2.2 Seccomp & AppArmor Hardening Audit Findings & Evidence Summary
**Date:** 2026-10-24  
**Environment:** Local Ubuntu 24.04 LTS on VirtualBox (6 vCPUs, 8 GB RAM, kernel 6.8.0-147-generic)  
**Status / Sign-off Readiness:** Fully Implemented & Empirically Verified (Ready for Final Commit)

#### 1. Security Profile Inventory & Confinement Architecture
| Service Name | Container Name | Runtime | Active Seccomp Profile | Active AppArmor Profile | Enforcement Status |
|:---|:---|:---:|:---|:---|:---|
| `model-server` | `bayora-model-server` | `runc` | `policies/seccomp/model-server-seccomp.json` | `bayora-model-server` | **Enforcing** (`/app/llama-server`) |
| `blue-filter` | `bayora-blue-filter` | `runc` | `policies/seccomp/python-service-seccomp.json` | `bayora-python-service` | **Enforcing** (`/usr/local/bin/python3.12`) |
| `baseline-stub` | `bayora-baseline-stub` | `runc` | `policies/seccomp/python-service-seccomp.json` | `bayora-python-service` | **Enforcing** (`/usr/local/bin/python3.12`) |
| `red-runner` | `bayora-red-runner` | `runsc` | gVisor Sentry Virtualization | N/A (unsupported by `runsc`) | **Full gVisor Sentry Sandbox** |

**Scope & Architectural Rationale:**
- **Red Runner under gVisor:** gVisor (`runsc`) runs inside an emulated userspace kernel (Sentry), virtualizing and intercepting all guest system calls before host kernel access. As confirmed in Docker runtime feature introspection, `runsc` does not support host AppArmor (`apparmor: false`). Applying host seccomp to gVisor is redundant with Sentry's existing syscall boundary.
- **Python Microservices (`blue-filter` & `baseline-stub`):** Both are lightweight FastAPI/Uvicorn containers running on native `runc`. They share a dedicated hardened seccomp profile (`python-service-seccomp.json`) and a dedicated AppArmor policy (`bayora-python-service`), restricting attack surface while permitting standard async socket I/O.
- **LLM Model Server (`model-server`):** Runs native `llama.cpp:server` on `runc`. Confined with tailored seccomp (`model-server-seccomp.json`) and tailored AppArmor (`bayora-model-server`), enforcing read-only model weight directory protection.

#### 2. Attack Surface Mitigations (SEC-005 & SEC-006)
- **SEC-005 Seccomp Syscall Filtering:**
  - Default action: `SCMP_ACT_ERRNO`.
  - Explicit unconditional denial of 18 high-risk syscalls: `ptrace`, `bpf`, `perf_event_open`, `userfaultfd`, `kexec_load`, `kexec_file_load`, `mount`, `umount`, `umount2`, `pivot_root`, `keyctl`, `add_key`, `request_key`, `init_module`, `finit_module`, `delete_module`, `process_vm_readv`, `process_vm_writev`.
  - Permits all standard glibc, OpenMP threadpool, and networking syscalls required for stable execution.
- **SEC-006 AppArmor Mandatory Access Control:**
  - **Network Raw Denial:** Explicitly enforces `deny network raw` and `deny network packet`, preventing packet-crafting and raw socket privilege escalation.
  - **Filesystem & Mount Lockdown:** Explicitly denies `mount`, `remount`, `umount`, and `pivot_root`.
  - **Capability Lockdown:** Denies high-risk capabilities including `CAP_MAC_ADMIN`, `CAP_MAC_OVERRIDE`, `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`, and `CAP_NET_RAW`.
  - **Process Tracing Denial:** Explicitly blocks cross-container `ptrace` tracing.
  - **File-Access Confinement:** Restricts file access across containers. For `model-server`, strictly enforces read-only access to `/models/**` (`deny /models/** w`, `deny /models/** a`, `deny /models/** k`), and restricts writable locations across all services strictly to `/tmp/**` and standard character devices.

#### 3. Empirical Performance Verification ($N=10$)
Bounded end-to-end inference benchmark through evaluation gateway (`baseline-stub` -> `blue-filter` -> `model-server`):
| Metric | Reference Baseline (`runc`) | Phase 2.1 Post-Change | Phase 2.2 Hardened (Seccomp + AppArmor) | Overhead vs Baseline |
|:---|:---:|:---:|:---:|:---:|
| Requests Evaluated | 10 | 10 | 10 | Bounded sequential requests |
| Success / Timeout | 10/10 (0 timeouts) | 10/10 (0 timeouts) | 10/10 (0 timeouts) | 100% reliability |
| **Latency $p50$** | **$7,148.65\text{ ms}$** | **$4,859.72\text{ ms}$** | **$7,451.25\text{ ms}$** | **$+4.2\%$ (negligible)** |
| Latency $p95$ | $9,371.66\text{ ms}$ | $7,347.51\text{ ms}$ | $10,310.48\text{ ms}$ | $+10.0\%$ |
| **Generation Speed $p50$** | **$9.86\text{ tok/s}$** | **$14.98\text{ tok/s}$** | **$9.39\text{ tok/s}$** | **$-4.7\%$ (within host noise)** |
| Token Latency $p50$ | $101.38\text{ ms/tok}$ | $66.77\text{ ms/tok}$ | $106.64\text{ ms/tok}$ | $+5.2\%$ |
| Total Wall Duration | $76.41\text{ s}$ | $49.10\text{ s}$ | $76.96\text{ s}$ | Stable throughout run |

*Finding:* Unlike gVisor virtualization (which caused a 9.26x slowdown on CPU inference), kernel-native seccomp filters and AppArmor LSM checks impose no measurable computational overhead beyond host scheduling noise (about ±40%, given runc baseline samples ranging from 4,860 ms to 7,451 ms). The gVisor 9.26x slowdown remains far outside this noise band, confirming the architectural decision to retain runc for the model.

#### 4. Master Leak-Test Suite Verification (inside gVisor)
All 5 automated baseline leak tests were executed with `bayora-red-runner` executing inside gVisor:
| Test Script | Vulnerability ID | Execution Status | Security Outcome | Security Boundary Analysis |
|:---|:---|:---:|:---:|:---|
| `test_net_blue_direct.py` | SEC-008 | Clean (exit 0) | `still_reproducible` (PASS) | Flat bridge intact; network segmentation scheduled for Phase 3. |
| `test_net_model_direct.py` | SEC-008 | Clean (exit 0) | `still_reproducible` (PASS) | Direct HTTP connection succeeds; Phase 3 isolates zones. |
| `test_fs_blue_rules.py` | SEC-001 | Clean (exit 0) | `still_reproducible` (PASS) | Shared named volume `/shared_data` intact; volume removal scheduled for Phase 2.3. |
| `test_cache_timing.py` | LLM-001 | Clean (exit 0) | `still_reproducible` (PASS) | Prefix cache timing delta ($2,616.72\text{ ms}$) detected; cache hardening scheduled for Phase 6. |
| `test_log_exposure.py` | PRIV-001 | Clean (exit 0) | `still_reproducible` (PASS) | Unredacted prompts in stdout logs; audit ledger scheduled for Phase 5. |

*Finding:* Seccomp and AppArmor provide robust defense-in-depth against host kernel exploitation and container breakout without prematurely breaking intentional baseline application-level vulnerabilities prior to Phase 2.3 and Phase 3.

#### 5. Evidence Artifacts Provenance (Phase 2.2)
All 10 newly generated evidence artifacts are stored under:
`results/hardening/phase2.2-seccomp-apparmor/local-ubuntu-vm/`
1. `benchmark_phase2_2_hardened.json` — 10-request end-to-end gateway inference benchmark.
2. `leak_test_results.json` — Master leak test suite results under Phase 2.2 hardening.
3. `container_security_inspect.json` — Full Docker inspect metadata for all 4 services confirming runtime, seccomp, and AppArmor attributes.
4. `apparmor_status.txt` — Host `aa-status` confirming enforce mode and process confinement.
5. `docker_compose_ps.txt` — Running service inventory and port bindings.
6. `model_server_container_logs.txt` — Container logs for `bayora-model-server`.
7. `blue_filter_container_logs.txt` — Container logs for `bayora-blue-filter`.
8. `baseline_stub_container_logs.txt` — Container logs for `bayora-baseline-stub`.
9. `model_server_seccomp_health.json` — Health check response under custom seccomp.
10. `model_server_seccomp_inspect.json` — Initial seccomp inspect artifact.

#### 6. Rollback Procedure
If seccomp or AppArmor profile issues occur:
1. Revert `docker-compose.yml`: remove `security_opt` entries from services.
2. Execute `docker compose up -d` to restart services under default Docker confinement.
3. If necessary, unload host profiles via `sudo apparmor_parser -R /path/to/profile`.

---

### Phase 2.3 Least Privilege & Shared Volume Removal Audit Findings & Evidence Summary
**Date:** 2026-10-24  
**Environment:** Local Ubuntu 24.04 LTS on VirtualBox (6 vCPUs, 8 GB RAM, kernel 6.8.0-147-generic)  
**Status / Sign-off Readiness:** Fully Implemented & Empirically Verified (Ready for Final Commit)

#### 1. Changes Implemented
- **Shared Volume Elimination & Mount Lockdown (SEC-001 & R1 Invariant):**
  - Removed `shared_data:/shared_data` mount from `bayora-red-runner`.
  - Removed `shared_data:/shared_data` mount from `bayora-blue-filter`.
  - Reconfigured `bayora-blue-filter` via `BLUE_RULES_PATH=/app/blue_rules.json` to load its verified, baked-in container rules file.
  - Removed top-level `volumes: shared_data` definition from `docker-compose.yml`.
  - Restructured `bayora-red-runner` mounts: changed broad `./data/baseline:/app/data:ro` to payloads-only `./data/baseline/payloads.json:/app/data/payloads.json:ro` (preventing access to host `data/baseline/blue_rules.json`).
  - Replaced host-writable `./results/baseline:/app/results` mount with an in-memory `tmpfs: /app/results:rw,size=64m,noexec,nosuid`, ensuring Red has zero access to write to the host repository filesystem (strict enforcement of R1 invariant).
- **Capability Dropping & Privilege Escalation Prevention:**
  - Configured `cap_drop: ["ALL"]` across all four services (`bayora-model-server`, `bayora-blue-filter`, `bayora-baseline-stub`, `bayora-red-runner`).
  - Added `security_opt: - no-new-privileges:true` to all services.
  - Configured `blue-filter` and `baseline-stub` to run as non-root `user: "65534:65534"` with `read_only: true` rootfs and `tmpfs: /tmp`.
  - Published host ports strictly bound to localhost (`127.0.0.1:8000:8000`, `127.0.0.1:8001:8001`, `127.0.0.1:8080:8080`).
- **Reboot Persistence:**
  - Installed AppArmor profiles permanently to `/etc/apparmor.d/bayora-model-server` and `/etc/apparmor.d/bayora-python-service`.
  - Verified persistence through a full cold VM reboot (`docker compose down`, host reboot, `docker compose up -d`), confirming profiles remained in enforce mode and IP addresses matched `extra_hosts`.

#### 2. Security Outcomes & Leak Test Verification
Executed automated leak-test suite inside `bayora-red-runner`:
| Test Script | Vulnerability ID | Execution Status | Outcome | Security Analysis |
|:---|:---|:---:|:---:|:---|
| `test_fs_blue_rules.py` | SEC-001 | Exited 1 (File missing) | **SHARED VOLUME REMOVED** | The shared-volume path (`/shared_data/blue_rules.json`) and host data mount leakage (`/app/data/blue_rules.json`) have been completely removed, eliminating filesystem-based extraction of Blue defense rules. Direct network extraction of `/rules` (SEC-008) remains open over the bridge network until Phase 3 network segmentation. |
| `test_net_blue_direct.py` | SEC-008 | Clean (exit 0) | `still_reproducible` (PASS) | Flat bridge intact; network segmentation scheduled for Phase 3. |
| `test_net_model_direct.py` | SEC-008 | Clean (exit 0) | `still_reproducible` (PASS) | Direct HTTP connection succeeds; Phase 3 isolates zones. |
| `test_cache_timing.py` | LLM-001 | Clean (exit 0) | `still_reproducible` (PASS) | Prefix cache timing delta detected; cache hardening scheduled for Phase 6. |
| `test_log_exposure.py` | PRIV-001 | Clean (exit 0) | `still_reproducible` (PASS) | Unredacted prompts in stdout logs; audit ledger scheduled for Phase 5. (Note: Evaluated at Docker daemon/operator boundary via `docker logs`, not via in-container Red access). |

#### 3. Negative Security Tests Verification
Added explicit negative tests (`tests/hardening/test_negative_security.py`) to confirm that denied actions fail visibly:
- `ptrace` syscall: returns `-1` with `EPERM` (errno=1, Operation not permitted) enforced by custom Seccomp.
- Raw socket creation: raises `PermissionError: [Errno 13] Permission denied` enforced by AppArmor (`deny network raw`) and capability dropping.
- `mount` syscall: returns `-1` with `errno=1` (Operation not permitted) enforced by AppArmor (`deny mount`) and capability dropping.
- Rootfs write: fails with `[Errno 30] Read-only file system` enforced by Docker read-only container rootfs.


#### 4. Functional & Smoke Verification
- Blue Filter verified reading rules from `/app/blue_rules.json`: `/rules` returns 5 keywords and secret rule salt.
- Model Server health check passes (`/health` returns `{"status":"ok"}`).
- Gateway smoke test recorded in saved artifact `inference_smoke_test.txt`: $p50 = 8,001.58\text{ ms}$, $9.55\text{ tok/s}$, 0 timeouts, 0 errors (distinguished from an earlier interactive trial of $7,101.66\text{ ms}$).

#### 5. Evidence Artifacts Provenance (Phase 2.3)
Stored under `results/hardening/phase2.3-least-privilege/local-ubuntu-vm/`:
1. `leak_test_results.json` — Master leak test suite proving SEC-001 filesystem path removal.
2. `container_security_inspect.json` — Full Docker inspect of all 4 services confirming `CapDrop: ["ALL"]` and mount tables without shared volume.
3. `blue_filter_rules_verification.json` — Response proving Blue loads baked-in `/app/blue_rules.json`.
4. `inference_smoke_test.txt` — Gateway inference smoke test output ($8,001.58\text{ ms}$, $9.55\text{ tok/s}$).
5. `docker_compose_ps.txt` — Running service inventory and localhost port bindings.
6. `model_server_container_logs.txt` — Logs for `bayora-model-server`.
7. `blue_filter_container_logs.txt` — Logs for `bayora-blue-filter`.
8. `baseline_stub_container_logs.txt` — Logs for `bayora-baseline-stub`.
9. `negative_security_tests.txt` — Output of explicit negative security test executions.

#### 6. Rollback Procedure

If capability dropping or volume removal breaks a dependent workload:
1. Re-add `shared_data` volume to `docker-compose.yml` and revert `BLUE_RULES_PATH`.
2. Remove `cap_drop: ["ALL"]` to restore default Docker capabilities.
3. Recreate services via `docker compose up -d`.

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

