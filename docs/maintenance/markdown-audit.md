# Bayora Repository-Wide Markdown Documentation Audit & Reconciliation

> **Audit Date:** 28 October 2026<br>
> **Auditor:** Antigravity AI (Pair Programming with Operator)<br>
> **Purpose:** Authoritative inventory, status reconciliation, and verification audit of all project-owned Markdown files (`*.md`) in the BAYORA repository.<br>
> **Authoritative Baseline:** Phase 3 Verified Five-Zone Network Segmentation, Static IPAM Preflight (26/26 passed), Hardened Acceptance Suite (17/17 passed), and Persistent Systemd Host Firewall (`inet bayora_host_firewall`).

---

## 1. Executive Summary & Audit Scope

This document provides a complete, traceable accounting of all Markdown documentation across the `bayora_adversarial` repository. Every document has been audited against the actual source code, Docker Compose configuration, security profiles, test harnesses, and authentic execution evidence recorded on the Ubuntu 24.04 LTS reference VM as of **28 October 2026**.

### Core Reconciliation Principles Enforced:
1. **Truthfulness in Security Claims:** Hardened features are strictly distinguished across six states:
   - *Implemented and Verified:* Code/config exists and verifiable test evidence confirms enforcement.
   - *Implemented, but not recently verified:* Code exists, but test was not re-run in current session.
   - *Partially Implemented:* Functional baseline exists, but security controls or full endpoints are absent.
   - *Documented / Designed Only:* Architecture plans, contracts, or schemas exist without production code.
   - *Not Started:* Scheduled for later phases without current code.
   - *Blocked / Inconclusive:* Unverified or conditionally waived.
2. **Preservation of the Insecure Baseline:** `services/baseline-stub` (`version 0.1.0-baseline`) is preserved as the immutable Phase 1 baseline for scientific before-vs-after regression testing. The hardened Evaluation Gateway (`services/evaluation-gateway/`, `version 1.0.0-hardened`) is accurately documented as an approved architecture plan (Milestones 1–5), not an operational service.
3. **Host Firewall Persistence Qualification:** Table `inet bayora_host_firewall` is applied and active via systemd service `bayora-host-firewall.service`. However, an independent cold reboot verification has **not** been performed yet. This distinction is maintained consistently across all documents.
4. **Zero Credential Disclosure:** All documentation has been scrubbed of real secrets, private keys, and machine-specific host paths.

---

## 2. Complete Inventory of Repository Markdown Files

| # | Relative File Path | Category / Purpose | Last Documented State | Outdated Statements / Discrepancies Found | Reconciliation Action Taken |
|---|---|---|---|---|---|
| 1 | `README.md` | Primary Project Landing Page & Architecture Overview | Phase 3 (with Known Gap in firewall) | Stated `KNOWN_GAP_PRE_NFTABLES` for host SSH; test listener failure not updated; quickstart missing systemd firewall commands. | **SUBSTANTIVELY UPDATED**: Updated to 17/17 acceptance pass; documented persistent `bayora-host-firewall.service`; added test listener fix; updated quickstart and layout. |
| 2 | `task.md` | Master Project Task Tracker & Execution Log | Phase 3 (with Known Gap in firewall) | Table listed `red_to_bridge_host_sshd` as `KNOWN_GAP_PRE_NFTABLES`; suite verdict was `PASS (Hardened Policy Enforced with Known Gaps)`; missing listener remediation details and gateway plan. | **SUBSTANTIVELY UPDATED**: Updated to 17/17 passed (`PASS (All Hardened Policies Enforced)`); documented `bayora-host-firewall.service`; added listener fix details; documented Deliverable 3 gateway plan. |
| 3 | `docs/roadmap.md` | Phase-by-Phase Roadmap & Definition of Done | Phase 3.3 pending manual sudo | Listed Phase 3.3 as pending sudo; lacked listener remediation context; did not specify Gateway Milestones 1–5 in Phase 4. | **SUBSTANTIVELY UPDATED**: Reconciled Phase 3.3 to active systemd status; updated Phase 3 DoD with 17/17 passed; added Evaluation Gateway implementation prerequisites to Phase 4. |
| 4 | `docs/api/gateway-contract.md` | Ratified API Contract for Evaluation Gateway | Normative specification (Phase 0) | Did not explicitly delineate contract specification vs. current baseline stub vs. planned hardened gateway; potential ambiguity on endpoint 11. | **SUBSTANTIVELY UPDATED**: Appended Section 6 with complete 11-endpoint gap matrix; explicitly clarified `POST /v1/audit/runs/{run_id}/anchor` as normative path. |
| 5 | `docs/architecture/dfd.md` | Five-Zone Data Flow Diagram & Trust Crossings | Phase 0 Target / Phase 3 baseline | Mermaid diagram depicted future TCB components without clarifying target vs current deployment; Section 6.2 listed pre-firewall gap. | **SUBSTANTIVELY UPDATED**: Added target architecture notice to Section 2; updated Section 6.2 with verified 17/17 test results and persistent firewall service. |
| 6 | `docs/architecture/zones.md` | Five-Zone Specifications & State Machine | Phase 0 Target / Phase 3 baseline | Zone 4 Control Zone did not distinguish baseline stub from target Evaluation Gateway; Section 5.2 lacked persistent firewall details. | **SUBSTANTIVELY UPDATED**: Added implementation status note to Section 1.4; updated Section 5.2 with `bayora-host-firewall.service` and cold reboot caveat. |
| 7 | `docs/threat-model/stride.md` | 42-Cell STRIDE Threat Model Across 7 Crossings | Phase 0 Target / Phase 3 baseline | Section 4.2 listed bridge host exposure as an unmitigated known gap pending operator sudo. | **SUBSTANTIVELY UPDATED**: Updated Section 4.2 to mitigated and active via systemd service (`PASS_ISOLATED`); noted cold reboot verification pending. |
| 8 | `docs/risk/risk-register.md` | Comprehensive 22-Item Risk Register | Phase 0 Target / Phase 3 baseline | Risk R-23 listed as open known gap pending sudo; lacked operational risks for VM clock dilation and baseline preservation. | **SUBSTANTIVELY UPDATED**: Updated R-23 to mitigated via systemd (`PASS_ISOLATED`); added Risk R-24 (VM timer dilation) and R-25 (gateway baseline scope risk). |
| 9 | `services/model-server/README.md` | Model Server Deployment & Hardening Specification | Phase 3 Segmentation | Accurate; verified all claims against `docker-compose.yml` (`runc`, seccomp, AppArmor, `172.20.3.20`, `--cache-prompt` active). | **REVIEWED — NO CHANGE NEEDED**: File is accurate, concise, and correctly specifies current configuration and pending Phase 6 cache removal. |
| 10 | `docs/demo/submission_checklist.md` | Hack in Hills '26 Pre-Submission Checklist | Phase 3 Verified | Created in current session; audited for relative link validity and secret leaks. | **REVIEWED & VERIFIED**: Confirmed all links are repository-relative; placeholders used for missing video/post links; blockers accurately stated. |
| 11 | `docs/demo/prototype_demo_script.md` | Step-by-Step Terminal Prototype Walkthrough | Phase 3 Verified | Created in current session; verified commands against running stack. | **REVIEWED & VERIFIED**: All commands match live container configuration (`runsc`, static IPAM, 17-test suite, curl inference). |
| 12 | `docs/demo/one_minute_elevator_pitch.md` | 60-Second Video Script & Social Post Template | Phase 3 Verified | Created in current session; contains mandatory phrase “Hack in Hills, powered by TinyFish”. | **REVIEWED & VERIFIED**: Word count ~135 words; accurate claims; social placeholders clean. |
| 13 | `docs/demo/slide_outline.md` | 10-Slide Pitch Presentation Structure | Phase 3 Verified | Created in current session; strictly 10 slides; Slide 2 is explicitly Problem Statement. | **REVIEWED & VERIFIED**: Complies with all hackathon presentation constraints. |
| 14 | `Bayora PRD.md` | Hackathon Problem Requirements Document | Phase 0 (Oct 7, 2026) | External competition specification file; ignored in `.gitignore`. | **EXCLUDED FROM MODIFICATION**: External competition reference document preserved without modification. |

---

## 3. Authoritative Implementation Status (as of 28 October 2026)

### 3.1 Implemented & Verified Controls
1. **gVisor Syscall Isolation (Zone 1 - Red):** `bayora-red-runner` operates under `runtime: runsc` (Sentry kernel virtualization). Container kernel ring confirms `Starting gVisor...`.
2. **System Call & Capability Confinement (Zones 1–4):** `cap_drop: ALL` and `no-new-privileges: true` active on all four containers. Custom seccomp filters applied to Model (`model-server-seccomp.json`) and Python services (`python-service-seccomp.json`), unconditionally blocking 18 high-risk syscalls.
3. **Mandatory Access Control (Zones 2 & 3):** Tailored AppArmor profiles (`bayora-model-server`, `bayora-python-service`) loaded and enforced in the host kernel.
4. **Least-Privilege Storage:** Shared named volumes removed. Red restricted to read-only payload bind mount (`payloads.json:ro`) and in-memory `tmpfs` results volume (`/app/results`). Blue and Gateway run with `read_only: true` root filesystems.
5. **Deterministic Network Segmentation (Phase 3):**
   - 4 isolated bridge networks (`red-net`, `blue-net`, `model-net`, `gateway-host-net`).
   - Static IPAM configuration verified 100% compliant across 26 assertions (`scripts/check_network_ipam.py`).
   - Single multi-homed gateway invariant enforced: Gateway (`bayora-baseline-stub`) is the sole multi-homed container (`172.20.1.2`, `172.20.2.2`, `172.20.3.2`, `172.20.0.2`). Tenants are strictly single-homed.
   - Host port publication locked down: Backend ports 8001 and 8080 are NOT published; Gateway is bound strictly to `127.0.0.1:8000:8000`.
6. **Host Firewall Remediation (Phase 3.3):** Dedicated table `inet bayora_host_firewall` drops tenant bridge packets destined to host ports (including SSH on port 22). Managed and enabled via systemd unit `bayora-host-firewall.service`.
7. **Reverse-Isolation Probe Harness:** Dedicated probe server (`scripts/test_listener_server.py`) returns HTTP 200 `BAYORA_TEST_LISTENER_OK` with zero filesystem exposure and handles rapid socket rebind via `allow_reuse_address = True`.
8. **Automated Verification:** 17 of 17 tests passed in `tests/network/test_phase3_network_acceptance.py --hardened`, achieving `PASS (All Hardened Policies Enforced)`.

### 3.2 Implemented, but Conditionally Qualified
1. **Host Firewall Cold Reboot Persistence:** The systemd unit `bayora-host-firewall.service` is `enabled` and `active` with nonzero packet drop counters. However, an independent post-reboot verification cycle has **not** been executed to preserve VM stability.
2. **Phase 2.0 Contention Benchmark:** Evaluated under unconstrained 6-core and 4-core stress, inducing severe host starvation and soft-lockup alarms on unpinned hybrid CPU cores. Formally waived for Phase 2.0; bounded rerun ($\le 2$ stressor cores) deferred to Phase 7.

### 3.3 Partially Implemented / Preserved Baseline
1. **Evaluation Gateway Mediation:** Currently deployed as `services/baseline-stub/` (`version 0.1.0-baseline`). It routes requests through Blue filter to Model, but lacks OPA policy enforcement, rate limiting, query budget ($Q$) tracking, mTLS validation, and structured RFC 7807 problem details. This baseline is preserved deliberately for comparative testing.

### 3.4 Designed & Planned Only (Not Started)
1. **Hardened Evaluation Gateway (`services/evaluation-gateway/`):** Full 11-endpoint architecture, 5-state lifecycle state machine (`SETUP -> COMMITTED -> RUNNING -> CLOSED -> REVEALED`), SQLite WAL persistence, atomic query budget ($Q=200$), and double-commit ledger planned across 5 milestones.
2. **Phase 4 (Identity & Policy):** OpenBao secrets engine, `step-ca` automated PKI/mTLS, and OPA/Rego ABAC sidecar.
3. **Phase 5 (Audit Ledger):** Append-only SHA-256 chained hash ledger with Ed25519 cryptographic signatures and external Git anchoring.
4. **Phase 6 (LLM Hardening):** Stateless inference, prompt canary tokens, and KV prompt cache removal (`--cache-prompt false`).
5. **Phase 7 (Resource Governance):** Cgroup v2 CPU bandwidth quotas, memory limits, and CPU pinning (`cpuset`).
6. **Phase 8 (Runtime Monitoring):** Falco eBPF probe and Prometheus observability.
7. **Phase 9–10 (CI Assurance & Turnkey Release):** Regression stress suite, image signing with Cosign, and turnkey `make up` automation.

---

## 4. Cross-Document Consistency Matrix

| Topic / Element | Standardized Value / Specification | Verified Agreement Across Documents |
|---|---|---|
| **Project Name** | BAYORA | `README.md`, `task.md`, `roadmap.md`, `dfd.md`, `zones.md`, `stride.md`, `risk-register.md`, `demo/*` |
| **Trust Zones** | Zone 1 (Red), Zone 2 (Blue), Zone 3 (Model), Zone 4 (Control), Zone 5 (Audit) | Consistent across all architecture and specification documents |
| **Sole Multi-Homed Node** | Evaluation Gateway in Zone 4 | Enforced in `docker-compose.yml`, documented in `dfd.md`, `zones.md`, `README.md`, `task.md` |
| **Static IP Allocations** | Gateway (`172.20.1.2`, `2.2`, `3.2`, `0.2`), Red (`1.10`), Blue (`2.10`), Model (`3.20`) | Verified in `check_network_ipam.py`, `README.md`, `task.md`, `roadmap.md`, `dfd.md`, `zones.md` |
| **Host Port Bindings** | Only `127.0.0.1:8000:8000` (Gateway). Zero backend ports published. | Verified in `docker-compose.yml`, `README.md`, `task.md`, `ipam_audit_output.txt` |
| **Acceptance Suite Verdict** | `PASS (All Hardened Policies Enforced)` (17/17 passed) | Consistent across `README.md`, `task.md`, `roadmap.md`, `acceptance_test_report.json`, `demo/*` |
| **Host Firewall State** | Table `inet bayora_host_firewall` active via `bayora-host-firewall.service` (Cold reboot pending) | Reconciled across `README.md`, `task.md`, `roadmap.md`, `dfd.md`, `zones.md`, `stride.md`, `risk-register.md` |
| **Evaluation Gateway Status** | Current: `baseline-stub` (insecure baseline); Planned: `evaluation-gateway` (Milestones 1–5) | Consistent across `README.md`, `task.md`, `roadmap.md`, `gateway-contract.md`, `zones.md`, `demo/*` |
| **Authoritative Anchor Path** | `POST /v1/audit/runs/{run_id}/anchor` | Ratified in `gateway-contract.md` Section 3.4 & 6; reconciled in `task.md` and planning artifacts |

---

## 5. Security & Sensitive Data Audit Summary

- **Private Keys / Key Material:** 0 occurrences found across all Markdown documents.
- **API Keys / Bearer Tokens:** No live secrets exposed. Example tokens in documentation use explicit non-production placeholders (e.g., `bayora-admin-token-2026`).
- **File System Paths:** No Windows machine-specific paths (`C:\Users\...`) remain in general-purpose Markdown files. Repository-relative paths are used exclusively.
- **PRD / Problem Statement Exclusions:** Internal competition documents (`Bayora PRD.md`, `Hack_in_Hills_26_PS04_Bayora.pdf`) are confirmed excluded via `.gitignore`.
