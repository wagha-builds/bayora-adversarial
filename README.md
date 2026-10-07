# Bayora — Adversarial AI Evaluation Platform

> **Proof of Concept: Hardened Five-Zone Sandbox for Adversarial LLM Safety Evaluations**  
> *Project Phase: Phase 0 — Alignment + Threat Model (Documentation Only)*

---

## 1. Executive Summary

Bayora is an adversarial testing harness and sandboxed evaluation platform designed to assess Large Language Models (LLMs) against sophisticated jailbreak, prompt injection, and extraction attacks without risking:
1. **Model Weight or Parameter Theft:** Zero unauthorized extraction of model weights or embeddings.
2. **Evaluation State Poisoning:** Protection against cross-query state leakage, KV cache snooping, or shared memory side-channels.
3. **Defense Bypass & Profiling:** Red teams cannot learn or probe Blue team defensive heuristics due to strict mediation and uniform refusal responses.
4. **Audit Log Tampering:** All evaluation events are cryptographically recorded in an append-only hash chain anchored to an external trust root.

---

## 2. Core Security Invariants

Bayora enforces four non-negotiable security requirements across all phases:

* **R1 (Red Isolation):** The Red Team container operates in an isolated network segment under gVisor (`runsc`), with zero access to the host filesystem, other zone networks, or the model server. Red can ONLY communicate via authenticated HTTP requests to the Evaluation Gateway.
* **R2 (Blue Integrity):** Blue defenses execute as sealed input/output filters. Red has no access to Blue's code, models, token representations, or classification scores. Responses to blocked queries are generic and uniform.
* **R3 (Model Confidentiality & Statelessness):** The model server runs in a dedicated zone with KV caching, session state, and prompt caching disabled. The server is strictly bound to dedicated CPU cores (`taskset` / `cpuset`) to prevent side-channel timing attacks.
* **R4 (Audit Immutability):** Every query, response token count, latency metric, and policy verdict is signed with Ed25519 and chained via SHA-256 in an append-only ledger anchored externally.

---

## 3. Five-Zone Architecture Overview

All workloads exist within strictly partitioned network and computational zones:

```
┌─────────────────────────────────────────────────────────────┐
│                        HOST BOUNDARY                        │
│                                                             │
│   ┌───────────────┐                  ┌───────────────┐      │
│   │   ZONE 1:     │   HTTP Requests  │    ZONE 4:    │      │
│   │   RED TEAM    │ ───────────────> │  CONTROL ZONE │      │
│   │ (Untrusted)   │ <─────────────── │ (Gateway+OPA) │      │
│   └───────────────┘  Refusal / Resp  └───┬───────┬───┘      │
│                                          │       │          │
│                      Sanitized Prompt    │       │ Log      │
│                      ┌───────────────────┘       │ Event    │
│                      │                           ▼          │
│                      ▼                   ┌───────────────┐  │
│               ┌───────────────┐          │    ZONE 5:    │  │
│               │    ZONE 2:    │          │  AUDIT ZONE   │  │
│               │   BLUE TEAM   │          │ (Hash Ledger) │  │
│               │ (Defenses)    │          └───────────────┘  │
│               └──────┬────────┘                             │
│                      │ Forward Cleared Prompt               │
│                      ▼                                      │
│               ┌───────────────┐                             │
│               │    ZONE 3:    │                             │
│               │  MODEL ZONE   │                             │
│               │  (llama.cpp)  │                             │
│               └───────────────┘                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Documentation Index (Phase 0 Deliverables)

All Phase 0 artifacts live in the [`docs/`](docs/) directory:

- **Architecture:**
  - [`docs/architecture/dfd.md`](docs/architecture/dfd.md): Five-zone Data Flow Diagram, trust boundaries, and network crossing matrix.
  - [`docs/architecture/zones.md`](docs/architecture/zones.md): Zone specifications, lifecycle state machine, and trust assumptions.
- **Threat Model:**
  - [`docs/threat-model/stride.md`](docs/threat-model/stride.md): Complete 42-cell STRIDE analysis across all 7 trust crossings.
- **API Specification:**
  - [`docs/api/gateway-contract.md`](docs/api/gateway-contract.md): Evaluation Gateway OpenAPI specification (all 11 FR-003 endpoints).
- **Risk Assessment:**
  - [`docs/risk/risk-register.md`](docs/risk/risk-register.md): 22-item risk register with residual risk ratings and mitigations.
- **Project Tracking:**
  - [`task.md`](task.md): Master sub-task tracker and execution status.

---

## 5. Development Roadmap

- **Phase 0:** Alignment & Threat Model *(CURRENT)*
- **Phase 1:** Insecure Baseline (Docker Compose single network — demonstrating vulnerabilities)
- **Phase 2:** Five-Zone Network Isolation (Docker bridge networks, internal DNS, unskippable Gateway)
- **Phase 3:** OS & Kernel Hardening (gVisor `runsc`, seccomp, AppArmor, `nftables`, dedicated cpusets)
- **Phase 4:** Identity, Secrets & Policy (OpenBao, `step-ca` mTLS, OPA ABAC engine)
- **Phase 5:** Audit Ledger & External Anchoring (SHA-256 hash chain, Ed25519 signing, Git anchor)
- **Phase 6:** LLM Hardening (llama.cpp stateless configuration, uniform refusal, cache timing mitigation)
- **Phase 7:** Automated Test Harness (Side-channel probes, policy bypass tests, ledger verification)
- **Phase 8:** Real-time Monitoring & Telemetry (Falco eBPF, Prometheus, Grafana)
- **Phase 9:** Stress Testing & Edge Cases (High concurrency, network partitions, resource exhaustion)
- **Phase 10:** Final Polish & Single-Command Deployment (`make up`, demo walkthrough)
