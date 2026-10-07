# Bayora STRIDE Threat Model v0

> **Document Version:** 1.0 (Phase 0 Deliverable)  
> **Status:** RATIFIED  
> **PRD References:** §11, §17, §32, SEC-001 through SEC-014, FR-001 through FR-005, AUD-001 through AUD-005  
> **Threat-Model Owner:** Lead Security Architect / Solo Developer (Confirmed via D-CONF-7)

---

## 1. Actors, Assets & Attack Surfaces

### 1.1 System Actors
| Actor ID | Actor Name | Trust Level | Description |
|---|---|---|---|
| **ACT-1** | **Red Team / Attacker** | Untrusted | Executes automated jailbreaks, prompt injections, and extraction attacks via the Zone 1 container. |
| **ACT-2** | **Blue Team / Defender** | Semi-Trusted | Provides input/output security filters, classifier models, and heuristic guardrails in Zone 2. |
| **ACT-3** | **Model Server** | High (Target) | Runs inference on `llama.cpp` in Zone 3; passive receiver of prompts. |
| **ACT-4** | **Evaluation Gateway** | Trusted (TCB) | Mediates and orchestrates all communications in Zone 4; enforces OPA policies. |
| **ACT-5** | **Evaluator / Admin** | Fully Trusted | Human operator managing evaluation runs, lifecycles, and configuration. |
| **ACT-6** | **External Auditor** | Independent | Inspects signed ledger entries and Merkle proofs against external trust anchors. |

### 1.2 System Assets
| Asset ID | Asset Name | Sensitivity | Security Objective |
|---|---|---|---|
| **AST-1** | **Model Weights & Parameters** | Critical | Confidentiality & Integrity. Prevent extraction, tampering, or weight theft. |
| **AST-2** | **Blue Defense Logic & Heuristics**| High | Confidentiality & Integrity. Prevent Red from profiling rules, weights, or thresholds. |
| **AST-3** | **Red Attack Corpora** | Confidential | Embargo Integrity. Prevent premature leakage before run publication. |
| **AST-4** | **Audit Ledger & Proofs** | Critical | Immutability & Non-repudiation. Append-only, Ed25519 signed, Merkle anchored. |
| **AST-5** | **Evaluation State & KV Cache** | High | Statelessness. Zero cross-query residual data, cache-timing side-channels, or memory persistence. |
| **AST-6** | **Host Kernel & Infrastructure** | Critical | Availability & Isolation. Prevent container breakouts, hypervisor escape, and resource exhaustion. |

### 1.3 Attack Surfaces
1. **Network Ingress (Port 8000 on Gateway):** The HTTP REST API exposed to the Red Team container.
2. **Container Syscall Interface:** Linux syscalls exposed to untrusted user code inside Red/Blue containers.
3. **LLM Inference Engine:** Prompt injection vectors, model behavior manipulation, and token-generation side channels.
4. **Cache & Microarchitectural Timing:** Differential CPU cache latency, KV-cache hits, and inference execution time.
5. **Audit Ledger Pipeline:** Tampering with SQLite run metadata, unanchored block modification, or log truncation.

---

## 2. Complete 42-Cell STRIDE Analysis Matrix

Evaluating all **7 Trust-Boundary Crossings (X1 through X7)** across the **6 STRIDE Categories** ($7 \times 6 = 42$ cells).  
*(Note: Interface X8 from the DFD represents intra-zone communication within the Control Zone TCB and is not an external/tenant crossing).*

| Crossing | S - Spoofing | T - Tampering | R - Repudiation | I - Information Disclosure | D - Denial of Service | E - Elevation of Privilege |
|---|---|---|---|---|---|---|
| **X1: Red $\leftrightarrow$ Gateway** | **Threat:** Red impersonates Evaluator Admin or another team.<br/>**Mitigation:** Role-Based API keys validated by OPA middleware (SEC-001). | **Threat:** Red mutates headers or injects malicious payloads to alter run metadata.<br/>**Mitigation:** Strict Pydantic JSON schema validation; immutable `run_id` binding (FR-003). | **Threat:** Red claims an offensive prompt was injected by the platform.<br/>**Mitigation:** SHA-256 digest of prompt logged and Ed25519-signed in Audit Ledger before model execution (AUD-001). | **Threat:** Red probes Blue defense heuristics or model state via error messages or latency.<br/>**Mitigation:** Uniform refusal strings; jittered response latency; no debug info leaked (SEC-002, D-CONF-10). | **Threat:** Red floods Gateway with queries to exhaust resources.<br/>**Mitigation:** Hard query budget ($Q=200$); token bucket rate limiting; cgroup v2 memory limits (SEC-009, D-CONF-6). | **Threat:** Red exploits Gateway HTTP parser to achieve RCE in Control Zone.<br/>**Mitigation:** Minimal FastAPI codebase; non-root user; read-only container; seccomp filter (SEC-011). |
| **X2: Gateway $\leftrightarrow$ Blue Defense** | **Threat:** Malicious container pretends to be Blue Defense.<br/>**Mitigation:** Mutual TLS with certificates issued by `step-ca` containing Zone 2 SAN (SEC-012). | **Threat:** Blue filter alters prompts before they reach the model without audit log recording.<br/>**Mitigation:** Gateway records both pre-filter and post-filter prompt hashes in the ledger (AUD-002). | **Threat:** Blue claims it never flagged a blocked attack query.<br/>**Mitigation:** Blue classification verdict signed and recorded in hash ledger (AUD-003). | **Threat:** Blue steals Red's proprietary attack strategies and leaks them.<br/>**Mitigation:** Blue container has no egress network access; read-only filesystem; ephemeral execution (SEC-008). | **Threat:** Blue filter executes infinite regex / ReDoS to hang the evaluation pipeline.<br/>**Mitigation:** Strict 500ms timeout per filter call; process killed on expiration; circuit breaker trips (FR-004). | **Threat:** Blue filter attempts privilege escalation into Control Zone via mTLS socket.<br/>**Mitigation:** Gateway validates mTLS client certs; drops all Linux capabilities in Blue container (SEC-011). |
| **X3: Gateway $\leftrightarrow$ Model Server** | **Threat:** Rogue process impersonates `llama.cpp` model server.<br/>**Mitigation:** mTLS authentication between Gateway and Model container using internal CA (SEC-012). | **Threat:** Model parameters or weights altered in memory during inference.<br/>**Mitigation:** Model weights mounted read-only (`:ro`); initial weights SHA-256 hash verified at boot (LLM-001). | **Threat:** Model generates toxic response but claims it was modified by Gateway.<br/>**Mitigation:** Raw generated token stream hashed and signed at Gateway boundary before inspection (AUD-001). | **Threat:** Attacker extracts model weights or system prompts via side channels.<br/>**Mitigation:** Dedicated physical CPU core (`cpuset 0`); KV/prompt caching disabled (`--cache-prompt false`) (LLM-002). | **Threat:** Long prompt triggers Out-Of-Memory (OOM) on model server.<br/>**Mitigation:** Gateway truncates prompts at 8,192 tokens; cgroup v2 hard 4 GB limit; strict OOM score pinning (SEC-009). | **Threat:** Model server attempts to escape container into host kernel.<br/>**Mitigation:** Dropped capabilities (`ALL`); seccomp filter blocking `sys_admin`, `ptrace`; read-only rootfs (SEC-011). |
| **X4: Gateway $\leftrightarrow$ Audit Ledger** | **Threat:** Unauthorized container writes false entries to Audit Ledger.<br/>**Mitigation:** Ledger listens exclusively on isolated Unix socket accessible only by Control Gateway (AUD-001). | **Threat:** Retroactive modification of past query/verdict events.<br/>**Mitigation:** Append-only SHA-256 hash chain; each block includes the hash of the preceding block (AUD-004). | **Threat:** Platform operator denies that an evaluation run occurred or modifies score.<br/>**Mitigation:** Every block signed with Ed25519 private key stored in OpenBao (AUD-004). | **Threat:** Attacker reads audit ledger to extract secret attack prompts.<br/>**Mitigation:** Raw prompts encrypted at rest using `age` public keys; only cryptographic digests public (SEC-014). | **Threat:** Disk exhaustion attack by flooding audit logs.<br/>**Mitigation:** Strict query limit ($Q=200$ per run); capped block size; dedicated storage volume quota (AUD-001). | **Threat:** Attacker modifies ledger process to corrupt memory.<br/>**Mitigation:** Audit container runs as unprivileged user; memory capped at 2 GB (SEC-009). |
| **X5: Admin $\leftrightarrow$ Gateway** | **Threat:** Attacker brute-forces or spoofs Admin Evaluator identity.<br/>**Mitigation:** Strong Admin API token or mTLS client certificate; separate role in OpenBao (D-CONF-5). | **Threat:** Interception and modification of run parameters in transit.<br/>**Mitigation:** TLS 1.3 encryption on Admin management port (SEC-005). | **Threat:** Admin creates/destroys runs without audit trail.<br/>**Mitigation:** All administrative lifecycle calls recorded in immutable ledger as genesis/closure blocks (AUD-001). | **Threat:** Admin credentials exposed in configuration files or Git.<br/>**Mitigation:** Credentials injected dynamically via OpenBao; `.gitignore` prevents secret check-in (SEC-013). | **Threat:** Admin port flooded with unauthenticated requests.<br/>**Mitigation:** Admin port bound to internal network interface or protected by host `nftables` firewall. | **Threat:** Admin API exposed to Red Team container.<br/>**Mitigation:** OPA middleware strictly separates `/v1/eval/query` (Red) from `/v1/admin/*` endpoints (FR-003). |
| **X6: Ledger $\leftrightarrow$ Trust Anchor** | **Threat:** Man-in-the-middle impersonates GitHub API / Rekor server.<br/>**Mitigation:** TLS certificate pinning and verification against trusted public CA root (SEC-006). | **Threat:** Attacker intercepts external push and alters published Merkle root.<br/>**Mitigation:** Merkle root is signed with Ed25519; verified against external public key (AUD-005). | **Threat:** Platform claims it anchored root when it did not.<br/>**Mitigation:** External anchor returns cryptographic receipt / commit SHA recorded locally (AUD-005). | **Threat:** Publicly anchored root reveals confidential attack prompts.<br/>**Mitigation:** Only the 32-byte SHA-256 Merkle root is published; zero prompt or completion data leaked (SEC-006). | **Threat:** GitHub / Rekor API rate limits or network outage blocks evaluation.<br/>**Mitigation:** Anchoring is asynchronous post-run (`CLOSED` state); failure triggers alert without corrupting run state. | **Threat:** Compromised GitHub deployment token used to attack other repos.<br/>**Mitigation:** Fine-grained personal access token scoped strictly to single anchor repository with write-only access. |
| **X7: Sandboxed Containers $\leftrightarrow$ Host Kernel** | **Threat:** Compromised container spoofs kernel identity or UID 0 on host.<br/>**Mitigation:** User namespace remapping (`userns-remap: default`); container root maps to high unprivileged UID (SEC-007). | **Threat:** Container modifies host `/proc`, `/sys`, or host filesystem.<br/>**Mitigation:** Read-only root filesystems; strict mask of `/proc/kcore`, `/sys/firmware`; no privileged flags (SEC-011). | **Threat:** Malicious container actions untraceable at kernel level.<br/>**Mitigation:** Falco runtime security monitoring with modern eBPF probe logging all syscall anomalies (SEC-010). | **Threat:** Container snoops on other containers via shared kernel memory or side-channels.<br/>**Mitigation:** gVisor (`runsc`) user-space kernel virtualization for Red container; CPU core pinning (`cpuset`) (SEC-007). | **Threat:** Fork bomb or CPU exhaustion halts the host machine.<br/>**Mitigation:** Cgroup v2 PID limits (`pids.max = 256`); strict CFS CPU bandwidth caps (SEC-009). | **Threat:** Container executes kernel exploit (e.g., privilege escalation vulnerability).<br/>**Mitigation:** gVisor intercepts syscalls in user space; default seccomp profile drops 300+ dangerous syscalls (SEC-007). |

---

## 3. Attack Scenarios & Mitigations Summary

1. **Scenario 1: The Leaky Oracle Attack:**
   - *Attack:* Red submits subtle variations of jailbreak prompts to observe whether refusal error codes or response times differ, reverse-engineering Blue's regex patterns.
   - *Mitigation:* Gateway returns identical refusal strings for all block reasons with jittered response times. Query budget $Q=200$ strictly caps total information gain to $\le 200$ bits per run.

2. **Scenario 2: The Direct Model Pivot Attack:**
   - *Attack:* Red attempts to discover and directly call `http://model:8080/completion` to bypass Blue defenses.
   - *Mitigation:* Docker bridge network isolation and host `nftables` ensure Red cannot route to the Model network. The model server rejects non-mTLS connections.

3. **Scenario 3: The Cache Snooping Attack:**
   - *Attack:* Red sends a warm-up prompt, measures token generation latency on subsequent prompts to detect if previous queries primed the KV cache.
   - *Mitigation:* `llama.cpp` runs with prompt and KV caching disabled; slots reset after every query; Model runs on physically dedicated CPU cores (Cores 0-1) on Ampere Altra ARM64.
