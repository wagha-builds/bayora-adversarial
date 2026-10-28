# Bayora Comprehensive Risk Register (R-01 through R-22)

> **Document Version:** 1.0 (Phase 0 Deliverable)  
> **Status:** RATIFIED  
> **PRD References:** §39, §40, §41, SEC-001 through SEC-014, AUD-001 through AUD-005  
> **Threat-Model Owner:** Lead Security Architect / Solo Developer (Confirmed via D-CONF-7)

---

## 1. Risk Methodology & Scoring Matrix

Risks are evaluated using a standard 5×5 Likelihood and Impact matrix (PRD §41):

* **Likelihood:** 1 (Rare), 2 (Unlikely), 3 (Possible), 4 (Likely), 5 (Almost Certain)
* **Impact:** 1 (Insignificant), 2 (Minor), 3 (Moderate), 4 (Major), 5 (Catastrophic)
* **Risk Score:** $\text{Likelihood} \times \text{Impact} \in [1, 25]$
  - **1–4:** Low (Acceptable)
  - **5–9:** Medium (Tolerable with controls)
  - **10–14:** High (Mitigation mandatory)
  - **15–25:** Critical (System cannot operate without blocking control)

---

## 2. Theoretical Oracle Bound Analysis

A primary concern in adversarial safety testing is **Defense Extraction via Oracle Probing** (R-05).

* **Theoretical Bound Proof:**
  - Let $D$ be the confidential Blue defense rule set.
  - Let $Q$ be the query budget allocated to an evaluation run ($Q = 200$).
  - For each query $q_i$, the Gateway returns either a generic model completion or a uniform refusal token:  
    $$y_i \in \{\text{Allowed}, \text{Blocked}\}$$
  - Because all block conditions return an identical string with randomized latency jitter, the feedback channel conveys at most $1$ bit of information per query:  
    $$H(y_i) \le 1 \text{ bit}$$
  - Over the entire run, the maximum mutual information $I(D; Y)$ that Red can extract about the defense is strictly bounded by:
    $$I(D; Y) \le \sum_{i=1}^Q H(y_i) \le Q \text{ bits} = 200 \text{ bits}$$
  - **Conclusion:** $200$ bits is mathematically insufficient to reconstruct non-trivial neural classifier weights or complex regex defense policies.

---

## 3. Complete Risk Register (All 22 Entries)

| Risk ID | Threat / Failure Mode | Pre L / I (Score) | Architectural Mitigation | Post L / I (Score) | Detection & Telemetry | Future Work / Hardening |
|---|---|---|---|---|---|---|
| **R-01** | Red container breakout via host kernel vulnerability | 3 / 5 (15 - Critical) | gVisor (`runsc`) user-space kernel virtualization. Drops all Linux capabilities; `userns-remap: default`; read-only rootfs (SEC-007). | 1 / 4 (4 - Low) | Falco modern eBPF probe monitoring unexpected syscalls outside gVisor boundary. | MicroVM isolation via Cloud Hypervisor / Firecracker. |
| **R-02** | Direct network pivot from Red to Model/Blue bypassing Gateway | 4 / 5 (20 - Critical) | Isolated Docker bridge networks per zone. Host `nftables` blocks inter-bridge forwarding. Kernel IP forwarding disabled (`net.ipv4.ip_forward=0`) (SEC-008). | 1 / 4 (4 - Low) | Network flow logging; Falco alerts on unauthorized bridge traffic. | WireGuard point-to-point mesh with hardware cryptographic keys. |
| **R-03** | Model weight theft or exfiltration | 3 / 5 (15 - Critical) | Model directory mounted strictly read-only (`:ro`). Model container has no external internet egress. Ephemeral `/tmp` on tmpfs (LLM-001). | 1 / 4 (4 - Low) | Inode access monitoring; model process memory dump traps. | AMD SEV-SNP / Intel SGX Confidential Computing memory encryption. |
| **R-04** | Cache-timing side channel (KV cache / CPU microarchitecture) | 4 / 3 (12 - High) | Model pinned to dedicated physical core (Core 0) on Ampere Altra ARM64 (no SMT/hyperthreading). KV and prompt caching disabled (`--cache-prompt false`) (LLM-002, D-CONF-3). | 1 / 2 (2 - Low) | Latency jitter injection on Gateway responses; execution time variance tracking. | Constant-time inference engine implementation. |
| **R-05** | Blue defense extraction via binary oracle probing | 4 / 4 (16 - Critical) | Uniform refusal response for all filter blocks (D-CONF-10); query budget ceiling $Q=200$ (D-CONF-6); theoretical bound $\le 200$ bits per run. | 2 / 2 (4 - Low) | Query similarity clustering in Gateway to detect gradient-free optimization attacks. | Differential privacy budget tracking per evaluated model. |
| **R-06** | Pre-evaluation or in-flight collusion / embargo breach | 3 / 4 (12 - High) | Cryptographic hash commitment of all assets in `COMMITTED` phase before run start. Zero Blue filter visibility granted to Red during evaluation (SEC-002). | 1 / 3 (3 - Low) | Audit ledger phase transition checks; uncommitted asset detection alerts. | Multi-party computation (MPC) for score derivation. |
| **R-07** | Gateway compromise / vulnerability (TCB expansion in Python) | 3 / 4 (12 - High) | Minimal FastAPI surface; unskippable OPA ABAC middleware; Pydantic strict schemas; runs as unprivileged user in hardened container (SEC-001). | 2 / 2 (4 - Low) | Gateway audit log; process crash monitoring; OPA decision logging. | Rewrite Gateway in Go (Rust) with formal TCB verification. |
| **R-08** | Audit log retroactive tampering or truncation | 3 / 5 (15 - Critical) | Append-only SHA-256 hash chain; each block Ed25519-signed; periodic Merkle roots published out-of-band to GitHub/Rekor (AUD-001, AUD-005). | 1 / 3 (3 - Low) | Hash chain verification CLI (`make verify`); cryptographic consistency monitor. | Public blockchain anchoring (Ethereum / Bitcoin OP_RETURN). |
| **R-09** | Evaluator Admin key compromise / rogue operator | 2 / 5 (10 - High) | Dedicated OpenBao roles and distinct step-ca certificates for Admin actions. Dual-custody signing for final score reveal (D-CONF-5). | 1 / 4 (4 - Low) | OpenBao access audit logs; alerting on admin operations outside schedule. | M-of-N threshold multi-signature authorization. |
| **R-10** | DoS via query flooding / resource exhaustion | 4 / 3 (12 - High) | Strict query budget ($Q=200$); token bucket rate limiting (10 req/min); cgroup v2 memory/CPU hard limits on Red container (SEC-009). | 1 / 2 (2 - Low) | Gateway rate-limit metric tracking (HTTP 429 count); cgroup pressure metrics. | Distributed IP reputation and ingress WAF filtering. |
| **R-11** | Model prompt injection inducing toxic/unauthorized output | 5 / 4 (20 - Critical) | Dual-layer Blue defenses: input prompt sanitization filter AND output response safety classifier (SEC-002, FR-004). | 2 / 2 (4 - Low) | Output filter violation logs in Audit Ledger; evaluator alerts. | Dynamic reinforcement learning safety guardrails. |
| **R-12** | Blue filter ReDoS / algorithmic complexity attack | 3 / 3 (9 - Medium) | Strict 500ms execution timeout enforced by Gateway; non-backtracking regex engines; isolated cgroup CPU quota (FR-004). | 1 / 2 (2 - Low) | Upstream latency tracking; circuit breaker trip counters. | WebAssembly (Wasm) sandbox execution for all Blue filters. |
| **R-13** | External anchor outage or rate-limiting (GitHub/Rekor) | 3 / 2 (6 - Medium) | Asynchronous post-run anchoring; local ledger persists independently; retry queue with exponential backoff (AUD-005). | 2 / 1 (2 - Low) | Anchor sync status monitor; commit SHA receipt verification. | Multi-cloud fallback anchor providers. |
| **R-14** | Model server memory leakage across evaluation runs | 3 / 4 (12 - High) | Model container restarted or context memory slot fully reset (`slot_id: -1`) between evaluation runs; `--no-mmap` flag set (LLM-002). | 1 / 2 (2 - Low) | Model container memory footprint differential tracking in Prometheus. | Ephemeral model container destruction and recreation per run. |
| **R-15** | Lateral movement via shared Docker daemon socket | 3 / 5 (15 - Critical) | Docker socket (`/var/run/docker.sock`) is NEVER mounted into any tenant container; daemon protected by rootless/userns-remap (SEC-007). | 1 / 4 (4 - Low) | Host auditd / Falco monitoring for unauthorized socket connection attempts. | Rootless Podman or standalone runc without central daemon. |
| **R-16** | Clock drift or timestamp manipulation in audit ledger | 2 / 3 (6 - Medium) | Host chrony NTP synchronization; block sequence ordered strictly by monotonic integer counter and cryptographic parent hash (AUD-004). | 1 / 1 (1 - Low) | NTP synchronization monitoring; sequence discontinuity detection. | Roughtime secure time protocol integration. |
| **R-17** | Plaintext exploit / attack corpus leakage in audit logs | 3 / 4 (12 - High) | Sensitive attack prompts and zero-day payloads encrypted at rest with `age` public keys; only SHA-256 hashes public in ledger (SEC-014). | 1 / 2 (2 - Low) | Automated DLP scanning on exported audit bundles before release. | Zero-knowledge proof (ZKP) verifiable computations. |
| **R-18** | Supply chain vulnerability in base container images | 3 / 4 (12 - High) | Minimal distroless/Alpine base images; pinned image digests (`@sha256:...`); local build without remote downloads during run (SEC-013). | 1 / 2 (2 - Low) | Trivy container vulnerability scanner in CI/CD pipeline. | Cosign signature verification for all base images. |
| **R-19** | Defense timeout / Failure Open (Previously: Microarchitectural side-channel) | 1 / 2 (2 - Low) | Virtualized cloud VM abstraction. Note: Baseline gateway returns misleading "Blue filter unreachable" on timeout; hardened gateway must distinguish unreachable vs timeout (FR-013). | 1 / 1 (1 - Low) | Timeout metrics in Gateway. | Explicit "defense unavailable" handling in Phase 7. |
| **R-20** | gVisor runtime incompatibility on Model container | 4 / 3 (12 - High) | Evaluated with 1-2h timebox; fallback to hardened `runc` with custom seccomp/AppArmor profile if performance unacceptable (D-CONF-8). | 2 / 2 (4 - Low) | Tokens-per-second benchmark comparing gVisor vs runc on ARM64. | Native Linux KVM MicroVM virtualization. |
| **R-21** | Host kernel eBPF probe bypass or Falco failure | 2 / 4 (8 - Medium) | Falco uses modern eBPF probe mode (bypasses OCI kernel signing issues); systemd watchdog auto-restarts failed agent (SEC-010). | 1 / 2 (2 - Low) | Falco health check heartbeat; systemd journal monitoring. | Redundant kernel auditd logging daemon. |
| **R-22** | False positive cascade in Blue defense halting evaluation | 3 / 3 (9 - Medium) | Evaluation run includes benign calibration benchmark prompts prior to adversarial suite; false positive rate threshold checks. | 2 / 1 (2 - Low) | Gateway tracks block-ratio metrics; alerts if benign queries exceed threshold. | Dynamic human-in-the-loop review for disputed blocks. |

---

## 4. Phase 3 Residual Risk Reconciliation (October 2026)

### 4.1 Verified Mitigations
- **R-02 (Direct Network Pivot / SEC-008):** **MITIGATED & VERIFIED.** Dedicated internal Docker bridge networks (`red-net`, `blue-net`, `model-net`) with static IPAM enforce strict Layer 3 network isolation. Negative tests confirmed Red cannot reach Blue or Model by hostname or container IP (`PASS_ISOLATED`). Residual risk score: **4 (Low)**.

### 4.2 New Risk Finding: Docker Bridge Host Exposure (R-23)
- **Risk ID:** **R-23**
- **Threat / Failure Mode:** Docker bridge gateways assign host kernel IP (`172.20.1.1` on `red-net`). Host services bound to `0.0.0.0` (such as OpenSSH on port 22) were reachable from within tenant containers across the bridge gateway, leaking the SSH daemon banner (`SSH-2.0-OpenSSH_9.6p1`).
- **Pre L / I (Score):** 4 / 4 (16 - Critical)
- **Architectural Mitigation:** Dedicated host firewall table `inet bayora_host_firewall` hooking `input` chain at priority `filter - 1`. Explicitly drops traffic from tenant subnets (`172.20.1.0/24`, `172.20.2.0/24`, `172.20.3.0/24`) destined to host ports while preserving established/related connections, loopback, and admin SSH on `enp0s3`.
- **Post L / I (Score):** 1 / 3 (3 - Low).
- **Current Operational Status:** **MITIGATED & ACTIVE VIA SYSTEMD (`PASS_ISOLATED`).** Applied via `scripts/apply_phase3_host_firewall.sh`; service `/etc/systemd/system/bayora-host-firewall.service` is active and enabled; acceptance test `red_to_bridge_host_sshd` verified `PASS_ISOLATED`. (Note: Cold reboot persistence verification remains an open verification item; safe rollback provided via `scripts/rollback_phase3_host_firewall.sh`).

### 4.3 Unaddressed Risks Remaining Reproducible (Scheduled for Future Phases)
- **R-04 (Cache Timing / LLM-001):** Rerouted through the Evaluation Gateway; cold/warm latency delta ($+3,644.29\text{ ms}$, `cache_n = 67`) remains reproducible until Phase 6 KV prompt cache removal.
- **R-17 / PRIV-001 (Container Log Exposure):** Raw prompts remain visible in `docker logs` at the operator daemon boundary; deferred to Phase 5 encrypted audit ledger.

### 4.4 Operational Risk: Host VM Scheduling & Contention Dilation (R-24)
- **Risk ID:** **R-24**
- **Threat / Failure Mode:** VirtualBox VM vCPUs scheduled across hybrid Intel P/E-cores on Windows 11 host experience guest timer dilation, soft-lockup alarms, and client timeouts under unconstrained multi-core CPU flood.
- **Current Mitigation & Waiver:** Accepted waiver for Phase 2.0 baseline; unconstrained stress testing avoided on VM. Bounded contention benchmark ($\le 2$ stressor cores leaving $\ge 2$ cores free) deferred to Phase 7 cgroup v2 testing.

### 4.5 Scope Risk: Baseline Stub vs. Hardened Gateway Conflation (R-25)
- **Risk ID:** **R-25**
- **Threat / Failure Mode:** Prematurely replacing `services/baseline-stub` would destroy the vulnerable baseline required for scientific before-vs-after regression testing (SEC-001, SEC-008, LLM-001).
- **Architectural Mitigation:** The baseline stub is preserved as `services/baseline-stub` (`version 0.1.0-baseline`). The hardened Evaluation Gateway (`services/evaluation-gateway/`, `version 1.0.0-hardened`) is designed as a separate service toggled via Docker Compose profiles (`COMPOSE_PROFILES=hardened` vs `COMPOSE_PROFILES=baseline`) to strictly preserve the single multi-homed gateway invariant.
