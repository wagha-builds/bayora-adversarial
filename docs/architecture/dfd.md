# Bayora Five-Zone Architecture & Data-Flow Specification

> **Document Version:** 1.0 (Phase 0 Deliverable)  
> **Status:** RATIFIED  
> **PRD References:** §10, §16, §17, §18, SEC-001 through SEC-014, FR-001 through FR-005

---

## 1. Architectural Principles & The Five-Zone Rule

Bayora enforces the **Five-Zone Rule** as its foundational security boundary:

1. **Strict Partitioning:** Every process, container, network interface, file mount, and secret belongs to exactly one zone.
2. **Zero Direct Cross-Zone Traffic:** Direct network routing between tenant zones (e.g., Red to Blue, Red to Model, Blue to Red) is strictly forbidden and cryptographically blocked.
3. **Gateway Mediation:** The **Evaluation Gateway** in Zone 4 (Control Zone) is the sole multihomed mediator. All cross-zone exchanges must terminate at the Gateway, undergo policy validation via Open Policy Agent (OPA), and be committed to the Audit Ledger before dispatch.
4. **Defense in Depth:** Isolation is enforced simultaneously at three tiers:
   - **Layer 3/4:** Isolated Docker bridge networks and host `nftables` rules.
   - **Layer 7:** Mutual TLS (mTLS) with short-lived certificates issued by `step-ca`.
   - **Kernel/Syscall:** gVisor (`runsc`) user-space kernel sandboxing and seccomp-bpf filters.

---

## 2. Five-Zone Architecture Diagram

> **Architecture Scope Note:** The diagram below illustrates the full **Target Architecture (Phases 4–5)**, including the OpenBao secrets engine, `step-ca` PKI, OPA policy sidecar, and Zone 5 append-only audit ledger. The **currently deployed Phase 3 stack** consists of `bayora-red-runner`, `bayora-baseline-stub` (insecure routing stub), `bayora-blue-filter`, and `bayora-model-server` across 4 segmented networks, as detailed in Section 6.

### 2.1 Complete System Topology (Mermaid)

```mermaid
flowchart TB
    subgraph EXT["External Boundary"]
        USER["Evaluator / Admin (Human)"]
        ANCHOR["External Trust Anchor (GitHub / Rekor)"]
    end

    subgraph HOST["Host OS Boundary (Ubuntu 24.04 LTS / ARM64 Ampere Altra)"]
        subgraph Z1["Zone 1: Red Team (Untrusted / Adversary)"]
            RED["Red Harness / Attack Client<br/>(gVisor runsc sandbox)"]
        end

        subgraph Z4["Zone 4: Control Zone (Trust Root & Mediation)"]
            GW["Evaluation Gateway<br/>(FastAPI Orchestrator)"]
            OPA["Policy Engine<br/>(Open Policy Agent)"]
            BAO["Secrets Engine<br/>(OpenBao)"]
            CA["Internal PKI<br/>(step-ca)"]
            GW <--> OPA
            GW <--> BAO
            GW <--> CA
        end

        subgraph Z2["Zone 2: Blue Team (Proprietary Defenses)"]
            BLUE_IN["Input Sanitizer & Classifier<br/>(Sealed Runtime)"]
            BLUE_OUT["Output Leak Detector<br/>(Sealed Runtime)"]
        end

        subgraph Z3["Zone 3: Model Zone (Target LLM)"]
            MODEL["llama.cpp Server<br/>(Qwen2.5-1.5B Q4_K_M)<br/>[No KV/Prompt Cache]"]
        end

        subgraph Z5["Zone 5: Audit Zone (Immutable Ledger)"]
            LEDGER["Append-Only Ledger<br/>(SHA-256 Chain + Ed25519)"]
            TEL["Telemetry Collector<br/>(eBPF / Falco)"]
            LEDGER --- TEL
        end
    end

    %% Network Flows & Crossings
    USER == "X5: Admin Auth (mTLS / Token)" ==> GW
    RED == "X1: Evaluator API / Submit Query" ==> GW
    GW == "X2a: Inspect Prompt" ==> BLUE_IN
    BLUE_IN == "Verdict (Allow/Block)" ==> GW
    GW == "X3a: Forward Prompt" ==> MODEL
    MODEL == "Raw LLM Tokens" ==> GW
    GW == "X2b: Inspect Response" ==> BLUE_OUT
    BLUE_OUT == "Verdict (Allow/Block)" ==> GW
    GW == "Uniform Refusal or Filtered Output" ==> RED
    GW == "X4: Append Event" ==> LEDGER
    LEDGER == "X6: Publish Merkle Root" ==> ANCHOR
    
    %% Kernel Boundary
    RED -.- "X7: Syscall Virtualization" -.- HOST
    BLUE_IN -.- "X7: Syscall Virtualization" -.- HOST
    MODEL -.- "X7: Syscall Virtualization" -.- HOST
```

### 2.2 Text / ASCII Flow Topology

```
+-----------------------------------------------------------------------------------------+
|                                    HOST OS BOUNDARY                                     |
|                                                                                         |
|  +--------------------+         [X1: HTTP]          +--------------------------------+  |
|  |    ZONE 1: RED     | --------------------------> |        ZONE 4: CONTROL         |  |
|  |  Adversary Client  | <-------------------------- |  Evaluation Gateway + OPA      |  |
|  |  (gVisor runsc)    |      [Uniform Refusal]      |  (Multi-homed Orchestrator)    |  |
|  +--------------------+                             +---------------+----------------+  |
|                                                                     |                   |
|                   +-------------------------------------------------+                   |
|                   |                         |                       |                   |
|                   | [X2: mTLS]              | [X3: mTLS]            | [X4: IPC/Socket]  |
|                   v                         v                       v                   |
|          +------------------+      +------------------+    +------------------+         |
|          |   ZONE 2: BLUE   |      |   ZONE 3: MODEL  |    |  ZONE 5: AUDIT   |         |
|          | Defense Filters  |      | llama.cpp Server |    | Append-Only Log  |         |
|          | (Sealed Runtime) |      | (Cache Disabled) |    | (Ed25519 Signed) |         |
|          +------------------+      +------------------+    +--------+---------+         |
|                                                                     |                   |
+---------------------------------------------------------------------|-------------------+
                                                                      | [X6: HTTPS]
                                                                      v
                                                           +--------------------+
                                                           | EXTERNAL TRUST     |
                                                           | ANCHOR (Git/Rekor) |
                                                           +--------------------+
```

---

## 3. Trust Boundary Crossings Matrix

The architecture defines eight distinct trust crossings. Each crossing represents a change in trust tier, authorization context, and threat profile.

| Crossing | Source Zone | Destination Zone | Protocol / Transport | Authentication & Authz | Directionality | PRD Reference |
|---|---|---|---|---|---|---|
| **X1** | Zone 1 (Red) | Zone 4 (Control) | HTTP / REST | Bearer Token / API Key (Red Role) | Bidirectional (Req/Resp) | SEC-001, FR-003 |
| **X2** | Zone 4 (Control) | Zone 2 (Blue) | HTTP / mTLS | Mutual TLS (`step-ca` issued certs) | Bidirectional (Req/Resp) | SEC-002, FR-004 |
| **X3** | Zone 4 (Control) | Zone 3 (Model) | HTTP / mTLS | Mutual TLS (`step-ca` issued certs) | Bidirectional (Req/Resp) | SEC-003, LLM-001 |
| **X4** | Zone 4 (Control) | Zone 5 (Audit) | Unix Domain Socket / mTLS | Zone 4 Service Credential | Write-Only (Append) | SEC-004, AUD-001 |
| **X5** | External Evaluator | Zone 4 (Control) | HTTPS / CLI | Admin Token / Evaluator Client Cert | Bidirectional (Mgmt) | FR-001, SEC-005 |
| **X6** | Zone 5 (Audit) | External Anchor | HTTPS (GitHub / Rekor API) | Fine-grained Personal Access Token | Egress-Only (Publish) | SEC-006, AUD-005 |
| **X7** | Sandboxed Workloads | Host Kernel | Syscalls (gVisor `runsc` virtualized) | Kernel Capabilities / seccomp | Syscall Trap / Filter | SEC-007, SEC-011 |
| **X8** | Zone 4 (Control) | OpenBao / `step-ca` | HTTPS / mTLS | AppRole / Token authentication | Internal Zone 4 | SEC-012, SEC-013 |

> **Note on Crossings vs. STRIDE Matrix (42 Cells):**  
> Crossings **X1 through X7** represent inter-zone, cross-tenant, host-kernel, or external trust-boundary crossings. These 7 crossings are systematically analyzed across the 6 STRIDE categories ($7 \times 6 = 42\text{ cells}$) in [`docs/threat-model/stride.md`](../threat-model/stride.md). Crossing **X8** represents intra-zone communication within the Control Zone TCB (Gateway to OpenBao / `step-ca`), contained within the same trust tier and secured by local mTLS and AppRole authentication.

---

## 4. Boundary Content & Inspection Rules

To prevent side-channel leakage, defense profiling, and prompt extraction, the Gateway enforces strict content transformation rules at each boundary:

### 4.1 Crossing X1 (Red $\leftrightarrow$ Gateway)
- **Ingress Inspection:**
  - Red payload must be JSON with schema: `{"run_id": str, "prompt": str, "target_model": str, "metadata": dict}`.
  - Max prompt size: 8,192 tokens / 32 KB.
  - Rate limiting & budget check: Rejects requests if cumulative query count exceeds budget $Q$ ($Q=200$ for standard runs).
- **Egress Transformation:**
  - If Blue filters block the prompt OR response: Gateway returns HTTP 200 with a **uniform refusal string**:  
    `{"status": "blocked", "response": "Request was refused by evaluation safety policy."}`.
  - Zero information is returned regarding which filter triggered, rule IDs, detection scores, or execution latency.
  - Jittered response delay is injected to normalize timing distributions and defeat timing-based oracle extraction.

### 4.2 Crossing X2 (Gateway $\leftrightarrow$ Blue Defense)
- **Input Inspection:** Prompt is forwarded with isolated ephemeral context. Blue receives only the prompt text and anonymized query index.
- **Output Inspection:** If the model returns tokens, the completion is forwarded to Blue's output filter before Red ever receives it.
- **Isolation Guarantee:** Blue has zero visibility into Red client state, IP addresses, or historical query sequences.

### 4.3 Crossing X3 (Gateway $\leftrightarrow$ Model Server)
- **Stateless Invocation:** Prompt is dispatched to `llama.cpp` over mTLS.
- **Cache Invalidation:** Every inference request mandates `cache_prompt: false` and `slot_id: -1` (fresh context slot). No KV state is retained across requests.
- **Generation Bounds:** Enforces strict temperature, top-p, seed pinning, and max response token limits.

### 4.4 Crossing X4 (Gateway $\leftrightarrow$ Audit Ledger)
- **Non-blocking Write:** Evaluation events (prompt hash, completion hash, filter verdicts, timing metrics) are pushed to the ledger socket.
- **Redaction Policy:** Prompts flagged as confidential or containing adversarial exploits are stored encrypted using `age` public keys; only cryptographic hashes (SHA-256) and signatures are stored in plaintext.

---

## 5. Network Isolation Matrix

The host firewall (`nftables`) and Docker engine configuration enforce the following connectivity rules:

| From Zone \ To Zone | Zone 1 (Red) | Zone 2 (Blue) | Zone 3 (Model) | Zone 4 (Control) | Zone 5 (Audit) | Internet / External |
|---|---|---|---|---|---|---|
| **Zone 1 (Red)** | Local Only | **DENIED** | **DENIED** | **ALLOWED (Port 8000)** | **DENIED** | **DENIED** |
| **Zone 2 (Blue)** | **DENIED** | Local Only | **DENIED** | **ALLOWED (mTLS)** | **DENIED** | **DENIED** |
| **Zone 3 (Model)** | **DENIED** | **DENIED** | Local Only | **ALLOWED (mTLS)** | **DENIED** | **DENIED** |
| **Zone 4 (Control)**| **ALLOWED (Resp)** | **ALLOWED (mTLS)** | **ALLOWED (mTLS)** | Local Only | **ALLOWED (mTLS/IPC)**| **DENIED (Except Admin)** |
| **Zone 5 (Audit)** | **DENIED** | **DENIED** | **DENIED** | **ALLOWED (Resp)** | Local Only | **ALLOWED (Egress Anchor)**|

**Core Guarantee:** The only container with multi-interface access is the Evaluation Gateway in Zone 4. All inter-zone routing via IP forwarding is disabled at the host kernel (`net.ipv4.ip_forward = 0`).

---

## 6. Phase 3 Implemented Network Topology & Verification (October 2026)

### 6.1 Implemented Zone Subnets & Static Addresses
In Phase 3, the DFD network boundaries were materialized using 4 distinct Docker networks with explicit IPAM:
- **`red-net` (`172.20.1.0/24`, `internal: true`):**
  - `bayora-red-runner`: `172.20.1.10`
  - `bayora-baseline-stub` (Gateway): `172.20.1.2`
- **`blue-net` (`172.20.2.0/24`, `internal: true`):**
  - `bayora-blue-filter`: `172.20.2.10`
  - `bayora-baseline-stub` (Gateway): `172.20.2.2`
- **`model-net` (`172.20.3.0/24`, `internal: true`):**
  - `bayora-model-server`: `172.20.3.20`
  - `bayora-baseline-stub` (Gateway): `172.20.3.2`
- **`gateway-host-net` (`172.20.0.0/24`, `internal: false`):**
  - `bayora-baseline-stub` (Gateway): `172.20.0.2` [Published: `127.0.0.1:8000:8000`]

### 6.2 Empirical Isolation Verification
Verified via `tests/network/test_phase3_network_acceptance.py`:
1. **Red $\rightarrow$ Gateway (X1):** `PASS_AUTHORIZED` (resolves `172.20.1.2`, HTTP 200).
2. **Gateway $\rightarrow$ Blue (X2) & Gateway $\rightarrow$ Model (X3):** `PASS_AUTHORIZED` (backend health checks pass).
3. **Cross-Zone Denials (Red $\rightarrow$ Blue, Red $\rightarrow$ Model, Blue $\leftrightarrow$ Model):** `PASS_ISOLATED` (timed out or unreachable; no L3 route).
4. **Reverse Probes (Blue $\rightarrow$ Red, Model $\rightarrow$ Red):** `PASS_ISOLATED` (fails to reach Red's dedicated probe server on `172.20.1.10:8088`, using `scripts/test_listener_server.py`).
5. **Bridge Host Exposure (Phase 3.3):** Red $\rightarrow$ `172.20.1.1:22` (Host SSH) is blocked (`PASS_ISOLATED`, packets dropped by `inet bayora_host_firewall`). The table is persistent via systemd service `bayora-host-firewall.service` (with cold reboot verification pending).
6. **Overall Suite Verdict:** `PASS (All Hardened Policies Enforced)` (17/17 checks passed).
