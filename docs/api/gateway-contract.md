# Bayora Evaluation Gateway API Contract

> **Document Version:** 1.0 (Phase 0 Deliverable)  
> **Status:** RATIFIED  
> **PRD References:** §19, FR-001, FR-002, FR-003, FR-004, SEC-001, SEC-002, AUD-001

---

## 1. Overview & Architectural Role

The **Evaluation Gateway** is the core orchestrator and trusted computing base (TCB) residing in Zone 4 (Control Zone). It terminates all external and cross-zone communications, mediates between Red Team, Blue Defenses, Model Server, and Audit Ledger, and enforces declarative access control policies via an unskippable Open Policy Agent (OPA) middleware.

---

## 2. Gateway Core Invariants

Every API call processed by the Evaluation Gateway MUST satisfy five non-negotiable invariants:

1. **Inv-1 (Deny-by-Default OPA Policy):** Every incoming HTTP request must pass through the OPA middleware before reaching any route handler. If OPA returns `allow: false`, the Gateway immediately aborts with HTTP 403.
2. **Inv-2 (Double Ledger Commit):** For every evaluation query, the Gateway records:
   - Event A: Request arrival with SHA-256 digest of input prompt and metadata (pre-execution).
   - Event B: Query completion with filter verdicts, token counts, and execution latency (post-execution).
3. **Inv-3 (Strict Budget Enforcement):** The Gateway tracks cumulative queries per `run_id`. Once the query count reaches budget $Q$ ($Q=200$ for standard runs, configurable per run manifest), subsequent queries are rejected with HTTP 429.
4. **Inv-4 (Uniform Refusal Semantics):** If Blue input or output filters flag a query as violating safety policies, the Gateway returns HTTP 200 with an identical, invariant refusal string. No information regarding filter identity, scores, or latency is disclosed.
5. **Inv-5 (State-Machine Enforcement):** Requests are only accepted in valid lifecycle states (e.g., `/v1/eval/query` is rejected unless the run is in `RUNNING` state).

---

## 3. All 11 FR-003 Endpoints Specification

### Category A: Run Management & Lifecycle (Evaluator / Admin Only)

#### 1. `POST /v1/eval/runs`
* **Caller:** Evaluator / Admin
* **Permitted Phase:** Any (Creates initial `SETUP` state)
* **Description:** Initializes a new evaluation run manifest.
* **Request Body:**
  ```json
  {
    "run_name": "qwen2.5-jailbreak-eval-01",
    "target_model_id": "model-qwen2.5-1.5b",
    "blue_defense_id": "blue-semantic-shield-v1",
    "query_budget": 200,
    "max_duration_seconds": 3600,
    "metadata": {
      "evaluator": "lead_security_architect",
      "red_suite": "advbench_subset_50"
    }
  }
  ```
* **Response (HTTP 201 Created):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "status": "SETUP",
    "created_at": "2026-10-07T05:00:00Z",
    "query_budget": 200
  }
  ```

#### 2. `GET /v1/eval/runs/{run_id}`
* **Caller:** Evaluator / Admin, Red Team (Read-only status)
* **Permitted Phase:** All
* **Description:** Retrieves the current state, budget usage, and metadata of a run.
* **Response (HTTP 200 OK):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "status": "RUNNING",
    "queries_executed": 42,
    "query_budget": 200,
    "started_at": "2026-10-07T05:05:00Z",
    "target_model": "model-qwen2.5-1.5b"
  }
  ```

#### 3. `POST /v1/eval/runs/{run_id}/commit`
* **Caller:** Evaluator / Admin
* **Permitted Phase:** `SETUP` $\rightarrow$ `COMMITTED`
* **Description:** Freezes attack manifests, defense configurations, and model weights by computing SHA-256 digests and writing the genesis block to the Audit Ledger.
* **Response (HTTP 200 OK):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "status": "COMMITTED",
    "genesis_block_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
  ```

#### 4. `POST /v1/eval/runs/{run_id}/start`
* **Caller:** Evaluator / Admin
* **Permitted Phase:** `COMMITTED` $\rightarrow$ `RUNNING`
* **Description:** Unlocks the evaluation pipeline and authorizes Red Team query submissions.
* **Response (HTTP 200 OK):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "status": "RUNNING",
    "started_at": "2026-10-07T05:05:00Z"
  }
  ```

#### 5. `POST /v1/eval/runs/{run_id}/close`
* **Caller:** Evaluator / Admin
* **Permitted Phase:** `RUNNING` $\rightarrow$ `CLOSED`
* **Description:** Terminates the evaluation session, stops query processing, calculates final block hashes, and triggers Merkle tree root anchoring.
* **Response (HTTP 200 OK):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "status": "CLOSED",
    "closed_at": "2026-10-07T05:45:00Z",
    "total_queries": 200,
    "final_block_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
  }
  ```

---

### Category B: Inference & Evaluation (Red Team & Evaluator)

#### 6. `POST /v1/eval/query`
* **Caller:** Red Team (Zone 1)
* **Permitted Phase:** `RUNNING` only
* **Description:** Primary evaluation endpoint. Receives Red's test prompt, routes through Blue input filter, dispatches to Model if cleared, inspects Model response with Blue output filter, and returns result.
* **Request Body:**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "prompt": "Explain the mechanical design of a clock escapement.",
    "parameters": {
      "max_tokens": 256,
      "temperature": 0.0
    }
  }
  ```
* **Response on Pass (HTTP 200 OK):**
  ```json
  {
    "status": "completed",
    "response": "An escapement is a mechanical linkage in a clock that regulates...",
    "finish_reason": "stop"
  }
  ```
* **Response on Block (HTTP 200 OK — Uniform Refusal):**
  ```json
  {
    "status": "blocked",
    "response": "Request was refused by evaluation safety policy.",
    "finish_reason": "safety_policy"
  }
  ```

#### 7. `GET /v1/eval/runs/{run_id}/budget`
* **Caller:** Red Team, Evaluator
* **Permitted Phase:** `RUNNING`, `CLOSED`
* **Description:** Returns remaining query allowance without disclosing timing or filter statistics.
* **Response (HTTP 200 OK):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "queries_used": 75,
    "queries_remaining": 125,
    "budget_exhausted": false
  }
  ```

---

### Category C: Defense & Model Registration (Admin Only)

#### 8. `POST /v1/admin/defenses/register`
* **Caller:** Evaluator / Admin
* **Permitted Phase:** `SETUP`
* **Description:** Registers a Blue defense container endpoint, input/output inspection contract, and expected SHA-256 binary hash.
* **Request Body:**
  ```json
  {
    "defense_id": "blue-semantic-shield-v1",
    "endpoint_url": "https://blue-defense:8443/inspect",
    "sha256_hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  }
  ```
* **Response (HTTP 200 OK):**
  ```json
  {
    "status": "registered",
    "defense_id": "blue-semantic-shield-v1"
  }
  ```

#### 9. `POST /v1/admin/models/register`
* **Caller:** Evaluator / Admin
* **Permitted Phase:** `SETUP`
* **Description:** Registers the target model server endpoint, verified SHA-256 weights hash, and inference limits.
* **Request Body:**
  ```json
  {
    "model_id": "model-qwen2.5-1.5b",
    "endpoint_url": "https://model-server:8080/completion",
    "weights_sha256": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b74f23f55fb29",
    "context_window": 8192
  }
  ```
* **Response (HTTP 200 OK):**
  ```json
  {
    "status": "registered",
    "model_id": "model-qwen2.5-1.5b"
  }
  ```

---

### Category D: Audit & Ledger Verification (Evaluator & Auditor)

#### 10. `GET /v1/audit/runs/{run_id}/blocks`
* **Caller:** Evaluator / Admin, External Auditor
* **Permitted Phase:** `CLOSED`, `REVEALED`
* **Description:** Exports the signed block sequence for cryptographic audit and verification.
* **Response (HTTP 200 OK):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "total_blocks": 401,
    "blocks": [
      {
        "index": 0,
        "type": "GENESIS",
        "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "block_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "signature": "3045022100..."
      }
    ]
  }
  ```

#### 11. `POST /v1/audit/runs/{run_id}/anchor`
* **Caller:** Evaluator / Admin
* **Permitted Phase:** `CLOSED` $\rightarrow$ `REVEALED`
* **Description:** Manually triggers out-of-band publication of the final Merkle root to the External Trust Anchor (GitHub Private Repo / Rekor).
* **Response (HTTP 200 OK):**
  ```json
  {
    "run_id": "run-f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "anchor_target": "github.com/org/bayora-anchors",
    "commit_sha": "7d5e1b2f8a4c9e0d3b6a1f5c8e2b7a9d0c3e4f5a",
    "status": "anchored"
  }
  ```

---

## 4. Error Taxonomy & Status Codes

All errors returned by the Gateway use RFC 7807 Problem Details formatting:

| HTTP Status | Error Type / Code | Scenario | Leaked Info |
|---|---|---|---|
| **400 Bad Request** | `INVALID_PAYLOAD` | Request does not conform to JSON schema. | Schema validation path only; zero internal state. |
| **403 Forbidden** | `POLICY_DENIED` | OPA policy denies caller role or route access. | Generic message: `Access denied by policy.` |
| **404 Not Found** | `RUN_NOT_FOUND` | Specified `run_id` does not exist. | `Run identifier not found.` |
| **409 Conflict** | `INVALID_LIFECYCLE_STATE` | Action requested is invalid in current run state. | Current state and expected state. |
| **429 Too Many Requests** | `BUDGET_EXHAUSTED` | Query limit $Q$ ($Q=200$) reached. | `Evaluation query budget exhausted.` |
| **500 Internal Error** | `LEDGER_FAILURE` | Audit ledger write failed or socket disconnected. | Platform halts to prevent un-audited evaluation. |
| **504 Gateway Timeout** | `UPSTREAM_TIMEOUT` | Blue filter or Model timed out ($>500$ ms for Blue). | Upstream process failure recorded in audit log. |

---

## 5. Phase 3 Implemented Gateway Network Bindings (October 2026)

### 5.1 Multi-Homed Network Interface Allocation
In Phase 3, the Evaluation Gateway (`bayora-baseline-stub`) operates as the sole multi-homed container across internal zones:

| Interface Network | Gateway IPv4 Address | Permitted Ingress / Egress Roles |
|---|---|---|
| `red-net` (`172.20.1.0/24`) | `172.20.1.2` | Ingress evaluation queries from `bayora-red-runner` (`172.20.1.10`); uniform refusal return. |
| `blue-net` (`172.20.2.0/24`) | `172.20.2.2` | Egress prompt inspection to `bayora-blue-filter` (`172.20.2.10:8001`); ingress filter verdicts. |
| `model-net` (`172.20.3.0/24`) | `172.20.3.2` | Egress prompt dispatch to `bayora-model-server` (`172.20.3.20:8080`); ingress model token streams. |
| `gateway-host-net` (`172.20.0.0/24`) | `172.20.0.2` | Ingress Evaluator / Admin API calls; bound to host port `127.0.0.1:8000:8000`. |

### 5.2 Endpoint Routing in Phase 3
- Red targets `http://baseline-stub:8000/query`, which resolves via `/etc/hosts` to `172.20.1.2`.
- Gateway routes backend filter calls to `http://172.20.2.10:8001` across `blue-net`.
- Gateway routes backend completion calls to `http://172.20.3.20:8080` across `model-net`.
- Host processes interact with the Gateway strictly through `http://127.0.0.1:8000`.

---

## 6. Contract-to-Implementation Gap Matrix (as of 28 October 2026)

> **Important Truthfulness Notice:**
> Sections 1 through 4 define the **normative target API specification**. The actual repository currently runs `services/baseline-stub/` (Phase 1 Insecure Baseline). The hardened Evaluation Gateway (`services/evaluation-gateway/`) is **planned and designed across 5 milestones**, but its production implementation is **not yet started**.

| # | Endpoint & HTTP Method | Category | Contract Role & Permitted State | Baseline Stub (`baseline-stub`) Status | Hardened Gateway Status | Implementation Milestone |
|---|---|---|---|---|---|---|
| 1 | `POST /v1/eval/runs` | A: Lifecycle | Admin (`SETUP` creator) | **NOT IMPLEMENTED** | Planned | Milestone 2 |
| 2 | `GET /v1/eval/runs/{run_id}` | A: Lifecycle | Admin / Red (All states) | **NOT IMPLEMENTED** | Planned | Milestone 2 |
| 3 | `POST /v1/eval/runs/{run_id}/commit` | A: Lifecycle | Admin (`SETUP -> COMMITTED`) | **NOT IMPLEMENTED** | Planned | Milestone 2 |
| 4 | `POST /v1/eval/runs/{run_id}/start` | A: Lifecycle | Admin (`COMMITTED -> RUNNING`) | **NOT IMPLEMENTED** | Planned | Milestone 2 |
| 5 | `POST /v1/eval/runs/{run_id}/close` | A: Lifecycle | Admin (`RUNNING -> CLOSED`) | **NOT IMPLEMENTED** | Planned | Milestone 2 |
| 6 | `POST /v1/eval/query` | B: Inference | Red Team (`RUNNING` only) | **INCOMPATIBLE** (exposes `/runs/{id}/query` & `/query` without OPA, budget, or ledger) | Planned | Milestone 4 |
| 7 | `GET /v1/eval/runs/{run_id}/budget` | B: Inference | Red / Admin (`RUNNING`, `CLOSED`) | **NOT IMPLEMENTED** | Planned | Milestone 3 |
| 8 | `POST /v1/admin/defenses/register` | C: Admin | Admin (`SETUP`) | **NOT IMPLEMENTED** | Planned | Milestone 2 |
| 9 | `POST /v1/admin/models/register` | C: Admin | Admin (`SETUP`) | **NOT IMPLEMENTED** | Planned | Milestone 2 |
| 10 | `GET /v1/audit/runs/{run_id}/blocks` | D: Audit | Admin / Auditor (`CLOSED`, `REVEALED`) | **NOT IMPLEMENTED** | Planned | Milestone 3 |
| 11 | `POST /v1/audit/runs/{run_id}/anchor` | D: Audit | Admin (`CLOSED -> REVEALED`) | **NOT IMPLEMENTED** | Planned | Milestone 3 |

*Authoritative Path Clarification for Endpoint 11:*
The normative endpoint path ratified in this specification is **`POST /v1/audit/runs/{run_id}/anchor`** (Category D: Audit & Ledger Verification). Any informal design references to `/v1/admin/audit/anchor` are strictly superseded by this contract.
