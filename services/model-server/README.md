# Model Server Configuration (Phase 1 Baseline)

## Specification
- **Base Image:** `ghcr.io/ggml-org/llama.cpp:server` (multi-arch: x86_64 and aarch64)
- **Model:** `Qwen2.5-1.5B-Instruct-Q4_K_M.gguf`
- **Pinned SHA-256:** `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`
- **Mount:** `/models/qwen2.5-1.5b-instruct-q4_k_m.gguf:/models/model.gguf:ro` (Strictly mounted read-only)
- **Execution Command:**
  ```bash
  -m /models/model.gguf --host 0.0.0.0 --port 8080 -c 2048 -t 2 --cache-prompt
  ```
- **Port:** `8080` (Internal to `model-net`; NOT published to host in Phase 3)
- **Baseline vs. Hardened State:**
  - *Phase 1 Baseline:* Prompt caching enabled (`--cache-prompt`); unauthenticated endpoint accessible directly from all containers across flat bridge network.
  - *Phase 2 Hardening:* Hardened `runc` execution (after gVisor trial measured 9.26x CPU overhead); `cap_drop: ["ALL"]`; `security_opt: [no-new-privileges:true, seccomp=policies/seccomp/model-server-seccomp.json, apparmor=bayora-model-server]`; model weights mounted strictly read-only (`:ro`).
  - *Phase 3 Network Segmentation:* Single-homed on dedicated internal bridge `model-net` (`172.20.3.20`, `internal: true`). Port `8080` removed from host port mappings. Direct access from `red-runner` and `blue-filter` is blocked at Layer 3; accessible exclusively by the Evaluation Gateway (`172.20.3.2`).
  - *Pending Phase 6:* Disabling `--cache-prompt` and enforcing context resets to eliminate the KV-cache timing oracle (LLM-001).
