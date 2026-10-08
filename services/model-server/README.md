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
- **Port:** `8080`
- **Insecure Baseline Properties:**
  - Prompt caching enabled by default (`--cache-prompt`).
  - KV-cache reuse enabled across requests, reproducing the timing oracle leak path (PRD LLM-001).
  - Unauthenticated endpoint accessible directly from all containers on default bridge network.
