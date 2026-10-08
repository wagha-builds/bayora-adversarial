#!/usr/bin/env bash
set -euo pipefail

# Bayora - Model Download and Verification Wrapper
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Bayora Model Weights Download & Verification ==="
python3 "${SCRIPT_DIR}/download_model.py" --dest-dir "${REPO_ROOT}/models" "$@"
