#!/usr/bin/env bash
# ==============================================================================
# Bayora AppArmor Profiles Loader
# Loads custom Bayora AppArmor profiles into the Linux host kernel.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
POLICIES_DIR="${REPO_ROOT}/policies/apparmor"

echo "[*] Loading Bayora AppArmor profiles..."
if [ ! -d "${POLICIES_DIR}" ]; then
  echo "[!] ERROR: Policies directory not found at ${POLICIES_DIR}"
  exit 1
fi

for profile in "${POLICIES_DIR}"/*; do
  if [ -f "${profile}" ]; then
    fname="$(basename "${profile}")"
    echo "[+] Installing and loading ${fname} to /etc/apparmor.d/${fname}..."
    sudo cp -f "${profile}" "/etc/apparmor.d/${fname}"
    sudo apparmor_parser -r -v "/etc/apparmor.d/${fname}"
  fi
done

echo "[*] Verifying loaded profiles..."
sudo aa-status | grep bayora || true
echo "[+] All Bayora AppArmor profiles successfully installed to /etc/apparmor.d and active."

