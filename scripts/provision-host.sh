#!/usr/bin/env bash
# ==============================================================================
# Bayora Host Provisioning Script (Multi-Arch: x86_64 / arm64)
# Compatible with Ubuntu 24.04 LTS (Local VM or Oracle Cloud OCI)
# ==============================================================================
set -euo pipefail

echo "========================================================================"
echo " Starting Bayora Host Provisioning"
echo "========================================================================"

ARCH=$(uname -m)
echo "[*] Detected Architecture: ${ARCH}"

# 1. Update and install core dependencies
echo "[*] Updating apt package lists and installing core utilities..."
sudo apt-get update -y
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    apparmor \
    apparmor-utils \
    jq \
    python3 \
    python3-pip \
    git \
    ufw

# 2. Verify cgroup v2
echo "[*] Verifying cgroup v2..."
CGROUP_TYPE=$(stat -fc %T /sys/fs/cgroup)
if [ "${CGROUP_TYPE}" != "cgroup2fs" ]; then
    echo "[!] WARNING: System is not running cgroup v2 (reported: ${CGROUP_TYPE})."
    echo "    Add 'systemd.unified_cgroup_hierarchy=1' to kernel cmdline if needed."
else
    echo "[+] Confirmed: cgroup v2 is active (cgroup2fs)."
fi

# 3. Verify AppArmor
echo "[*] Verifying AppArmor status..."
if command -v aa-status &>/dev/null; then
    sudo aa-status || echo "[!] AppArmor reported warning/errors."
    echo "[+] AppArmor is present."
else
    echo "[!] AppArmor utilities missing!"
fi

# 4. Install Docker CE (Official Repository)
if ! command -v docker &>/dev/null; then
    echo "[*] Installing Docker Engine..."
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo systemctl enable --now docker
    echo "[+] Docker Engine installed successfully."
else
    echo "[+] Docker is already installed: $(docker --version)"
fi

# Add current user to docker group if not present
if ! groups "$USER" | grep &>/dev/null '\bdocker\b'; then
    echo "[*] Adding user ${USER} to docker group..."
    sudo usermod -aG docker "$USER"
    echo "    (Note: You may need to run 'newgrp docker' or re-login for this to take effect)."
fi

# 5. Install gVisor (runsc) - Architecture Aware
if ! command -v runsc &>/dev/null; then
    echo "[*] Installing gVisor (runsc) for ${ARCH}..."
    GVISOR_URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
    curl -fsSL "${GVISOR_URL}/runsc" -o /tmp/runsc
    curl -fsSL "${GVISOR_URL}/runsc.sha512" -o /tmp/runsc.sha512
    cd /tmp && sha512sum -c runsc.sha512
    sudo chmod a+rx /tmp/runsc
    sudo mv /tmp/runsc /usr/local/bin/runsc
    rm -f /tmp/runsc.sha512
    echo "[+] gVisor installed: $(runsc --version | head -n 1)"
else
    echo "[+] gVisor (runsc) is already installed: $(runsc --version | head -n 1)"
fi

# 6. Configure Docker daemon for gVisor runtime
echo "[*] Configuring Docker daemon to register runsc runtime..."
sudo runsc install
sudo systemctl restart docker
echo "[+] Docker restarted with runsc configured."

# 7. Smoke test runsc with hello-world
echo "[*] Testing gVisor integration with Docker..."
if sudo docker run --rm --runtime=runsc hello-world &>/dev/null; then
    echo "[+] SUCCESS: 'docker run --runtime=runsc hello-world' passed!"
else
    echo "[!] WARNING: runsc smoke test failed. Check daemon.json and dmesg."
fi

# 8. Record Host Fingerprint
echo "[*] Recording host fingerprint..."
FINGERPRINT_FILE="host_fingerprint.json"
cat <<EOF > "${FINGERPRINT_FILE}"
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "hostname": "$(hostname)",
  "architecture": "${ARCH}",
  "kernel": "$(uname -r)",
  "cpu_model": "$(lscpu | grep 'Model name' | sed 's/Model name:[ \t]*//' || echo 'Unknown')",
  "vcpus": $(nproc),
  "total_memory_kb": $(grep MemTotal /proc/meminfo | awk '{print $2}'),
  "cgroup_version": "${CGROUP_TYPE}",
  "docker_version": "$(docker --version 2>/dev/null || echo 'Unknown')",
  "runsc_version": "$(runsc --version 2>/dev/null | head -n 1 || echo 'Unknown')"
}
EOF

echo "[+] Host fingerprint written to $(pwd)/${FINGERPRINT_FILE}:"
cat "${FINGERPRINT_FILE}"

echo "========================================================================"
echo " Host Provisioning Completed Successfully!"
echo "========================================================================"
