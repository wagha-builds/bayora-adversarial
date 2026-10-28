#!/usr/bin/env bash
# ==============================================================================
# apply_phase3_host_firewall.sh
# Phase 3.3 Host Firewall Remediation (Docker Bridge Host Exposure)
#
# Threat Model:
# Docker bridge networks assign the host kernel as the default gateway IP
# (e.g., 172.20.1.1 on red-net). Services listening on 0.0.0.0 (such as OpenSSH
# on port 22) are directly exposed to tenant containers across the bridge.
#
# Remediation & Persistence Architecture:
# 1. Installs an isolated nftables configuration at /etc/nftables.d/bayora-host-firewall.nft.
# 2. Creates a dedicated systemd oneshot service (bayora-host-firewall.service)
#    configured with 'After=network.target docker.service'.
# 3. Enables the service so the ruleset persists across host reboots automatically.
#
# Safety Guarantees:
# - Strictly never flushes entire rulesets or modifies the host default nftables configuration.
# - Preserves existing Docker iptables/nftables forwarding and NAT rules.
# - Preserves established/related connections and loopback traffic.
# - Preserves external administrative SSH on enp0s3 (never locks out operator).
# - Idempotent: safe to run multiple times without duplicate rules or errors.
# - Creates pre-change backup and post-change ruleset capture in results/.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${REPO_ROOT}/results/hardening/phase3-network/local-ubuntu-vm"

mkdir -p "${EVIDENCE_DIR}"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "=== Bayora Phase 3.3 Host Firewall Remediation ==="
echo "Timestamp (UTC): ${TIMESTAMP}"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] ERROR: This script requires root privileges to configure host nftables."
    echo "    Please run with: sudo bash $0"
    exit 1
fi

# 1. Backup current nftables ruleset
BACKUP_FILE="${EVIDENCE_DIR}/nftables_backup_pre_phase3.3.nft"
echo "[*] Capturing pre-change firewall ruleset to ${BACKUP_FILE}..."
nft list ruleset > "${BACKUP_FILE}" 2>/dev/null || echo "# nftables empty or uninitialized" > "${BACKUP_FILE}"

# 2. Write dedicated nftables configuration file
CONFIG_DIR="/etc/nftables.d"
CONFIG_FILE="${CONFIG_DIR}/bayora-host-firewall.nft"
mkdir -p "${CONFIG_DIR}"

echo "[*] Writing persistent ruleset to ${CONFIG_FILE}..."
cat > "${CONFIG_FILE}" << 'EOF'
# ==============================================================================
# Bayora Host Firewall Ruleset
# Blocks tenant bridge traffic to host services (including SSH port 22)
# Allows administrative SSH on external interface enp0s3
# ==============================================================================

table inet bayora_host_firewall
delete table inet bayora_host_firewall

table inet bayora_host_firewall {
    chain input {
        type filter hook input priority filter - 1; policy accept;

        # 1. Allow established and related connections
        ct state established,related accept

        # 2. Allow loopback traffic
        iifname "lo" accept

        # 3. Allow administrative SSH from external/host-NAT interface
        iifname "enp0s3" tcp dport 22 accept

        # 4. Explicitly drop tenant bridge traffic to host SSH (port 22)
        ip saddr { 172.20.1.0/24, 172.20.2.0/24, 172.20.3.0/24 } tcp dport 22 counter drop

        # 5. Drop any attempts from tenant bridges to host-bound ports
        ip saddr { 172.20.1.0/24, 172.20.2.0/24, 172.20.3.0/24 } counter drop
    }
}
EOF

chmod 0644 "${CONFIG_FILE}"

# 3. Create dedicated systemd oneshot service for reboot persistence
SERVICE_FILE="/etc/systemd/system/bayora-host-firewall.service"
echo "[*] Configuring persistence service at ${SERVICE_FILE}..."
cat > "${SERVICE_FILE}" << 'EOF'
[Unit]
Description=Bayora Phase 3 Host Firewall (Tenant-to-Host Isolation)
After=network.target docker.service
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables.d/bayora-host-firewall.nft
ExecStop=/usr/sbin/nft delete table inet bayora_host_firewall

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "${SERVICE_FILE}"

# 4. Reload systemd, enable and activate service
echo "[*] Enabling and starting bayora-host-firewall.service..."
systemctl daemon-reload
systemctl enable bayora-host-firewall.service
systemctl restart bayora-host-firewall.service

# 5. Verify active table and capture post-change ruleset
POST_RULES_FILE="${EVIDENCE_DIR}/nftables_ruleset_post_phase3.3.nft"
echo "[*] Capturing post-change firewall ruleset to ${POST_RULES_FILE}..."
nft list table inet bayora_host_firewall > "${POST_RULES_FILE}"

echo "[+] Phase 3.3 host firewall rules successfully applied and enabled for persistence!"
echo "    Table: inet bayora_host_firewall"
echo "    Service: bayora-host-firewall.service (enabled)"
echo "    Blocked subnets to host: 172.20.1.0/24 (red), 172.20.2.0/24 (blue), 172.20.3.0/24 (model)"
echo ""
nft list table inet bayora_host_firewall
