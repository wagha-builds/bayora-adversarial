#!/usr/bin/env bash
# ==============================================================================
# rollback_phase3_host_firewall.sh
# Safely removes the Bayora Phase 3.3 host firewall table and systemd service.
#
# Safety Guarantees:
# - Disables and removes ONLY the Bayora systemd unit and configuration.
# - Deletes ONLY table 'inet bayora_host_firewall'.
# - Never touches default host nftables configurations or Docker iptables/nftables translation tables.
# ==============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] ERROR: This script requires root privileges."
    echo "    Please run with: sudo bash $0"
    exit 1
fi

echo "[*] Rolling back Bayora Phase 3 host firewall..."

# 1. Stop and disable systemd service
if systemctl is-active --quiet bayora-host-firewall.service 2>/dev/null; then
    echo "[*] Stopping bayora-host-firewall.service..."
    systemctl stop bayora-host-firewall.service
fi

if systemctl is-enabled --quiet bayora-host-firewall.service 2>/dev/null; then
    echo "[*] Disabling bayora-host-firewall.service..."
    systemctl disable bayora-host-firewall.service
fi

# 2. Delete nftables table if still present
echo "[*] Deleting table inet bayora_host_firewall..."
nft delete table inet bayora_host_firewall 2>/dev/null || echo "[*] Table inet bayora_host_firewall does not exist."

# 3. Clean up unit file and configuration
echo "[*] Removing configuration and systemd service files..."
rm -f /etc/systemd/system/bayora-host-firewall.service
rm -f /etc/nftables.d/bayora-host-firewall.nft
systemctl daemon-reload

echo "[+] Rollback complete. Docker and host firewall configurations remain untouched."
