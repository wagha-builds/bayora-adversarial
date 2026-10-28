#!/usr/bin/env python3
"""
tests/network/test_firewall_scripts_static.py
Static audit and validation test suite for Phase 3.3 host firewall scripts.

Validates:
1. Root privilege enforcement checks in apply and rollback scripts.
2. Invariant: Neither script uses 'flush ruleset'.
3. Invariant: Neither script modifies or overwrites /etc/nftables.conf.
4. Idempotence: Table creation uses delete-then-create pattern.
5. Isolation: Table name strictly scoped to 'inet bayora_host_firewall'.
6. Persistence: Dedicated systemd service 'bayora-host-firewall.service' configured.
7. Policy: Drops tenant subnets (172.20.1.0/24, 172.20.2.0/24, 172.20.3.0/24) to port 22.
8. Safety: Allows administrative SSH on external interface 'enp0s3'.
9. Rollback: Cleanly removes systemd unit and configuration without touching Docker tables.
"""

import os
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
APPLY_SCRIPT = os.path.join(REPO_ROOT, "scripts", "apply_phase3_host_firewall.sh")
ROLLBACK_SCRIPT = os.path.join(REPO_ROOT, "scripts", "rollback_phase3_host_firewall.sh")


class TestFirewallScriptsStatic(unittest.TestCase):

    def setUp(self):
        with open(APPLY_SCRIPT, "r", encoding="utf-8") as f:
            self.apply_content = f.read()
        with open(ROLLBACK_SCRIPT, "r", encoding="utf-8") as f:
            self.rollback_content = f.read()

    def test_root_privilege_checks(self):
        """Both scripts must check for root EUID before executing privileged commands."""
        self.assertIn('[ "$(id -u)" -ne 0 ]', self.apply_content)
        self.assertIn('[ "$(id -u)" -ne 0 ]', self.rollback_content)

    def test_no_destructive_flush_ruleset(self):
        """Scripts must NEVER run 'flush ruleset' which would wipe Docker forwarding and NAT."""
        self.assertNotIn("flush ruleset", self.apply_content.lower())
        self.assertNotIn("flush ruleset", self.rollback_content.lower())

    def test_no_overwrite_of_nftables_conf(self):
        """Scripts must NEVER overwrite /etc/nftables.conf."""
        self.assertNotIn("/etc/nftables.conf", self.apply_content)
        self.assertNotIn("/etc/nftables.conf", self.rollback_content)

    def test_idempotent_table_declaration(self):
        """Apply script must ensure table declaration is idempotent (table ... delete table ... table { ... })."""
        self.assertIn("table inet bayora_host_firewall", self.apply_content)
        self.assertIn("delete table inet bayora_host_firewall", self.apply_content)

    def test_persistence_systemd_service(self):
        """Apply script must configure and enable bayora-host-firewall.service."""
        self.assertIn("/etc/systemd/system/bayora-host-firewall.service", self.apply_content)
        self.assertIn("systemctl enable bayora-host-firewall.service", self.apply_content)
        self.assertIn("After=network.target docker.service", self.apply_content)

    def test_firewall_policy_rules(self):
        """Ruleset must drop all three tenant subnets to port 22 and host ports."""
        expected_subnets = "172.20.1.0/24, 172.20.2.0/24, 172.20.3.0/24"
        self.assertIn(expected_subnets, self.apply_content)
        self.assertIn("tcp dport 22 counter drop", self.apply_content)
        self.assertIn('iifname "enp0s3" tcp dport 22 accept', self.apply_content)
        self.assertIn('iifname "lo" accept', self.apply_content)
        self.assertIn("ct state established,related accept", self.apply_content)

    def test_rollback_completeness(self):
        """Rollback script must disable service, delete table, and clean up files."""
        self.assertIn("systemctl disable bayora-host-firewall.service", self.rollback_content)
        self.assertIn("nft delete table inet bayora_host_firewall", self.rollback_content)
        self.assertIn("rm -f /etc/systemd/system/bayora-host-firewall.service", self.rollback_content)
        self.assertIn("rm -f /etc/nftables.d/bayora-host-firewall.nft", self.rollback_content)


if __name__ == "__main__":
    unittest.main()
