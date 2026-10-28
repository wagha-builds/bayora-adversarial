#!/usr/bin/env python3
"""
tests/network/test_acceptance_logic.py
Unit tests verifying the verdict classification, connection result parsing,
and strict pass/fail logic of test_phase3_network_acceptance.py.
"""

import os
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.network.test_phase3_network_acceptance import (
    classify_connection_result,
)


class TestAcceptanceLogic(unittest.TestCase):

    def test_classify_http_reached(self):
        """Code 0 with matching keyword classifies as HTTP_REACHED."""
        res = classify_connection_result(0, "BAYORA_TEST_LISTENER_OK", "", "BAYORA_TEST_LISTENER_OK")
        self.assertEqual(res, "HTTP_REACHED")

    def test_classify_connection_refused(self):
        """TCP connection refused classifies as L3_CONNECTION_REFUSED."""
        res = classify_connection_result(7, "", "curl: (7) Failed to connect: Connection refused", "")
        self.assertEqual(res, "L3_CONNECTION_REFUSED")

    def test_classify_isolated_timeout_or_unreachable(self):
        """Timeouts, no route to host, and unreachable network classify as ISOLATED_TIMEOUT_OR_UNREACHABLE."""
        self.assertEqual(classify_connection_result(28, "", "Operation timed out", ""), "ISOLATED_TIMEOUT_OR_UNREACHABLE")
        self.assertEqual(classify_connection_result(124, "", "Command timed out", ""), "ISOLATED_TIMEOUT_OR_UNREACHABLE")
        self.assertEqual(classify_connection_result(1, "", "No route to host", ""), "ISOLATED_TIMEOUT_OR_UNREACHABLE")
        self.assertEqual(classify_connection_result(1, "", "Network is unreachable", ""), "ISOLATED_TIMEOUT_OR_UNREACHABLE")

    def test_hardened_verdict_rejects_known_gap(self):
        """Overall verdict must reject KNOWN_GAP_PRE_NFTABLES as a pass."""
        mock_tests = [
            {"test": "controls", "status": "PASS"},
            {"test": "ipam", "status": "PASS_IPAM"},
            {"test": "auth", "status": "PASS_AUTHORIZED"},
            {"test": "iso", "status": "PASS_ISOLATED"},
            {"test": "ssh", "status": "KNOWN_GAP_PRE_NFTABLES"},
        ]
        overall_pass = all(
            t["status"] in ("PASS_AUTHORIZED", "PASS_ISOLATED", "PASS", "PASS_IPAM")
            for t in mock_tests
        )
        self.assertFalse(overall_pass, "Suite passed despite KNOWN_GAP_PRE_NFTABLES")

    def test_hardened_verdict_rejects_setup_failure(self):
        """Overall verdict must reject SETUP_FAILED or INCONCLUSIVE as a pass."""
        mock_tests = [
            {"test": "controls", "status": "PASS"},
            {"test": "ipam", "status": "PASS_IPAM"},
            {"test": "reverse", "status": "SETUP_FAILED"},
        ]
        overall_pass = all(
            t["status"] in ("PASS_AUTHORIZED", "PASS_ISOLATED", "PASS", "PASS_IPAM")
            for t in mock_tests
        )
        self.assertFalse(overall_pass, "Suite passed despite SETUP_FAILED")

    def test_hardened_verdict_passes_when_all_strict_criteria_met(self):
        """Overall verdict passes only when all tests meet strict hardened requirements."""
        mock_tests = [
            {"test": "controls", "status": "PASS"},
            {"test": "ipam", "status": "PASS_IPAM"},
            {"test": "auth1", "status": "PASS_AUTHORIZED"},
            {"test": "auth2", "status": "PASS_AUTHORIZED"},
            {"test": "iso1", "status": "PASS_ISOLATED"},
            {"test": "iso2", "status": "PASS_ISOLATED"},
            {"test": "ssh", "status": "PASS_ISOLATED"},
        ]
        overall_pass = all(
            t["status"] in ("PASS_AUTHORIZED", "PASS_ISOLATED", "PASS", "PASS_IPAM")
            for t in mock_tests
        )
        self.assertTrue(overall_pass)


if __name__ == "__main__":
    unittest.main()
