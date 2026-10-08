#!/usr/bin/env python3
"""
Leak Test 1: test_net_blue_direct (SEC-008)
Verifies that Red can directly connect to Blue's filter port across the flat bridge network,
bypassing the evaluation gateway entirely.
"""

import sys
import httpx

BLUE_URL = "http://blue-filter:8001"


def test_net_blue_direct() -> dict:
    print(f"[*] Testing direct network connection to Blue filter at {BLUE_URL} ...")
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{BLUE_URL}/rules")
            if resp.status_code == 200:
                data = resp.json()
                print(f"[!] SUCCESS (LEAK DEMONSTRATED): Direct connection to Blue succeeded!")
                print(f"    Extracted rules directly: {len(data.get('blocked_keywords', []))} keywords")
                return {
                    "test": "test_net_blue_direct",
                    "status": "PASS",  # PASS means vulnerability successfully reproduced
                    "detail": "Direct HTTP connection to Blue filter succeeded without gateway",
                    "status_code": resp.status_code,
                    "extracted_rules_count": len(data.get("blocked_keywords", []))
                }
            else:
                return {
                    "test": "test_net_blue_direct",
                    "status": "FAIL",
                    "detail": f"Unexpected status code: {resp.status_code}"
                }
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return {
            "test": "test_net_blue_direct",
            "status": "FAIL",
            "detail": str(e)
        }


if __name__ == "__main__":
    res = test_net_blue_direct()
    sys.exit(0 if res["status"] == "PASS" else 1)
