#!/usr/bin/env python3
"""
Leak Test 3: test_fs_blue_rules (SEC-001)
Verifies that Red can read Blue's internal configuration and proprietary rule definitions
directly from the shared Docker named volume (/shared_data/blue_rules.json).
"""

import json
import os
import sys

SHARED_RULES_PATH = "/shared_data/blue_rules.json"


def test_fs_blue_rules() -> dict:
    print(f"[*] Testing filesystem access to shared rules file at {SHARED_RULES_PATH} ...")
    if not os.path.exists(SHARED_RULES_PATH):
        print(f"[-] Shared rules file does not exist at {SHARED_RULES_PATH}")
        return {
            "test": "test_fs_blue_rules",
            "status": "FAIL",
            "detail": f"File {SHARED_RULES_PATH} not found in shared mount"
        }

    try:
        with open(SHARED_RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        salt = data.get("secret_rule_salt")
        keywords = data.get("blocked_keywords", [])
        print(f"[!] SUCCESS (LEAK DEMONSTRATED): Red extracted Blue's rules via shared volume!")
        print(f"    Secret rule salt: {salt}")
        print(f"    Blocked keywords found: {keywords}")

        return {
            "test": "test_fs_blue_rules",
            "status": "PASS",  # PASS means vulnerability successfully reproduced
            "detail": "Red directly read and extracted Blue defense rules from shared storage",
            "secret_salt_leaked": salt,
            "blocked_keywords_count": len(keywords)
        }
    except Exception as e:
        print(f"[-] Failed to read rules file: {e}")
        return {
            "test": "test_fs_blue_rules",
            "status": "FAIL",
            "detail": str(e)
        }


if __name__ == "__main__":
    res = test_fs_blue_rules()
    sys.exit(0 if res["status"] == "PASS" else 1)
