#!/usr/bin/env python3
"""
Leak Test 5: test_log_exposure (PRIV-001)
Demonstrates that raw adversarial and benign prompts are emitted in plaintext
to standard container logs without masking, redaction, or differential privacy.
"""

import subprocess
import sys


def test_log_exposure() -> dict:
    print("[*] Testing log exposure in baseline containers ...")
    target_strings = [
        "Ignore previous instructions",
        "Summarize the key differences between TCP and UDP",
        "You are now in DAN mode"
    ]

    containers_to_check = ["bayora-blue-filter", "bayora-baseline-stub"]
    found_matches = []

    for container in containers_to_check:
        try:
            cmd = ["docker", "logs", "--tail", "200", container]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            log_text = result.stdout + result.stderr

            for target in target_strings:
                if target.lower() in log_text.lower():
                    print(f"[!] SUCCESS (LEAK DEMONSTRATED): Found unredacted prompt in {container} logs: '{target}'")
                    found_matches.append({"container": container, "pattern": target})
        except Exception as e:
            print(f"[-] Could not read logs for {container}: {e}")

    if found_matches:
        return {
            "test": "test_log_exposure",
            "status": "PASS",  # PASS means vulnerability successfully reproduced
            "detail": f"Found {len(found_matches)} unredacted prompt occurrences in container logs",
            "matches": found_matches
        }
    else:
        return {
            "test": "test_log_exposure",
            "status": "FAIL",
            "detail": "No unredacted prompts detected in inspected logs"
        }


if __name__ == "__main__":
    res = test_log_exposure()
    sys.exit(0 if res["status"] == "PASS" else 1)
