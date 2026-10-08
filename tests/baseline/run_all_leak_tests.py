#!/usr/bin/env python3
"""
Master Leak-Test Suite Runner (Phase 1 Baseline)
Executes all 5 automated leak tests, aggregates results, and saves
a structured evidence report to results/baseline/leak_test_results.json.
In Phase 1, ALL tests MUST PASS (demonstrating that the vulnerabilities exist).
"""

import json
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
RESULTS_DIR = os.path.join(REPO_ROOT, "results", "baseline")


def run_container_test(test_filename: str) -> dict:
    """Execute a test script inside the red-runner container."""
    container_script_path = f"/app/tests/{test_filename}"
    local_script_path = os.path.join(SCRIPT_DIR, test_filename)

    # Copy script into container
    subprocess.run(
        ["docker", "cp", local_script_path, f"bayora-red-runner:{container_script_path}"],
        check=True,
        capture_output=True
    )

    # Run script inside container
    res = subprocess.run(
        ["docker", "exec", "bayora-red-runner", "python", container_script_path],
        capture_output=True,
        text=True
    )

    print(res.stdout)
    if res.stderr:
        print(res.stderr, file=sys.stderr)

    # Parse status
    status = "PASS" if res.returncode == 0 else "FAIL"
    return {
        "test": test_filename.replace(".py", ""),
        "status": status,
        "return_code": res.returncode,
        "stdout": res.stdout.strip()
    }


def run_host_test(test_filename: str) -> dict:
    """Execute a test script directly on host/WSL."""
    local_script_path = os.path.join(SCRIPT_DIR, test_filename)
    res = subprocess.run(
        [sys.executable, local_script_path],
        capture_output=True,
        text=True
    )

    print(res.stdout)
    if res.stderr:
        print(res.stderr, file=sys.stderr)

    status = "PASS" if res.returncode == 0 else "FAIL"
    return {
        "test": test_filename.replace(".py", ""),
        "status": status,
        "return_code": res.returncode,
        "stdout": res.stdout.strip()
    }


def main():
    print("=" * 70)
    print(" BAYORA PHASE 1 — AUTOMATED INSECURE BASELINE LEAK-TEST SUITE")
    print("=" * 70)
    print("[*] Note: A 'PASS' verdict confirms that the intended vulnerability was successfully demonstrated.")
    print("[*] In later hardened phases, these exact tests are expected to FAIL.\n")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    start_time = time.time()
    results = []

    # Ensure /app/tests directory exists inside red-runner
    subprocess.run(["docker", "exec", "bayora-red-runner", "mkdir", "-p", "/app/tests"], check=False)

    tests_in_container = [
        "test_net_blue_direct.py",
        "test_net_model_direct.py",
        "test_fs_blue_rules.py",
        "test_cache_timing.py",
    ]

    for t in tests_in_container:
        print(f"\n--- Running: {t} (inside bayora-red-runner) ---")
        result = run_container_test(t)
        results.append(result)

    print(f"\n--- Running: test_log_exposure.py (from Docker host) ---")
    log_result = run_host_test("test_log_exposure.py")
    results.append(log_result)

    total_duration = time.time() - start_time

    # Summary table
    print("\n" + "=" * 70)
    print(" LEAK TEST RESULTS SUMMARY")
    print("=" * 70)
    print(f"{'TEST NAME':<28} | {'STATUS':<8} | {'MEANING'}")
    print("-" * 70)

    all_passed = True
    for r in results:
        status_str = r['status']
        if status_str != "PASS":
            all_passed = False
        meaning = "Vulnerability Reproduced (Leak Confirmed)" if status_str == "PASS" else "Vulnerability NOT Reproduced (Investigation Required)"
        print(f"{r['test']:<28} | {status_str:<8} | {meaning}")

    print("-" * 70)
    overall_status = "ALL LEAKS CONFIRMED (PASS)" if all_passed else "SOME LEAKS FAILED"
    print(f"Overall Baseline Verdict: {overall_status} ({len(results)} tests in {total_duration:.2f}s)")
    print("=" * 70)

    # Save to JSON
    report_data = {
        "suite": "Phase 1 Insecure Baseline Leak Tests",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(results),
        "all_leaks_confirmed": all_passed,
        "duration_seconds": round(total_duration, 2),
        "results": results
    }

    report_path = os.path.join(RESULTS_DIR, "leak_test_results.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n[+] Full evidence report saved to: {report_path}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
