#!/usr/bin/env python3
"""
test_unloaded_recovery.py
Post-contention unloaded recovery check (Phase 2.0 VM Baseline).
Evaluates whether baseline latency returns to normal after the 
4-core contention stressor was stopped and VM recovered.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://baseline-stub:8000")
RESULTS_PATH = os.environ.get("RESULTS_PATH", "/app/results/local-ubuntu-vm/unloaded_recovery_results.json")
NUM_REQUESTS = int(os.environ.get("NUM_REQUESTS", "10"))
BASE_PROMPT = "Summarize the key differences between TCP and UDP protocols."


def main():
    print("=" * 60)
    print(" UNLOADED RECOVERY CHECK (Post-Contention Baseline)")
    print(f" Target: {GATEWAY_URL} | Requests: {NUM_REQUESTS}")
    print("=" * 60)

    latencies = []
    outcomes = {
        "completed": 0,
        "timeout": 0,
        "error": 0
    }

    start_total = time.time()
    for i in range(NUM_REQUESTS):
        prompt = f"{BASE_PROMPT} [Salt: {uuid.uuid4().hex}]"
        req = urllib.request.Request(
            f"{GATEWAY_URL}/query",
            data=json.dumps({"prompt": prompt}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=45.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                dt_ms = (time.time() - t0) * 1000
                latencies.append(dt_ms)
                if data.get("status") in ["completed", "blocked"]:
                    outcomes["completed"] += 1
                else:
                    outcomes["error"] += 1
                print(f"[{i+1:02d}/{NUM_REQUESTS}] Completed in {dt_ms:.2f} ms")
        except urllib.error.URLError as e:
            dt_ms = (time.time() - t0) * 1000
            outcomes["timeout"] += 1
            print(f"[{i+1:02d}/{NUM_REQUESTS}] Timeout/URLError after {dt_ms:.2f} ms: {e}")
        except Exception as e:
            dt_ms = (time.time() - t0) * 1000
            outcomes["error"] += 1
            print(f"[{i+1:02d}/{NUM_REQUESTS}] Error after {dt_ms:.2f} ms: {e}")

    total_duration = time.time() - start_total

    if not latencies:
        print("\n[!] No successful requests recorded.")
        sys.exit(1)

    lat_sorted = sorted(latencies)
    mid = len(lat_sorted) // 2
    p50 = (lat_sorted[mid - 1] + lat_sorted[mid]) / 2.0 if len(lat_sorted) % 2 == 0 else lat_sorted[mid]
    idx_95 = min(int(len(lat_sorted) * 0.95), len(lat_sorted) - 1)
    p95 = lat_sorted[idx_95]
    max_ms = max(latencies)

    report = {
        "test_name": "Post-Contention Unloaded Recovery Check",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": "LOCAL_UBUNTU_VM_VBOX",
        "requests_total": NUM_REQUESTS,
        "completed_count": outcomes["completed"],
        "timeout_count": outcomes["timeout"],
        "error_count": outcomes["error"],
        "total_duration_seconds": round(total_duration, 2),
        "latency_metrics": {
            "p50_ms": round(p50, 2),
            "p95_ms": round(p95, 2),
            "max_ms": round(max_ms, 2)
        },
        "raw_latencies_ms": [round(l, 2) for l in latencies],
        "notes": "Executed on healthy VM after 4-core contention stressor was halted. Compares recovery latency to initial unloaded performance; similarity demonstrates operational recovery but does not prove total absence of subtle state drift."
    }

    print("\n" + "=" * 60)
    print(" RECOVERY CHECK RESULTS")
    print("=" * 60)
    print(f"Completed: {outcomes['completed']}/{NUM_REQUESTS}")
    print(f"p50 Latency: {p50:.2f} ms")
    print(f"p95 Latency: {p95:.2f} ms")
    print(f"Max Latency: {max_ms:.2f} ms")
    print("=" * 60)

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Results saved to {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
