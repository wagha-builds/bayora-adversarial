#!/usr/bin/env python3
"""
test_resource_contention.py

Baseline Resource Contention Test (PERF-004, RES-004).
Measures the R4 validity distortion by simulating a CPU-bound 
attack from the Red container (burning all available cores) and 
comparing p50, p95, and max latencies against the unloaded baseline.
Also checks for failure-open timeout vulnerabilities (R-19).
"""

import json
import multiprocessing
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://baseline-stub:8000")
RESULTS_PATH = os.environ.get("RESULTS_PATH", "/app/results/contention_baseline_results.json")
NUM_REQUESTS = 15  # 15 requests per condition
BASE_PROMPT = "Summarize the key differences between TCP and UDP protocols."

def cpu_burner():
    """Burns CPU cycles infinitely to cause host contention."""
    while True:
        _ = 999999 ** 2

def run_workload(condition_name, num_requests):
    print(f"\n[*] Starting {condition_name} workload ({num_requests} requests) ...")
    latencies = []
    outcomes = {
        "completed": 0,
        "blue_timeout": 0,
        "model_timeout": 0,
        "error": 0,
        "blue_timeout_passed": 0
    }
    
    for i in range(num_requests):
        # Append unique UUID to force full prompt processing (controls for cache effects)
        prompt = f"{BASE_PROMPT} [Salt: {uuid.uuid4().hex}]"
        
        req = urllib.request.Request(
            f"{GATEWAY_URL}/query",
            data=json.dumps({"prompt": prompt}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        
        start_time = time.time()
        try:
            with urllib.request.urlopen(req, timeout=45.0) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                latency = (time.time() - start_time) * 1000
                latencies.append(latency)
                
                status = result.get("status")
                if status in ["completed", "blocked"]:
                    outcomes["completed"] += 1
                else:
                    outcomes["error"] += 1
                    
        except urllib.error.URLError as e:
            latency = (time.time() - start_time) * 1000
            
            if isinstance(e.reason, socket.timeout):
                outcomes["model_timeout"] += 1
            elif hasattr(e, 'code'):
                try:
                    body = e.read().decode("utf-8")
                    if "timeout" in body.lower():
                        outcomes["blue_timeout"] += 1
                    else:
                        outcomes["error"] += 1
                except:
                    outcomes["error"] += 1
            else:
                outcomes["error"] += 1
        except Exception as e:
            outcomes["error"] += 1
            print(f"\n[!] Request failed: {repr(e)}")
            
        sys.stdout.write(".")
        sys.stdout.flush()
        
    print()
    if not latencies:
        return {"p50_ms": None, "p95_ms": None, "max_ms": None, "outcomes": outcomes, "raw_latencies_ms": []}
        
    lat_sorted = sorted(latencies)
    mid = len(lat_sorted) // 2
    p50 = (lat_sorted[mid - 1] + lat_sorted[mid]) / 2.0 if len(lat_sorted) % 2 == 0 else lat_sorted[mid]
    
    idx_95 = min(int(len(lat_sorted) * 0.95), len(lat_sorted) - 1)
    p95 = lat_sorted[idx_95]
    
    return {
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "max_ms": round(max(latencies), 2),
        "outcomes": outcomes,
        "raw_latencies_ms": [round(l, 2) for l in latencies]
    }

def main():
    print("="*60)
    print(" BASELINE RESOURCE CONTENTION TEST (Phase 1.9b)")
    print("="*60)
    
    core_count = multiprocessing.cpu_count()
    stressor_cores = int(os.environ.get("STRESSOR_CORES", "4"))
    
    # Run Alternating Orders: Unloaded -> Loaded -> Loaded -> Unloaded
    # Round 1: Unloaded
    unloaded_1 = run_workload("UNLOADED (Round 1)", NUM_REQUESTS)
    
    # Start Stress
    print(f"\n[*] Starting Red CPU stressor across {stressor_cores} cores (detected: {core_count} vCPUs)...")
    burners = []
    for _ in range(stressor_cores):
        p = multiprocessing.Process(target=cpu_burner)
        p.daemon = True
        p.start()
        burners.append(p)
        
    try:
        print("[*] Waiting 3 seconds for contention to peak...")
        time.sleep(3)

        # Round 2: Loaded
        loaded_1 = run_workload("LOADED (Round 1)", NUM_REQUESTS)

        # Round 3: Loaded
        loaded_2 = run_workload("LOADED (Round 2)", NUM_REQUESTS)
    finally:
        # Stop Stress reliably under all conditions
        print("\n[*] Stopping Red CPU stressor...")
        for p in burners:
            try:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=1.0)
                    if p.is_alive():
                        p.kill()
            except Exception as e:
                print(f"[!] Warning cleaning up burner: {e}")

    print("[*] Waiting 3 seconds for host to cool down...")
    time.sleep(3)

    # Round 4: Unloaded
    unloaded_2 = run_workload("UNLOADED (Round 2)", NUM_REQUESTS)

    with open("/proc/meminfo", "r") as f:
        meminfo = f.read()
    mem_total = next((line.split()[1] for line in meminfo.split("\n") if "MemTotal" in line), "Unknown")

    # Compute degradation ratio
    # Note: This ratio compares the p50 latency of completed requests across unloaded and loaded conditions.
    # If requests fail or time out (or if the benchmark is interrupted), omitted requests bias completed-request
    # statistics. The ratio is validly interpretable only for complete runs where timeouts and errors are
    # tracked as distinct outcomes; it should not be claimed as an unbiased metric for partial/interrupted runs.
    unloaded_p50s = [u["p50_ms"] for u in [unloaded_1, unloaded_2] if u.get("p50_ms") is not None]
    loaded_p50s = [l["p50_ms"] for l in [loaded_1, loaded_2] if l.get("p50_ms") is not None]
    avg_unloaded_p50 = sum(unloaded_p50s) / len(unloaded_p50s) if unloaded_p50s else None
    avg_loaded_p50 = sum(loaded_p50s) / len(loaded_p50s) if loaded_p50s else None
    degradation_ratio = round(avg_loaded_p50 / avg_unloaded_p50, 2) if (avg_unloaded_p50 and avg_loaded_p50) else None

    report = {
        "test_name": "Resource Contention Distortion (Baseline)",
        "framework_phase": "Phase 1 - Insecure Baseline",
        "environment": os.environ.get("BENCHMARK_ENV", "LOCAL_UBUNTU_VM_VBOX"),
        "host_cores_detected": core_count,
        "stressor_cores_active": stressor_cores,
        "tuning_note": "4 stressor processes + 2 inference threads saturated all 6 vCPUs and still produced soft lockups (see evidence logs). The evidence run used STRESSOR_CORES=4. Use <=2 or a quota in future runs.",
        "host_memory_kb": mem_total,
        "requests_per_condition": NUM_REQUESTS,
        "p50_degradation_ratio": degradation_ratio,
        "results_alternating": {
            "unloaded_1": unloaded_1,
            "loaded_1": loaded_1,
            "loaded_2": loaded_2,
            "unloaded_2": unloaded_2
        }
    }
    
    print("\n--- TEST RESULTS ---")
    print(json.dumps(report, indent=2))
    
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(report, f, indent=2)
        
    print(f"\n[+] Evidence saved to {RESULTS_PATH}")

if __name__ == "__main__":
    sys.exit(main())
