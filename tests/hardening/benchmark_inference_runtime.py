#!/usr/bin/env python3
"""
benchmark_inference_runtime.py
Phase 2.1 Bounded Inference & Runtime Overhead Benchmark.
Measures end-to-end gateway latency and model server token generation metrics
(tokens/sec, ms/token) across reproducible, salted requests.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid


GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000")
NUM_REQUESTS = int(os.environ.get("NUM_REQUESTS", "10"))
BENCHMARK_LABEL = os.environ.get("BENCHMARK_LABEL", "reference_runc")
RUNTIME_UNDER_TEST = os.environ.get("RUNTIME_UNDER_TEST", "runc")
RESULTS_PATH = os.environ.get("RESULTS_PATH", "")
BASE_PROMPT = "Summarize the key differences between TCP and UDP protocols."
TIMEOUT_SECS = float(os.environ.get("TIMEOUT_SECS", "45.0"))


def percentile(data, p):
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * (p / 100.0))
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]


def median(data):
    if not data:
        return 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    mid = n // 2
    if n % 2 == 0:
        return (sorted_data[mid - 1] + sorted_data[mid]) / 2.0
    return float(sorted_data[mid])


def main():
    print("=" * 65)
    print(f" BAYORA RUNTIME INFERENCE BENCHMARK ({BENCHMARK_LABEL})")
    print(f" Target: {GATEWAY_URL}/query | Runtime: {RUNTIME_UNDER_TEST} | Requests: {NUM_REQUESTS}")
    print("=" * 65)

    records = []
    latencies = []
    tokens_per_sec_list = []
    ms_per_token_list = []
    outcomes = {"completed": 0, "timeout": 0, "error": 0}

    wall_start = time.time()
    for i in range(NUM_REQUESTS):
        salt = uuid.uuid4().hex[:12]
        prompt = f"{BASE_PROMPT} [Salt: {salt}]"
        payload = json.dumps({"prompt": prompt}).encode("utf-8")
        req = urllib.request.Request(
            f"{GATEWAY_URL}/query",
            data=payload,
            headers={"Content-Type": "application/json"}
        )

        t0 = time.time()
        req_record = {
            "request_index": i + 1,
            "salt": salt,
            "status": "pending",
            "client_elapsed_ms": None,
            "timings": None,
            "tokens_predicted": None
        }

        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                elapsed_ms = (time.time() - t0) * 1000
                data = json.loads(resp.read().decode("utf-8"))
                req_record["client_elapsed_ms"] = round(elapsed_ms, 2)
                latencies.append(elapsed_ms)

                if data.get("status") in ["completed", "blocked"]:
                    outcomes["completed"] += 1
                    req_record["status"] = data.get("status")
                else:
                    outcomes["error"] += 1
                    req_record["status"] = "upstream_error"

                timings = data.get("timings")
                if timings:
                    req_record["timings"] = timings
                    tps = timings.get("predicted_per_second")
                    ms_pt = timings.get("predicted_per_token_ms")
                    pred_n = timings.get("predicted_n")
                    req_record["tokens_predicted"] = pred_n
                    if tps:
                        tokens_per_sec_list.append(tps)
                    if ms_pt:
                        ms_per_token_list.append(ms_pt)

                tps_str = f"{timings.get('predicted_per_second', 0):.2f} tok/s" if timings else "N/A"
                print(f"[{i+1:02d}/{NUM_REQUESTS}] {req_record['status']} in {elapsed_ms:.2f} ms | Gen: {tps_str}")
        except urllib.error.URLError as e:
            elapsed_ms = (time.time() - t0) * 1000
            outcomes["timeout"] += 1
            req_record["status"] = "timeout"
            req_record["client_elapsed_ms"] = round(elapsed_ms, 2)
            req_record["error"] = str(e)
            print(f"[{i+1:02d}/{NUM_REQUESTS}] TIMEOUT after {elapsed_ms:.2f} ms: {e}")
        except Exception as e:
            elapsed_ms = (time.time() - t0) * 1000
            outcomes["error"] += 1
            req_record["status"] = "client_error"
            req_record["client_elapsed_ms"] = round(elapsed_ms, 2)
            req_record["error"] = repr(e)
            print(f"[{i+1:02d}/{NUM_REQUESTS}] ERROR after {elapsed_ms:.2f} ms: {e}")

        records.append(req_record)

    total_wall_time = time.time() - wall_start

    p50_lat = median(latencies)
    p95_lat = percentile(latencies, 95)
    mean_lat = sum(latencies) / len(latencies) if latencies else 0.0
    min_lat = min(latencies) if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0

    p50_tps = median(tokens_per_sec_list)
    mean_tps = sum(tokens_per_sec_list) / len(tokens_per_sec_list) if tokens_per_sec_list else 0.0

    p50_ms_pt = median(ms_per_token_list)
    mean_ms_pt = sum(ms_per_token_list) / len(ms_per_token_list) if ms_per_token_list else 0.0

    report = {
        "benchmark_label": BENCHMARK_LABEL,
        "runtime_under_test": RUNTIME_UNDER_TEST,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_url": GATEWAY_URL,
        "requests_requested": NUM_REQUESTS,
        "outcomes": outcomes,
        "total_wall_duration_seconds": round(total_wall_time, 2),
        "latency_metrics_ms": {
            "p50": round(p50_lat, 2),
            "p95": round(p95_lat, 2),
            "mean": round(mean_lat, 2),
            "min": round(min_lat, 2),
            "max": round(max_lat, 2)
        },
        "throughput_metrics": {
            "p50_tokens_per_second": round(p50_tps, 2),
            "mean_tokens_per_second": round(mean_tps, 2),
            "p50_ms_per_token": round(p50_ms_pt, 2),
            "mean_ms_per_token": round(mean_ms_pt, 2)
        },
        "raw_latencies_ms": [round(l, 2) for l in latencies],
        "detailed_records": records
    }

    print("\n" + "=" * 65)
    print(f" BENCHMARK SUMMARY ({BENCHMARK_LABEL} — {RUNTIME_UNDER_TEST})")
    print("=" * 65)
    print(f" Completed: {outcomes['completed']}/{NUM_REQUESTS} | Timeouts: {outcomes['timeout']} | Errors: {outcomes['error']}")
    print(f" End-to-End Latency: p50 = {p50_lat:.2f} ms | p95 = {p95_lat:.2f} ms | min = {min_lat:.2f} ms | max = {max_lat:.2f} ms")
    if tokens_per_sec_list:
        print(f" Generation Speed:   p50 = {p50_tps:.2f} tok/s | mean = {mean_tps:.2f} tok/s")
        print(f" Token Latency:      p50 = {p50_ms_pt:.2f} ms/token | mean = {mean_ms_pt:.2f} ms/token")
    print(f" Wall Duration:     {total_wall_time:.2f} s")
    print("=" * 65)

    if RESULTS_PATH:
        os.makedirs(os.path.dirname(os.path.abspath(RESULTS_PATH)), exist_ok=True)
        with open(RESULTS_PATH, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Results saved to: {RESULTS_PATH}")

    return 0 if outcomes["completed"] == NUM_REQUESTS else 1


if __name__ == "__main__":
    sys.exit(main())
