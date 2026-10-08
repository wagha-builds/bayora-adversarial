#!/usr/bin/env python3
"""
Leak Test 4: test_cache_timing (LLM-001)
Demonstrates the prefix caching timing oracle:
Sends two identical prompt requests with a long shared prefix.
Measures the prompt evaluation latency delta between cold and warm requests.
"""

import sys
import time
import httpx

MODEL_URL = "http://model-server:8080"
LONG_PREFIX = (
    "In the year 2026, autonomous evaluation platforms were deployed to assess adversarial AI security. "
    "Researchers developed a set of five strict security zones with hardware-assisted memory isolation, "
    "unskippable policy engines, and append-only ledgers to ensure verifiable integrity during red-teaming. "
    "Please analyze the following cryptographic protocol: "
)


def test_cache_timing() -> dict:
    print(f"[*] Testing KV prefix caching timing oracle against {MODEL_URL} ...")
    try:
        with httpx.Client(timeout=60.0) as client:
            # 1. Cold request (initial prompt ingestion into KV cache)
            print("    Sending Request 1 (Cold cache) ...")
            t0 = time.perf_counter()
            resp1 = client.post(
                f"{MODEL_URL}/completion",
                json={"prompt": LONG_PREFIX + "Query alpha.", "n_predict": 5}
            )
            resp1.raise_for_status()
            dt1_ms = (time.perf_counter() - t0) * 1000
            data1 = resp1.json()
            timings1 = data1.get("timings", {})
            prompt_ms_1 = timings1.get("prompt_ms", dt1_ms)

            # 2. Warm request (identical prefix, prompt caching active)
            print("    Sending Request 2 (Warm cache with identical prefix) ...")
            t1 = time.perf_counter()
            resp2 = client.post(
                f"{MODEL_URL}/completion",
                json={"prompt": LONG_PREFIX + "Query beta.", "n_predict": 5}
            )
            resp2.raise_for_status()
            dt2_ms = (time.perf_counter() - t1) * 1000
            data2 = resp2.json()
            timings2 = data2.get("timings", {})
            prompt_ms_2 = timings2.get("prompt_ms", dt2_ms)

            delta_ms = prompt_ms_1 - prompt_ms_2
            cache_n = timings2.get("cache_n", 0)

            print(f"    Request 1 prompt processing: {prompt_ms_1:.2f} ms")
            print(f"    Request 2 prompt processing: {prompt_ms_2:.2f} ms (cached tokens: {cache_n})")
            print(f"    Timing Delta (Speedup): {delta_ms:.2f} ms")

            # Check if cache speedup occurred or cache reuse reported
            is_leaking = (prompt_ms_2 < prompt_ms_1) or (cache_n > 0)
            status = "PASS" if is_leaking else "FAIL"

            if is_leaking:
                print(f"[!] SUCCESS (LEAK DEMONSTRATED): Prefix caching timing oracle detected!")

            return {
                "test": "test_cache_timing",
                "status": status,
                "detail": "Measured timing discrepancy demonstrating prompt cache reuse",
                "cold_prompt_ms": round(prompt_ms_1, 2),
                "warm_prompt_ms": round(prompt_ms_2, 2),
                "delta_ms": round(delta_ms, 2),
                "cached_tokens": cache_n,
                "speedup_ratio": round(prompt_ms_1 / max(prompt_ms_2, 0.001), 2)
            }
    except Exception as e:
        print(f"[-] Timing test error: {e}")
        return {
            "test": "test_cache_timing",
            "status": "FAIL",
            "detail": str(e)
        }


if __name__ == "__main__":
    res = test_cache_timing()
    sys.exit(0 if res["status"] == "PASS" else 1)
