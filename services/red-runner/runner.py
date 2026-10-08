#!/usr/bin/env python3
"""
Red Runner Service (Phase 1 Insecure Baseline)
Executes synthetic adversarial and benign evaluation prompts against the baseline stub,
and supports baseline leak verification tests across the shared Docker environment.
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Dict, List, Any
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [red-runner] %(message)s")
logger = logging.getLogger("red-runner")

DEFAULT_GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://baseline-stub:8000")
PAYLOADS_PATH = os.environ.get("PAYLOADS_PATH", "/app/data/payloads.json")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/results")


def load_payloads(filepath: str) -> List[Dict[str, Any]]:
    for path in [filepath, "data/baseline/payloads.json", "/shared_data/payloads.json"]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                payloads = json.load(f)
                logger.info("Loaded %d payloads from %s", len(payloads), path)
                return payloads
    raise FileNotFoundError(f"No payloads file found at {filepath} or fallbacks.")


def run_pipeline(gateway_url: str, payloads: List[Dict[str, Any]], run_id: str = "baseline-run-001") -> Dict[str, Any]:
    """Execute evaluation payloads through the baseline routing stub."""
    logger.info("Starting baseline pipeline run '%s' against %s ...", run_id, gateway_url)
    results = []
    total_start = time.perf_counter()

    with httpx.Client(timeout=120.0) as client:
        # Check gateway health
        try:
            h = client.get(f"{gateway_url}/health")
            logger.info("Gateway health: %s (HTTP %d)", h.json().get("status"), h.status_code)
        except Exception as e:
            logger.error("Failed to connect to gateway at %s: %s", gateway_url, e)
            return {"error": f"Gateway unreachable: {e}", "run_id": run_id}

        for item in payloads:
            p_id = item["id"]
            category = item["category"]
            prompt = item["prompt"]
            logger.info("Firing [%s] (%s): '%s'", p_id, category, prompt[:60])

            t0 = time.perf_counter()
            try:
                resp = client.post(
                    f"{gateway_url}/runs/{run_id}/query",
                    json={"prompt": prompt, "max_tokens": 64, "temperature": 0.7}
                )
                dt_ms = (time.perf_counter() - t0) * 1000
                data = resp.json()
                results.append({
                    "id": p_id,
                    "category": category,
                    "prompt": prompt,
                    "status_code": resp.status_code,
                    "status": data.get("status"),
                    "latency_ms": round(dt_ms, 2),
                    "filter_action": data.get("filter_result", {}).get("action"),
                    "matched_keyword": data.get("filter_result", {}).get("matched_keyword"),
                    "model_output": data.get("model_output"),
                    "timings": data.get("timings")
                })
                logger.info("-> [%s] %s in %.2f ms (filter: %s)", p_id, data.get("status"), dt_ms, data.get("filter_result", {}).get("action"))
            except Exception as e:
                dt_ms = (time.perf_counter() - t0) * 1000
                logger.error("-> [%s] ERROR: %s", p_id, e)
                results.append({
                    "id": p_id,
                    "category": category,
                    "prompt": prompt,
                    "error": str(e),
                    "latency_ms": round(dt_ms, 2)
                })

    total_duration_s = time.perf_counter() - total_start
    summary = {
        "run_id": run_id,
        "phase": "1-insecure-baseline",
        "total_payloads": len(payloads),
        "total_duration_seconds": round(total_duration_s, 2),
        "results": results
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_file = os.path.join(OUTPUT_DIR, f"{run_id}_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info("Saved pipeline results to %s", out_file)
    return summary


def main():
    parser = argparse.ArgumentParser(description="Bayora Red Runner (Phase 1 Baseline)")
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL, help="URL of baseline stub gateway")
    parser.add_argument("--payloads", default=PAYLOADS_PATH, help="Path to payloads JSON file")
    parser.add_argument("--run-id", default="baseline-run-001", help="Identifier for evaluation run")
    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    summary = run_pipeline(args.gateway_url, payloads, args.run_id)
    print(f"Pipeline finished. Total items: {len(summary.get('results', []))}")


if __name__ == "__main__":
    main()
