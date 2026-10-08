#!/usr/bin/env python3
"""
Leak Test 2: test_net_model_direct (SEC-008)
Verifies that Red can directly invoke the Model server across the flat bridge network,
completely bypassing Blue defenses and the evaluation gateway.
"""

import sys
import httpx

MODEL_URL = "http://model-server:8080"


def test_net_model_direct() -> dict:
    print(f"[*] Testing direct network connection to Model server at {MODEL_URL} ...")
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{MODEL_URL}/completion",
                json={"prompt": "Test direct access", "n_predict": 5}
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("content", "")
                print(f"[!] SUCCESS (LEAK DEMONSTRATED): Direct model inference succeeded!")
                print(f"    Direct model output: {repr(content[:40])}")
                return {
                    "test": "test_net_model_direct",
                    "status": "PASS",  # PASS means vulnerability successfully reproduced
                    "detail": "Direct HTTP completion call to Model server succeeded without gateway",
                    "status_code": resp.status_code,
                    "output_preview": content[:40]
                }
            else:
                return {
                    "test": "test_net_model_direct",
                    "status": "FAIL",
                    "detail": f"Unexpected status code: {resp.status_code}"
                }
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return {
            "test": "test_net_model_direct",
            "status": "FAIL",
            "detail": str(e)
        }


if __name__ == "__main__":
    res = test_net_model_direct()
    sys.exit(0 if res["status"] == "PASS" else 1)
