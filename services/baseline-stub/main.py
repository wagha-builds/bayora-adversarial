"""
Baseline Routing Stub (Phase 1 Insecure Baseline)
Intentionally naive evaluation gateway:
- Routes requests: Red -> Blue -> Model without OPA/ABAC enforcement.
- Plain unencrypted HTTP communication between all microservices.
- No rate limiting, query budget ($Q$) check, or mTLS validation.
- Emits raw prompt and model output logs to stdout without redaction.
- Direct bypass routes remain completely available across the shared bridge network.
"""

import logging
import os
import time
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException
import httpx
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [baseline-stub] %(message)s")
logger = logging.getLogger("baseline-stub")

app = FastAPI(
    title="Evaluation Gateway - Baseline Stub (Insecure)",
    description="Naive routing stub for Phase 1. Intentionally omits mTLS, OPA, Vault, and budget guards.",
    version="0.1.0-baseline"
)

BLUE_FILTER_URL = os.environ.get("BLUE_FILTER_URL", "http://blue-filter:8001")
MODEL_SERVER_URL = os.environ.get("MODEL_SERVER_URL", "http://model-server:8080")


class QueryRequest(BaseModel):
    prompt: str
    max_tokens: int = 64
    temperature: float = 0.7


class QueryResponse(BaseModel):
    status: str
    prompt: str
    filter_result: Dict[str, Any]
    model_output: Optional[str] = None
    timings: Optional[Dict[str, Any]] = None
    latency_ms: float


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "baseline-stub",
        "phase": "1-insecure-baseline",
        "security_note": "Intentionally naive stub. No OPA, no mTLS, no ABAC."
    }


@app.post("/runs/{run_id}/query", response_model=QueryResponse)
@app.post("/query", response_model=QueryResponse)
async def evaluate_query(req: QueryRequest, run_id: Optional[str] = "run-default"):
    start_time = time.perf_counter()
    logger.info("Received query for run_id=%s: prompt='%s'", run_id, req.prompt)

    # 1. Forward prompt to naive Blue filter
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            blue_resp = await client.post(
                f"{BLUE_FILTER_URL}/evaluate",
                json={"prompt": req.prompt, "prompt_id": run_id}
            )
            blue_resp.raise_for_status()
            filter_data = blue_resp.json()
        except Exception as e:
            logger.error("Failed to query Blue filter at %s: %s", BLUE_FILTER_URL, e)
            raise HTTPException(status_code=502, detail=f"Blue filter unreachable: {e}")

    # 2. Check Blue filter verdict
    if not filter_data.get("allowed", False):
        total_time_ms = (time.perf_counter() - start_time) * 1000
        logger.warning("Query blocked by Blue filter: %s", filter_data.get("reason"))
        return QueryResponse(
            status="blocked",
            prompt=req.prompt,
            filter_result=filter_data,
            model_output=None,
            timings=None,
            latency_ms=round(total_time_ms, 2)
        )

    # 3. Forward to Model server if allowed
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            model_resp = await client.post(
                f"{MODEL_SERVER_URL}/completion",
                json={
                    "prompt": req.prompt,
                    "n_predict": req.max_tokens,
                    "temperature": req.temperature
                }
            )
            model_resp.raise_for_status()
            model_data = model_resp.json()
        except Exception as e:
            logger.error("Failed to query Model server at %s: %s", MODEL_SERVER_URL, e)
            raise HTTPException(status_code=502, detail=f"Model server unreachable: {e}")

    total_time_ms = (time.perf_counter() - start_time) * 1000
    model_content = model_data.get("content", "")
    timings = model_data.get("timings", {})
    logger.info("Query completed in %.2f ms. Output: '%s'", total_time_ms, model_content[:50])

    return QueryResponse(
        status="completed",
        prompt=req.prompt,
        filter_result=filter_data,
        model_output=model_content,
        timings=timings,
        latency_ms=round(total_time_ms, 2)
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
