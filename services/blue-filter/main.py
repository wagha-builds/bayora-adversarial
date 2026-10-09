"""
Naive Blue Filter Microservice (Phase 1 Baseline)
Intentionally vulnerable baseline implementation:
- Directly reads rules from a shared volume path (/shared_data/blue_rules.json).
- Performs simple case-insensitive substring matching against blocked keywords.
- Exposes internal rules over an unauthenticated endpoint.
- Emits detailed unredacted logs to stdout.
"""

import json
import logging
import os
from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel

# Configure raw stdout logging (Intentionally insecure: PRD Sec 4 raw logging)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [blue-filter] %(message)s")
logger = logging.getLogger("blue-filter")

app = FastAPI(title="Naive Blue Filter (Baseline)", version="0.1.0")

RULES_SHARED_PATH = os.environ.get("BLUE_RULES_PATH", "/shared_data/blue_rules.json")
RULES_FALLBACK_PATH = os.path.join(os.path.dirname(__file__), "blue_rules.json")


def load_rules() -> dict:
    """Load filtering rules from shared volume or fallback local file."""
    for path in [RULES_SHARED_PATH, RULES_FALLBACK_PATH, "data/baseline/blue_rules.json"]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logger.info("Loaded rules from %s: %d keywords", path, len(data.get("blocked_keywords", [])))
                    return data
            except Exception as e:
                logger.error("Failed to read rules from %s: %s", path, e)
    # Default minimal fallback
    return {
        "version": "1.0-default-fallback",
        "blocked_keywords": [
            "ignore previous instructions",
            "dan mode",
            "system override",
            "reveal all internal",
            "bypass filter"
        ],
        "secret_rule_salt": "BLUE_DEFENSE_PROPRIETARY_RULESET_v1_HASH_2026"
    }


class FilterRequest(BaseModel):
    prompt: str
    prompt_id: Optional[str] = None


class FilterResponse(BaseModel):
    allowed: bool
    reason: str
    action: str
    matched_keyword: Optional[str] = None


@app.on_event("startup")
def startup_event():
    """On startup, ensure rules are populated in the shared volume path."""
    if not os.path.exists(RULES_SHARED_PATH):
        try:
            os.makedirs(os.path.dirname(RULES_SHARED_PATH), exist_ok=True)
            rules = load_rules()
            with open(RULES_SHARED_PATH, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2)
            logger.info("Initialized shared rules at %s", RULES_SHARED_PATH)
        except Exception as e:
            logger.warning("Could not initialize %s: %s", RULES_SHARED_PATH, e)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "blue-filter", "phase": "1-insecure-baseline"}


@app.get("/rules")
def get_rules():
    """Unauthenticated endpoint exposing internal defense rules (Insecure baseline behavior)."""
    return load_rules()


@app.post("/evaluate", response_model=FilterResponse)
def evaluate_prompt(req: FilterRequest):
    # Log prompt in plain text (demonstrates PRD Sec 4 log exposure)
    logger.info("Evaluating prompt_id=%s, payload='%s'", req.prompt_id, req.prompt)

    rules = load_rules()
    blocked_keywords = rules.get("blocked_keywords", [])
    import time
    
    prompt_lower = req.prompt.lower()
    
    # R-19 Test Hook: Only enabled if environment variable is set
    if "simulate_slow_filter_r19" in prompt_lower and os.environ.get("ENABLE_R19_TEST_HOOK") == "1":
        logger.warning("Simulating 35s slow filter for R-19 test...")
        time.sleep(35)
        
    for kw in blocked_keywords:
        if kw.lower() in prompt_lower:
            logger.warning("PROMPT BLOCKED! Keyword matched: '%s'", kw)
            return FilterResponse(
                allowed=False,
                reason=f"Blocked by keyword filter: '{kw}'",
                action="BLOCK",
                matched_keyword=kw
            )

    logger.info("Prompt passed filter")
    return FilterResponse(
        allowed=True,
        reason="Passed filter",
        action="PASS",
        matched_keyword=None
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
