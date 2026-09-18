"""The ShieldNet-AI decision engine.

One request in, one Decision out. Both the /check_request demo endpoint and the
reverse-proxy gateway call `evaluate()`, so they can never drift apart.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, Optional

from src.hybrid_waf import config
from src.hybrid_waf.core.request_parser import ParsedRequest, extract_features
from src.hybrid_waf.utils.signature_checker import check_parsed_request

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

os.makedirs(os.path.dirname(config.LOG_PATH) or ".", exist_ok=True)

waf_logger = logging.getLogger("waf_detections")
waf_logger.setLevel(logging.INFO)
waf_logger.propagate = False

if not waf_logger.handlers:
    _handler = logging.FileHandler(config.LOG_PATH, encoding="utf-8")
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    waf_logger.addHandler(_handler)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    action: str = "allow"            # "allow" | "block"
    status: str = "valid"            # "valid" | "malicious" | "obfuscated"
    category: Optional[str] = None
    matched_pattern: Optional[str] = None
    location: Optional[str] = None   # e.g. "query:q", "body:comment", "header:User-Agent"
    layer: Optional[str] = None      # "signature" | "ml" | None
    ml_prediction: Optional[int] = None
    features: Optional[Dict[str, float]] = None
    mode: str = "monitor"
    enforced: bool = False           # True when the block was actually applied
    method: str = ""
    path: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Lazy model loading
# ---------------------------------------------------------------------------

_model = None
_model_error: Optional[str] = None


def _get_model():
    """Load the model once, on first use.

    Loading lazily means a missing or corrupt model file degrades the WAF to
    signature-only instead of preventing the app from starting at all.
    """
    global _model, _model_error
    if _model is not None or _model_error is not None:
        return _model

    try:
        from src.hybrid_waf.utils.ml_checker import get_model
        _model = get_model()
    except Exception as exc:  # noqa: BLE001 - degrade, don't crash
        _model_error = str(exc)
        waf_logger.info(json.dumps({"event": "model_load_failed", "error": _model_error}))
    return _model


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(parsed: ParsedRequest) -> Decision:
    """Run the two-layer pipeline against a parsed request."""
    decision = Decision(
        mode=config.MODE,
        method=parsed.method,
        path=parsed.path,
    )

    # --- Layer 1: signature ------------------------------------------------
    sig = check_parsed_request(parsed)
    status = sig["status"]

    if status == "malicious":
        decision.action = "block"
        decision.status = "malicious"
        decision.category = sig["category"]
        decision.matched_pattern = sig["matched_pattern"]
        decision.location = sig["location"]
        decision.layer = "signature"
        decision.enforced = config.is_blocking()
        _log(decision)
        return decision

    if status == "valid":
        decision.action = "allow"
        decision.status = "valid"
        _log(decision)
        return decision

    # --- Layer 2: ML (only for obfuscated requests) ------------------------
    decision.status = "obfuscated"
    decision.category = sig["category"]
    decision.matched_pattern = sig["matched_pattern"]
    decision.location = sig["location"]
    decision.layer = "ml"

    features = extract_features(parsed)
    decision.features = features

    model = _get_model()
    if model is None:
        # Fail open on the ML layer: signature said "suspicious but not proven".
        # Blocking on an unavailable model would break the site on deploy error.
        decision.action = "allow"
        decision.ml_prediction = None
        _log(decision)
        return decision

    from src.hybrid_waf.utils.ml_checker import to_frame
    prediction = int(model.predict(to_frame(features))[0])
    decision.ml_prediction = prediction

    if prediction == 1:
        decision.action = "block"
        decision.enforced = config.is_blocking()
    else:
        decision.action = "allow"

    _log(decision)
    return decision


def _log(decision: Decision) -> None:
    """One JSON object per line. Greppable, and parseable for tuning."""
    record = {
        "mode": decision.mode,
        "action": decision.action,
        "enforced": decision.enforced,
        "status": decision.status,
        "layer": decision.layer,
        "category": decision.category,
        "location": decision.location,
        "method": decision.method,
        "path": decision.path,
    }
    if decision.ml_prediction is not None:
        record["ml_prediction"] = decision.ml_prediction
    if decision.action == "block" and decision.matched_pattern:
        record["matched_pattern"] = decision.matched_pattern
    waf_logger.info(json.dumps(record))
