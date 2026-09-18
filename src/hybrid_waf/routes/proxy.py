"""The /check_request analyzer endpoint used by the WAF's own test UI.

This shares the decision engine with the gateway, so what you see here is
exactly what the gateway would do to a real request.
"""

from flask import Blueprint, jsonify, request

from src.hybrid_waf.core.engine import evaluate
from src.hybrid_waf.core.request_parser import parse_request_line

proxy_bp = Blueprint("proxy", __name__)


@proxy_bp.route("/check_request", methods=["POST"])
def check_request():
    data = request.get_json(silent=True) or {}
    user_input = (data.get("user_request") or "").strip()

    if not user_input:
        return jsonify({"status": "error", "message": "No request provided."}), 400

    parsed = parse_request_line(user_input)
    decision = evaluate(parsed)

    payload = {
        "status": decision.status,
        "action": decision.action,
        "category": decision.category,
        "location": decision.location,
        "layer": decision.layer,
        "mode": decision.mode,
        "enforced": decision.enforced,
    }

    if decision.status == "malicious":
        payload["message"] = (
            "Critical Alert! Malicious pattern detected in your request. Access Denied! \U0001f512"
        )
        payload["detail"] = _describe(decision)
        return jsonify(payload)

    if decision.status == "obfuscated":
        payload["final_status"] = "malicious" if decision.action == "block" else "valid"
        payload["features"] = decision.features
        payload["ml_prediction"] = decision.ml_prediction
        payload["message"] = "Suspicious Pattern Detected - Engaging Advanced AI Analysis..."
        if decision.ml_prediction is None:
            payload["ml_verdict"] = "\u26a0\ufe0f ML model unavailable - allowed on signature evidence alone."
        elif decision.action == "block":
            payload["ml_verdict"] = "\U0001f6a8 Threat Confirmed! AI Defense System Blocked Suspicious Activity. \U0001f512"
        else:
            payload["ml_verdict"] = "\u2705 Advanced AI Scan Complete: Request Verified Safe \u2728"
        payload["detail"] = _describe(decision)
        return jsonify(payload)

    payload["message"] = "All Clear! Your request passed our security checks with flying colors. \u2728"
    return jsonify(payload)


def _describe(decision) -> str:
    """Human-readable explanation of where and why a request tripped a rule."""
    if not decision.location:
        return ""
    category = (decision.category or "unknown").replace("_", " ")
    return f"Matched {category} in {decision.location}"
