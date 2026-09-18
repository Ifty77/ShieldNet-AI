"""Reverse-proxy gateway.

    Browser -> ShieldNet-AI (this) -> protected backend application

Allowed requests are forwarded upstream and the response is streamed back.
Blocked requests get HTTP 403 and the backend never sees them.
"""

import requests
from flask import Blueprint, Response, jsonify, request

from src.hybrid_waf import config
from src.hybrid_waf.core.engine import evaluate
from src.hybrid_waf.core.request_parser import parse_flask_request

gateway_bp = Blueprint("gateway", __name__)

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _forward_headers(incoming) -> dict:
    """Strip hop-by-hop headers, then add standard proxy headers."""
    headers = {
        key: value
        for key, value in incoming.items()
        if key.lower() not in config.HOP_BY_HOP_HEADERS
    }
    headers["X-Forwarded-For"] = request.remote_addr or ""
    headers["X-Forwarded-Proto"] = request.scheme
    headers["X-Forwarded-Host"] = request.host
    headers["X-ShieldNet"] = "1"
    return headers


def _blocked_response(decision) -> Response:
    payload = {
        "error": "Forbidden",
        "message": "Request blocked by ShieldNet-AI.",
        "detection": {
            "status": decision.status,
            "category": decision.category,
            "location": decision.location,
            "layer": decision.layer,
        },
    }
    response = jsonify(payload)
    response.status_code = 403
    response.headers["X-ShieldNet-Action"] = "block"
    return response


@gateway_bp.route("/", defaults={"path": ""}, methods=ALL_METHODS)
@gateway_bp.route("/<path:path>", methods=ALL_METHODS)
def gateway(path):
    # The WAF's own UI is served locally and is never proxied.
    full_path = "/" + path
    if full_path.startswith(config.WAF_OWN_PATHS):
        # Flask matches more specific rules first, so reaching here means no
        # WAF route claimed it. Treat it as not found rather than proxying.
        return jsonify({"error": "Not found"}), 404

    parsed = parse_flask_request(request)
    decision = evaluate(parsed)

    if decision.action == "block" and decision.enforced:
        return _blocked_response(decision)

    # Monitor mode, or an allowed request: forward upstream.
    upstream = f"{config.BACKEND_URL.rstrip('/')}{request.full_path.rstrip('?')}"

    try:
        upstream_response = requests.request(
            method=request.method,
            url=upstream,
            headers=_forward_headers(request.headers),
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=config.BACKEND_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        return (
            jsonify(
                {
                    "error": "Bad Gateway",
                    "message": "The protected application is unreachable.",
                    "detail": str(exc),
                }
            ),
            502,
        )

    response_headers = [
        (name, value)
        for name, value in upstream_response.raw.headers.items()
        if name.lower() not in config.HOP_BY_HOP_HEADERS
    ]

    response = Response(
        upstream_response.content,
        status=upstream_response.status_code,
        headers=response_headers,
    )

    # Make monitor-mode decisions visible without changing behaviour.
    response.headers["X-ShieldNet-Action"] = decision.action
    response.headers["X-ShieldNet-Mode"] = decision.mode
    if decision.action == "block" and not decision.enforced:
        response.headers["X-ShieldNet-WouldBlock"] = "1"

    return response
