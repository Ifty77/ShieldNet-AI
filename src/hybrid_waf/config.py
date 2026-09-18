"""Configuration for ShieldNet-AI.

Every value can be overridden with an environment variable, so you can flip
between monitor and block without editing code.
"""

import os

# The single backend this gateway protects.
# Browser -> ShieldNet-AI (port 5000) -> BACKEND_URL (port 5001)
BACKEND_URL = os.environ.get("SHIELDNET_BACKEND", "http://127.0.0.1:5001")

# "monitor" -> decisions are logged, every request is forwarded.
# "block"   -> malicious requests get HTTP 403 and never reach the backend.
#
# Always start in monitor mode on a new deployment. Read the log, confirm the
# false positives are acceptable, then switch to block.
MODE = os.environ.get("SHIELDNET_MODE", "monitor").lower()

# Seconds to wait on the backend before giving up.
BACKEND_TIMEOUT = float(os.environ.get("SHIELDNET_TIMEOUT", "10"))

# Paths served by the WAF's own UI. These are never proxied to the backend.
WAF_OWN_PATHS = ("/waf", "/static", "/check_request")

# Hop-by-hop headers that must not be forwarded (RFC 2616 13.5.1).
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}

LOG_PATH = os.environ.get("SHIELDNET_LOG", "logs/detections.log")


def is_blocking() -> bool:
    return MODE == "block"
