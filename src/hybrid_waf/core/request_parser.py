"""
Canonical request parsing and feature extraction for ShieldNet-AI.

THIS MODULE IS THE SINGLE SOURCE OF TRUTH.

Both dataset generation (offline) and live detection (online) import from here.
Do not reimplement any of these functions anywhere else -- doing so reintroduces
training/serving skew, where the model is trained on features that do not mean
the same thing as the features it is asked to predict on.
"""

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlparse

# ---------------------------------------------------------------------------
# Canonical constants -- change these in ONE place only
# ---------------------------------------------------------------------------

SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~%&=")

FEATURE_ORDER: List[str] = [
    "URI_Length",
    "GET_Length",
    "POST_Length",
    "URI_Entropy",
    "GET_Entropy",
    "POST_Entropy",
    "Numeric_Text_Ratio",
    "Special_Char_Count",
]

ENTROPY_ROUNDING = 4

# Headers worth inspecting. Kept short on purpose: inspecting every header
# produces noise, and most attacker-controlled surface lives in these.
INSPECTED_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "Cookie",
]


# ---------------------------------------------------------------------------
# Primitive feature functions
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def numeric_text_ratio(text: str) -> float:
    """Digits as a fraction of all alphanumeric characters. Bounded [0, 1]."""
    if not text:
        return 0.0
    digits = sum(ch.isdigit() for ch in text)
    letters = sum(ch.isalpha() for ch in text)
    total = digits + letters
    return digits / total if total > 0 else 0.0


def special_char_count(text: str) -> int:
    return sum(ch in SPECIAL_CHARS for ch in text)


# ---------------------------------------------------------------------------
# Canonical parsed request
# ---------------------------------------------------------------------------

@dataclass
class ParsedRequest:
    """A normalized view of an HTTP request, independent of Flask."""

    method: str = "GET"
    path: str = "/"
    query_string: str = ""
    body: str = ""
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    # Derived, filled in by __post_init__
    query_params: List[Tuple[str, str]] = field(default_factory=list)
    body_params: List[Tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.query_params = _safe_parse_qsl(self.query_string)
        self.body_params = _parse_body(self.body, self.content_type)

    # -- feature parts ------------------------------------------------------
    @property
    def uri(self) -> str:
        return f"{self.path}?{self.query_string}" if self.query_string else self.path

    @property
    def get_data(self) -> str:
        return self.query_string

    @property
    def post_data(self) -> str:
        """Body canonicalized to `k=v&k=v` regardless of original encoding.

        JSON and form bodies are flattened to the same shape so that a JSON
        request and an equivalent form request produce identical features.
        """
        if not self.body_params:
            return self.body.strip()
        return "&".join(f"{k}={v}" for k, v in self.body_params)

    # -- inspection surface -------------------------------------------------
    def inspection_points(self) -> List[Tuple[str, str]]:
        """Every attacker-controllable string, tagged with where it came from.

        Returns a list of (location, value). The signature engine walks this
        so a block decision can say exactly which field tripped it.
        """
        points: List[Tuple[str, str]] = [("path", self.path)]

        for key, value in self.query_params:
            points.append((f"query:{key}", value))

        for key, value in self.body_params:
            points.append((f"body:{key}", value))

        # Unparsed body (e.g. raw XML/text) still gets inspected as a whole.
        if self.body and not self.body_params:
            points.append(("body:<raw>", self.body))

        for name in INSPECTED_HEADERS:
            value = self.headers.get(name)
            if value:
                points.append((f"header:{name}", value))

        return [(loc, val) for loc, val in points if val]


def _safe_parse_qsl(qs: str) -> List[Tuple[str, str]]:
    if not qs:
        return []
    try:
        return parse_qsl(qs, keep_blank_values=True)
    except (ValueError, UnicodeDecodeError):
        return []


def _flatten_json(obj: Any, prefix: str = "") -> List[Tuple[str, str]]:
    """Flatten nested JSON so deep fields are still inspected.

    {"user": {"name": "x"}} -> [("user.name", "x")]
    """
    out: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            out.extend(_flatten_json(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            out.extend(_flatten_json(value, f"{prefix}[{i}]"))
    else:
        out.append((prefix or "<root>", "" if obj is None else str(obj)))
    return out


def _parse_body(body: str, content_type: str) -> List[Tuple[str, str]]:
    if not body:
        return []
    ctype = (content_type or "").lower()

    if "json" in ctype:
        try:
            return _flatten_json(json.loads(body))
        except (ValueError, TypeError):
            return []

    if "form-urlencoded" in ctype:
        return _safe_parse_qsl(body)

    # Unknown content type: try form, then JSON, then give up and treat as raw.
    guessed = _safe_parse_qsl(body)
    if guessed and any(v for _, v in guessed):
        return guessed
    try:
        return _flatten_json(json.loads(body))
    except (ValueError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Builders -- the two entry points into ParsedRequest
# ---------------------------------------------------------------------------

def parse_raw_request(
    method: str = "GET",
    path: str = "/",
    query_string: str = "",
    body: str = "",
    content_type: str = "",
    headers: Optional[Dict[str, str]] = None,
) -> ParsedRequest:
    """Build a ParsedRequest from primitive parts. Used by dataset generation."""
    return ParsedRequest(
        method=method.upper(),
        path=path,
        query_string=query_string,
        body=body,
        content_type=content_type,
        headers=headers or {},
    )


def parse_request_line(full_request: str) -> ParsedRequest:
    """Build a ParsedRequest from the compact `/path?q=1||POST||body` format.

    This keeps the existing synthetic-dataset notation working while routing it
    through exactly the same code path as a live request.
    """
    if "||POST||" in full_request:
        url_part, body = full_request.split("||POST||", 1)
        method, content_type = "POST", "application/x-www-form-urlencoded"
    else:
        url_part, body = full_request, ""
        method, content_type = "GET", ""

    parsed = urlparse(url_part)
    return parse_raw_request(
        method=method,
        path=parsed.path or "/",
        query_string=parsed.query,
        body=body.strip(),
        content_type=content_type,
    )


def parse_flask_request(req) -> ParsedRequest:
    """Build a ParsedRequest from a live Flask request object."""
    try:
        body = req.get_data(as_text=True) or ""
    except Exception:
        body = ""

    return parse_raw_request(
        method=req.method,
        path=req.path,
        query_string=req.query_string.decode("utf-8", errors="replace"),
        body=body,
        content_type=req.headers.get("Content-Type", ""),
        headers={k: v for k, v in req.headers.items()},
    )


# ---------------------------------------------------------------------------
# Feature extraction -- the ONLY implementation
# ---------------------------------------------------------------------------

def extract_features_from_parts(uri: str, get_data: str, post_data: str) -> Dict[str, float]:
    combined = f"{uri} {get_data} {post_data}"
    return {
        "URI_Length": len(uri),
        "GET_Length": len(get_data),
        "POST_Length": len(post_data),
        "URI_Entropy": round(shannon_entropy(uri), ENTROPY_ROUNDING),
        "GET_Entropy": round(shannon_entropy(get_data), ENTROPY_ROUNDING),
        "POST_Entropy": round(shannon_entropy(post_data), ENTROPY_ROUNDING),
        "Numeric_Text_Ratio": round(numeric_text_ratio(combined), ENTROPY_ROUNDING),
        "Special_Char_Count": special_char_count(combined),
    }


def extract_features(parsed: ParsedRequest) -> Dict[str, float]:
    """Extract the canonical feature dict from a ParsedRequest."""
    return extract_features_from_parts(parsed.uri, parsed.get_data, parsed.post_data)


def features_to_list(features: Dict[str, float]) -> List[float]:
    """Flatten a feature dict into FEATURE_ORDER. Guards against key drift."""
    missing = [name for name in FEATURE_ORDER if name not in features]
    if missing:
        raise KeyError(f"Missing features: {missing}")
    return [features[name] for name in FEATURE_ORDER]


def normalize_text(text: str) -> str:
    """Whitespace-collapse and double URL-decode. Used before signature matching."""
    if not text:
        return ""
    collapsed = " ".join(text.split())
    return unquote(unquote(collapsed))
