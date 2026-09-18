import re
from src.hybrid_waf.core.request_parser import normalize_text

# -----------------------------
# Attack pattern groups
# -----------------------------
PATTERN_GROUPS = {
    "sql_injection": [
        r"(?i)\bunion\s+select\b",
        r"(?i)\bselect\b.+\bfrom\b",
        r"(?i)\binsert\b.+\binto\b",
        r"(?i)\bupdate\b.+\bset\b",
        r"(?i)\bdelete\b.+\bfrom\b",
        r"(?i)\bdrop\s+table\b",
        r"(?i)\btruncate\s+table\b",
        r"(?i)\bor\s+1=1\b",
        r"(?i)\band\s+1=1\b",
        r"(?i)'\s*or\s*'1'\s*=\s*'1",
        r'(?i)"\s*or\s*"1"\s*=\s*"1',
        r"(?i)'\s*or\s*1=1\s*--?",
        r"(?i)\bwaitfor\s+delay\b",
        r"(?i)\bsleep\s*\(",
        r"(?i)\bbenchmark\s*\(",
        r"(?i)\bextractvalue\s*\(",
        r"(?i)\bload_file\s*\(",
        r"(?i)\binto\s+outfile\b",
        r"(?i)\bxp_cmdshell\s*\(",
        r"(?i)\b@@version\b",
        r"(?i)\b@@datadir\b",
        r"(?i)\buser\s*\(",
        r"(?i)\bdatabase\s*\(",
        r"(?i)\border\s+by\s+\d+\b",
        r"(?i)\bgroup\s+by\b.+\bhaving\b",
        r"--",
        r"/\*.*?\*/",
    ],

    "xss": [
        r"(?i)<script\b[^>]*>.*?</script>",
        r"(?i)<img\b[^>]*onerror\s*=",
        r"(?i)<svg\b[^>]*onload\s*=",
        r"(?i)<iframe\b",
        r"(?i)\bjavascript\s*:",
        r"(?i)\bonerror\s*=",
        r"(?i)\bonload\s*=",
        r"(?i)\bonmouseover\s*=",
        r"(?i)\bonclick\s*=",
        r"(?i)\bdocument\.cookie\b",
        r"(?i)\bwindow\.location\b",
        r"(?i)\beval\s*\(",
        r"(?i)\balert\s*\(",
        r"(?i)\bconfirm\s*\(",
        r"(?i)\bprompt\s*\(",
        r"(?i)\binnerhtml\s*=",
        r"(?i)\bsrcdoc\s*=",
        r"(?i)data:text/html",
        r"(?i)String\.fromCharCode\s*\(",
    ],

    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"(?i)%2e%2e%2f",
        r"(?i)%2e%2e\\",
        r"(?i)/etc/passwd",
        r"(?i)\\windows\\system32",
        r"(?i)/proc/self/environ",
    ],

    "command_injection": [
        r"[;&|`]\s*(cat|ls|whoami|id|uname|pwd|rm|curl|wget|nc|bash|sh)\b",
        r"\$\(.+?\)",
        r"(?i)\b(cmd|powershell|bash|sh)\b",
    ],

    "ssrf": [
        r"(?i)\bfile://",
        r"(?i)\bgopher://",
        r"(?i)\bftp://",
        r"(?i)http://127\.0\.0\.1",
        r"(?i)http://localhost",
        r"(?i)169\.254\.169\.254",
        r"(?i)metadata\.google\.internal",
        r"(?i)kubernetes\.default\.svc",
        r"(?i)http://10\.",
        r"(?i)http://192\.168\.",
        r"(?i)0x7f000001",
    ],

    "header_injection": [
        r"(?i)%0d%0a",
        r"(?i)\r\n",
        r"(?i)\n(?:host|content-length|cookie|authorization):",
    ],
}

OBFUSCATION_PATTERNS = [
    r"(?i)(%[0-9a-f]{2}){2,}",          # repeated URL encoding
    r"(\\x[0-9A-Fa-f]{2}){2,}",         # hex escapes
    r"(\\u[0-9A-Fa-f]{4}){2,}",         # unicode escapes
    r"(?i)\bchar\s*\(",
    r"(?i)\bconcat\s*\(",
    r"(?i)\bsubstr\s*\(",
    r"(?i)\bfromcharcode\s*\(",
    r"(?i)\bbase64_decode\b",
    r"(?i)\bbase64_encode\b",
    r"(?i)\bdecodeURIComponent\b",
    r"(?i)\bencodeURIComponent\b",
    r"(?i)\bxor\b",
]


# Precompile once at import. Regex compilation in a per-request loop is the
# single biggest avoidable cost in the signature layer.
COMPILED_GROUPS = {
    category: [(re.compile(p, re.IGNORECASE | re.DOTALL), p) for p in patterns]
    for category, patterns in PATTERN_GROUPS.items()
}
COMPILED_OBFUSCATION = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), p) for p in OBFUSCATION_PATTERNS
]


def normalize_input(user_input: str) -> str:
    """Kept for backwards compatibility. Delegates to the canonical normalizer."""
    return normalize_text(user_input)


def _scan(text: str):
    """Scan one string. Returns (status, category, pattern) or None if clean."""
    normalized = normalize_text(text)
    if not normalized:
        return None

    for category, patterns in COMPILED_GROUPS.items():
        for compiled, raw in patterns:
            if compiled.search(normalized):
                return ("malicious", category, raw)

    for compiled, raw in COMPILED_OBFUSCATION:
        if compiled.search(normalized):
            return ("obfuscated", "obfuscation", raw)

    return None


def check_signature(user_input: str) -> dict:
    """Scan a single string.

    Returns:
        {
            "status": "malicious" | "obfuscated" | "valid",
            "category": str | None,
            "matched_pattern": str | None,
            "location": str | None,
            "normalized_input": str,
        }
    """
    normalized = normalize_text(user_input)
    hit = _scan(user_input)

    if hit is None:
        return {
            "status": "valid",
            "category": None,
            "matched_pattern": None,
            "location": None,
            "normalized_input": normalized,
        }

    status, category, pattern = hit
    return {
        "status": status,
        "category": category,
        "matched_pattern": pattern,
        "location": None,
        "normalized_input": normalized,
    }


def check_parsed_request(parsed) -> dict:
    """Scan every inspection point of a ParsedRequest.

    A malicious hit short-circuits immediately. An obfuscated hit is remembered
    but scanning continues, because a later field may be outright malicious and
    that is the stronger verdict.
    """
    obfuscated_hit = None

    for location, value in parsed.inspection_points():
        hit = _scan(value)
        if hit is None:
            continue

        status, category, pattern = hit
        if status == "malicious":
            return {
                "status": "malicious",
                "category": category,
                "matched_pattern": pattern,
                "location": location,
                "normalized_input": normalize_text(value),
            }

        if obfuscated_hit is None:
            obfuscated_hit = {
                "status": "obfuscated",
                "category": category,
                "matched_pattern": pattern,
                "location": location,
                "normalized_input": normalize_text(value),
            }

    if obfuscated_hit:
        return obfuscated_hit

    return {
        "status": "valid",
        "category": None,
        "matched_pattern": None,
        "location": None,
        "normalized_input": "",
    }
