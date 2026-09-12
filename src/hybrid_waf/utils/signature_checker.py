import re
from urllib.parse import unquote

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


def normalize_input(user_input: str) -> str:
    if not user_input:
        return ""
    text = " ".join(user_input.split())
    decoded_once = unquote(text)
    decoded_twice = unquote(decoded_once)
    return decoded_twice


def check_signature(user_input: str):
    """
    Returns a dict:
    {
        "status": "malicious" | "obfuscated" | "valid",
        "category": "sql_injection" | "xss" | ... | None,
        "matched_pattern": "<regex>" | None,
        "normalized_input": "<decoded text>"
    }
    """
    normalized = normalize_input(user_input)

    # Check direct malicious patterns
    for category, patterns in PATTERN_GROUPS.items():
        for pattern in patterns:
            if re.search(pattern, normalized, re.IGNORECASE | re.DOTALL):
                return {
                    "status": "malicious",
                    "category": category,
                    "matched_pattern": pattern,
                    "normalized_input": normalized
                }

    # Check obfuscation patterns
    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE | re.DOTALL):
            return {
                "status": "obfuscated",
                "category": "obfuscation",
                "matched_pattern": pattern,
                "normalized_input": normalized
            }

    return {
        "status": "valid",
        "category": None,
        "matched_pattern": None,
        "normalized_input": normalized
    }