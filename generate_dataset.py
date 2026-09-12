import math
import random
import string
from collections import Counter
from urllib.parse import urlparse, parse_qs
import pandas as pd


# -----------------------------
# 1) Feature extraction helpers
# -----------------------------
SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~%&=")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def numeric_text_ratio(text: str) -> float:
    if not text:
        return 0.0
    digits = sum(ch.isdigit() for ch in text)
    letters = sum(ch.isalpha() for ch in text)
    total = digits + letters
    return digits / total if total > 0 else 0.0


def special_char_count(text: str) -> int:
    return sum(ch in SPECIAL_CHARS for ch in text)


def split_request_parts(full_request: str):
    """
    Splits a synthetic HTTP-like request into:
    - URI path + query
    - GET/query string only
    - POST body only
    """
    if "||POST||" in full_request:
        url_part, post_body = full_request.split("||POST||", 1)
    else:
        url_part, post_body = full_request, ""

    parsed = urlparse(url_part)
    uri = parsed.path
    if parsed.query:
        uri = f"{parsed.path}?{parsed.query}"

    get_data = parsed.query
    post_data = post_body.strip()
    return uri, get_data, post_data


def extract_features(full_request: str):
    uri, get_data, post_data = split_request_parts(full_request)

    combined_text = f"{uri} {get_data} {post_data}"

    return {
        "URI_Length": len(uri),
        "GET_Length": len(get_data),
        "POST_Length": len(post_data),
        "URI_Entropy": round(shannon_entropy(uri), 4),
        "GET_Entropy": round(shannon_entropy(get_data), 4),
        "POST_Entropy": round(shannon_entropy(post_data), 4),
        "Numeric_Text_Ratio": round(numeric_text_ratio(combined_text), 4),
        "Special_Char_Count": special_char_count(combined_text),
    }


# -----------------------------
# 2) Payload generators
# -----------------------------
NORMAL_PATHS = [
    "/",
    "/home",
    "/about",
    "/products",
    "/product/view",
    "/search",
    "/login",
    "/register",
    "/profile",
    "/api/data",
    "/blog/post",
]

NORMAL_PARAMS = {
    "id": ["1", "2", "10", "25", "103"],
    "page": ["1", "2", "3", "4"],
    "category": ["books", "electronics", "fashion", "sports"],
    "q": ["phone", "laptop", "bag", "chair", "python"],
    "user": ["alice", "bob", "john", "emma"],
    "sort": ["asc", "desc", "price", "date"],
}


SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT username,password FROM users --",
    "'; DROP TABLE users; --",
    "' OR 'a'='a",
    "admin' --",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

CMD_PAYLOADS = [
    "; ls -la",
    "&& cat /etc/passwd",
    "| whoami",
    "; rm -rf /",
    "$(uname -a)",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "../../../../var/log/auth.log",
]

ENCODED_ATTACKS = [
    "%27%20OR%201%3D1%20--",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


def rand_str(n=6):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def build_normal_request():
    path = random.choice(NORMAL_PATHS)

    query_parts = []
    for _ in range(random.randint(0, 3)):
        key = random.choice(list(NORMAL_PARAMS.keys()))
        value = random.choice(NORMAL_PARAMS[key])
        query_parts.append(f"{key}={value}")

    query = "&".join(query_parts)
    url = f"{path}?{query}" if query else path

    if random.random() < 0.3:
        post_body = f"name={rand_str()}&email={rand_str()}@mail.com&age={random.randint(18,50)}"
        return f"{url}||POST||{post_body}"

    return url


def build_malicious_request():
    attack_type = random.choice(["sqli", "xss", "cmd", "path", "encoded"])

    base_path = random.choice(NORMAL_PATHS)

    if attack_type == "sqli":
        payload = random.choice(SQLI_PAYLOADS)
        return f"{base_path}?id={random.randint(1,99)}&user={payload}"

    if attack_type == "xss":
        payload = random.choice(XSS_PAYLOADS)
        return f"{base_path}?q={payload}"

    if attack_type == "cmd":
        payload = random.choice(CMD_PAYLOADS)
        return f"{base_path}?file=test.txt{payload}"

    if attack_type == "path":
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        return f"{base_path}?file={payload}"

    payload = random.choice(ENCODED_ATTACKS)
    if random.random() < 0.5:
        return f"{base_path}?input={payload}"
    return f"{base_path}||POST||username=admin&comment={payload}"


# -----------------------------
# 3) Dataset builder
# -----------------------------
def generate_dataset(normal_count=500, malicious_count=500, seed=42):
    random.seed(seed)

    rows = []

    for _ in range(normal_count):
        req = build_normal_request()
        features = extract_features(req)
        features["label"] = 0
        rows.append(features)

    for _ in range(malicious_count):
        req = build_malicious_request()
        features = extract_features(req)
        features["label"] = 1
        rows.append(features)

    df = pd.DataFrame(rows)

    # Shuffle rows
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = generate_dataset(normal_count=1000, malicious_count=1000, seed=42)

    output_path = "data/waf_dataset.csv"
    df.to_csv(output_path, index=False)

    print(f"Dataset saved to: {output_path}")
    print(df.head())
    print("\nClass distribution:")
    print(df["label"].value_counts())