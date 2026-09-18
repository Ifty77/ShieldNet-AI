"""Generate the synthetic training dataset.

Critical: this script does NOT define its own feature functions. It builds
requests, parses them with the same parser the live gateway uses, and extracts
features with the same extractor. If you need to change a feature, change it in
src/hybrid_waf/core/request_parser.py and rerun this script plus train_model.py.
"""

import os
import random
import string

import pandas as pd

from src.hybrid_waf.core.request_parser import (
    FEATURE_ORDER,
    extract_features,
    parse_raw_request,
)

NORMAL_PATHS = [
    "/", "/home", "/about", "/products", "/product/view", "/search",
    "/login", "/register", "/profile", "/api/data", "/blog/post", "/comments",
]

NORMAL_PARAMS = {
    "id": ["1", "2", "10", "25", "103"],
    "page": ["1", "2", "3", "4"],
    "category": ["books", "electronics", "fashion", "sports"],
    "q": ["phone", "laptop", "bag", "chair", "python", "running shoes"],
    "user": ["alice", "bob", "john", "emma"],
    "sort": ["asc", "desc", "price", "date"],
}

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT username,password FROM users --",
    "'; DROP TABLE users; --",
    "' OR 'a'='a",
    "admin' --",
    "1' AND SLEEP(5) --",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(document.cookie)",
]

CMD_PAYLOADS = ["; ls -la", "&& cat /etc/passwd", "| whoami", "; rm -rf /", "$(uname -a)"]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "../../../../var/log/auth.log",
]

ENCODED_ATTACKS = [
    "%27%20OR%201%3D1%20--",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "CHAR(97,100,109,105,110)",
    "CONCAT(0x61,0x64,0x6d,0x69,0x6e)",
]


def rand_str(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def build_normal_request():
    path = random.choice(NORMAL_PATHS)

    parts = []
    for _ in range(random.randint(0, 3)):
        key = random.choice(list(NORMAL_PARAMS.keys()))
        parts.append(f"{key}={random.choice(NORMAL_PARAMS[key])}")
    query = "&".join(parts)

    if random.random() < 0.3:
        body = f"name={rand_str()}&email={rand_str()}@mail.com&age={random.randint(18, 50)}"
        return parse_raw_request(
            method="POST", path=path, query_string=query, body=body,
            content_type="application/x-www-form-urlencoded",
        )

    return parse_raw_request(method="GET", path=path, query_string=query)


def build_malicious_request():
    attack = random.choice(["sqli", "xss", "cmd", "path", "encoded"])
    path = random.choice(NORMAL_PATHS)

    if attack == "sqli":
        payload = random.choice(SQLI_PAYLOADS)
        return parse_raw_request(
            method="GET", path=path,
            query_string=f"id={random.randint(1, 99)}&user={payload}",
        )

    if attack == "xss":
        return parse_raw_request(
            method="GET", path=path, query_string=f"q={random.choice(XSS_PAYLOADS)}"
        )

    if attack == "cmd":
        return parse_raw_request(
            method="GET", path=path,
            query_string=f"file=test.txt{random.choice(CMD_PAYLOADS)}",
        )

    if attack == "path":
        return parse_raw_request(
            method="GET", path=path,
            query_string=f"file={random.choice(PATH_TRAVERSAL_PAYLOADS)}",
        )

    payload = random.choice(ENCODED_ATTACKS)
    if random.random() < 0.5:
        return parse_raw_request(method="GET", path=path, query_string=f"input={payload}")
    return parse_raw_request(
        method="POST", path=path, body=f"username=admin&comment={payload}",
        content_type="application/x-www-form-urlencoded",
    )


def generate_dataset(normal_count: int = 1000, malicious_count: int = 1000, seed: int = 42):
    random.seed(seed)
    rows = []

    for _ in range(normal_count):
        features = extract_features(build_normal_request())
        features["label"] = 0
        rows.append(features)

    for _ in range(malicious_count):
        features = extract_features(build_malicious_request())
        features["label"] = 1
        rows.append(features)

    df = pd.DataFrame(rows, columns=FEATURE_ORDER + ["label"])
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    df = generate_dataset()
    df.to_csv("data/waf_dataset.csv", index=False)
    print("Dataset saved to: data/waf_dataset.csv")
    print(df.head())
    print("\nClass distribution:")
    print(df["label"].value_counts())
