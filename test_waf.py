"""Verification suite. Run with: python test_waf.py"""

import sys
import threading
import time

from flask import Flask, request as flask_request

from src.hybrid_waf.core.request_parser import (
    extract_features, parse_flask_request, parse_raw_request,
)

_probe = Flask(__name__)
failures = 0


def check(name, condition, detail=""):
    global failures
    status = "PASS" if condition else "FAIL"
    if not condition:
        failures += 1
    print(f"  [{status}] {name}" + (f"  {detail}" if detail and not condition else ""))


print("\n1. Training/serving feature parity")
cases = [
    ("GET", "/search", "q=laptop&user=alice", "", ""),
    ("GET", "/products", "id=103&page=2", "", ""),
    ("GET", "/search", "q=' OR 1=1 --", "", ""),
    ("POST", "/comments", "", "author=bob&comment=nice",
     "application/x-www-form-urlencoded"),
]
for method, path, qs, body, ctype in cases:
    train = extract_features(parse_raw_request(method, path, qs, body, ctype))
    with _probe.test_request_context(
        path=path + ("?" + qs if qs else ""), method=method,
        data=body, content_type=ctype or None,
    ):
        serve = extract_features(parse_flask_request(flask_request))
    check(f"{method} {path} identical", train == serve, f"{train} != {serve}")

print("\n2. JSON and form bodies produce identical features")
f_form = extract_features(parse_raw_request(
    "POST", "/c", body="author=bob&comment=hi",
    content_type="application/x-www-form-urlencoded"))
f_json = extract_features(parse_raw_request(
    "POST", "/c", body='{"author":"bob","comment":"hi"}',
    content_type="application/json"))
check("form == json", f_form == f_json)

print("\n3. Detection across every inspection surface")
from src.hybrid_waf.core.engine import evaluate  # noqa: E402

surface_cases = [
    ("query param", parse_raw_request("GET", "/s", "q=' OR 1=1 --"), "block", "query:q"),
    ("form body", parse_raw_request(
        "POST", "/c", body="comment=<script>alert(1)</script>",
        content_type="application/x-www-form-urlencoded"), "block", "body:comment"),
    ("nested JSON", parse_raw_request(
        "POST", "/a", body='{"user":{"bio":"<img src=x onerror=alert(1)>"}}',
        content_type="application/json"), "block", "body:user.bio"),
    ("header", parse_raw_request(
        "GET", "/", headers={"User-Agent": "' UNION SELECT pw FROM users --"}),
        "block", "header:User-Agent"),
    ("path", parse_raw_request("GET", "/../../etc/passwd"), "block", "path"),
    ("benign", parse_raw_request("GET", "/search", "q=laptop"), "allow", None),
]
for name, parsed, want_action, want_loc in surface_cases:
    d = evaluate(parsed)
    check(f"{name} -> {want_action}", d.action == want_action and d.location == want_loc,
          f"got action={d.action} location={d.location}")

print("\n4. Gateway blocks before the backend is reached")
from demo_app.app import app as backend  # noqa: E402

threading.Thread(
    target=lambda: backend.run(port=5001, debug=False, use_reloader=False),
    daemon=True).start()
time.sleep(2)

reached = []
backend.before_request_funcs.setdefault(None, []).append(
    lambda: reached.append(flask_request.path))

import app as wafmod  # noqa: E402
from src.hybrid_waf import config  # noqa: E402

client = wafmod.app.test_client()

gateway_cases = [
    ("benign search", "GET", "/search?q=laptop", None, 200, True),
    ("benign comment", "POST", "/comments",
     {"author": "b", "comment": "nice"}, 201, True),
    ("SQLi query", "GET", "/search?q=' OR 1=1 --", None, 403, False),
    ("XSS json body", "POST", "/comments",
     {"author": "b", "comment": "<img src=x onerror=alert(1)>"}, 403, False),
]
for name, method, path, js, want_code, want_reach in gateway_cases:
    before = len(reached)
    r = client.open(path, method=method, json=js)
    did_reach = len(reached) > before
    if config.is_blocking():
        check(f"{name}: HTTP {want_code}", r.status_code == want_code,
              f"got {r.status_code}")
        check(f"{name}: reached backend = {want_reach}", did_reach == want_reach)
    else:
        check(f"{name}: forwarded in monitor mode", did_reach)

print("\n5. /check_request error handling")
r = client.post("/check_request", json={})
check("empty request -> HTTP 400", r.status_code == 400)
r = client.post("/check_request", json={"user_request": "/search?q=laptop"})
check("benign -> HTTP 200 valid", r.status_code == 200
      and r.get_json()["status"] == "valid")

print("\n" + "=" * 50)
print("ALL CHECKS PASSED" if failures == 0 else f"{failures} CHECK(S) FAILED")
sys.exit(1 if failures else 0)
