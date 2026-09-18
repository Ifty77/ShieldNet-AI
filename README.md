# 🛡️ ShieldNet-AI

**A hybrid Web Application Firewall — signature detection plus a machine learning layer — running as a reverse proxy in front of a real demo application, with a live decision console.**

    Browser  →  ShieldNet-AI gateway  →  protected application

Every request passes through two layers of defense before it reaches the app it protects. Allowed requests are forwarded and never know a WAF is there. Blocked requests receive HTTP 403 and never arrive.

---

## How It Works

1. **Signature layer.** Every attacker-controllable part of the request — path, query parameters, form fields, JSON body (including nested objects), and a short list of headers — is checked against regex rules covering SQL injection, XSS, path traversal, command injection, SSRF, and header injection. A clear match blocks immediately, tagged with exactly where it matched (e.g. `query:q`, `body:comment`, `header:User-Agent`).

2. **ML layer.** Requests that look obfuscated (encoded payloads, `CHAR()`/`CONCAT()` tricks) but don't clearly match a signature are scored by a LightGBM model trained on 8 statistical features — length, Shannon entropy, numeric/text ratio, special-character density — across the URI, query string, and body.

Both layers share **one** feature-extraction implementation (`src/hybrid_waf/core/request_parser.py`), used by both dataset generation and live detection. This guarantees the model is never scored on features that mean something different than what it was trained on.

Every decision is logged as JSON to `logs/detections.log` and streamed live to the console.

---

## What's in this repo

| Piece | Purpose |
|---|---|
| **ShieldNet-AI gateway** (`app.py`, port 5000) | Reverse proxy + detection engine |
| **Fernwood Supply** (`demo_app/`, port 5001) | A small demo app it protects — login, search, comments |
| **Live console** (`/waf`) | Real-time stream of allow/block decisions, with one-click attack samples |
| **Request analyzer** (`/waf/home`) | Test a request string without sending it upstream |
| **Monitor mode** | Log every decision without enforcing any of them — always start here on new traffic |

### Monitor mode vs. blocking

```
SHIELDNET_MODE=monitor   # default — logs what would happen, forwards everything
SHIELDNET_MODE=block     # enforces — malicious requests get HTTP 403
```

Run monitor mode first against real traffic, review `logs/detections.log` (or the console) for false positives, then switch to `block`.

---

## Project Structure

```
ShieldNet-AI/
├── app.py                         # Gateway entry point
├── run_demo.py                    # Starts gateway + demo app together
├── test_waf.py                    # 20-check verification suite
├── generate_dataset.py            # Builds the training dataset
├── train_model.py                 # Trains and saves the ML model
├── data/waf_dataset.csv
├── logs/detections.log            # JSON-lines decision log
├── demo_app/
│   ├── app.py                     # Fernwood Supply — the protected application
│   └── templates/shop.html
├── src/hybrid_waf/
│   ├── config.py                  # Backend URL, MODE, timeouts
│   ├── core/
│   │   ├── request_parser.py      # SINGLE SOURCE OF TRUTH for parsing + features
│   │   └── engine.py              # evaluate() -> Decision; logging
│   ├── models/ml_model.pkl
│   ├── routes/
│   │   ├── gateway.py             # Reverse proxy, enforces 403
│   │   ├── proxy.py               # /check_request (shares the engine)
│   │   └── main.py                # Console, analyzer, status, events API
│   └── utils/
│       ├── signature_checker.py   # Per-field regex scanning
│       ├── preprocessor.py        # Back-compat shim over core
│       └── ml_checker.py          # Named-column model inference
├── templates/
│   ├── dashboard.html             # Live console
│   ├── index.html / home.html     # Landing page / analyzer UI
└── static/
```

---

## Getting Started

### Prerequisites
- Python 3.9+
- pip

### Installation

```bash
git clone https://github.com/Ifty77/ShieldNet-AI.git
cd ShieldNet-AI

python -m venv .venv
# Windows
.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Build the model

```bash
python generate_dataset.py
python train_model.py
```

### Verify

```bash
python test_waf.py
```

Expect `ALL CHECKS PASSED`.

### Run

```bash
python run_demo.py            # monitor mode
python run_demo.py block      # blocking enabled
```

Then open:

| URL | What it is |
|---|---|
| `http://127.0.0.1:5000/` | Fernwood Supply, the protected shop |
| `http://127.0.0.1:5000/waf` | Live decision console |
| `http://127.0.0.1:5000/waf/home` | Request analyzer |
| `http://127.0.0.1:5000/waf/status` | Current mode, as JSON |

---

## Demonstrating it

With `python run_demo.py block` running, try:

```bash
curl "http://127.0.0.1:5000/search?q=laptop"
curl "http://127.0.0.1:5000/search?q=' OR 1=1 --"
```

| Request | Result |
|---|---|
| benign search / login / comment | 200/200/201, reaches the app |
| SQL injection in query | **403**, never reaches the app |
| XSS in a JSON body | **403**, never reaches the app |
| injection via a header | **403**, never reaches the app |

The clearest evidence is the demo app's own console: it logs every request it actually receives. When ShieldNet-AI blocks something, there is no line for it — the attack never arrived.

---

## API — `/check_request`

Analyze a request string directly, without a live backend.

**POST** `/check_request`
```json
{ "user_request": "/products?id=1' OR '1'='1" }
```

```json
{
  "status": "malicious",
  "action": "block",
  "category": "sql_injection",
  "location": "query:id",
  "message": "Critical Alert! Malicious pattern detected in your request. Access Denied! 🔒"
}
```

---

## License

Open source, available under the [MIT License](LICENSE).