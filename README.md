# 🛡️ ShieldNet-AI

**AI-powered hybrid Web Application Firewall combining signature-based detection with machine learning for real-time threat analysis.**

ShieldNet-AI inspects incoming web requests through two layers of defense: a fast signature-matching engine for known attack patterns, and a machine learning model that catches obfuscated or previously unseen threats that static rules miss.

---

## How It Works

Every request goes through a two-layer pipeline:

1. **Layer 1 — Signature Detection**
   The request is checked against a curated set of regex patterns covering common attack categories:
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Path Traversal
   - Command Injection
   - Server-Side Request Forgery (SSRF)
   - HTTP Header Injection

   If a request clearly matches a known attack pattern, it's blocked immediately. If it's clean, it's marked valid. If it looks obfuscated (e.g. encoded payloads, `CHAR()`/`CONCAT()` tricks, base64), it's escalated to Layer 2.

2. **Layer 2 — ML Analysis**
   Obfuscated requests are converted into 8 numerical features — length, Shannon entropy, numeric-to-text ratio, and special character counts across the URI, GET, and POST data — and passed to a trained ML model (scikit-learn / LightGBM) for a final malicious/valid verdict.

All detection results are logged to `logs/detections.log` for auditing.

---

## Tech Stack

- **Backend:** Python, Flask
- **ML:** scikit-learn, LightGBM, joblib
- **Frontend:** HTML, CSS, JavaScript (server-rendered via Jinja templates)

---

## Project Structure

```
ShieldNet-AI/
├── app.py                     # Flask app entry point
├── generate_dataset.py        # Generates the training dataset
├── train_model.py             # Trains and saves the ML model
├── data/
│   └── waf_dataset.csv        # Training dataset
├── logs/
│   └── detections.log         # Runtime detection logs
├── src/hybrid_waf/
│   ├── models/
│   │   └── ml_model.pkl       # Trained ML model
│   ├── routes/
│   │   ├── main.py            # Page routes (landing, dashboard)
│   │   └── proxy.py           # /check_request detection endpoint
│   └── utils/
│       ├── signature_checker.py   # Regex-based signature detection
│       ├── preprocessor.py        # Feature extraction for ML
│       └── ml_checker.py          # ML model inference
├── templates/                 # HTML pages
├── static/                    # CSS/JS assets
└── requirements.txt
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

### Running the App

```bash
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

### (Optional) Retraining the ML Model

A pretrained model is included at `src/hybrid_waf/models/ml_model.pkl`. To regenerate it:

```bash
python generate_dataset.py
python train_model.py
```

---

## API

**POST** `/check_request`

Request body:
```json
{
  "user_request": "/products?id=1' OR '1'='1",
  "uri": "/products",
  "get_data": "id=1' OR '1'='1",
  "post_data": ""
}
```

Response:
```json
{
  "status": "malicious",
  "message": "Critical Alert! Malicious pattern detected in your request. Access Denied! 🔒"
}
```

---

## License

This project is open source and available under the [MIT License](LICENSE).
