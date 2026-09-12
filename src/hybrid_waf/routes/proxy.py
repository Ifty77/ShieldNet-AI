from flask import Blueprint, request, jsonify
from src.hybrid_waf.utils.signature_checker import check_signature
import logging
import os

proxy_bp = Blueprint('proxy', __name__)

# Make sure logs folder exists
os.makedirs('logs', exist_ok=True)

# Create a dedicated logger for WAF detections
waf_logger = logging.getLogger('waf_detections')
waf_logger.setLevel(logging.INFO)

# Prevent duplicate handlers in debug mode
if not waf_logger.handlers:
    fh = logging.FileHandler('logs/detections.log')
    fh.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    fh.setFormatter(formatter)
    waf_logger.addHandler(fh)


@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    data = request.get_json(silent=True) or {}

    user_input = data.get("user_request", "").strip()
    uri = data.get("uri", user_input).strip()
    get_data = data.get("get_data", "").strip()
    post_data = data.get("post_data", "").strip()

    if not user_input:
        return jsonify({
            "status": "error",
            "message": "No request provided."
        }), 400

    # --- Step 1: Signature-Based Detection ---
    signature_result = check_signature(user_input)
    signature_status = signature_result["status"]

    if signature_status == "valid":
        waf_logger.info(f"{user_input} - valid")
        return jsonify({
            "status": "valid",
            "message": "All Clear! Your request passed our security checks with flying colors. ✨"
        })

    if signature_status == "malicious":
        waf_logger.info(f"{user_input} - malicious(signature)")
        return jsonify({
            "status": "malicious",
            "message": "Critical Alert! Malicious pattern detected in your request. Access Denied! 🔒"
        })

    # --- Step 2: ML-Based Anomaly Detection ---
    if signature_status == "obfuscated":
        from src.hybrid_waf.utils.preprocessor import extract_features
        from src.hybrid_waf.utils.ml_checker import check_ml_prediction

        features = extract_features(uri, get_data, post_data)
        prediction = check_ml_prediction(features)

        final_status = "malicious" if prediction == 1 else "valid"

        waf_logger.info(
            f"{user_input} - malicious(ML)" if prediction == 1
            else f"{user_input} - valid"
        )

        return jsonify({
            "status": "obfuscated",
            "final_status": final_status,
            "message": "Suspicious Pattern Detected - Engaging Advanced AI Analysis...",
            "ml_verdict": (
                "🚨 Threat Confirmed! AI Defense System Blocked Suspicious Activity. 🔒"
                if final_status == "malicious"
                else "✅ Advanced AI Scan Complete: Request Verified Safe ✨"
            ),
            "features": features
        })

    return jsonify({
        "status": "error",
        "message": "Unknown detection result."
    }), 500