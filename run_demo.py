"""Start the protected backend and the ShieldNet-AI gateway together.

    python run_demo.py            # monitor mode (nothing is blocked)
    python run_demo.py block      # blocking enabled

Then browse to http://127.0.0.1:5000
"""

import os
import sys
import threading
import time

if len(sys.argv) > 1 and sys.argv[1].lower() in ("block", "monitor"):
    os.environ["SHIELDNET_MODE"] = sys.argv[1].lower()

from src.hybrid_waf import config  # noqa: E402  (import after env is set)


def start_backend():
    from demo_app.app import app as backend
    backend.run(port=5001, debug=False, use_reloader=False)


if __name__ == "__main__":
    threading.Thread(target=start_backend, daemon=True).start()
    time.sleep(1.5)

    from app import app as waf

    print("=" * 62)
    print("  ShieldNet-AI demo")
    print(f"  mode      : {config.MODE.upper()}")
    print(f"  gateway   : http://127.0.0.1:5000   (send traffic here)")
    print(f"  backend   : {config.BACKEND_URL}   (protected app)")
    print(f"  WAF UI    : http://127.0.0.1:5000/waf")
    print(f"  log       : {config.LOG_PATH}")
    if not config.is_blocking():
        print("  NOTE: monitor mode - decisions logged, nothing blocked.")
    print("=" * 62)

    waf.run(port=5000, debug=False, use_reloader=False)
