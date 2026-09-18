from flask import Flask

from src.hybrid_waf import config
from src.hybrid_waf.routes.gateway import gateway_bp
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

app = Flask(__name__)

# Order matters. The WAF's own UI and analyzer routes register first; the
# gateway catch-all registers last so it only sees paths nothing else claimed.
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)
app.register_blueprint(gateway_bp)

if __name__ == "__main__":
    print(f"[ShieldNet-AI] mode={config.MODE}  backend={config.BACKEND_URL}")
    if not config.is_blocking():
        print("[ShieldNet-AI] MONITOR MODE - decisions are logged, nothing is blocked.")
    app.run(port=5000, debug=True)
