from flask import Flask
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

app = Flask(__name__)

app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)

if __name__ == "__main__":
    app.run(debug=True)