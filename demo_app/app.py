"""ShopDemo - the application that ShieldNet-AI protects.

Runs on port 5001. In the demo topology nothing talks to it directly:

    Browser -> ShieldNet-AI :5000 -> ShopDemo :5001

This app is written defensively on purpose. It uses parameterized SQL and
escapes output, so it is NOT itself vulnerable. The point of the demo is to
show that ShieldNet-AI stops hostile traffic *before* it arrives -- which you
can verify by watching this app's own request log stay empty when an attack is
blocked upstream.
"""

import html
import logging
import sqlite3
from flask import Flask, g, jsonify, render_template, request

app = Flask(__name__)
DB_PATH = ":memory:"

logging.basicConfig(
    level=logging.INFO,
    format="[ShopDemo] %(asctime)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("shopdemo")

PRODUCTS = [
    (1, "Mechanical Keyboard", "electronics", 89.99),
    (2, "Noise Cancelling Headphones", "electronics", 199.00),
    (3, "Running Shoes", "sports", 74.50),
    (4, "Yoga Mat", "sports", 25.00),
    (5, "Clean Code", "books", 34.99),
    (6, "The Pragmatic Programmer", "books", 39.99),
]

USERS = {"alice": "wonderland", "bob": "builder"}

COMMENTS = []


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.execute(
            "CREATE TABLE products (id INTEGER, name TEXT, category TEXT, price REAL)"
        )
        g.db.executemany("INSERT INTO products VALUES (?,?,?,?)", PRODUCTS)
        g.db.commit()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def log_request():
    """Every request that reaches this app gets logged.

    When the WAF blocks something, nothing appears here. That silence is the
    demonstration.
    """
    log.info(
        "REACHED BACKEND: %s %s | args=%s | body=%s",
        request.method,
        request.path,
        dict(request.args),
        request.get_data(as_text=True)[:200],
    )


def wants_html() -> bool:
    """Browsers ask for text/html explicitly; curl and the test suite do not."""
    return "text/html" in (request.headers.get("Accept") or "")


@app.route("/")
def index():
    if wants_html():
        return render_template("shop.html", query="", results=all_products())
    return jsonify(
        {
            "app": "Fernwood Supply",
            "protected_by": "ShieldNet-AI",
            "endpoints": ["/login (POST)", "/search?q=", "/comments (GET, POST)"],
        }
    )


def all_products():
    rows = get_db().execute(
        "SELECT id, name, category, price FROM products"
    ).fetchall()
    return [
        {"id": r[0], "name": r[1], "category": r[2], "price": r[3]} for r in rows
    ]


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if USERS.get(username) == password:
        return jsonify({"status": "ok", "user": username, "message": "Login successful"})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/search")
def search():
    query = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()

    # Parameterized -- this app does not concatenate user input into SQL.
    sql = "SELECT id, name, category, price FROM products WHERE name LIKE ?"
    params = [f"%{query}%"]
    if category:
        sql += " AND category = ?"
        params.append(category)

    rows = get_db().execute(sql, params).fetchall()
    results = [
        {"id": r[0], "name": r[1], "category": r[2], "price": r[3]} for r in rows
    ]

    if wants_html():
        return render_template("shop.html", query=query, results=results)

    return jsonify({"query": query, "count": len(rows), "results": results})


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "GET":
        return jsonify({"count": len(COMMENTS), "comments": COMMENTS})

    data = request.get_json(silent=True) or request.form
    author = (data.get("author") or "anonymous").strip()
    body = (data.get("comment") or "").strip()

    if not body:
        return jsonify({"status": "error", "message": "Comment body is required"}), 400

    # Escaped on the way in -- stored data is never raw HTML.
    entry = {"author": html.escape(author), "comment": html.escape(body)}
    COMMENTS.append(entry)
    return jsonify({"status": "ok", "stored": entry}), 201


if __name__ == "__main__":
    app.run(port=5001, debug=False)
