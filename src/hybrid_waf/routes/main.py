import json
import os
from collections import deque

from flask import Blueprint, jsonify, render_template, request

from src.hybrid_waf import config

main_bp = Blueprint("main", __name__)

MAX_EVENTS = 60


@main_bp.route("/waf")
def dashboard():
    return render_template("dashboard.html")


@main_bp.route("/waf/about")
def landing():
    return render_template("index.html")


@main_bp.route("/waf/home")
def home():
    return render_template("home.html")


@main_bp.route("/waf/status")
def status():
    return jsonify(
        {
            "mode": config.MODE,
            "blocking": config.is_blocking(),
            "backend": config.BACKEND_URL,
        }
    )


@main_bp.route("/waf/api/events")
def events():
    """Recent decisions, newest first, plus running counts.

    Reads the tail of the detection log rather than keeping state in memory, so
    the console still works after a restart and reflects what was written to
    disk -- the same record you would grep during tuning.
    """
    tail = deque(maxlen=MAX_EVENTS)
    counts = {"allowed": 0, "blocked": 0, "would_block": 0}

    try:
        with open(config.LOG_PATH, encoding="utf-8") as handle:
            for line in handle:
                parsed = _parse_line(line)
                if parsed is None:
                    continue

                if parsed["action"] == "block":
                    key = "blocked" if parsed["enforced"] else "would_block"
                else:
                    key = "allowed"
                counts[key] += 1

                tail.append(parsed)
    except FileNotFoundError:
        pass

    return jsonify({"events": list(reversed(tail)), "counts": counts})


def _parse_line(line: str):
    """Split '<timestamp> {json}' into a flat event dict, or None if unusable."""
    brace = line.find("{")
    if brace == -1:
        return None

    try:
        record = json.loads(line[brace:])
    except ValueError:
        return None

    if "action" not in record:
        return None  # e.g. the model_load_failed marker

    timestamp = line[:brace].strip()
    record["time"] = timestamp.split(" ")[-1] if timestamp else ""
    record.setdefault("enforced", False)
    record.setdefault("category", None)
    record.setdefault("location", None)
    record.setdefault("method", "")
    record.setdefault("path", "")
    return record
