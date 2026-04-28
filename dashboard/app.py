"""Flask dashboard — serves the real-time honeypot analytics UI via SSE."""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from flask_cors import CORS

from honeypot.db import (
    all_ips_with_coords,
    command_frequency,
    high_interest_sessions,
    hourly_volume,
    init_db,
    mitre_frequency,
    recent_sessions,
    stats_today,
    top_asns,
    top_countries,
    top_credentials,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "changeme")
REQUIRE_AUTH = DASHBOARD_USERNAME and DASHBOARD_PASSWORD != ""


def _check_auth(username: str, password: str) -> bool:
    return username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD


def _auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not REQUIRE_AUTH:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not _check_auth(auth.username, auth.password):
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Honeypot Dashboard"'},
            )
        return f(*args, **kwargs)
    return decorated


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
@_auth_required
def index():
    return render_template("index.html")


# ── JSON API ──────────────────────────────────────────────────────────────────

@app.route("/api/stats")
@_auth_required
def api_stats():
    return jsonify(stats_today())


@app.route("/api/countries")
@_auth_required
def api_countries():
    return jsonify(top_countries(10))


@app.route("/api/asns")
@_auth_required
def api_asns():
    return jsonify(top_asns(10))


@app.route("/api/credentials")
@_auth_required
def api_credentials():
    return jsonify(top_credentials(10))


@app.route("/api/commands")
@_auth_required
def api_commands():
    return jsonify(command_frequency(20))


@app.route("/api/mitre")
@_auth_required
def api_mitre():
    return jsonify(mitre_frequency(15))


@app.route("/api/hourly")
@_auth_required
def api_hourly():
    hours = int(request.args.get("hours", 24))
    return jsonify(hourly_volume(hours))


@app.route("/api/sessions")
@_auth_required
def api_sessions():
    limit = int(request.args.get("limit", 50))
    return jsonify(recent_sessions(limit))


@app.route("/api/sessions/high-interest")
@_auth_required
def api_high_interest():
    return jsonify(high_interest_sessions(20))


@app.route("/api/map")
@_auth_required
def api_map():
    return jsonify(all_ips_with_coords())


# ── SSE endpoint ──────────────────────────────────────────────────────────────

def _sse_packet(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.route("/api/events")
@_auth_required
def api_events():
    """Server-Sent Events stream — pushes dashboard data every 3 seconds."""

    @stream_with_context
    def generate():
        yield _sse_packet("connected", {"ts": datetime.now(timezone.utc).isoformat()})

        last_session_count = 0
        while True:
            try:
                payload = {
                    "stats": stats_today(),
                    "countries": top_countries(10),
                    "asns": top_asns(10),
                    "credentials": top_credentials(10),
                    "commands": command_frequency(20),
                    "mitre": mitre_frequency(15),
                    "hourly": hourly_volume(24),
                    "map_points": all_ips_with_coords(),
                    "high_interest": high_interest_sessions(10),
                }

                # Only send recent sessions if the count changed (avoid huge payloads)
                sessions = recent_sessions(20)
                if len(sessions) != last_session_count:
                    payload["sessions"] = sessions
                    last_session_count = len(sessions)

                yield _sse_packet("update", payload)
            except GeneratorExit:
                return
            except Exception as exc:
                logger.warning("SSE error: %s", exc)

            time.sleep(3)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("DASHBOARD_PORT", 8080))
    logger.info("Dashboard starting on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
