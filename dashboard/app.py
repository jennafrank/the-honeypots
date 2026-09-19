"""Flask dashboard — serves the real-time honeypot analytics UI via SSE."""

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from flask_cors import CORS

from honeypot.db import (
    abandonment_stats,
    all_ips_with_coords,
    command_frequency,
    credential_patterns,
    easter_egg_leaderboard,
    first_cmd_stats,
    high_interest_sessions,
    hourly_heatmap,
    hourly_volume,
    init_db,
    initial_cmd_event_id,
    ip_session_history,
    mitre_frequency,
    new_commands_since,
    recent_sessions,
    return_visitors,
    sophistication_distribution,
    stats,
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


def _since(range_param: str | None) -> str | None:
    """Convert ?range= query param to ISO datetime floor, or None for all time."""
    if range_param == "24h":
        return (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    return None


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
@_auth_required
def index():
    return render_template("index.html")


# ── JSON API ──────────────────────────────────────────────────────────────────

@app.route("/api/stats")
@_auth_required
def api_stats():
    return jsonify(stats(_since(request.args.get("range"))))


@app.route("/api/countries")
@_auth_required
def api_countries():
    return jsonify(top_countries(10, since=_since(request.args.get("range"))))


@app.route("/api/asns")
@_auth_required
def api_asns():
    return jsonify(top_asns(10, since=_since(request.args.get("range"))))


@app.route("/api/credentials")
@_auth_required
def api_credentials():
    return jsonify(top_credentials(10, since=_since(request.args.get("range"))))


@app.route("/api/commands")
@_auth_required
def api_commands():
    return jsonify(command_frequency(20, since=_since(request.args.get("range"))))


@app.route("/api/mitre")
@_auth_required
def api_mitre():
    return jsonify(mitre_frequency(15, since=_since(request.args.get("range"))))


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
    return jsonify(high_interest_sessions(20, since=_since(request.args.get("range"))))


@app.route("/api/map")
@_auth_required
def api_map():
    return jsonify(all_ips_with_coords(since=_since(request.args.get("range"))))


@app.route("/api/credential-patterns")
@_auth_required
def api_credential_patterns():
    return jsonify(credential_patterns(since=_since(request.args.get("range"))))


@app.route("/api/heatmap")
@_auth_required
def api_heatmap():
    return jsonify(hourly_heatmap(since=_since(request.args.get("range"))))


@app.route("/api/first-commands")
@_auth_required
def api_first_commands():
    return jsonify(first_cmd_stats(since=_since(request.args.get("range"))))


@app.route("/api/easter-eggs")
@_auth_required
def api_easter_eggs():
    return jsonify(easter_egg_leaderboard(since=_since(request.args.get("range"))))


@app.route("/api/sophistication")
@_auth_required
def api_sophistication():
    return jsonify(sophistication_distribution(since=_since(request.args.get("range"))))


@app.route("/api/return-visitors")
@_auth_required
def api_return_visitors():
    return jsonify(return_visitors(20, since=_since(request.args.get("range"))))


@app.route("/api/abandonment")
@_auth_required
def api_abandonment():
    return jsonify(abandonment_stats(since=_since(request.args.get("range"))))


@app.route("/api/sessions/ip/<ip>")
@_auth_required
def api_ip_history(ip: str):
    return jsonify(ip_session_history(ip))


@app.route("/api/commands/live")
@_auth_required
def api_commands_live():
    last_id = int(request.args.get("since_id", initial_cmd_event_id(100)))
    cmds, new_id = new_commands_since(last_id, 100)
    return jsonify({"commands": cmds, "last_id": new_id})


# ── SSE endpoint ──────────────────────────────────────────────────────────────

def _sse_packet(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.route("/api/events")
@_auth_required
def api_events():
    """Server-Sent Events stream — pushes dashboard data every 3 seconds."""
    range_param = request.args.get("range")

    @stream_with_context
    def generate():
        since = _since(range_param)
        last_cmd_id = initial_cmd_event_id(50)
        last_session_count = 0

        yield _sse_packet("connected", {"ts": datetime.now(timezone.utc).isoformat()})

        while True:
            try:
                new_cmds, new_cmd_id = new_commands_since(last_cmd_id)
                last_cmd_id = new_cmd_id

                payload = {
                    "stats": stats(since=since),
                    "countries": top_countries(10, since=since),
                    "asns": top_asns(10, since=since),
                    "credentials": top_credentials(10, since=since),
                    "commands": command_frequency(20, since=since),
                    "mitre": mitre_frequency(15, since=since),
                    "hourly": hourly_volume(24),
                    "map_points": all_ips_with_coords(since=since),
                    "high_interest": high_interest_sessions(10, since=since),
                    "credential_patterns": credential_patterns(since=since),
                    "heatmap": hourly_heatmap(since=since),
                    "first_commands": first_cmd_stats(since=since),
                    "easter_eggs": easter_egg_leaderboard(since=since),
                    "sophistication": sophistication_distribution(since=since),
                    "return_visitors": return_visitors(10, since=since),
                }

                if new_cmds:
                    payload["new_commands"] = new_cmds

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
