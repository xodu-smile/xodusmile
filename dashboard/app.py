"""
Flask Dashboard
"""

from flask import Flask, jsonify, render_template, request


def create_app(agent):
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/status")
    def api_status():
        return jsonify(agent.status())

    @app.route("/api/events")
    def api_events():
        return jsonify({"events": agent.store.recent(100)})

    @app.route("/api/processes")
    def api_processes():
        return jsonify({"processes": agent.processes(limit=60)})

    @app.route("/api/actions")
    def api_actions():
        return jsonify({"actions": agent.responder.actions(limit=100)})

    @app.route("/api/reset", methods=["POST"])
    def api_reset():
        agent.engine.reset()
        return jsonify({"ok": True})

    @app.route("/api/kill", methods=["POST"])
    def api_kill():
        body = request.get_json(silent=True) or {}
        try:
            pid = int(body.get("pid"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "pid required"}), 400
        reason = str(body.get("reason") or "manual-via-dashboard")
        action = agent.responder.manual_kill(pid, reason=reason)
        return jsonify({"ok": True, "action": action.to_dict()})

    @app.route("/api/release", methods=["POST"])
    def api_release():
        body = request.get_json(silent=True) or {}
        try:
            pid = int(body.get("pid"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "pid required"}), 400
        ok = agent.responder.manual_release(pid)
        return jsonify({"ok": ok})

    return app
