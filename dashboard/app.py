"""
Flask Dashboard
"""

from flask import Flask, Response, jsonify, render_template, request

import attack_map


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

    @app.route("/api/heartbeat")
    def api_heartbeat():
        # Lightweight liveness probe used by the watchdog service.  We
        # touch the engine's internal state (taking a single lock) so a
        # deep deadlock surfaces here even when the bare HTTP listener
        # is still answering.
        score = agent.engine.current_score()
        return jsonify({"ok": True, "score": score})

    @app.route("/api/events")
    def api_events():
        # The dashboard "recent activity" panel reflects the *active* detection
        # window (engine), not the permanent store, so it stays consistent with
        # the threat score and clears when the operator resets it — instead of
        # showing stale CRITICAL rows under an "all clear" score.  Newest first.
        # The full audit trail still lives in the SQLite store + incident reports.
        sigs = agent.engine.recent_signals(100)
        # Annotate each event with its MITRE ATT&CK technique(s) so the admin
        # view can show a standard taxonomy badge without changing detection.
        return jsonify({
            "events": [attack_map.annotate_signal_dict(s.to_dict())
                       for s in reversed(sigs)]
        })

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

    @app.route("/api/reports")
    def api_reports():
        return jsonify({"reports": agent.incident_reporter.recent(limit=100)})

    @app.route("/api/reports/<path:filename>")
    def api_report_body(filename: str):
        body = agent.incident_reporter.read_report(filename)
        if body is None:
            return jsonify({"ok": False, "error": "not found"}), 404
        # text/markdown so browsers render-as-text and curl pipes cleanly.
        return Response(body, mimetype="text/markdown; charset=utf-8")

    # ----------------------------------------------------- administrator panel

    @app.route("/api/admin/health")
    def api_admin_health():
        """System-health snapshot: responder mode, driver, uptime, detectors."""
        return jsonify(agent.health())

    @app.route("/api/admin/mode", methods=["POST"])
    def api_admin_mode():
        """Change the responder mode (off|quarantine|kill) at runtime."""
        body = request.get_json(silent=True) or {}
        mode = str(body.get("mode") or "").lower()
        if mode not in ("off", "quarantine", "kill"):
            return jsonify({"ok": False,
                            "error": "mode must be off|quarantine|kill"}), 400
        try:
            new_mode = agent.set_responder_mode(mode)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
        return jsonify({"ok": True, "mode": new_mode})

    @app.route("/api/admin/threats")
    def api_admin_threats():
        """Per-PID threat breakdown with ATT&CK tags for triage."""
        return jsonify(agent.threat_breakdown())

    @app.route("/api/admin/allowlist", methods=["GET"])
    def api_admin_allowlist_get():
        return jsonify({"entries": agent.allowlist.entries()})

    @app.route("/api/admin/allowlist", methods=["POST"])
    def api_admin_allowlist_add():
        body = request.get_json(silent=True) or {}
        value = str(body.get("value") or "").strip()
        if not value:
            return jsonify({"ok": False, "error": "value required"}), 400
        try:
            entry = agent.allowlist.add(
                value, kind=str(body.get("kind") or ""),
                note=str(body.get("note") or ""))
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        return jsonify({"ok": True, "entry": entry,
                        "entries": agent.allowlist.entries()})

    @app.route("/api/admin/allowlist", methods=["DELETE"])
    def api_admin_allowlist_del():
        body = request.get_json(silent=True) or {}
        value = str(body.get("value") or "").strip()
        if not value:
            return jsonify({"ok": False, "error": "value required"}), 400
        removed = agent.allowlist.remove(value, kind=str(body.get("kind") or ""))
        return jsonify({"ok": True, "removed": removed,
                        "entries": agent.allowlist.entries()})

    return app
