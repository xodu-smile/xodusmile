"""
Flask Dashboard
"""

from flask import Flask, jsonify, render_template


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

    @app.route("/api/reset", methods=["POST"])
    def api_reset():
        agent.engine.reset()
        return jsonify({"ok": True})

    return app
