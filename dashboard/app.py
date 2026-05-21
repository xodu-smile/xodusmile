"""
Flask Dashboard
"""

from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request


REPORT_DEFAULT_LIMIT = 500
REPORT_MAX_LIMIT = 5000


def _md_escape(s) -> str:
    """Escape characters that would break the markdown table cell."""
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _build_markdown_report(agent, limit: int) -> str:
    status = agent.status()
    stats = status.get("stats") or {}
    events = agent.store.recent(limit)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append("# Ransomware Detector — Event Report")
    lines.append("")
    lines.append(f"_Generated {now}._")
    lines.append("")
    lines.append("## State")
    lines.append("")
    lines.append(f"- Threat level: **{status.get('level', '?')}**")
    lines.append(f"- Cumulative score (120s): **{status.get('score', 0)}**")
    lines.append(f"- Events in DB: **{stats.get('total', 0)}**")
    lines.append(f"- Events in this report: **{len(events)}** (limit={limit})")
    lines.append("")

    by_det = stats.get("by_detector") or {}
    by_sev = stats.get("by_severity") or {}
    if by_det or by_sev:
        lines.append("## Stats")
        lines.append("")
    if by_det:
        lines.append("### By detector")
        lines.append("")
        lines.append("| Detector | Count |")
        lines.append("|---|---:|")
        for k in sorted(by_det, key=lambda x: -by_det[x]):
            lines.append(f"| {_md_escape(k)} | {by_det[k]} |")
        lines.append("")
    if by_sev:
        lines.append("### By severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for k in sorted(by_sev, key=lambda x: sev_order.get(x, 99)):
            lines.append(f"| {_md_escape(k)} | {by_sev[k]} |")
        lines.append("")

    lines.append("## Events")
    lines.append("")
    if not events:
        lines.append("_No events recorded._")
        lines.append("")
        return "\n".join(lines)

    lines.append("| # | Time (UTC) | Severity | Detector / Name | W | Score | Level | Message | Metadata |")
    lines.append("|---:|---|---|---|---:|---:|---|---|---|")
    for i, e in enumerate(events, 1):
        ts = e.get("timestamp")
        try:
            tstr = datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except (TypeError, ValueError):
            tstr = "?"
        meta = e.get("metadata") or {}
        meta_str = " ".join(f"{k}={v}" for k, v in meta.items()) if isinstance(meta, dict) else str(meta)
        lines.append(
            "| {i} | {ts} | {sev} | {det} / {name} | {w} | {sc} | {lv} | {msg} | {meta} |".format(
                i=i,
                ts=_md_escape(tstr),
                sev=_md_escape(e.get("severity", "")),
                det=_md_escape(e.get("detector", "")),
                name=_md_escape(e.get("name", "")),
                w=e.get("weight", 0),
                sc=e.get("score_after", 0),
                lv=_md_escape(e.get("level_after", "")),
                msg=_md_escape(e.get("message", "")),
                meta=_md_escape(meta_str),
            )
        )

    lines.append("")
    return "\n".join(lines)


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

    @app.route("/api/report")
    def api_report():
        try:
            limit = int(request.args.get("limit", REPORT_DEFAULT_LIMIT))
        except ValueError:
            limit = REPORT_DEFAULT_LIMIT
        limit = max(1, min(limit, REPORT_MAX_LIMIT))
        body = _build_markdown_report(agent, limit)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"ransom-detector-report-{stamp}.md"
        return Response(
            body,
            mimetype="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

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
