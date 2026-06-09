"""
Flask Dashboard
---------------
인증(authentication) 추가 (기업 제품 요구사항):
  대시보드는 응답 모드 변경, 프로세스 강제 종료, 허용목록 편집 같은 **상태
  변경/관리자 작업**을 노출한다.  이 엔드포인트들이 무인증이면 같은 호스트에
  접근 가능한 누구나(또는 SSRF/로컬 악성코드가) 보호를 꺼버릴 수 있다.

  → 토큰 기반 인증을 도입한다.  ``agent.auth_token`` 이 설정돼 있으면
    변경성/관리자 엔드포인트는 ``X-API-Key: <token>`` 또는
    ``Authorization: Bearer <token>`` 헤더를 요구한다.  토큰이 비어 있으면
    (로컬 개발) 인증은 비활성.  읽기 전용 엔드포인트는 기본 공개이되,
    ``auth_required_for_reads`` 정책이 켜지면 함께 보호된다.  watchdog 의
    ``/api/heartbeat`` 는 항상 공개(가용성 프로브).
"""

import hmac
from functools import wraps

from flask import Flask, Response, jsonify, render_template, request

import attack_map


def create_app(agent):
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # 공백 토큰은 무효 처리 — 우발적으로 빈/공백 비밀로 인증이 켜지지 않게.
    token = (getattr(agent, "auth_token", "") or "").strip()
    protect_reads = bool(getattr(agent, "auth_required_for_reads", False))

    def _authorized() -> bool:
        """요청이 유효 토큰을 제시했는지.  토큰 미설정 시 항상 허용."""
        if not token:
            return True
        supplied = request.headers.get("X-API-Key", "")
        if not supplied:
            auth = request.headers.get("Authorization", "")
            if auth[:7].lower() == "bearer ":
                supplied = auth[7:].strip()
        # 타이밍 공격 방지 상수시간 비교.
        return bool(supplied) and hmac.compare_digest(supplied, token)

    def require_auth(view):
        """변경성/관리자 엔드포인트: 토큰이 설정돼 있으면 항상 인증 요구."""
        @wraps(view)
        def wrapped(*a, **kw):
            if not _authorized():
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return view(*a, **kw)
        return wrapped

    def maybe_auth(view):
        """읽기 엔드포인트: 정책이 켜진 경우에만 인증 요구."""
        @wraps(view)
        def wrapped(*a, **kw):
            if protect_reads and not _authorized():
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return view(*a, **kw)
        return wrapped

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/status")
    @maybe_auth
    def api_status():
        return jsonify(agent.status())

    @app.route("/api/heartbeat")
    def api_heartbeat():
        # Lightweight liveness probe used by the watchdog service.  We
        # touch the engine's internal state (taking a single lock) so a
        # deep deadlock surfaces here even when the bare HTTP listener
        # is still answering.  Always unauthenticated so the watchdog can
        # probe liveness without holding the operator token.
        score = agent.engine.current_score()
        return jsonify({"ok": True, "score": score})

    @app.route("/api/events")
    @maybe_auth
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
    @maybe_auth
    def api_processes():
        return jsonify({"processes": agent.processes(limit=60)})

    @app.route("/api/actions")
    @maybe_auth
    def api_actions():
        return jsonify({"actions": agent.responder.actions(limit=100)})

    @app.route("/api/reset", methods=["POST"])
    @require_auth
    def api_reset():
        agent.engine.reset()
        return jsonify({"ok": True})

    @app.route("/api/kill", methods=["POST"])
    @require_auth
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
    @require_auth
    def api_release():
        body = request.get_json(silent=True) or {}
        try:
            pid = int(body.get("pid"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "pid required"}), 400
        ok = agent.responder.manual_release(pid)
        return jsonify({"ok": ok})

    @app.route("/api/reports")
    @maybe_auth
    def api_reports():
        return jsonify({"reports": agent.incident_reporter.recent(limit=100)})

    @app.route("/api/reports/<path:filename>")
    @maybe_auth
    def api_report_body(filename: str):
        body = agent.incident_reporter.read_report(filename)
        if body is None:
            return jsonify({"ok": False, "error": "not found"}), 404
        # text/markdown so browsers render-as-text and curl pipes cleanly.
        return Response(body, mimetype="text/markdown; charset=utf-8")

    # ----------------------------------------------------- administrator panel

    @app.route("/api/admin/health")
    @require_auth
    def api_admin_health():
        """System-health snapshot: responder mode, driver, uptime, detectors."""
        return jsonify(agent.health())

    @app.route("/api/admin/mode", methods=["POST"])
    @require_auth
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
    @require_auth
    def api_admin_threats():
        """Per-PID threat breakdown with ATT&CK tags for triage."""
        return jsonify(agent.threat_breakdown())

    @app.route("/api/admin/allowlist", methods=["GET"])
    @require_auth
    def api_admin_allowlist_get():
        return jsonify({"entries": agent.allowlist.entries()})

    @app.route("/api/admin/allowlist", methods=["POST"])
    @require_auth
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
    @require_auth
    def api_admin_allowlist_del():
        body = request.get_json(silent=True) or {}
        value = str(body.get("value") or "").strip()
        if not value:
            return jsonify({"ok": False, "error": "value required"}), 400
        removed = agent.allowlist.remove(value, kind=str(body.get("kind") or ""))
        return jsonify({"ok": True, "removed": removed,
                        "entries": agent.allowlist.entries()})

    return app
