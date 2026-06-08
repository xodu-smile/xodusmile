"""
Tests for dashboard authentication (dashboard/app.py)
-----------------------------------------------------
When agent.auth_token is set, mutating/admin endpoints require the token via
X-API-Key or Authorization: Bearer.  Heartbeat is always open; reads are open
unless auth_required_for_reads is set.
"""

import pytest

flask = pytest.importorskip("flask")

from dashboard.app import create_app
from scoring import ScoringEngine, Signal, Severity


class _Engine(ScoringEngine):
    pass


class _Responder:
    mode = "kill"
    def actions(self, limit=50): return []
    def manual_kill(self, pid, reason="manual"):
        from responder import KillAction
        return KillAction(0.0, pid, "x", "x", reason, "kill", False, True)
    def manual_release(self, pid): return True


class _Allowlist:
    def entries(self): return []
    def add(self, *a, **k): return {}
    def remove(self, *a, **k): return False


class _Reporter:
    def recent(self, limit=50): return []
    def read_report(self, fn): return "x"


class FakeAgent:
    def __init__(self, token="", reads=False):
        self.auth_token = token
        self.auth_required_for_reads = reads
        self.engine = ScoringEngine()
        self.responder = _Responder()
        self.allowlist = _Allowlist()
        self.incident_reporter = _Reporter()
    def status(self): return {"score": 0}
    def health(self): return {"ok": True}
    def processes(self, limit=60): return []
    def set_responder_mode(self, mode): return mode
    def threat_breakdown(self): return {"threats": []}


def _client(token="", reads=False):
    app = create_app(FakeAgent(token=token, reads=reads))
    app.config["TESTING"] = True
    return app.test_client()


class TestNoToken:
    def test_all_open_when_no_token(self):
        c = _client(token="")
        assert c.get("/api/heartbeat").status_code == 200
        assert c.post("/api/reset").status_code == 200
        assert c.get("/api/admin/health").status_code == 200


class TestTokenRequired:
    def test_heartbeat_always_open(self):
        c = _client(token="s3cr3t")
        assert c.get("/api/heartbeat").status_code == 200

    def test_mutating_blocked_without_token(self):
        c = _client(token="s3cr3t")
        assert c.post("/api/reset").status_code == 401

    def test_admin_blocked_without_token(self):
        c = _client(token="s3cr3t")
        assert c.get("/api/admin/health").status_code == 401

    def test_x_api_key_accepted(self):
        c = _client(token="s3cr3t")
        r = c.post("/api/reset", headers={"X-API-Key": "s3cr3t"})
        assert r.status_code == 200

    def test_bearer_accepted(self):
        c = _client(token="s3cr3t")
        r = c.get("/api/admin/health",
                  headers={"Authorization": "Bearer s3cr3t"})
        assert r.status_code == 200

    def test_wrong_token_rejected(self):
        c = _client(token="s3cr3t")
        r = c.post("/api/reset", headers={"X-API-Key": "wrong"})
        assert r.status_code == 401


class TestReadProtection:
    def test_reads_open_by_default(self):
        c = _client(token="s3cr3t", reads=False)
        assert c.get("/api/status").status_code == 200

    def test_reads_protected_when_enabled(self):
        c = _client(token="s3cr3t", reads=True)
        assert c.get("/api/status").status_code == 401
        r = c.get("/api/status", headers={"X-API-Key": "s3cr3t"})
        assert r.status_code == 200

    def test_heartbeat_open_even_with_read_protection(self):
        c = _client(token="s3cr3t", reads=True)
        assert c.get("/api/heartbeat").status_code == 200
