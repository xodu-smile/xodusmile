"""
Tests for dashboard/app.py Flask routes.
------------------------------------------
Skipped entirely if Flask is not installed.
Uses a fake agent object to avoid psutil/wmi/win32 dependencies.
"""

import pytest

flask = pytest.importorskip("flask")  # skip whole module if flask absent

import json
from scoring import Signal, Severity

# Import after importorskip so collection only proceeds when flask is present
from dashboard.app import create_app


# ---------------------------------------------------------------------------
# Fake agent and sub-objects
# ---------------------------------------------------------------------------

class FakeEngine:
    def __init__(self):
        self._score = 42
        self._signals = [
            Signal(
                detector="canary",
                name="canary_modified",
                weight=30,
                severity=Severity.HIGH,
                message="Canary touched",
                metadata={"path": r"C:\canary\decoy.txt"},
            )
        ]

    def current_score(self):
        return self._score

    def recent_signals(self, n=100):
        return list(self._signals)

    def reset(self):
        self._signals.clear()
        self._score = 0


class FakeResponder:
    def __init__(self):
        self._actions = []
        self.mode = "kill"
        self._released = []
        self._killed = []

    def actions(self, limit=50):
        return list(self._actions[-limit:])

    def manual_kill(self, pid, reason="manual"):
        from responder import KillAction
        import time
        a = KillAction(
            timestamp=time.time(), pid=pid, process_name="victim.exe",
            cmdline="victim.exe", reason=reason, mode="kill",
            quarantined=False, terminated=True,
        )
        self._killed.append(pid)
        return a

    def manual_release(self, pid):
        self._released.append(pid)
        return True


class FakeAllowlist:
    def __init__(self):
        self._entries = []

    def entries(self):
        return list(self._entries)

    def add(self, value, kind="", note=""):
        entry = {"kind": kind or "name", "value": value, "note": note, "added_at": 0.0}
        # Deduplicate
        if not any(e["value"] == value for e in self._entries):
            self._entries.append(entry)
        return entry

    def remove(self, value, kind=""):
        before = len(self._entries)
        self._entries = [e for e in self._entries if e["value"] != value]
        return len(self._entries) != before


class FakeIncidentReporter:
    def __init__(self):
        self.recent_records = []

    @property
    def recent(self):
        return self.recent_records

    def read_report(self, filename):
        return f"# Report: {filename}\n\nContent here."


class FakeAgent:
    def __init__(self):
        self.engine = FakeEngine()
        self.responder = FakeResponder()
        self.allowlist = FakeAllowlist()
        self.incident_reporter = FakeIncidentReporter()

    def status(self):
        return {
            "score": self.engine.current_score(),
            "level": "HIGH",
            "mode": "kill",
        }

    def health(self):
        return {
            "ok": True,
            "score": self.engine.current_score(),
            "mode": self.responder.mode,
            "uptime": 12345.0,
        }

    def processes(self, limit=60):
        return []

    def set_responder_mode(self, mode):
        self.responder.mode = mode
        return mode

    def threat_breakdown(self):
        return {"threats": []}

    def incident_reporter_recent(self, limit=50):
        return []


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    agent = FakeAgent()
    app = create_app(agent)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, agent


# ---------------------------------------------------------------------------
# GET /api/admin/health
# ---------------------------------------------------------------------------

class TestAdminHealth:
    def test_returns_200(self, client):
        c, agent = client
        resp = c.get("/api/admin/health")
        assert resp.status_code == 200

    def test_returns_json(self, client):
        c, agent = client
        resp = c.get("/api/admin/health")
        data = json.loads(resp.data)
        assert isinstance(data, dict)

    def test_response_contains_ok_key(self, client):
        c, agent = client
        resp = c.get("/api/admin/health")
        data = json.loads(resp.data)
        assert "ok" in data


# ---------------------------------------------------------------------------
# POST /api/admin/mode
# ---------------------------------------------------------------------------

class TestAdminMode:
    def test_valid_mode_quarantine_returns_200(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/mode",
            data=json.dumps({"mode": "quarantine"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_valid_mode_kill_returns_200(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/mode",
            data=json.dumps({"mode": "kill"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_valid_mode_off_returns_200(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/mode",
            data=json.dumps({"mode": "off"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_valid_mode_returns_ok_true(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/mode",
            data=json.dumps({"mode": "quarantine"}),
            content_type="application/json",
        )
        data = json.loads(resp.data)
        assert data["ok"] is True

    def test_invalid_mode_returns_400(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/mode",
            data=json.dumps({"mode": "bogus"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_invalid_mode_returns_ok_false(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/mode",
            data=json.dumps({"mode": "bogus"}),
            content_type="application/json",
        )
        data = json.loads(resp.data)
        assert data["ok"] is False

    def test_missing_mode_key_returns_400(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/mode",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/admin/threats
# ---------------------------------------------------------------------------

class TestAdminThreats:
    def test_returns_200(self, client):
        c, agent = client
        resp = c.get("/api/admin/threats")
        assert resp.status_code == 200

    def test_returns_json(self, client):
        c, agent = client
        resp = c.get("/api/admin/threats")
        data = json.loads(resp.data)
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# GET /api/admin/allowlist
# ---------------------------------------------------------------------------

class TestAdminAllowlistGet:
    def test_returns_200(self, client):
        c, agent = client
        resp = c.get("/api/admin/allowlist")
        assert resp.status_code == 200

    def test_returns_entries_key(self, client):
        c, agent = client
        resp = c.get("/api/admin/allowlist")
        data = json.loads(resp.data)
        assert "entries" in data

    def test_entries_is_a_list(self, client):
        c, agent = client
        resp = c.get("/api/admin/allowlist")
        data = json.loads(resp.data)
        assert isinstance(data["entries"], list)


# ---------------------------------------------------------------------------
# POST /api/admin/allowlist
# ---------------------------------------------------------------------------

class TestAdminAllowlistPost:
    def test_post_with_value_returns_200(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/allowlist",
            data=json.dumps({"value": "backup.exe", "kind": "name"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_post_with_value_returns_ok_true(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/allowlist",
            data=json.dumps({"value": "backup.exe"}),
            content_type="application/json",
        )
        data = json.loads(resp.data)
        assert data["ok"] is True

    def test_post_without_value_returns_400(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/allowlist",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_post_with_empty_value_returns_400(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/allowlist",
            data=json.dumps({"value": "   "}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_post_returns_entries_list(self, client):
        c, agent = client
        resp = c.post(
            "/api/admin/allowlist",
            data=json.dumps({"value": "myapp.exe"}),
            content_type="application/json",
        )
        data = json.loads(resp.data)
        assert "entries" in data
        assert isinstance(data["entries"], list)

    def test_post_adds_entry_visible_in_get(self, client):
        c, agent = client
        c.post(
            "/api/admin/allowlist",
            data=json.dumps({"value": "agent.exe"}),
            content_type="application/json",
        )
        resp = c.get("/api/admin/allowlist")
        data = json.loads(resp.data)
        values = [e["value"] for e in data["entries"]]
        assert "agent.exe" in values


# ---------------------------------------------------------------------------
# DELETE /api/admin/allowlist
# ---------------------------------------------------------------------------

class TestAdminAllowlistDelete:
    def test_delete_existing_entry_returns_200(self, client):
        c, agent = client
        # First add an entry
        agent.allowlist.add("todelete.exe")
        resp = c.delete(
            "/api/admin/allowlist",
            data=json.dumps({"value": "todelete.exe"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_delete_returns_ok_true(self, client):
        c, agent = client
        agent.allowlist.add("app.exe")
        resp = c.delete(
            "/api/admin/allowlist",
            data=json.dumps({"value": "app.exe"}),
            content_type="application/json",
        )
        data = json.loads(resp.data)
        assert data["ok"] is True

    def test_delete_without_value_returns_400(self, client):
        c, agent = client
        resp = c.delete(
            "/api/admin/allowlist",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_delete_returns_entries_list(self, client):
        c, agent = client
        agent.allowlist.add("app.exe")
        resp = c.delete(
            "/api/admin/allowlist",
            data=json.dumps({"value": "app.exe"}),
            content_type="application/json",
        )
        data = json.loads(resp.data)
        assert "entries" in data


# ---------------------------------------------------------------------------
# GET /api/events — each event must have an 'attack' key
# ---------------------------------------------------------------------------

class TestApiEvents:
    def test_returns_200(self, client):
        c, agent = client
        resp = c.get("/api/events")
        assert resp.status_code == 200

    def test_returns_events_key(self, client):
        c, agent = client
        resp = c.get("/api/events")
        data = json.loads(resp.data)
        assert "events" in data

    def test_events_is_a_list(self, client):
        c, agent = client
        resp = c.get("/api/events")
        data = json.loads(resp.data)
        assert isinstance(data["events"], list)

    def test_each_event_has_attack_key(self, client):
        c, agent = client
        resp = c.get("/api/events")
        data = json.loads(resp.data)
        for event in data["events"]:
            assert "attack" in event, (
                f"Event {event.get('name')} is missing 'attack' key"
            )

    def test_attack_key_is_a_list(self, client):
        c, agent = client
        resp = c.get("/api/events")
        data = json.loads(resp.data)
        for event in data["events"]:
            assert isinstance(event["attack"], list)

    def test_known_signal_has_nonempty_attack_list(self, client):
        c, agent = client
        # FakeEngine has a canary_modified signal which maps to T1486
        resp = c.get("/api/events")
        data = json.loads(resp.data)
        canary_events = [e for e in data["events"] if e.get("name") == "canary_modified"]
        if canary_events:
            assert len(canary_events[0]["attack"]) > 0


# ---------------------------------------------------------------------------
# GET /api/status
# ---------------------------------------------------------------------------

class TestApiStatus:
    def test_returns_200(self, client):
        c, agent = client
        resp = c.get("/api/status")
        assert resp.status_code == 200

    def test_returns_score_key(self, client):
        c, agent = client
        resp = c.get("/api/status")
        data = json.loads(resp.data)
        assert "score" in data


# ---------------------------------------------------------------------------
# POST /api/reset
# ---------------------------------------------------------------------------

class TestApiReset:
    def test_returns_200(self, client):
        c, agent = client
        resp = c.post("/api/reset")
        assert resp.status_code == 200

    def test_returns_ok_true(self, client):
        c, agent = client
        resp = c.post("/api/reset")
        data = json.loads(resp.data)
        assert data["ok"] is True


# ---------------------------------------------------------------------------
# POST /api/kill — bad pid returns 400
# ---------------------------------------------------------------------------

class TestApiKill:
    def test_missing_pid_returns_400(self, client):
        c, agent = client
        resp = c.post(
            "/api/kill",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_nonnumeric_pid_returns_400(self, client):
        c, agent = client
        resp = c.post(
            "/api/kill",
            data=json.dumps({"pid": "notanumber"}),
            content_type="application/json",
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/release — bad pid returns 400
# ---------------------------------------------------------------------------

class TestApiRelease:
    def test_missing_pid_returns_400(self, client):
        c, agent = client
        resp = c.post(
            "/api/release",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400
