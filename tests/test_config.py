"""
Tests for config.py — file-based policy loader.
"""

import json
import os

import pytest

from config import Config, DashboardConfig


class TestDefaults:
    def test_defaults_are_safe(self):
        cfg = Config()
        assert cfg.responder_mode == "kill"
        assert cfg.enable_minifilter is True
        assert cfg.dashboard.port == 5000
        assert cfg.dashboard.auth_token == ""
        assert cfg.syslog.enabled is False
        assert cfg.webhook.enabled is False

    def test_missing_file_uses_defaults(self, tmp_path):
        cfg = Config.load(str(tmp_path / "nope.toml"))
        assert cfg.responder_mode == "kill"
        assert cfg.source_path is None


class TestJsonLoad:
    def test_loads_general_and_sections(self, tmp_path):
        path = tmp_path / "ransomguard.json"
        path.write_text(json.dumps({
            "general": {
                "responder_mode": "quarantine",
                "enable_tamper_protection": False,
                "watch_dirs": ["/data/a", "/data/b"],
            },
            "dashboard": {"port": 8080, "auth_required_for_reads": True},
            "syslog": {"enabled": True, "host": "10.0.0.5", "port": 1514},
            "webhook": {"enabled": True, "url": "https://hook/x"},
        }), encoding="utf-8")
        cfg = Config.load(str(path))
        assert cfg.responder_mode == "quarantine"
        assert cfg.enable_tamper_protection is False
        assert cfg.watch_dirs == ["/data/a", "/data/b"]
        assert cfg.dashboard.port == 8080
        assert cfg.dashboard.auth_required_for_reads is True
        assert cfg.syslog.enabled is True and cfg.syslog.host == "10.0.0.5"
        assert cfg.syslog.port == 1514
        assert cfg.webhook.url == "https://hook/x"
        assert cfg.source_path == str(path)

    def test_unknown_keys_ignored(self, tmp_path):
        path = tmp_path / "ransomguard.json"
        path.write_text(json.dumps({"dashboard": {"bogus": 1, "port": 9}}),
                        encoding="utf-8")
        cfg = Config.load(str(path))
        assert cfg.dashboard.port == 9

    def test_broken_file_falls_back_to_defaults(self, tmp_path):
        path = tmp_path / "ransomguard.json"
        path.write_text("{not valid json", encoding="utf-8")
        cfg = Config.load(str(path))
        assert cfg.responder_mode == "kill"   # did not crash


class TestEnvOverride:
    def test_env_token_wins_over_file(self, tmp_path, monkeypatch):
        path = tmp_path / "ransomguard.json"
        path.write_text(json.dumps({"dashboard": {"auth_token": "fromfile"}}),
                        encoding="utf-8")
        monkeypatch.setenv("RANSOMGUARD_AUTH_TOKEN", "fromenv")
        cfg = Config.load(str(path))
        assert cfg.dashboard.auth_token == "fromenv"

    def test_env_webhook_enables(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RANSOMGUARD_WEBHOOK_URL", "https://env/hook")
        cfg = Config.load(str(tmp_path / "nope.json"))
        assert cfg.webhook.url == "https://env/hook"
        assert cfg.webhook.enabled is True

    def test_env_syslog_host_enables(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RANSOMGUARD_SYSLOG_HOST", "siem.local")
        cfg = Config.load(str(tmp_path / "nope.json"))
        assert cfg.syslog.host == "siem.local"
        assert cfg.syslog.enabled is True


class TestToDict:
    def test_token_is_masked(self):
        cfg = Config()
        cfg.dashboard = DashboardConfig(auth_token="supersecret")
        d = cfg.to_dict()
        assert d["dashboard"]["auth_token"] == "***"

    def test_no_token_not_masked(self):
        d = Config().to_dict()
        assert d["dashboard"]["auth_token"] == ""


class TestTokenHygiene:
    def test_whitespace_token_stripped_to_empty(self, tmp_path):
        path = tmp_path / "ransomguard.json"
        path.write_text('{"dashboard": {"auth_token": "   "}}', encoding="utf-8")
        cfg = Config.load(str(path))
        assert cfg.dashboard.auth_token == ""   # whitespace → auth stays OFF

    def test_token_surrounding_whitespace_trimmed(self, tmp_path):
        path = tmp_path / "ransomguard.json"
        path.write_text('{"dashboard": {"auth_token": "  s3cret  "}}',
                        encoding="utf-8")
        cfg = Config.load(str(path))
        assert cfg.dashboard.auth_token == "s3cret"
