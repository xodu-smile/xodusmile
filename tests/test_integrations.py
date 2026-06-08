"""
Tests for integrations.py — SIEM (CEF/syslog) + webhook forwarding.
"""

import socket
import time

import pytest

import integrations
from config import SyslogConfig, WebhookConfig, Config


def _event(name="canary_modified", msg="Canary touched", **meta):
    return {
        "detector": "canary", "name": name, "weight": 80,
        "severity": "CRITICAL", "message": msg, "metadata": meta,
        "timestamp": 1000.0,
    }


class TestSevOk:
    def test_meets_minimum(self):
        assert integrations._sev_ok("CRITICAL", "HIGH") is True
        assert integrations._sev_ok("HIGH", "HIGH") is True

    def test_below_minimum(self):
        assert integrations._sev_ok("MEDIUM", "HIGH") is False
        assert integrations._sev_ok("INFO", "LOW") is False


class TestBuildCef:
    def test_header_and_fields(self):
        cef = integrations.build_cef(_event(pid=1234, process="evil.exe"),
                                     score=160, level="CRITICAL", host="HOST1")
        assert cef.startswith("CEF:0|RansomGuard|EDR|")
        assert "|canary_modified|" in cef
        assert "cn2=160" in cef            # total score
        assert "cs3=CRITICAL" in cef       # threat level
        assert "dpid=1234" in cef
        assert "mitreTechnique" in cef and "T1486" in cef  # ATT&CK mapped

    def test_escapes_equals_in_extension(self):
        cef = integrations.build_cef(
            _event(process="a=b"), score=1, level="HIGH")
        assert "dproc=a\\=b" in cef

    def test_header_strips_newline_no_log_injection(self):
        # Attacker-controlled message must not be able to forge a new syslog line.
        evt = _event(msg="legit\n<134>FORGED RansomGuard: CEF:0|x")
        cef = integrations.build_cef(evt, score=1, level="HIGH")
        assert "\n" not in cef and "\r" not in cef


class TestFromConfig:
    def test_disabled_when_nothing_configured(self):
        fwd = integrations.from_config(Config())
        assert fwd.enabled is False
        # forward() must be a safe no-op
        fwd.forward(_event(), 10, "CRITICAL")

    def test_enabled_with_syslog(self):
        cfg = Config()
        cfg.syslog = SyslogConfig(enabled=True, host="127.0.0.1", port=5514)
        fwd = integrations.from_config(cfg)
        assert fwd.enabled is True

    def test_webhook_without_url_is_disabled(self):
        fwd = integrations.EventForwarder(
            webhook=WebhookConfig(enabled=True, url=""))
        assert fwd.enabled is False

    def test_webhook_file_scheme_rejected(self):
        fwd = integrations.EventForwarder(
            webhook=WebhookConfig(enabled=True, url="file:///etc/passwd"))
        assert fwd.webhook is None and fwd.enabled is False

    def test_webhook_https_accepted(self):
        fwd = integrations.EventForwarder(
            webhook=WebhookConfig(enabled=True, url="https://hook/x"))
        assert fwd.webhook is not None


class TestSyslogRoundtrip:
    def test_udp_cef_is_received(self):
        # Bind an ephemeral UDP socket to act as the SIEM collector.
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(3.0)
        port = rx.getsockname()[1]
        try:
            cfg = SyslogConfig(enabled=True, host="127.0.0.1", port=port,
                               protocol="udp", min_severity="HIGH")
            fwd = integrations.EventForwarder(syslog=cfg, hostname="HOST1")
            fwd.start()
            try:
                fwd.forward(_event(), score=160, level="CRITICAL")
                data, _ = rx.recvfrom(8192)
            finally:
                fwd.stop()
            text = data.decode("utf-8", errors="replace")
            assert "CEF:0|RansomGuard|EDR|" in text
            assert "canary_modified" in text
        finally:
            rx.close()

    def test_below_min_severity_not_sent(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(0.7)
        port = rx.getsockname()[1]
        try:
            cfg = SyslogConfig(enabled=True, host="127.0.0.1", port=port,
                               protocol="udp", min_severity="CRITICAL")
            fwd = integrations.EventForwarder(syslog=cfg)
            fwd.start()
            try:
                fwd.forward(_event(severity="MEDIUM"), score=40, level="MEDIUM")
                time.sleep(0.2)
                with pytest.raises(socket.timeout):
                    rx.recvfrom(4096)
            finally:
                fwd.stop()
        finally:
            rx.close()


class TestWebhookPayload:
    def test_webhook_posts_json(self, monkeypatch):
        captured = {}

        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b""

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = req.data
            return _Resp()

        monkeypatch.setattr(integrations.urllib.request, "urlopen", fake_urlopen)
        fwd = integrations.EventForwarder(
            webhook=WebhookConfig(enabled=True, url="https://hook/x",
                                  min_severity="HIGH"))
        fwd._send_webhook(_event(), 160, "CRITICAL")
        import json
        payload = json.loads(captured["body"])
        assert captured["url"] == "https://hook/x"
        assert payload["level"] == "CRITICAL"
        assert payload["signal"] == "canary_modified"
        assert payload["mitre_attack"]      # has ATT&CK techniques
