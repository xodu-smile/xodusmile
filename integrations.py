"""
External Integrations — SIEM / Webhook Forwarding
-------------------------------------------------
탐지 이벤트를 기업의 보안 운영 인프라로 *밖으로* 내보낸다.

왜 필요한가 (단독 EDR → 기업 제품):
  실제 SOC 는 단말마다 대시보드를 들여다보지 않는다.  엔드포인트 에이전트는
  중앙 **SIEM**(Splunk/QRadar/ArcSight/Sentinel)과 **알림/SOAR**(Slack/Teams/
  PagerDuty)로 이벤트를 밀어 넣어야 한다.  이 모듈은 두 가지 표준 출구를 준다:

    1. Syslog + **CEF**(Common Event Format) — 사실상 모든 SIEM 이 파싱한다.
    2. 범용 **JSON Webhook** — Slack/Teams/PagerDuty/SOAR 로 곧장.

설계 원칙:
  - **fail-open**: 통합이 느리거나 죽어도 탐지/응답은 절대 멈추지 않는다.
    전송은 백그라운드 워커 스레드에서 비동기로, 큐가 차면 드롭(카운트만).
  - **외부 의존성 0**: 표준 라이브러리(socket, urllib)만 사용.
  - **min_severity 필터**: 노이즈 억제 — 기본 HIGH 이상만 내보낸다.
  - 비밀(webhook url)은 config 에서 오며, 환경변수로 주입 가능(config 참조).
"""

from __future__ import annotations

import json
import queue
import socket
import threading
import time
import urllib.request
from typing import List, Optional

import attack_map

# 등급 비교용 순위.
_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# CEF 권장 severity(0-10) 매핑.
_CEF_SEV = {"INFO": 1, "LOW": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
# Syslog priority: facility(16=local0)*8 + severity(level).  alert≈1.
_SYSLOG_PRI = {"INFO": 134, "LOW": 133, "MEDIUM": 132, "HIGH": 131, "CRITICAL": 129}

_QUEUE_MAX = 1000


def _sev_ok(level: str, minimum: str) -> bool:
    return _SEV_RANK.get(level, 0) >= _SEV_RANK.get(minimum, 3)


def _cef_escape(value: str) -> str:
    """CEF extension 값 이스케이프(= 와 \\ 와 개행)."""
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", " ").replace("\r", " "))


def _cef_header_escape(value: str) -> str:
    """CEF 헤더 필드 이스케이프(| 와 \\, 그리고 개행 제거).

    개행(\\r/\\n)을 제거하지 않으면 공격자가 제어하는 프로세스명/파일명/메시지가
    syslog 라인에 끼어들어 SIEM 에 가짜 레코드를 주입(log injection)할 수 있다."""
    return (str(value).replace("\\", "\\\\").replace("|", "\\|")
            .replace("\r", " ").replace("\n", " "))


def build_cef(event: dict, score: int, level: str,
              host: str = "RansomGuard") -> str:
    """탐지 이벤트(signal dict)를 CEF 한 줄로 직렬화한다.

    형식: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    """
    name = event.get("name", "signal")
    techs = attack_map.techniques_for(name)
    tid = techs[0].tid if techs else ""
    header = "|".join([
        "CEF:0",
        "RansomGuard", "EDR", "1.2",
        _cef_header_escape(name),
        _cef_header_escape(event.get("message", name)),
        str(_CEF_SEV.get(level, 5)),
    ])
    meta = event.get("metadata") or {}
    ext = {
        "rt": int(event.get("timestamp", time.time()) * 1000),
        "cs1Label": "detector", "cs1": event.get("detector", ""),
        "cs2Label": "mitreTechnique", "cs2": tid,
        "cs3Label": "threatLevel", "cs3": level,
        "cn1Label": "weight", "cn1": event.get("weight", 0),
        "cn2Label": "totalScore", "cn2": score,
        "dvchost": host,
    }
    if meta.get("pid"):
        ext["dpid"] = meta["pid"]
    if meta.get("process"):
        ext["dproc"] = meta["process"]
    if meta.get("path"):
        ext["fname"] = meta["path"]
    parts = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items())
    return header + "|" + parts


class EventForwarder:
    """탐지 이벤트를 syslog(CEF) + webhook 으로 비동기 전송.

    ``agent`` 가 ``forward()`` 를 시그널 콜백에서 호출한다.  실제 네트워크 I/O
    는 워커 스레드에서 처리하므로 탐지 핫패스를 막지 않는다.
    """

    def __init__(self, *, syslog=None, webhook=None,
                 hostname: Optional[str] = None):
        # syslog / webhook 은 config.SyslogConfig / WebhookConfig (또는 None).
        self.syslog = syslog if (syslog and getattr(syslog, "enabled", False)) else None
        self.webhook = self._validate_webhook(webhook)
        try:
            self.hostname = hostname or socket.gethostname()
        except Exception:
            self.hostname = "RansomGuard"
        self._q: "queue.Queue[tuple]" = queue.Queue(maxsize=_QUEUE_MAX)
        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._dropped = 0
        self._sent = 0
        self._errors = 0
        self._lock = threading.Lock()

    @staticmethod
    def _validate_webhook(webhook):
        """Webhook 설정을 검증한다.  http/https 스킴만 허용 — file://, ftp://
        같은 스킴을 urlopen 에 넘기면 SSRF/로컬 파일 읽기로 악용될 수 있다."""
        if not (webhook and getattr(webhook, "enabled", False)
                and getattr(webhook, "url", "")):
            return None
        from urllib.parse import urlparse
        scheme = urlparse(webhook.url).scheme.lower()
        if scheme not in ("http", "https"):
            print(f"[integrations] webhook disabled: unsafe URL scheme "
                  f"{scheme!r} (only http/https allowed)")
            return None
        return webhook

    @property
    def enabled(self) -> bool:
        return self.syslog is not None or self.webhook is not None

    # ----------------------------------------------------------------- lifecycle

    def start(self) -> None:
        if not self.enabled or self._worker is not None:
            return
        self._worker = threading.Thread(
            target=self._run, name="event-forwarder", daemon=True)
        self._worker.start()
        outs = []
        if self.syslog:
            outs.append(f"syslog://{self.syslog.host}:{self.syslog.port}")
        if self.webhook:
            outs.append("webhook")
        print(f"[integrations] forwarder started → {', '.join(outs)}")

    def stop(self) -> None:
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=3.0)
            self._worker = None

    # ------------------------------------------------------------------- enqueue

    def forward(self, event: dict, score: int, level: str) -> None:
        """탐지 이벤트를 전송 큐에 넣는다(비차단).  등급 필터를 통과한 것만."""
        if not self.enabled:
            return
        try:
            self._q.put_nowait((event, int(score), str(level)))
        except queue.Full:
            with self._lock:
                self._dropped += 1

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "sent": self._sent,
                "errors": self._errors,
                "dropped": self._dropped,
                "syslog": bool(self.syslog),
                "webhook": bool(self.webhook),
            }

    # -------------------------------------------------------------------- worker

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                event, score, level = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._dispatch(event, score, level)
                with self._lock:
                    self._sent += 1
            except Exception as e:
                with self._lock:
                    self._errors += 1
                print(f"[integrations] forward error: {e}")

    def _dispatch(self, event: dict, score: int, level: str) -> None:
        if self.syslog and _sev_ok(level, self.syslog.min_severity):
            self._send_syslog(event, score, level)
        if self.webhook and _sev_ok(level, self.webhook.min_severity):
            self._send_webhook(event, score, level)

    def _send_syslog(self, event: dict, score: int, level: str) -> None:
        cef = build_cef(event, score, level, host=self.hostname)
        pri = _SYSLOG_PRI.get(level, 132)
        # RFC3164-ish: <PRI>HOSTNAME TAG: MSG  (대부분 SIEM 이 관대하게 파싱)
        # defense-in-depth: 조립된 라인에서도 개행을 제거(레코드 위조 방지).
        line = (f"<{pri}>{self.hostname} RansomGuard: {cef}"
                .replace("\r", " ").replace("\n", " "))
        data = line.encode("utf-8", errors="replace")
        if (self.syslog.protocol or "udp").lower() == "tcp":
            with socket.create_connection(
                    (self.syslog.host, self.syslog.port), timeout=4.0) as s:
                s.sendall(data + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, (self.syslog.host, self.syslog.port))

    def _send_webhook(self, event: dict, score: int, level: str) -> None:
        name = event.get("name", "signal")
        message = str(event.get("message", ""))[:1000]
        # metadata 는 공격자가 일부 제어 가능(파일 경로/프로세스명)하므로 키 개수와
        # 값 길이를 제한해 비대한 페이로드 전송을 막는다.
        raw_meta = event.get("metadata") or {}
        safe_meta = {
            str(k)[:128]: (str(v)[:512] if isinstance(v, str) else v)
            for k, v in list(raw_meta.items())[:50]
        }
        payload = {
            "source": "RansomGuard EDR",
            "host": self.hostname,
            "level": level,
            "score": score,
            "signal": name,
            "detector": event.get("detector", ""),
            "message": message,
            "mitre_attack": attack_map.technique_dicts_for(name),
            "metadata": safe_meta,
            "timestamp": event.get("timestamp", time.time()),
            # Slack/Teams 가 그대로 보여줄 수 있는 사람용 요약.
            "text": f"[{level}] RansomGuard@{self.hostname}: "
                    f"{message or name} (score={score})",
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.webhook.timeout_sec) as resp:
            resp.read()


def from_config(cfg) -> EventForwarder:
    """``config.Config`` 에서 EventForwarder 를 만든다(아무 출구도 없으면 no-op)."""
    return EventForwarder(syslog=getattr(cfg, "syslog", None),
                          webhook=getattr(cfg, "webhook", None))
