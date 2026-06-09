"""
Central Configuration
---------------------
기업 배포(fleet)에서 RansomGuard 를 *파일 기반 정책* 으로 운영하기 위한 설정 로더.

왜 필요한가 (학습용 PoC → 실제 제품):
  학습용 프로토타입은 CLI 플래그만으로 충분하다.  그러나 수백 대에 배포되는
  실제 제품은 **버전 관리되고 중앙에서 배포 가능한 설정 파일**이 필요하다:
    - 감시 경로/응답 모드/변조 방지 등 운영 정책
    - 대시보드 인증 토큰(평문 CLI 노출 회피)
    - SIEM/Webhook 통합 엔드포인트
  GPO/Intune/Ansible 등으로 ``ransomguard.toml`` 한 파일만 밀어넣으면 정책이
  일괄 적용되게 한다.

설계:
  - TOML(파이썬 3.11+ ``tomllib``) 우선, 없으면 JSON 으로 폴백 — 외부 의존성 0.
  - 비밀(인증 토큰)은 **환경변수가 파일보다 우선**한다(시크릿을 디스크에 안 남김):
        RANSOMGUARD_AUTH_TOKEN, RANSOMGUARD_WEBHOOK_URL, RANSOMGUARD_SYSLOG_HOST
  - 모든 값에 안전한 기본값 → 설정 파일이 없어도 기존 CLI 동작과 100% 동일.
  - 파일을 못 읽거나 깨져도 절대 죽지 않는다(경고 후 기본값) — 탐지 가용성 우선.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

try:
    import tomllib  # Python 3.11+
    HAS_TOMLLIB = True
except ImportError:
    HAS_TOMLLIB = False


# 설정 파일 자동 탐색 순서(첫 번째로 존재하는 것 사용).
DEFAULT_CONFIG_NAMES = ("ransomguard.toml", "ransomguard.json", "config.toml")


@dataclass
class SyslogConfig:
    """SIEM(Splunk/QRadar/ArcSight 등) 으로 보낼 syslog(CEF) 설정."""
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 514
    protocol: str = "udp"          # "udp" | "tcp"
    min_severity: str = "HIGH"     # 이 등급 이상만 전송


@dataclass
class WebhookConfig:
    """범용 JSON Webhook(Slack/Teams/PagerDuty/SOAR) 설정."""
    enabled: bool = False
    url: str = ""
    min_severity: str = "HIGH"
    timeout_sec: float = 4.0


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    # 인증 토큰.  비어 있으면 인증 비활성(로컬 개발 편의).  환경변수가 우선.
    auth_token: str = ""
    # True 면 읽기 전용 엔드포인트(GET)에도 인증을 요구한다.  변조성/관리자
    # 엔드포인트는 토큰이 설정돼 있으면 *항상* 인증을 요구한다(이 값과 무관).
    auth_required_for_reads: bool = False


@dataclass
class Config:
    # --- general ---
    watch_dirs: List[str] = field(default_factory=list)
    db_path: str = "detector.db"
    reports_dir: str = "reports"
    responder_mode: str = "kill"          # off | quarantine | kill
    enable_minifilter: bool = True
    enable_tamper_protection: bool = True
    notify_user: bool = True
    allowlist_path: str = "allowlist.json"

    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    syslog: SyslogConfig = field(default_factory=SyslogConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)

    # 설정이 로드된 원본 경로(진단용; 없으면 None).
    source_path: Optional[str] = None

    # ------------------------------------------------------------------ loading

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        """설정 파일을 읽어 Config 를 만든다.

        ``path`` 가 None 이면 현재 디렉터리에서 DEFAULT_CONFIG_NAMES 를 탐색한다.
        파일이 없으면 모든 기본값으로 구성한다(에러 아님).  환경변수 비밀은
        항상 마지막에 덮어쓴다.
        """
        cfg = cls()
        resolved = cls._resolve_path(path)
        if resolved is not None:
            try:
                raw = cls._read_file(resolved)
                cfg._apply_dict(raw)
                cfg.source_path = str(resolved)
            except Exception as e:               # 깨진 설정이 탐지를 막으면 안 됨
                print(f"[config] failed to load {resolved}: {e}; using defaults")
        cfg._apply_env_overrides()
        # 공백뿐인 토큰이 "설정된 비밀"로 오인돼 인증이 켜지는 것을 막는다.
        cfg.dashboard.auth_token = (cfg.dashboard.auth_token or "").strip()
        return cfg

    @staticmethod
    def _resolve_path(path: Optional[str]) -> Optional[Path]:
        if path:
            p = Path(path)
            return p if p.exists() else None
        for name in DEFAULT_CONFIG_NAMES:
            p = Path(name)
            if p.exists():
                return p
        return None

    @staticmethod
    def _read_file(path: Path) -> dict:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            return json.loads(text)
        # .toml (or unknown) → TOML if available, else try JSON as a courtesy.
        if HAS_TOMLLIB:
            return tomllib.loads(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                "TOML support requires Python 3.11+ (tomllib); "
                "either upgrade or provide a .json config"
            ) from e

    def _apply_dict(self, raw: dict) -> None:
        if not isinstance(raw, dict):
            return
        gen = raw.get("general", raw)          # allow flat or [general] table
        for key in ("db_path", "reports_dir", "responder_mode",
                    "allowlist_path"):
            if isinstance(gen.get(key), str):
                setattr(self, key, gen[key])
        for key in ("enable_minifilter", "enable_tamper_protection",
                    "notify_user"):
            if isinstance(gen.get(key), bool):
                setattr(self, key, gen[key])
        wd = gen.get("watch_dirs")
        if isinstance(wd, list):
            self.watch_dirs = [str(x) for x in wd]

        self._apply_section(raw.get("dashboard"), self.dashboard)
        self._apply_section(raw.get("syslog"), self.syslog)
        self._apply_section(raw.get("webhook"), self.webhook)

    @staticmethod
    def _apply_section(data, target) -> None:
        """``data`` dict 의 키를 dataclass ``target`` 의 같은 이름 필드에 타입을
        보존하며 덮어쓴다(알 수 없는 키는 무시)."""
        if not isinstance(data, dict):
            return
        for f_name, current in list(vars(target).items()):
            if f_name not in data:
                continue
            val = data[f_name]
            # 기존 필드 타입에 맞춰 보수적으로 캐스팅.
            try:
                if isinstance(current, bool):
                    target.__dict__[f_name] = bool(val)
                elif isinstance(current, int) and not isinstance(current, bool):
                    target.__dict__[f_name] = int(val)
                elif isinstance(current, float):
                    target.__dict__[f_name] = float(val)
                else:
                    target.__dict__[f_name] = str(val)
            except (TypeError, ValueError):
                continue

    def _apply_env_overrides(self) -> None:
        """비밀/배포 시 주입값은 환경변수가 파일을 이긴다."""
        tok = os.environ.get("RANSOMGUARD_AUTH_TOKEN")
        if tok:
            self.dashboard.auth_token = tok
        url = os.environ.get("RANSOMGUARD_WEBHOOK_URL")
        if url:
            self.webhook.url = url
            self.webhook.enabled = True
        host = os.environ.get("RANSOMGUARD_SYSLOG_HOST")
        if host:
            self.syslog.host = host
            self.syslog.enabled = True

    # ------------------------------------------------------------------ helpers

    def to_dict(self) -> dict:
        d = asdict(self)
        # 비밀은 직렬화에서 가린다(대시보드 health 등에 노출 방지).
        if d.get("dashboard", {}).get("auth_token"):
            d["dashboard"]["auth_token"] = "***"
        return d
