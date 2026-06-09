"""
Operator Allowlist
------------------
운영자(시스템 관리자)가 *런타임에* 신뢰 프로세스를 등록하는 허용 목록.

왜 필요한가 (오탐 방지 + 관리자 기능):
  ``actor_trust.py`` 는 Microsoft 시스템 컴포넌트(Defender/servicing/WMI)만
  하드코딩으로 신뢰한다 — 이건 변조 불가의 안전한 기본값이다.  하지만 실제
  현장에는 **정상적으로 대량 파일 변경/암호화를 수행하는 서드파티 앱**이 있다:

    - 백업 소프트웨어(Veeam/Acronis), 동기화 클라이언트
    - 정식 압축/암호화 도구(7-Zip, VeraCrypt), 빌드 시스템
    - 회사 표준 배포 에이전트

  이런 앱이 RansomGuard 에 의해 종료되면 업무가 망가진다(오탐).  관리자가
  대시보드/CLI 로 이들을 **명시적으로 허용**할 수 있어야 한다.

설계 — 안전을 위해 의도적으로 보수적:
  - 항목은 (a) 프로세스 **이름**(예: ``veeamagent.exe``) 또는 (b) 이미지
    **경로 접두사**(예: ``C:\\Program Files\\Veeam\\``)로 지정한다.  경로
    접두사 항목이 더 안전하다 — 이름만 같은 위장(%TEMP%\\veeamagent.exe)을
    막는다.
  - 신뢰 판정은 **검증된 on-disk 이미지 경로**로만 한다(actor_trust 와 동일
    철학).  경로를 못 읽으면 fail-closed → 미허용 → 정상 채점.
  - 허용 목록은 **점수 가산을 면제**하고 **never-kill 로 보호**하지만, canary
    변조나 실제 암호화 폭주 같은 고신뢰 단발 신호까지 무력화하지는 않는다
    (아래 ``exempt_signal`` 의 보수적 정책 참조) — 관리자가 실수로 전체
    탐지를 꺼버리는 일을 막는다.
  - JSON 파일에 영속화(기본 ``allowlist.json``).  파일은 tamper.harden_paths
    대상에 포함될 수 있다.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# canary / 실제 암호화 폭주처럼 "허용된 앱이라도 정상이라면 절대 일으키지 않을"
# 고신뢰 신호는 허용 목록으로도 면제하지 않는다.  관리자가 백업 앱을 허용했다고
# 해서, 그 이름을 위장한 랜섬웨어의 canary 침해까지 눈감아주면 안 되기 때문이다.
# (경로 접두사 항목은 위장을 막지만, 이름 항목은 막지 못하므로 이 안전장치가 필요.)
_NEVER_EXEMPT_SIGNALS = frozenset({
    "canary_modified", "canary_deleted",
    "ransom_note_spread",
    "defender_self_disable",
})


@dataclass
class AllowEntry:
    """허용 목록의 한 항목."""
    kind: str           # "name" | "path"
    value: str          # name(소문자 basename) 또는 path 접두사(소문자)
    note: str = ""      # 운영자 메모 (예: "사내 백업 에이전트")
    added_at: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def matches(self, name_lower: str, path_lower: str) -> bool:
        if self.kind == "name":
            return bool(name_lower) and name_lower == self.value
        if self.kind == "path":
            return bool(path_lower) and path_lower.startswith(self.value)
        return False


def _normalize(kind: str, value: str) -> AllowEntry:
    """입력을 정규화해 AllowEntry 를 만든다.

    - 경로처럼 보이면(구분자 포함 또는 명시 kind=="path") path 접두사 항목.
    - 그 외에는 name 항목(basename, 소문자).
    """
    v = (value or "").strip()
    if not v:
        raise ValueError("empty allowlist value")
    kind = (kind or "").strip().lower()
    looks_like_path = ("\\" in v or "/" in v or (len(v) >= 2 and v[1] == ":"))
    if kind == "path" or (kind not in ("name", "path") and looks_like_path):
        return AllowEntry(kind="path", value=os.path.normcase(v), added_at=time.time())
    # 이름 항목: 디렉터리 부분 제거 + 소문자
    base = os.path.basename(v).lower()
    return AllowEntry(kind="name", value=base, added_at=time.time())


class Allowlist:
    """스레드 세이프 허용 목록 + JSON 영속화 + PID 신뢰 판정.

    ``signal_exempt`` 를 scoring 의 trust classifier 와 합성하고,
    ``pid_allowed`` 를 responder 의 never-kill 보강에 쓴다.
    """

    def __init__(self, path: str = "allowlist.json", *, autoload: bool = True):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._entries: List[AllowEntry] = []
        # pid -> (create_time, allowed) 캐시.  PID 재사용 방어를 위해 create_time
        # 을 함께 저장한다(actor_trust 와 동일 패턴).
        self._cache: dict[int, tuple[float, bool]] = {}
        if autoload:
            self.load()

    # ----------------------------------------------------------- persistence

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        items = raw.get("entries", raw) if isinstance(raw, dict) else raw
        loaded: List[AllowEntry] = []
        for it in items or []:
            try:
                loaded.append(AllowEntry(
                    kind=str(it["kind"]).lower(),
                    value=str(it["value"]),
                    note=str(it.get("note", "")),
                    added_at=float(it.get("added_at", 0.0) or 0.0),
                ))
            except (KeyError, TypeError, ValueError):
                continue
        with self._lock:
            self._entries = loaded
            self._cache.clear()

    def save(self) -> None:
        with self._lock:
            data = {"entries": [e.to_dict() for e in self._entries]}
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            os.replace(tmp, self.path)   # 원자적 교체
        except OSError as e:
            print(f"[allowlist] save failed: {e}")

    # ------------------------------------------------------------------- CRUD

    def entries(self) -> List[dict]:
        with self._lock:
            return [e.to_dict() for e in self._entries]

    def add(self, value: str, *, kind: str = "", note: str = "") -> dict:
        """허용 항목 추가(중복은 무시).  추가된(혹은 기존) 항목 dict 반환."""
        entry = _normalize(kind, value)
        entry.note = (note or "").strip()
        with self._lock:
            for e in self._entries:
                if e.kind == entry.kind and e.value == entry.value:
                    return e.to_dict()
            self._entries.append(entry)
            self._cache.clear()
        self.save()
        return entry.to_dict()

    def remove(self, value: str, *, kind: str = "") -> bool:
        """일치하는 항목 제거.  제거됐으면 True."""
        target = _normalize(kind, value)
        with self._lock:
            before = len(self._entries)
            self._entries = [
                e for e in self._entries
                if not (e.kind == target.kind and e.value == target.value)
            ]
            removed = len(self._entries) != before
            if removed:
                self._cache.clear()
        if removed:
            self.save()
        return removed

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._cache.clear()
        self.save()

    # ----------------------------------------------------------- matching API

    def matches(self, name: str, exe_path: str = "") -> bool:
        """이름/경로가 허용 목록의 어떤 항목과 일치하는지 (PID 조회 없이)."""
        name_lower = (name or "").lower()
        path_lower = os.path.normcase(exe_path) if exe_path else ""
        with self._lock:
            return any(e.matches(name_lower, path_lower) for e in self._entries)

    def pid_allowed(self, pid: Optional[int]) -> bool:
        """``pid`` 의 검증된 이미지가 허용 목록에 있는지.

        경로/이름을 못 읽으면 fail-closed(미허용).  결과는 create_time 과 함께
        캐시한다.  허용 목록이 비어 있으면 빠르게 False.
        """
        if not pid or pid <= 0 or not HAS_PSUTIL:
            return False
        with self._lock:
            if not self._entries:
                return False
        try:
            proc = psutil.Process(pid)
            create_time = proc.create_time()
        except Exception:
            return False
        with self._lock:
            cached = self._cache.get(pid)
            if cached is not None and cached[0] == create_time:
                return cached[1]
        try:
            name = proc.name() or ""
        except Exception:
            name = ""
        try:
            exe = proc.exe() or ""
        except Exception:
            exe = ""
        allowed = self.matches(name, exe)
        with self._lock:
            if len(self._cache) >= 4096:
                self._cache.clear()
            self._cache[pid] = (create_time, allowed)
        return allowed

    def signal_exempt(self, sig) -> bool:
        """scoring trust classifier 용: 이 신호를 *점수에서 면제*할지.

        - 허용된 PID 가 낸 신호는 점수에서 빼되,
        - ``_NEVER_EXEMPT_SIGNALS`` (canary/note-spread 등 고신뢰 단발)는 면제 안 함.
          허용 목록의 이름 항목을 위장한 악성코드까지 무력화되는 것을 막는 안전장치.
        """
        if getattr(sig, "name", None) in _NEVER_EXEMPT_SIGNALS:
            return False
        pid = _pid_of_signal(sig)
        return self.pid_allowed(pid)


def _pid_of_signal(sig) -> Optional[int]:
    meta = getattr(sig, "metadata", None) or {}
    for key in ("pid", "ProcessId", "process_id", "child_pid"):
        val = meta.get(key)
        if isinstance(val, int) and val > 0:
            return val
    return None


def combine_trust(*classifiers):
    """여러 trust classifier 를 OR 로 합성한다.

    ScoringEngine 은 ``is_trusted_actor`` 콜백 하나만 받으므로, 시스템 신뢰
    (actor_trust.signal_actor_trusted)와 운영자 허용(Allowlist.signal_exempt)을
    하나로 묶을 때 쓴다.  어느 하나라도 면제로 보면 면제.
    """
    funcs = [c for c in classifiers if c is not None]

    def _combined(sig) -> bool:
        for f in funcs:
            try:
                if f(sig):
                    return True
            except Exception as e:
                print(f"[allowlist] trust classifier error: {e}")
        return False

    return _combined
