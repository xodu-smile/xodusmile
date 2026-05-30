"""
Scoring Engine
--------------
다중 시그널을 가중치로 합산하여 위협 수준을 판정한다.

설계 원칙 (보고서 5.2):
  - 단일 시그널은 오탐 위험. 여러 시그널이 동시 발생할 때 가중치 합산
  - Pre-encryption 시그널(VSS 삭제, BCD 조작)에는 더 높은 가중치
  - 시간 윈도우 내에서만 점수 누적 (오래된 신호는 자연 감쇠)
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, List, Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Signal:
    """탐지기가 발생시키는 단일 시그널."""
    detector: str           # 탐지기 이름 (e.g. "canary")
    name: str               # 시그널 이름 (e.g. "canary_modified")
    weight: int             # 가중치 (이 시그널이 위협도에 기여하는 점수)
    severity: Severity
    message: str
    metadata: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# 위협 수준 임계값 (튜닝 영역)
THRESHOLD_LOW = 30
THRESHOLD_MEDIUM = 60
THRESHOLD_HIGH = 100
THRESHOLD_CRITICAL = 150

# 시그널 누적 윈도우 (초). 이보다 오래된 시그널은 점수에서 제외
SIGNAL_WINDOW_SECONDS = 120

# 실제 파일 암호화/파괴가 진행 중임을 가리키는 시그널 이름들.
# "단지 의심스러운 프로세스 행위"(체인/fan-out 등)와 구분하기 위한 집합이다.
#   - 휴리스틱(체인, fan-out)을 이 활동과 상관(correlation) 있을 때만 가중하고
#   - responder 가 PID 를 죽이기 전에 이 활동을 corroboration 으로 요구한다.
ENCRYPTION_SIGNAL_NAMES = frozenset({
    # mass_io (파일 내용 기반)
    "magic_bytes_lost", "high_entropy_write", "modify_burst",
    "suspicious_extension",
    # canary (고신뢰 미끼 파일)
    "canary_modified", "canary_deleted",
    # 커널 미니필터 (PID 단위 관측)
    "kernel_write_burst", "kernel_rename_burst", "kernel_blocked_op",
})


class ScoringEngine:
    """
    탐지기들로부터 시그널을 수집해서 시간 윈도우 기반으로 점수를 합산한다.
    임계값을 넘으면 등록된 콜백(예: 대시보드 알림, 차단 액션)을 호출한다.
    """

    def __init__(self, window_seconds: int = SIGNAL_WINDOW_SECONDS):
        self._signals: deque[Signal] = deque()
        self._lock = threading.Lock()
        self._window = window_seconds
        self._listeners: List[Callable[[Signal, int, Severity], None]] = []
        self._last_alert_level: Severity = Severity.INFO

    def subscribe(self, listener: Callable[[Signal, int, Severity], None]) -> None:
        """시그널 발생 시 호출될 콜백 등록. (signal, current_score, threat_level)"""
        self._listeners.append(listener)

    def submit(self, signal: Signal) -> None:
        """탐지기가 시그널을 보고할 때 호출."""
        with self._lock:
            self._signals.append(signal)
            self._evict_old()
            score = self._current_score_locked()
            level = self._level_for_score(score)

        for listener in self._listeners:
            try:
                listener(signal, score, level)
            except Exception as e:
                # 리스너 실패가 엔진을 멈추면 안 됨
                print(f"[scoring] listener error: {e}")

    def current_score(self) -> int:
        with self._lock:
            self._evict_old()
            return self._current_score_locked()

    def current_level(self) -> Severity:
        return self._level_for_score(self.current_score())

    def recent_signals(self, limit: int = 50) -> List[Signal]:
        with self._lock:
            self._evict_old()
            return list(self._signals)[-limit:]

    def has_encryption_activity(self, exclude: Optional[Signal] = None) -> bool:
        """현재 윈도우 안에 실제 암호화/파괴 시그널이 있는지.

        ``exclude`` 로 넘긴 시그널 자신은 제외한다 — "방금 들어온 이 신호
        하나"만으로 corroboration 이 성립하지 않게 하기 위함.
        """
        with self._lock:
            self._evict_old()
            for s in self._signals:
                if s is exclude:
                    continue
                if s.name in ENCRYPTION_SIGNAL_NAMES:
                    return True
        return False

    def reset(self) -> None:
        with self._lock:
            self._signals.clear()

    # ---- internals ----

    def _evict_old(self) -> None:
        cutoff = time.time() - self._window
        while self._signals and self._signals[0].timestamp < cutoff:
            self._signals.popleft()

    def _current_score_locked(self) -> int:
        return sum(s.weight for s in self._signals)

    @staticmethod
    def _level_for_score(score: int) -> Severity:
        if score >= THRESHOLD_CRITICAL:
            return Severity.CRITICAL
        if score >= THRESHOLD_HIGH:
            return Severity.HIGH
        if score >= THRESHOLD_MEDIUM:
            return Severity.MEDIUM
        if score >= THRESHOLD_LOW:
            return Severity.LOW
        return Severity.INFO
