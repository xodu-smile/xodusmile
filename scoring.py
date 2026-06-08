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
    # ransom note (협박문 살포 — 암호화 정황의 직접 증거)
    "ransom_note_dropped", "ransom_note_spread",
    # 커널 미니필터 (PID 단위 관측)
    "kernel_write_burst", "kernel_rename_burst", "kernel_blocked_op",
})

# 단독으로는 점수에 기여하지 않고, "같은 PID 가 실제 암호화/파괴 활동을
# 보일 때에만" 가중되는 시그널들.  단일 파일 삭제는 가장 흔한 정상 행위
# (temp 청소, 앱 하우스키핑)라 그 자체로는 위협이 아니다 — read→encrypt→
# 원본삭제 패턴의 일부일 때에만 의미를 갖는다.  깨끗한 샌드박스에서 OS
# 하우스키핑 삭제가 점수를 CRITICAL 까지 밀어올리던 인플레의 주범이었다.
CORRELATION_GATED_NAMES = frozenset({"file_delete"})


class ScoringEngine:
    """
    탐지기들로부터 시그널을 수집해서 시간 윈도우 기반으로 점수를 합산한다.
    임계값을 넘으면 등록된 콜백(예: 대시보드 알림, 차단 액션)을 호출한다.
    """

    def __init__(self, window_seconds: int = SIGNAL_WINDOW_SECONDS,
                 *, is_trusted_actor: Optional[Callable[["Signal"], bool]] = None):
        self._signals: deque[Signal] = deque()
        self._lock = threading.Lock()
        self._window = window_seconds
        self._listeners: List[Callable[[Signal, int, Severity], None]] = []
        self._last_alert_level: Severity = Severity.INFO
        # Optional actor-trust classifier.  When set, a signal whose actor
        # resolves to a trusted system component (Defender, servicing, WMI…)
        # is stamped at submit time and excluded from the score so normal OS
        # housekeeping can't inflate the global level.  Injected by the agent;
        # left None in tests so scoring stays a pure function of weights.
        self._is_trusted_actor = is_trusted_actor

    def subscribe(self, listener: Callable[[Signal, int, Severity], None]) -> None:
        """시그널 발생 시 호출될 콜백 등록. (signal, current_score, threat_level)"""
        self._listeners.append(listener)

    def submit(self, signal: Signal) -> None:
        """탐지기가 시그널을 보고할 때 호출."""
        # Classify the actor once, here, outside the lock — resolving a PID's
        # image path can hit the OS, and we must not do that while holding the
        # scoring lock on the detector hot path.  The result is stamped onto
        # the signal so all the locked math below is pure dict lookups.
        if self._is_trusted_actor is not None and "actor_trusted" not in signal.metadata:
            try:
                signal.metadata["actor_trusted"] = bool(self._is_trusted_actor(signal))
            except Exception as e:
                print(f"[scoring] actor-trust classifier error: {e}")
                signal.metadata["actor_trusted"] = False

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
                # A trusted system actor's burst (e.g. TiWorker writing an
                # update, Defender scanning) must not corroborate a heuristic
                # flagged against an unrelated PID — that would turn benign OS
                # activity into a kill.  Skip it here too, not just in scoring.
                if self._trusted(s):
                    continue
                if s.name in ENCRYPTION_SIGNAL_NAMES:
                    return True
        return False

    def reset(self) -> None:
        with self._lock:
            self._signals.clear()

    def forget_pid(self, pid: int) -> int:
        """라이브 점수 윈도우에서 ``pid`` 에 귀속된 시그널을 모두 제거한다.

        responder 가 해당 PID 를 *종료(terminate)* 한 직후 호출된다 — 그
        프로세스가 가하던 위협은 끝났으므로, 직전 윈도우에 쌓인 그 PID 의
        신호가 *라이브* 위협 점수를 계속 부풀리면 안 된다.  이렇게 해야
        모든 활성 위협이 제거됐을 때 대시보드가 운영자의 수동 초기화 없이도
        스스로 "안전" 으로 복귀한다.

        다른 PID(아직 활동 중인 제2의 공격자)의 신호는 건드리지 않으므로
        동시 다발 공격은 점수를 그대로 유지한다.  PID 가 없는 시그널(예:
        canary)은 귀속이 불가능하므로 남으며, 재발생이 없으면 윈도우에서
        자연 감쇠한다.  영구 감사 기록(SQLite store, 인시던트 리포트,
        responder 액션 로그)은 영향받지 않는다 — 여기서는 인메모리 scoring
        deque 만 정리한다.  제거한 시그널 개수를 반환.
        """
        with self._lock:
            kept = deque(s for s in self._signals if self._pid_of(s) != pid)
            removed = len(self._signals) - len(kept)
            self._signals = kept
            return removed

    # ---- internals ----

    def _evict_old(self) -> None:
        cutoff = time.time() - self._window
        while self._signals and self._signals[0].timestamp < cutoff:
            self._signals.popleft()

    @staticmethod
    def _pid_of(sig: "Signal") -> Optional[int]:
        meta = sig.metadata or {}
        for key in ("pid", "ProcessId", "process_id", "child_pid"):
            val = meta.get(key)
            if isinstance(val, int) and val > 0:
                return val
        return None

    @staticmethod
    def _trusted(sig: "Signal") -> bool:
        """Was this signal's actor classified as a trusted system component
        at submit time?  Stamped by ``submit`` when a classifier is wired."""
        return bool((sig.metadata or {}).get("actor_trusted"))

    def _current_score_locked(self) -> int:
        # PID 단위 상관: 실제 암호화/파괴 시그널을 낸 PID 집합.  메타에 pid 가
        # 없는 암호화 시그널(예: canary)은 보수적으로 상관에서 제외 — 점수를
        # 부풀리지 않는 쪽으로.  신뢰 시스템 actor 의 시그널은 enc_pids 에도
        # 넣지 않는다 — 정상 OS 활동이 다른 PID 의 휴리스틱을 상관시키면 안 됨.
        enc_pids = set()
        for s in self._signals:
            if self._trusted(s):
                continue
            if s.name in ENCRYPTION_SIGNAL_NAMES:
                p = self._pid_of(s)
                if p is not None:
                    enc_pids.add(p)

        total = 0
        for s in self._signals:
            # 신뢰 시스템 actor (Defender 자기설정 쓰기, WMI/perf 재구축,
            # 서비싱 svchost/TiWorker 등) 는 점수에 합산하지 않는다.  이것이
            # 깨끗한 OS 가 부팅마다 CRITICAL 을 찍던 인플레의 근본 원인이었다.
            # 시그널 자체는 deque 에 남아 telemetry/대시보드로는 보인다.
            if self._trusted(s):
                continue
            if s.name in CORRELATION_GATED_NAMES:
                # 같은 PID 가 암호화 활동을 보일 때에만 weight 를 인정.
                if self._pid_of(s) in enc_pids:
                    total += s.weight
                # 그 외(고립된 삭제)는 0 기여 — telemetry 로만 남는다.
                continue
            total += s.weight
        return total

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
