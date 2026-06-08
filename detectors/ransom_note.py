"""
Ransom Note Detector
--------------------
랜섬웨어가 암호화 전후로 각 폴더에 떨어뜨리는 **협박문(ransom note)** 을 탐지한다.

근거 (보고서 2.x / 실측):
  거의 모든 현대 랜섬웨어 패밀리는 암호화한 폴더마다 동일한 안내문 파일을
  남긴다 — ``HOW_TO_DECRYPT.txt``, ``_readme.txt``, ``RESTORE-MY-FILES.txt``,
  ``DECRYPT_INSTRUCTIONS.html``, ``*.hta`` 등.  이 파일들은

    1. 이름 패턴이 매우 특징적이고("decrypt"/"recover"/"restore"+"files" 등),
    2. **여러 폴더에 동시에** 같은(또는 유사) 이름으로 퍼진다(spread).

  단일 README.txt 하나는 정상일 수 있으므로 그것만으로는 강하게 판정하지
  않는다 — **다중 디렉터리 확산**을 CRITICAL 의 핵심 조건으로 삼아 오탐을
  억제한다.

설계 (mass_io 와 동일: watchdog 이벤트 우선, 없으면 폴링 폴백):
  - watchdog 가 있으면 파일 생성/이동/수정 이벤트에서만 검사한다 — 거대한
    감시 트리(C:\\Users 등)를 매 주기 rglob 하는 비용을 피한다.
  - watchdog 가 없으면 재귀 폴링으로 폴백(작은 트리/테스트용).
  - 한 번 본 노트 경로는 다시 알리지 않는다(폭주 방지).
  - 서로 다른 디렉터리 ≥ ``SPREAD_DIR_THRESHOLD`` 개에서 노트가 나오면
    ``ransom_note_spread`` (CRITICAL).  단일 노트는 ``ransom_note_dropped`` (HIGH).
  - canary 가 트립하면(거의 확실한 랜섬웨어) 단일 노트도 즉시 강하게 본다.
"""

import re
import threading
import time
from pathlib import Path
from typing import Dict, List, Set

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

from .base import Detector
from scoring import Signal, Severity


# 협박문으로 인정할 파일 확장자 (또는 확장자 없는 README).
NOTE_EXTENSIONS = {".txt", ".html", ".htm", ".hta", ".rtf", ""}

# 협박문 파일명 패턴 (소문자 파일명 전체에 대해 검사).  특이도 높은 패턴만.
# 정상 파일(readme.md, license.txt 등)을 피하려고 "decrypt/recover/restore/
# ransom/unlock + files/data/your" 같은 강한 조합 위주로 구성한다.
_NOTE_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"how[\s_\-]*to[\s_\-]*decrypt",
        r"how[\s_\-]*to[\s_\-]*(restore|recover|back)[\s_\-]*(files|data)",
        r"decrypt[\s_\-]*(instruction|info|files|guide|note|me)",
        r"(recover|restore|unlock)[\s_\-]*(my|your)?[\s_\-]*files",
        r"(your|all)[\s_\-]*files[\s_\-]*(are|have been)?[\s_\-]*(encrypted|locked)",
        r"ransom[\s_\-]*(note|ware|message)",
        r"!{1,3}[\s_]*(readme|read[\s_\-]*me|restore|recover|decrypt)",
        r"_readme\.txt$",                       # STOP/Djvu 패밀리
        r"read[\s_\-]*me[\s_\-]*(for|to)[\s_\-]*decrypt",
        r"(help|info)[\s_\-]*(decrypt|restore|recover)",
        r"recovery[\s_\-]*(key|info|instruction)",
        r"unlock[\s_\-]*(your|my|files|data|instruction)",
    )
]

# 가중치 / 임계값
W_NOTE_SINGLE = 35        # 단일 협박문 (HIGH)
W_NOTE_SPREAD = 90        # 다중 디렉터리 확산 (CRITICAL) — 단발로 임계 근접
SPREAD_DIR_THRESHOLD = 2  # 서로 다른 디렉터리 이 개수 이상이면 spread
SPREAD_WINDOW_SEC = 60.0  # 이 시간 안에 모인 노트만 확산으로 집계
MAX_NOTE_BYTES = 65536    # 이보다 큰 파일은 협박문이 아니라고 보고 제외(보통 짧다)
POLL_INTERVAL = 2.0
# _seen_notes 가 장기 실행에서 무한정 커지지 않도록 상한(초과 시 초기화).
_SEEN_CAP = 20000


def is_ransom_note_name(filename: str) -> bool:
    """파일명이 협박문 패턴과 일치하는지."""
    fn = (filename or "").lower()
    return any(p.search(fn) for p in _NOTE_PATTERNS)


class RansomNoteDetector(Detector):
    name = "ransom_note"

    def __init__(self, engine, watch_dirs: List[str], poll_interval: float = POLL_INTERVAL):
        super().__init__(engine)
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.poll_interval = poll_interval
        self._lock = threading.Lock()
        # 이미 알린 노트 경로(소문자) — 재알림 방지.
        self._seen_notes: Set[str] = set()
        # 최근 관측한 (디렉터리, 시각) — 확산 판정용.
        self._recent_dirs: Dict[str, float] = {}
        self._observer = None
        # canary 트립 부스트(거의 확실한 랜섬웨어면 단일 노트도 강하게 본다).
        self._canary_tripped_at = 0.0
        engine.subscribe(self._on_engine_signal)

    # ---- canary 교차 신호 ----

    def _on_engine_signal(self, sig, score, level) -> None:
        if sig.detector == "canary":
            self._canary_tripped_at = time.time()

    def _boost_active(self) -> bool:
        return (time.time() - self._canary_tripped_at) < 30.0

    # ---- detector loop ----

    def run(self) -> None:
        # 시작 시점에 이미 있던 파일은 baseline 으로 등록(과거 노트로 알람 안 뜨게).
        self._scan(initial=True)

        if HAS_WATCHDOG:
            handler = _NoteHandler(self)
            self._observer = Observer()
            for d in self.watch_dirs:
                try:
                    d.mkdir(parents=True, exist_ok=True)
                    self._observer.schedule(handler, str(d), recursive=True)
                except OSError as e:
                    print(f"[{self.name}] cannot watch {d}: {e}")
            self._observer.start()
            print(f"[{self.name}] watching {len(self.watch_dirs)} directories "
                  f"(event-driven)")
            try:
                while not self._stop_event.is_set():
                    self._stop_event.wait(self.poll_interval)
                    self._prune(time.time())
            finally:
                self._observer.stop()
                self._observer.join(timeout=3.0)
            return

        # watchdog 미설치 — 폴링 폴백(작은 트리/테스트용).
        print(f"[{self.name}] watchdog not installed; falling back to polling")
        while not self._stop_event.is_set():
            try:
                self._scan(initial=False)
            except Exception as e:
                print(f"[{self.name}] scan error: {e}")
            self._stop_event.wait(self.poll_interval)

    def _prune(self, now: float) -> None:
        """확산 윈도우 밖의 디렉터리 관측을 정리한다(스레드 세이프)."""
        cutoff = now - SPREAD_WINDOW_SEC
        with self._lock:
            self._recent_dirs = {d: t for d, t in self._recent_dirs.items()
                                 if t >= cutoff}

    def _scan(self, initial: bool) -> None:
        """폴링 경로(및 시작 baseline): 감시 트리를 훑어 신규 노트를 검사한다."""
        self._prune(time.time())
        for base in self.watch_dirs:
            if not base.exists():
                continue
            for p in self._iter_files(base):
                self._consider_path(p, initial=initial)

    @staticmethod
    def _iter_files(base: Path):
        try:
            yield from (p for p in base.rglob("*") if p.is_file())
        except OSError:
            return

    def _consider_path(self, path: Path, initial: bool = False) -> None:
        """한 경로가 신규 협박문인지 판정하고, 맞으면 신호를 발생시킨다.

        watchdog 핸들러와 폴링 스캔이 공유하는 단일 판정 지점.
        """
        key = str(path).lower()
        with self._lock:
            if key in self._seen_notes:
                return
        if path.suffix.lower() not in NOTE_EXTENSIONS:
            return
        if not is_ransom_note_name(path.name):
            return
        try:
            if not path.is_file() or path.stat().st_size > MAX_NOTE_BYTES:
                return
        except OSError:
            return
        with self._lock:
            if key in self._seen_notes:        # 더블체크(경합 방지)
                return
            self._seen_notes.add(key)
            if len(self._seen_notes) > _SEEN_CAP:
                self._seen_notes = set()       # 메모리 상한(드물게 도달)
                self._seen_notes.add(key)
        if initial:
            # baseline — 알리지 않고 기록만.
            return
        self._handle_note(path, time.time())

    def _handle_note(self, path: Path, now: float) -> None:
        directory = str(path.parent).lower()
        with self._lock:
            self._recent_dirs[directory] = now
            spread = len(self._recent_dirs)

        if spread >= SPREAD_DIR_THRESHOLD:
            # 다중 폴더 확산 — 랜섬웨어 협박문 살포로 강하게 판정.
            self.emit(Signal(
                detector=self.name,
                name="ransom_note_spread",
                weight=W_NOTE_SPREAD,
                severity=Severity.CRITICAL,
                message=(f"Ransom note spread across {spread} directories "
                         f"(latest: {path.name})"),
                metadata={
                    "path": str(path),
                    "directory": str(path.parent),
                    "directories_affected": spread,
                    "window_sec": SPREAD_WINDOW_SEC,
                },
            ))
            return

        # 단일 노트 — HIGH(또는 canary 부스트 중이면 더 강하게).
        boosted = self._boost_active()
        self.emit(Signal(
            detector=self.name,
            name="ransom_note_dropped",
            weight=W_NOTE_SPREAD if boosted else W_NOTE_SINGLE,
            severity=Severity.CRITICAL if boosted else Severity.HIGH,
            message=(f"Possible ransom note created: {path.name}"
                     + (" (canary already tripped)" if boosted else "")),
            metadata={
                "path": str(path),
                "directory": str(path.parent),
                "canary_boost": boosted,
            },
        ))


if HAS_WATCHDOG:
    class _NoteHandler(FileSystemEventHandler):
        """파일 생성/이동/수정 이벤트에서만 협박문 판정을 돌린다."""

        def __init__(self, det: "RansomNoteDetector"):
            self.det = det

        def on_created(self, event):
            if not event.is_directory:
                self.det._consider_path(Path(event.src_path))

        def on_moved(self, event):
            if not event.is_directory:
                self.det._consider_path(Path(event.dest_path))

        def on_modified(self, event):
            if not event.is_directory:
                self.det._consider_path(Path(event.src_path))
