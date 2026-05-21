"""
Mass I/O Detector
-----------------
보고서 2.4 — 단시간 내 대량 파일 변경 패턴 탐지.

이 프로토타입은 사용자 모드에서 watchdog 라이브러리를 사용한다.
실제 EDR은 Minifilter 드라이버를 써야 하지만 (보고서 2.1) 학습/PoC 용도로는
충분히 보고서의 핵심 통찰을 검증할 수 있다.

추가 기능 (보고서 2.1의 일부를 사용자 모드에서 흉내):
  - Shannon 엔트로피 계산
  - 매직 바이트 검증 (PE, PDF, Office, ZIP, JPEG 등)
  - 단위 시간당 변경 빈도 → 가중치 가산
"""

import math
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

from .base import Detector
from scoring import Signal, Severity


# 알려진 매직 바이트
MAGIC_SIGNATURES: dict[bytes, str] = {
    b"\x4d\x5a": "PE",                       # MZ - Windows EXE/DLL
    b"\x25\x50\x44\x46": "PDF",              # %PDF
    b"\x50\x4b\x03\x04": "ZIP/Office",       # PK.. (zip, docx, xlsx)
    b"\xd0\xcf\x11\xe0": "OLE/Office",       # 구 Office, MSI
    b"\xff\xd8\xff": "JPEG",
    b"\x89\x50\x4e\x47": "PNG",
    b"\x47\x49\x46\x38": "GIF",
    b"\x52\x61\x72\x21": "RAR",
    b"\x37\x7a\xbc\xaf": "7Z",
    b"\x1f\x8b": "GZIP",
}

# 우리가 관심 있는 확장자 (랜섬웨어 타깃)
TARGET_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".txt", ".rtf", ".odt",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".mp3", ".mp4", ".avi",
    ".zip", ".rar", ".7z",
    ".sql", ".db", ".mdf",
    ".psd", ".dwg",
}

# 가중치
W_HIGH_ENTROPY_WRITE = 8       # 단일 파일이 고엔트로피로 변함
W_MAGIC_LOST = 12              # 매직바이트 소실
W_BURST_MODIFY = 25            # 단위 시간당 변경 임계 초과
W_SUSPICIOUS_EXT = 5           # 의심 확장자로 변경
W_FANOUT_BONUS = 20            # 한 burst가 여러 확장자/디렉터리에 걸침

# 임계값
ENTROPY_THRESHOLD = 7.5        # 8.0이 최대. 7.5+는 압축/암호화 의심
ENTROPY_THRESHOLD_BOOSTED = 6.8  # canary trip 직후엔 더 낮은 임계
ENTROPY_DELTA_THRESHOLD = 2.5  # 보고서 임계값
BURST_WINDOW_SEC = 10
BURST_THRESHOLD = 15           # 10초 안에 15개 이상 변경
MAX_SAMPLE_BYTES = 4096        # 엔트로피 계산용 샘플링 크기

# Fan-out 임계 (burst 윈도우 내 고유성)
FANOUT_EXT_THRESHOLD = 3       # 서로 다른 확장자 3개 이상
FANOUT_DIR_THRESHOLD = 2       # 서로 다른 부모 디렉터리 2개 이상

# Canary cross-signal
CANARY_BOOST_WINDOW = 30.0     # canary trip 후 N초 동안 mass_io를 aggressive하게
CANARY_BOOST_MULTIPLIER = 1.5  # 가중치 곱셈 (정수 라운딩)

# 캐시 상한 (메모리 보호)
MAX_TRACKED_FILES = 20000

# 알려진 랜섬웨어 확장자 (단순 데모용 — 실제로는 동적 학습 필요)
SUSPICIOUS_EXTENSIONS = {
    ".encrypted", ".enc", ".locked", ".crypted", ".crypt",
    ".wcry", ".wncry", ".wannacry",
    ".ryk", ".ryuk",
    ".lockbit",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        h -= p * math.log2(p)
    return h


def detect_magic(data: bytes) -> Optional[str]:
    for sig, label in MAGIC_SIGNATURES.items():
        if data.startswith(sig):
            return label
    return None


class MassIODetector(Detector):
    name = "mass_io"

    def __init__(self, engine, watch_dirs: List[str]):
        super().__init__(engine)
        self.watch_dirs = [Path(d) for d in watch_dirs]
        # 변경 이벤트: (ts, ext, parent_dir) — fan-out 계산용
        self._modify_events: Deque[Tuple[float, str, str]] = deque()
        # 파일별 마지막 알려진 매직 (rename/write 추적)
        self._last_magic: Dict[str, str] = {}
        # 파일별 마지막 측정 엔트로피 (delta 계산용)
        self._last_entropy: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._observer = None
        # canary cross-signal: 마지막 canary trip 시각
        self._canary_tripped_at: float = 0.0
        # ScoringEngine을 통해 canary 신호 수신
        self.engine.subscribe(self._on_engine_signal)

    def run(self) -> None:
        if not HAS_WATCHDOG:
            print("[mass_io] watchdog not installed; "
                  "falling back to simple polling")
            self._run_polling()
            return

        handler = _Handler(self)
        self._observer = Observer()
        for d in self.watch_dirs:
            d.mkdir(parents=True, exist_ok=True)
            self._observer.schedule(handler, str(d), recursive=True)
        self._observer.start()
        print(f"[mass_io] watching {len(self.watch_dirs)} directories")
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(1.0)
                self._check_burst()
        finally:
            self._observer.stop()
            self._observer.join(timeout=3.0)

    def _run_polling(self) -> None:
        """watchdog 미설치 시 폴백 — 단순 mtime 폴링."""
        seen: Dict[str, float] = {}
        while not self._stop_event.is_set():
            for d in self.watch_dirs:
                if not d.exists():
                    continue
                for p in d.rglob("*"):
                    if not p.is_file():
                        continue
                    try:
                        mtime = p.stat().st_mtime
                    except OSError:
                        continue
                    key = str(p)
                    if key in seen and seen[key] != mtime:
                        self.on_modified(p)
                    seen[key] = mtime
            self._stop_event.wait(2.0)
            self._check_burst()

    # ---- file event hooks ----

    def on_modified(self, path: Path) -> None:
        if not path.is_file():
            return
        ext = path.suffix.lower()
        parent = str(path.parent)
        now = time.time()
        with self._lock:
            self._modify_events.append((now, ext, parent))

        # 엔트로피 + 매직바이트 분석
        try:
            with open(path, "rb") as f:
                head = f.read(MAX_SAMPLE_BYTES)
        except OSError:
            return

        if not head:
            return

        ent = shannon_entropy(head)
        magic = detect_magic(head)
        key = str(path)
        prev_magic = self._last_magic.get(key)
        prev_entropy = self._last_entropy.get(key)
        self._record_file_state(key, magic or "UNKNOWN", ent)

        boosted = self._canary_boost_active()
        threshold = ENTROPY_THRESHOLD_BOOSTED if boosted else ENTROPY_THRESHOLD

        # 시그널 1: 매직바이트 소실 (이전엔 알려진 형식, 지금은 알 수 없음)
        if prev_magic and prev_magic != "UNKNOWN" and magic is None:
            self.emit(Signal(
                detector=self.name, name="magic_bytes_lost",
                weight=self._boost(W_MAGIC_LOST, boosted),
                severity=Severity.HIGH,
                message=f"File magic bytes lost: {path.name} (was {prev_magic})",
                metadata={"path": str(path), "previous_magic": prev_magic,
                          "entropy": round(ent, 3),
                          "canary_boost": boosted},
            ))

        # 시그널 2: 고엔트로피 + 알려진 형식이 아님 + (delta가 크거나 첫 관찰)
        if ent >= threshold and magic is None and ext in TARGET_EXTENSIONS:
            # 이미 high-entropy로 본 적 있는 파일을 다시 보는 건 신호가 아님
            # (이미 암호화/압축된 백업 파일을 다시 touch한 경우 등).
            # 첫 관찰일 때만, 또는 prev가 낮았다가 갑자기 올라간 경우에만 발화.
            delta = ent - prev_entropy if prev_entropy is not None else None
            is_jump = delta is not None and delta >= ENTROPY_DELTA_THRESHOLD
            is_first = prev_entropy is None
            if is_jump or is_first:
                reason = "delta" if is_jump else "first_seen"
                self.emit(Signal(
                    detector=self.name, name="high_entropy_write",
                    weight=self._boost(W_HIGH_ENTROPY_WRITE, boosted),
                    severity=Severity.MEDIUM,
                    message=(f"High-entropy write to user file: {path.name} "
                             f"(H={ent:.2f}"
                             + (f", ΔH={delta:.2f}" if delta is not None else "")
                             + f", {reason})"),
                    metadata={"path": str(path), "entropy": round(ent, 3),
                              "prev_entropy": (round(prev_entropy, 3)
                                               if prev_entropy is not None else None),
                              "delta": round(delta, 3) if delta is not None else None,
                              "reason": reason,
                              "canary_boost": boosted},
                ))

    def on_moved(self, src: Path, dest: Path) -> None:
        ext = dest.suffix.lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            self.emit(Signal(
                detector=self.name, name="suspicious_extension",
                weight=W_SUSPICIOUS_EXT * 3,  # 강한 시그널
                severity=Severity.HIGH,
                message=f"File renamed to suspicious extension: "
                        f"{src.name} -> {dest.name}",
                metadata={"src": str(src), "dest": str(dest)},
            ))
        with self._lock:
            self._modify_events.append((time.time(), ext, str(dest.parent)))

    def on_created(self, path: Path) -> None:
        with self._lock:
            self._modify_events.append(
                (time.time(), path.suffix.lower(), str(path.parent))
            )

    # ---- burst detection ----

    def _check_burst(self) -> None:
        cutoff = time.time() - BURST_WINDOW_SEC
        with self._lock:
            while self._modify_events and self._modify_events[0][0] < cutoff:
                self._modify_events.popleft()
            count = len(self._modify_events)
            unique_exts = {ext for _, ext, _ in self._modify_events if ext}
            unique_dirs = {d for _, _, d in self._modify_events}

        if count < BURST_THRESHOLD:
            return

        weight = W_BURST_MODIFY
        fanout_reason = []
        if len(unique_exts) >= FANOUT_EXT_THRESHOLD:
            weight += W_FANOUT_BONUS
            fanout_reason.append(f"{len(unique_exts)} exts")
        if len(unique_dirs) >= FANOUT_DIR_THRESHOLD:
            weight += W_FANOUT_BONUS
            fanout_reason.append(f"{len(unique_dirs)} dirs")

        boosted = self._canary_boost_active()
        weight = self._boost(weight, boosted)
        fanout_suffix = f" [fan-out: {', '.join(fanout_reason)}]" if fanout_reason else ""

        self.emit(Signal(
            detector=self.name, name="modify_burst",
            weight=weight,
            severity=Severity.HIGH,
            message=(f"File modification burst: {count} changes "
                     f"in {BURST_WINDOW_SEC}s{fanout_suffix}"),
            metadata={"count": count, "window_sec": BURST_WINDOW_SEC,
                      "unique_extensions": sorted(unique_exts),
                      "unique_dirs": len(unique_dirs),
                      "canary_boost": boosted},
        ))
        # 한 번 알린 뒤 윈도우 비워서 폭주 방지
        with self._lock:
            self._modify_events.clear()

    # ---- cross-signal & helpers ----

    def _on_engine_signal(self, signal, score, level) -> None:
        """ScoringEngine 리스너. canary 시그널을 받으면 mass_io를 aggressive 모드로."""
        if signal.detector == "canary":
            self._canary_tripped_at = time.time()

    def _canary_boost_active(self) -> bool:
        return (time.time() - self._canary_tripped_at) < CANARY_BOOST_WINDOW

    @staticmethod
    def _boost(weight: int, boosted: bool) -> int:
        if not boosted:
            return weight
        return int(round(weight * CANARY_BOOST_MULTIPLIER))

    def _record_file_state(self, key: str, magic: str, entropy: float) -> None:
        # 캐시 상한 — 가장 오래된 항목 일괄 정리 (간단한 LRU 대체).
        if len(self._last_magic) >= MAX_TRACKED_FILES:
            # dict 삽입 순서를 활용해서 앞쪽 절반 잘라냄.
            drop = len(self._last_magic) // 2
            for k in list(self._last_magic.keys())[:drop]:
                self._last_magic.pop(k, None)
                self._last_entropy.pop(k, None)
        self._last_magic[key] = magic
        self._last_entropy[key] = entropy


if HAS_WATCHDOG:
    class _Handler(FileSystemEventHandler):
        def __init__(self, det: "MassIODetector"):
            self.det = det

        def on_modified(self, event):
            if event.is_directory:
                return
            self.det.on_modified(Path(event.src_path))

        def on_created(self, event):
            if event.is_directory:
                return
            self.det.on_created(Path(event.src_path))

        def on_moved(self, event):
            if event.is_directory:
                return
            self.det.on_moved(Path(event.src_path), Path(event.dest_path))
