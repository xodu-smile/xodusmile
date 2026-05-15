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
from typing import Deque, Dict, List, Optional

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

# 임계값
ENTROPY_THRESHOLD = 7.5        # 8.0이 최대. 7.5+는 압축/암호화 의심
ENTROPY_DELTA_THRESHOLD = 2.5  # 보고서 임계값
BURST_WINDOW_SEC = 10
BURST_THRESHOLD = 15           # 10초 안에 15개 이상 변경
MAX_SAMPLE_BYTES = 4096        # 엔트로피 계산용 샘플링 크기

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
        # 변경 이벤트 타임스탬프 (process 단위 추적이 어려우므로 글로벌로)
        self._modify_times: Deque[float] = deque()
        # 파일별 마지막 알려진 매직 (rename/write 추적)
        self._last_magic: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._observer = None

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
        with self._lock:
            self._modify_times.append(time.time())

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
        prev_magic = self._last_magic.get(str(path))
        self._last_magic[str(path)] = magic or "UNKNOWN"

        # 시그널 1: 매직바이트 소실 (이전엔 알려진 형식, 지금은 알 수 없음)
        if prev_magic and prev_magic != "UNKNOWN" and magic is None:
            self.emit(Signal(
                detector=self.name, name="magic_bytes_lost",
                weight=W_MAGIC_LOST,
                severity=Severity.HIGH,
                message=f"File magic bytes lost: {path.name} (was {prev_magic})",
                metadata={"path": str(path), "previous_magic": prev_magic,
                          "entropy": round(ent, 3)},
            ))

        # 시그널 2: 고엔트로피 + 알려진 형식이 아님
        if ent >= ENTROPY_THRESHOLD and magic is None:
            ext = path.suffix.lower()
            if ext in TARGET_EXTENSIONS:
                self.emit(Signal(
                    detector=self.name, name="high_entropy_write",
                    weight=W_HIGH_ENTROPY_WRITE,
                    severity=Severity.MEDIUM,
                    message=f"High-entropy write to user file: {path.name} "
                            f"(H={ent:.2f})",
                    metadata={"path": str(path), "entropy": round(ent, 3)},
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
            self._modify_times.append(time.time())

    def on_created(self, path: Path) -> None:
        with self._lock:
            self._modify_times.append(time.time())

    # ---- burst detection ----

    def _check_burst(self) -> None:
        cutoff = time.time() - BURST_WINDOW_SEC
        with self._lock:
            while self._modify_times and self._modify_times[0] < cutoff:
                self._modify_times.popleft()
            count = len(self._modify_times)

        if count >= BURST_THRESHOLD:
            self.emit(Signal(
                detector=self.name, name="modify_burst",
                weight=W_BURST_MODIFY,
                severity=Severity.HIGH,
                message=f"File modification burst: {count} changes "
                        f"in {BURST_WINDOW_SEC}s",
                metadata={"count": count, "window_sec": BURST_WINDOW_SEC},
            ))
            # 한 번 알린 뒤 윈도우 비워서 폭주 방지
            with self._lock:
                self._modify_times.clear()


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
