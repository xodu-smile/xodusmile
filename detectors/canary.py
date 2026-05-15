"""
Canary File Detector
--------------------
보고서 2.2 — 사용자가 건드릴 일 없는 더미 파일을 배치하고
변경/삭제/이름 변경이 감지되면 매우 높은 신뢰도로 랜섬웨어로 판단.

설계:
  - 알파벳 앞쪽/뒤쪽에 배치되어 정렬 시 우선 처리될 가능성이 큼
  - 다양한 확장자 (랜섬웨어가 타겟하는 확장자 모두 커버)
  - 파일 해시를 저장해두고 폴링으로 변경 감지 (watchdog 의존성 최소화)
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Dict, List

from .base import Detector
from scoring import Signal, Severity


# 사용자 폴더가 정렬됐을 때 위 또는 아래에 위치하도록 의도적인 이름 사용
CANARY_FILENAMES = [
    "!!_DO_NOT_TOUCH_!!.docx",
    "0_important_notes.xlsx",
    "00_archive_index.pdf",
    "~$confidential_backup.docx",
    "zzz_old_records.txt",
]

# Canary는 단일 시그널만으로도 거의 확실하므로 매우 높은 가중치
CANARY_WEIGHT = 80


class CanaryDetector(Detector):
    name = "canary"

    def __init__(self, engine, watch_dirs: List[str], poll_interval: float = 1.5):
        super().__init__(engine)
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.poll_interval = poll_interval
        self._files: Dict[Path, str] = {}   # path -> sha256
        self._content = b"CANARY-FILE-DO-NOT-MODIFY-" + os.urandom(32)

    def deploy(self) -> List[Path]:
        """모든 watch_dir에 canary 파일 배치. 이미 있으면 해시만 갱신."""
        deployed = []
        for d in self.watch_dirs:
            d.mkdir(parents=True, exist_ok=True)
            for fname in CANARY_FILENAMES:
                p = d / fname
                if not p.exists():
                    p.write_bytes(self._content)
                self._files[p] = self._hash(p)
                deployed.append(p)
        print(f"[canary] deployed {len(deployed)} canary files across "
              f"{len(self.watch_dirs)} directories")
        return deployed

    def cleanup(self) -> None:
        """배치한 canary 파일 제거 (종료 시)."""
        for p in list(self._files.keys()):
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass

    @staticmethod
    def _hash(path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return ""

    def run(self) -> None:
        if not self._files:
            self.deploy()

        while not self._stop_event.is_set():
            for path, expected_hash in list(self._files.items()):
                if not path.exists():
                    self._raise_alert(
                        path, "canary_deleted",
                        f"Canary file deleted: {path.name}"
                    )
                    # 파일이 사라졌으니 더 이상 추적하지 않음
                    self._files.pop(path, None)
                    continue

                current = self._hash(path)
                if current != expected_hash:
                    self._raise_alert(
                        path, "canary_modified",
                        f"Canary file modified: {path.name}"
                    )
                    # 한 번 알린 뒤에는 새 해시로 갱신해서 같은 알람이 폭주하지 않게
                    self._files[path] = current

            self._stop_event.wait(self.poll_interval)

    def _raise_alert(self, path: Path, name: str, message: str) -> None:
        self.emit(Signal(
            detector=self.name,
            name=name,
            weight=CANARY_WEIGHT,
            severity=Severity.CRITICAL,
            message=message,
            metadata={"path": str(path), "directory": str(path.parent)},
        ))
