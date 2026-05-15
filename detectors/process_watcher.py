"""
Real-time Process Watcher (Windows 11)
--------------------------------------
psutil 기반 Win11 프로세스 감시기. WMI 이벤트 구독은 지연·드롭이 있을 수
있으므로 psutil 폴링을 병행해서 보강한다.

WMI 기반 ProcessCmdlineDetector 와 동일한 RULES 를 적용하고, 추가로:

  - 새로 떠난 프로세스 (PID 신규 등장 → cmdline 룰 평가)
  - Win11 LOLBin 부모-자식 의심 체인 (Office/Edge/explorer → script host)
  - 단일 프로세스의 폭발적 디스크 쓰기 (psutil.Process().io_counters)
  - 짧은 시간 안에 같은 부모가 다수 자식을 만드는 fan-out

대시보드용으로 최근 본 프로세스 스냅샷을 보관해 /api/processes 에서
실시간 조회할 수 있게 한다.
"""

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from .base import Detector
from .process_cmdline import evaluate_cmdline
from scoring import Signal, Severity


POLL_INTERVAL_SEC = 1.0
MAX_SNAPSHOT = 80
WRITE_BURST_BYTES = 50 * 1024 * 1024     # 1초 사이 단일 프로세스가 50MB+ 쓰면 의심
WRITE_BURST_WINDOW = 2.0
FANOUT_THRESHOLD = 12                     # 같은 부모가 윈도우 안에 자식 N개 이상
FANOUT_WINDOW = 5.0

# 부모-자식 chain 룰 (parent_name → child_name 이 의심)
# Win11 LOLBin 기준. 이름은 모두 소문자 비교.
SCRIPT_HOSTS = {
    "powershell.exe", "pwsh.exe",
    "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "bitsadmin.exe", "certutil.exe", "msbuild.exe",
    "installutil.exe",
}

SUSPICIOUS_CHAINS: Dict[str, set] = {
    # Microsoft 365 / Office → script host (매크로 → LOLBin)
    "winword.exe":   SCRIPT_HOSTS,
    "excel.exe":     SCRIPT_HOSTS,
    "powerpnt.exe":  SCRIPT_HOSTS,
    "outlook.exe":   SCRIPT_HOSTS,
    "onenote.exe":   SCRIPT_HOSTS,
    "msaccess.exe":  SCRIPT_HOSTS,
    "visio.exe":     SCRIPT_HOSTS,
    # PDF / 뷰어
    "acrord32.exe":  SCRIPT_HOSTS,
    "acrobat.exe":   SCRIPT_HOSTS,
    # 브라우저가 셸을 띄우는 건 거의 없음 (드라이브-바이 다운로드 → 실행 패턴)
    "msedge.exe":    SCRIPT_HOSTS,
    "chrome.exe":    SCRIPT_HOSTS,
    "firefox.exe":   SCRIPT_HOSTS,
    # Win11 OS 컴포넌트가 직접 PowerShell/cmd 를 spawn 하면 의심
    "explorer.exe":  {"powershell.exe", "pwsh.exe", "mshta.exe",
                      "regsvr32.exe", "rundll32.exe", "bitsadmin.exe",
                      "certutil.exe"},
    "runtimebroker.exe": SCRIPT_HOSTS,
    "searchhost.exe":    SCRIPT_HOSTS,
    "shellhost.exe":     SCRIPT_HOSTS,
    # 클라우드 스토리지 — OneDrive 가 cmd/powershell 을 띄우는 건 없음
    "onedrive.exe":  SCRIPT_HOSTS,
}


@dataclass
class ProcSnapshot:
    pid: int
    ppid: int
    name: str
    cmdline: str
    user: str
    started_at: float
    cpu_percent: float = 0.0
    rss_bytes: int = 0
    write_bytes: int = 0
    last_seen: float = field(default_factory=time.time)


class ProcessWatcher(Detector):
    """psutil 기반 실시간 프로세스 감시기.

    - run() 루프에서 1초 간격으로 전체 프로세스 목록을 다시 스냅샷
    - 새로 보인 PID는 cmdline 룰 + chain 룰로 평가
    - 활성 프로세스의 IO counters 를 추적해서 burst 감지
    """

    name = "process_watcher"

    def __init__(self, engine, poll_interval: float = POLL_INTERVAL_SEC):
        super().__init__(engine)
        self.poll_interval = poll_interval
        self._seen: Dict[int, ProcSnapshot] = {}
        self._last_io: Dict[int, Tuple[float, int]] = {}     # pid -> (ts, write_bytes)
        self._fanout: Dict[int, Deque[float]] = defaultdict(deque)
        self._own_pid = os.getpid()

    # --- public API for dashboard ----------------------------------

    def snapshot(self, limit: int = MAX_SNAPSHOT) -> List[dict]:
        """현재까지 추적 중인 프로세스를 최근 본 순으로 반환."""
        items = sorted(
            self._seen.values(),
            key=lambda p: (p.last_seen, p.started_at),
            reverse=True,
        )[:limit]
        return [
            {
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "cmdline": p.cmdline[:256],
                "user": p.user,
                "started_at": p.started_at,
                "cpu_percent": round(p.cpu_percent, 1),
                "rss_mb": round(p.rss_bytes / (1024 * 1024), 1),
                "last_seen": p.last_seen,
            }
            for p in items
        ]

    # --- detector loop ---------------------------------------------

    def run(self) -> None:
        if not HAS_PSUTIL:
            print(f"[{self.name}] psutil not installed; watcher inactive")
            self._stop_event.wait()
            return

        print(f"[{self.name}] real-time process watcher started "
              f"(interval={self.poll_interval}s)")

        # 첫 패스는 baseline — 시그널을 emit 하지 않고 기존 프로세스를 기록
        self._scan(initial=True)

        while not self._stop_event.is_set():
            try:
                self._scan(initial=False)
            except Exception as e:
                print(f"[{self.name}] scan error: {e}")
            self._stop_event.wait(self.poll_interval)

    def _scan(self, initial: bool) -> None:
        now = time.time()
        current_pids: set = set()

        attrs = ["pid", "ppid", "name", "cmdline", "username",
                 "create_time", "cpu_percent", "memory_info", "io_counters"]

        for proc in psutil.process_iter(attrs=attrs, ad_value=None):
            try:
                info = proc.info
            except psutil.NoSuchProcess:
                continue

            pid = info.get("pid")
            if pid is None or pid == self._own_pid:
                continue
            current_pids.add(pid)

            name = (info.get("name") or "").strip()
            cmd_list = info.get("cmdline") or []
            cmdline = " ".join(cmd_list) if isinstance(cmd_list, list) else str(cmd_list)
            ppid = info.get("ppid") or 0
            user = (info.get("username") or "").strip()
            started = info.get("create_time") or now
            mem = info.get("memory_info")
            rss = getattr(mem, "rss", 0) if mem else 0
            io = info.get("io_counters")
            write_bytes = getattr(io, "write_bytes", 0) if io else 0
            cpu = info.get("cpu_percent") or 0.0

            snap = self._seen.get(pid)
            is_new = snap is None or snap.started_at != started

            if is_new:
                snap = ProcSnapshot(
                    pid=pid, ppid=ppid, name=name, cmdline=cmdline,
                    user=user, started_at=started, cpu_percent=cpu,
                    rss_bytes=rss, write_bytes=write_bytes, last_seen=now,
                )
                self._seen[pid] = snap
                if not initial:
                    self._on_new_process(snap)
            else:
                snap.cpu_percent = cpu
                snap.rss_bytes = rss
                snap.last_seen = now
                snap.write_bytes = write_bytes

            if not initial:
                self._check_write_burst(pid, name, cmdline, write_bytes, now)

        # 사라진 PID 정리
        for pid in list(self._seen.keys()):
            if pid not in current_pids:
                self._seen.pop(pid, None)
                self._last_io.pop(pid, None)
                self._fanout.pop(pid, None)

    # --- event handlers --------------------------------------------

    def _on_new_process(self, snap: ProcSnapshot) -> None:
        # 1) cmdline 룰 적용
        for sig in evaluate_cmdline(self.name, snap.name, snap.cmdline,
                                    snap.pid, snap.ppid):
            self.emit(sig)

        # 2) 부모-자식 chain 검사 (Win11 LOLBin pattern, 정확 매치)
        parent = self._seen.get(snap.ppid)
        parent_name = (parent.name if parent else "").lower()
        child_name = snap.name.lower()
        suspect_children = SUSPICIOUS_CHAINS.get(parent_name)
        if suspect_children and child_name in suspect_children:
            self.emit(Signal(
                detector=self.name,
                name="suspicious_parent_child",
                weight=40,
                severity=Severity.HIGH,
                message=f"Suspicious process chain: {parent_name} → {child_name}",
                metadata={
                    "parent": parent_name,
                    "parent_pid": snap.ppid,
                    "child": child_name,
                    "child_pid": snap.pid,
                    "cmdline": snap.cmdline[:256],
                },
            ))

        # 3) 동일 부모의 fan-out 추적
        bucket = self._fanout[snap.ppid]
        bucket.append(time.time())
        cutoff = time.time() - FANOUT_WINDOW
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= FANOUT_THRESHOLD:
            self.emit(Signal(
                detector=self.name,
                name="child_fanout",
                weight=30,
                severity=Severity.MEDIUM,
                message=f"Parent pid={snap.ppid} ({parent_name or '?'}) "
                        f"spawned {len(bucket)} children in {FANOUT_WINDOW}s",
                metadata={
                    "parent_pid": snap.ppid,
                    "parent": parent_name,
                    "children": len(bucket),
                    "window_sec": FANOUT_WINDOW,
                },
            ))
            bucket.clear()

    def _check_write_burst(self, pid: int, name: str, cmdline: str,
                           write_bytes: int, now: float) -> None:
        prev = self._last_io.get(pid)
        self._last_io[pid] = (now, write_bytes)
        if prev is None:
            return
        prev_ts, prev_bytes = prev
        dt = now - prev_ts
        if dt <= 0 or dt > WRITE_BURST_WINDOW:
            return
        delta = write_bytes - prev_bytes
        if delta >= WRITE_BURST_BYTES:
            self.emit(Signal(
                detector=self.name,
                name="process_write_burst",
                weight=20,
                severity=Severity.MEDIUM,
                message=f"{name} (pid={pid}) wrote "
                        f"{delta / (1024*1024):.1f} MB in {dt:.1f}s",
                metadata={
                    "pid": pid,
                    "process": name,
                    "cmdline": cmdline[:256],
                    "bytes": delta,
                    "window_sec": round(dt, 2),
                },
            ))
