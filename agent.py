"""
Ransomware Detection Agent
--------------------------
모든 탐지기를 조립하고 백그라운드로 실행한다.
대시보드(Flask)와 같은 프로세스에서 실행될 수도 있고 독립 실행 가능하다.

커널 minifilter (RmDetectorFlt) 가 로드되어 있으면 EDR 모드로 동작한다:
프로세스 트리/이미지 로드/엔트로피 스파이크/in-kernel 점수/자동 종료
이벤트를 받아 ScoringEngine 에 합산하고, 커널이 직접 ZwTerminateProcess
까지 호출한다. 드라이버가 없을 때는 user-mode 와치독으로 폴백한다.
"""

import argparse
import os
import signal
import sys
import time
from pathlib import Path

from scoring import ScoringEngine, Signal, Severity
from event_store import EventStore
from detectors.canary import CanaryDetector
from detectors.mass_io import MassIODetector
from detectors.minifilter import MinifilterDetector
from detectors.process_cmdline import ProcessCmdlineDetector
from detectors.process_watcher import ProcessWatcher


# PID block escalation: trip when the scoring engine first crosses
# CRITICAL. The driver gets a one-shot block command per PID.
BLOCK_PID_AT_LEVEL = Severity.CRITICAL


class Agent:
    def __init__(self, watch_dirs, db_path: str = "detector.db"):
        self.engine = ScoringEngine()
        self.store = EventStore(db_path)
        self.engine.subscribe(self._on_signal)

        self.canary = CanaryDetector(self.engine, watch_dirs)
        self.mass_io = MassIODetector(self.engine, watch_dirs)
        self.minifilter = MinifilterDetector(self.engine, watch_dirs)
        self.proc = ProcessCmdlineDetector(self.engine)
        self.watcher = ProcessWatcher(self.engine)

        self.detectors = [self.canary, self.mass_io, self.minifilter,
                          self.proc, self.watcher]
        self._blocked_pids: set[int] = set()

    def _on_signal(self, sig: Signal, score: int, level: Severity) -> None:
        # 콘솔 알림
        bar = self._severity_bar(level)
        print(f"{bar} [{sig.detector}/{sig.name}] {sig.message}  "
              f"(weight={sig.weight}, total_score={score}, level={level.value})")
        # 영속화
        self.store.record(sig, score, level)
        # 커널이 이미 죽인 PID 는 차단 큐에 더 넣지 않는다
        if sig.name == "auto_terminated":
            pid = sig.metadata.get("pid")
            if isinstance(pid, int):
                self._blocked_pids.add(pid)
            return
        # PID 차단 에스컬레이션 (CRITICAL 진입 + PID 알려진 경우)
        if (level == BLOCK_PID_AT_LEVEL
                and self.minifilter.connected):
            pid = sig.metadata.get("pid")
            if isinstance(pid, int) and pid > 0 and pid not in self._blocked_pids:
                self._blocked_pids.add(pid)
                ok = self.minifilter.block_pid(pid)
                marker = "blocked" if ok else "block-failed"
                print(f"[agent] {marker} pid={pid} via minifilter "
                      f"(triggered by {sig.detector}/{sig.name})")

    @staticmethod
    def _severity_bar(level: Severity) -> str:
        return {
            Severity.INFO: "░░░░░",
            Severity.LOW: "▓░░░░",
            Severity.MEDIUM: "▓▓░░░",
            Severity.HIGH: "▓▓▓▓░",
            Severity.CRITICAL: "▓▓▓▓▓",
        }.get(level, "░░░░░")

    def start(self) -> None:
        print("=" * 60)
        print("  Ransomware Detection Agent — prototype")
        print("=" * 60)
        # canary 먼저 배치 -> 그 경로를 그대로 minifilter 에 알려준다
        canary_files = self.canary.deploy()
        self.minifilter.canary_paths = [str(p) for p in canary_files]
        for d in self.detectors:
            d.start()
        # 짧은 윈도우 동안 minifilter 가 커널 포트에 붙기를 기다린다
        for _ in range(20):
            if self.minifilter.connected:
                break
            time.sleep(0.1)
        if self.minifilter.connected:
            print(f"[agent] RmDetectorFlt ACTIVE — EDR mode "
                  f"(process tree + image load + entropy guard + susp-ext "
                  f"rename guard + auto-terminate)")
        else:
            print(f"[agent] RmDetectorFlt inactive (driver not loaded) — "
                  f"user-mode watchers only (no in-kernel kill)")
        print(f"[agent] {len(self.detectors)} detectors started")

    def stop(self) -> None:
        print("[agent] stopping...")
        for d in self.detectors:
            d.stop()
        try:
            self.canary.cleanup()
        except Exception:
            pass
        print("[agent] stopped")

    def status(self) -> dict:
        return {
            "score": self.engine.current_score(),
            "level": self.engine.current_level().value,
            "recent_signals": [s.to_dict() for s in self.engine.recent_signals(20)],
            "stats": self.store.stats(),
        }

    def processes(self, limit: int = 50) -> list:
        """대시보드 용 — 실시간 프로세스 스냅샷."""
        return self.watcher.snapshot(limit=limit)


def parse_args():
    p = argparse.ArgumentParser(description="Ransomware Detection Agent")
    p.add_argument(
        "--watch", action="append", default=None,
        help="Directory to watch (can be specified multiple times). "
             "Defaults to ./test_watch_dir",
    )
    p.add_argument("--db", default="detector.db", help="SQLite database path")
    p.add_argument(
        "--no-dashboard", action="store_true",
        help="Run agent only, without the web dashboard",
    )
    p.add_argument(
        "--port", type=int, default=5000,
        help="Dashboard port (default 5000)",
    )
    return p.parse_args()


def main():
    args = parse_args()
    watch = args.watch or [str(Path.cwd() / "test_watch_dir")]
    for d in watch:
        Path(d).mkdir(parents=True, exist_ok=True)

    agent = Agent(watch, db_path=args.db)
    agent.start()

    if not args.no_dashboard:
        # 대시보드는 같은 프로세스에서 별도 스레드로
        from dashboard.app import create_app
        import threading
        app = create_app(agent)
        threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=args.port,
                                   debug=False, use_reloader=False),
            daemon=True,
        ).start()
        print(f"[agent] dashboard at http://127.0.0.1:{args.port}")

    # 종료 시그널 핸들러
    stop_flag = {"v": False}

    def _shutdown(signum, frame):
        stop_flag["v"] = True

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        while not stop_flag["v"]:
            time.sleep(0.5)
    finally:
        agent.stop()


if __name__ == "__main__":
    main()
