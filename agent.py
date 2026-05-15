"""
Ransomware Detection Agent
--------------------------
모든 탐지기를 조립하고 백그라운드로 실행한다.
대시보드(Flask)와 같은 프로세스에서 실행될 수도 있고
독립 실행 가능하다.
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
from detectors.process_cmdline import ProcessCmdlineDetector


class Agent:
    def __init__(self, watch_dirs, db_path: str = "detector.db"):
        self.engine = ScoringEngine()
        self.store = EventStore(db_path)
        self.engine.subscribe(self._on_signal)

        self.canary = CanaryDetector(self.engine, watch_dirs)
        self.mass_io = MassIODetector(self.engine, watch_dirs)
        self.proc = ProcessCmdlineDetector(self.engine)

        self.detectors = [self.canary, self.mass_io, self.proc]

    def _on_signal(self, sig: Signal, score: int, level: Severity) -> None:
        # 콘솔 알림
        bar = self._severity_bar(level)
        print(f"{bar} [{sig.detector}/{sig.name}] {sig.message}  "
              f"(weight={sig.weight}, total_score={score}, level={level.value})")
        # 영속화
        self.store.record(sig, score, level)

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
        # canary 먼저 배치
        self.canary.deploy()
        for d in self.detectors:
            d.start()
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
