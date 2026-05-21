"""
Ransomware Detection Agent
--------------------------
Assembles every detector, the kernel minifilter bridge, and the
process-kill responder, and runs them in the background.  Can host its
own Flask dashboard in-process or run headless.
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
from detectors.process_watcher import ProcessWatcher
from detectors.minifilter_bridge import MinifilterBridge
from responder import ProcessResponder, ResponderMode


class Agent:
    def __init__(self,
                 watch_dirs,
                 *,
                 db_path: str = "detector.db",
                 responder_mode: ResponderMode = ResponderMode.KILL,
                 enable_minifilter: bool = True):
        self.engine = ScoringEngine()
        self.store = EventStore(db_path)
        self.engine.subscribe(self._on_signal)

        self.canary    = CanaryDetector(self.engine, watch_dirs)
        self.mass_io   = MassIODetector(self.engine, watch_dirs)
        self.proc      = ProcessCmdlineDetector(self.engine)
        self.watcher   = ProcessWatcher(self.engine)
        self.minifilter = MinifilterBridge(self.engine) if enable_minifilter else None

        # The responder talks to the kernel through the bridge, so it
        # needs a reference even when minifilter mode is off (in which
        # case it falls back to user-mode-only termination).
        self.responder = ProcessResponder(
            self.engine,
            mode=responder_mode,
            minifilter=self.minifilter,
        )
        self.responder.attach()

        self.detectors = [self.canary, self.mass_io, self.proc, self.watcher]
        if self.minifilter is not None:
            self.detectors.append(self.minifilter)

    def _on_signal(self, sig: Signal, score: int, level: Severity) -> None:
        bar = self._severity_bar(level)
        print(f"{bar} [{sig.detector}/{sig.name}] {sig.message}  "
              f"(weight={sig.weight}, total_score={score}, level={level.value})")
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
        print("  RansomGuard EDR — agent starting")
        print("=" * 60)
        self.canary.deploy()
        for d in self.detectors:
            d.start()
        print(f"[agent] {len(self.detectors)} detectors started "
              f"(responder={self.responder.mode.value}, "
              f"minifilter={'on' if self.minifilter else 'off'})")

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
            "responder": {
                "mode": self.responder.mode.value,
                "minifilter_connected": (
                    self.minifilter.is_connected if self.minifilter else False
                ),
                "recent_actions": self.responder.actions(limit=20),
            },
        }

    def processes(self, limit: int = 50) -> list:
        return self.watcher.snapshot(limit=limit)


def parse_args():
    p = argparse.ArgumentParser(description="RansomGuard EDR agent")
    p.add_argument(
        "--watch", action="append", default=None,
        help="Directory to watch (repeatable). Defaults to ./test_watch_dir",
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
    p.add_argument(
        "--mode", default="kill",
        choices=[m.value for m in ResponderMode],
        help="Responder mode: off | quarantine | kill (default kill)",
    )
    p.add_argument(
        "--no-minifilter", action="store_true",
        help="Disable the kernel minifilter bridge "
             "(falls back to user-mode-only detection)",
    )
    return p.parse_args()


def main():
    args = parse_args()
    watch = args.watch or [str(Path.cwd() / "test_watch_dir")]
    for d in watch:
        Path(d).mkdir(parents=True, exist_ok=True)

    agent = Agent(
        watch,
        db_path=args.db,
        responder_mode=ResponderMode(args.mode),
        enable_minifilter=not args.no_minifilter,
    )
    agent.start()

    if not args.no_dashboard:
        from dashboard.app import create_app
        import threading
        app = create_app(agent)
        threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=args.port,
                                   debug=False, use_reloader=False),
            daemon=True,
        ).start()
        print(f"[agent] dashboard at http://127.0.0.1:{args.port}")

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
