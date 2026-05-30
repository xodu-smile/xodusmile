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

from console import force_utf8
from scoring import ScoringEngine, Signal, Severity
from actor_trust import signal_actor_trusted
from event_store import EventStore
from detectors.canary import CanaryDetector
from detectors.mass_io import MassIODetector
from detectors.process_cmdline import ProcessCmdlineDetector
from detectors.process_watcher import ProcessWatcher
from detectors.minifilter_bridge import MinifilterBridge
from detectors.process_kernel import ProcessKernelDetector
from detectors.registry_kernel import RegistryKernelDetector
from responder import ProcessResponder, ResponderMode
from incident_report import IncidentReporter
import tamper


class Agent:
    def __init__(self,
                 watch_dirs,
                 *,
                 db_path: str = "detector.db",
                 responder_mode: ResponderMode = ResponderMode.KILL,
                 enable_minifilter: bool = True,
                 reports_dir: str = "reports",
                 notify_user: bool = True,
                 enable_tamper_protection: bool = True,
                 watchdog_pid: int | None = None):
        # Gate the score on *who* produced each signal: trusted system actors
        # (Defender, servicing, WMI/perf rebuild, svchost) don't inflate it.
        self.engine = ScoringEngine(is_trusted_actor=signal_actor_trusted)
        self.store = EventStore(db_path)
        self.engine.subscribe(self._on_signal)

        # Tamper hardening that doesn't depend on the driver: critical
        # process flag + restrictive DACLs on the DB and reports dir.
        # Do this before opening anything else attackers could race on.
        self._db_path = db_path
        self._reports_dir = reports_dir
        if enable_tamper_protection:
            tamper.set_process_critical(True)
            tamper.harden_paths([db_path, reports_dir])

        self.canary    = CanaryDetector(self.engine, watch_dirs)
        self.mass_io   = MassIODetector(self.engine, watch_dirs)
        self.proc      = ProcessCmdlineDetector(self.engine)
        self.watcher   = ProcessWatcher(self.engine)
        self.minifilter = MinifilterBridge(self.engine) if enable_minifilter else None

        # Kernel-sourced detectors are bridge-driven; only useful when
        # the minifilter is enabled.  They subscribe in their __init__
        # so it's safe to construct even if the driver isn't loaded yet.
        self.process_kernel: ProcessKernelDetector | None = None
        self.registry_kernel: RegistryKernelDetector | None = None
        if self.minifilter is not None:
            self.process_kernel = ProcessKernelDetector(self.engine, self.minifilter)
            self.registry_kernel = RegistryKernelDetector(self.engine, self.minifilter)
            # Tell the kernel to tamper-protect both us and the watchdog
            # (if we know about it).  The bridge re-sends these every
            # time it connects, so a driver reload doesn't lose them.
            if watchdog_pid:
                self.minifilter.add_protected_pid(watchdog_pid)

        self.incident_reporter = IncidentReporter(
            self.engine,
            reports_dir=reports_dir,
            notify=notify_user,
        )

        # The responder talks to the kernel through the bridge, so it
        # needs a reference even when minifilter mode is off (in which
        # case it falls back to user-mode-only termination).
        self.responder = ProcessResponder(
            self.engine,
            mode=responder_mode,
            minifilter=self.minifilter,
            on_action=self.incident_reporter.on_action,
        )
        self.responder.attach()

        self.detectors = [self.canary, self.mass_io, self.proc, self.watcher]
        if self.minifilter is not None:
            self.detectors.append(self.minifilter)
            self.detectors.append(self.process_kernel)
            self.detectors.append(self.registry_kernel)

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
        # Drop the critical-process flag FIRST.  If anything below raises
        # or hangs, the process must still be able to exit without a
        # bugcheck (CRITICAL_PROCESS_DIED -> reboot).  Idempotent.
        try:
            tamper.set_process_critical(False)
        except Exception:
            pass
        # Clean shutdown: ask the kernel driver to drop every quarantined
        # PID so they aren't stuck on next agent start.  An unclean exit
        # leaves the list sticky on purpose (anti-tamper default).
        if self.minifilter is not None and self.minifilter.is_connected:
            try:
                self.minifilter.flush_quarantine()
            except Exception:
                pass
        for d in self.detectors:
            # One detector failing to stop must not skip the rest.
            try:
                d.stop()
            except Exception as e:
                print(f"[agent] detector {getattr(d, 'name', d)} stop failed: {e}")
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
            "incidents": self.incident_reporter.recent(limit=20),
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
    p.add_argument(
        "--reports-dir", default="reports",
        help="Directory for markdown incident reports (default ./reports)",
    )
    p.add_argument(
        "--no-notify", action="store_true",
        help="Suppress desktop notifications when a process is killed",
    )
    p.add_argument(
        "--no-tamper-protection", action="store_true",
        help="Disable RtlSetProcessIsCritical + DACL hardening "
             "(useful during dev so you can taskkill the agent)",
    )
    p.add_argument(
        "--watchdog-pid", type=int, default=None,
        help="PID of the companion watchdog process; will be kernel-"
             "tamper-protected alongside the agent.",
    )
    return p.parse_args()


def main():
    force_utf8()
    args = parse_args()
    watch = args.watch or [str(Path.cwd() / "test_watch_dir")]
    for d in watch:
        Path(d).mkdir(parents=True, exist_ok=True)

    agent = Agent(
        watch,
        db_path=args.db,
        responder_mode=ResponderMode(args.mode),
        enable_minifilter=not args.no_minifilter,
        reports_dir=args.reports_dir,
        notify_user=not args.no_notify,
        enable_tamper_protection=not args.no_tamper_protection,
        watchdog_pid=args.watchdog_pid,
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
