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
from allowlist import Allowlist, combine_trust
from config import Config
import integrations
import attack_map
from event_store import EventStore
from detectors.canary import CanaryDetector
from detectors.mass_io import MassIODetector
from detectors.ransom_note import RansomNoteDetector
from detectors.process_cmdline import ProcessCmdlineDetector
from detectors.process_watcher import ProcessWatcher
from detectors.minifilter_bridge import MinifilterBridge
from detectors.process_kernel import ProcessKernelDetector
from detectors.registry_kernel import RegistryKernelDetector
from responder import ProcessResponder, ResponderMode
from incident_report import IncidentReporter
import tamper


# 위협도 정렬용 순위 (관리자 패널의 PID별 max_severity 비교에 사용).
_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


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
                 watchdog_pid: int | None = None,
                 allowlist_path: str = "allowlist.json",
                 auth_token: str = "",
                 auth_required_for_reads: bool = False,
                 forwarder=None):
        self._start_time = time.time()
        self._watch_dirs = list(watch_dirs)
        # Dashboard auth token (empty → auth disabled; local-dev convenience).
        # Consulted by dashboard.app to gate mutating/admin endpoints.
        self.auth_token = auth_token or ""
        # When True, read-only GET endpoints also require the token (the
        # heartbeat probe always stays open for the watchdog).
        self.auth_required_for_reads = bool(auth_required_for_reads)
        # External SIEM/webhook forwarder (integrations.EventForwarder | None).
        # Fed from _on_signal; runs its own background worker so network I/O
        # never blocks the detection hot path.
        self.forwarder = forwarder
        # Operator allowlist: third-party apps the admin explicitly trusts.  It
        # composes into the score's trust gate (its signals are exempted) and is
        # consulted by the responder as an extra never-kill layer.
        self.allowlist = Allowlist(allowlist_path)
        # Gate the score on *who* produced each signal: trusted system actors
        # (Defender, servicing, WMI/perf rebuild, svchost) don't inflate it —
        # combined with the operator allowlist so admin-trusted apps don't either.
        trust = combine_trust(signal_actor_trusted, self.allowlist.signal_exempt)
        self.engine = ScoringEngine(is_trusted_actor=trust)
        self.store = EventStore(db_path)
        self.engine.subscribe(self._on_signal)

        # Tamper hardening that doesn't depend on the driver: critical
        # process flag + restrictive DACLs on the DB and reports dir.
        # Do this before opening anything else attackers could race on.
        self._db_path = db_path
        self._reports_dir = reports_dir
        self._tamper_protection = enable_tamper_protection
        if enable_tamper_protection:
            tamper.set_process_critical(True)
            tamper.harden_paths([db_path, reports_dir])

        self.canary    = CanaryDetector(self.engine, watch_dirs)
        self.mass_io   = MassIODetector(self.engine, watch_dirs)
        self.ransom_note = RansomNoteDetector(self.engine, watch_dirs)
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
            allowlist=self.allowlist,
        )
        self.responder.attach()

        self.detectors = [self.canary, self.mass_io, self.ransom_note,
                          self.proc, self.watcher]
        if self.minifilter is not None:
            self.detectors.append(self.minifilter)
            self.detectors.append(self.process_kernel)
            self.detectors.append(self.registry_kernel)

    def _on_signal(self, sig: Signal, score: int, level: Severity) -> None:
        # Always persist every signal — INFO-level telemetry (benign OS/app
        # housekeeping, score-0 correlation-gated deletes) is still valuable
        # forensic data.  Only the *console* is quieted: INFO lines are pure
        # noise on screen and never escalate, so skip printing them while
        # keeping the full record in the store.  Detection is unchanged.
        self.store.record(sig, score, level)
        if level == Severity.INFO:
            return
        # Forward to external SIEM/webhook (non-blocking; the forwarder applies
        # its own min-severity filter).  Wrapped so a misbehaving integration
        # can never break detection/printing.
        if self.forwarder is not None:
            try:
                self.forwarder.forward(sig.to_dict(), score, level.value)
            except Exception as e:
                print(f"[agent] forwarder error: {e}")
        bar = self._severity_bar(level)
        print(f"{bar} [{sig.detector}/{sig.name}] {sig.message}  "
              f"(weight={sig.weight}, total_score={score}, level={level.value})")

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
        if self.forwarder is not None:
            try:
                self.forwarder.start()
            except Exception as e:
                print(f"[agent] forwarder start failed: {e}")
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
        # 진행 중이던 통합(campaign) 보고서를 최종 확정하고 finalizer 종료.
        try:
            self.incident_reporter.close()
        except Exception as e:
            print(f"[agent] incident reporter close failed: {e}")
        if self.forwarder is not None:
            try:
                self.forwarder.stop()
            except Exception as e:
                print(f"[agent] forwarder stop failed: {e}")
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

    # ----------------------------------------------------- admin / operator API

    def set_responder_mode(self, mode: str) -> str:
        """Change the active responder mode (off|quarantine|kill).  Admin control."""
        new_mode = self.responder.set_mode(ResponderMode(mode))
        return new_mode.value

    def health(self) -> dict:
        """System-health snapshot for the administrator panel."""
        return {
            "version": "1.2",
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "started_at": self._start_time,
            "responder_mode": self.responder.mode.value,
            "minifilter_enabled": self.minifilter is not None,
            "minifilter_connected": (
                self.minifilter.is_connected if self.minifilter else False
            ),
            "tamper_protection": self._tamper_protection,
            "watch_dirs": [str(d) for d in self._watch_dirs],
            "detectors": [getattr(d, "name", str(d)) for d in self.detectors],
            "detector_count": len(self.detectors),
            "allowlist_count": len(self.allowlist.entries()),
            "current_score": self.engine.current_score(),
            "current_level": self.engine.current_level().value,
            "auth_enabled": bool(self.auth_token),
            "integrations": (self.forwarder.stats()
                             if self.forwarder is not None
                             else {"enabled": False}),
        }

    def threat_breakdown(self, limit: int = 200) -> dict:
        """Per-PID contribution to the live threat score, with ATT&CK tags.

        The consumer view shows one aggregate score; an administrator needs to
        know *which* processes are driving it and *what techniques* they're
        exhibiting, so they can triage (kill the real culprit, allowlist a false
        positive).  We reproduce the scoring engine's correlation gate so the
        per-PID numbers reconcile with the global score.
        """
        from scoring import ENCRYPTION_SIGNAL_NAMES, CORRELATION_GATED_NAMES
        sigs = self.engine.recent_signals(limit=limit)

        def pid_of(s):
            meta = s.metadata or {}
            for k in ("pid", "ProcessId", "process_id", "child_pid"):
                v = meta.get(k)
                if isinstance(v, int) and v > 0:
                    return v
            return None

        # Reproduce the score's enc-PID correlation set (trusted actors excluded).
        enc_pids = set()
        for s in sigs:
            if ScoringEngine._trusted(s):
                continue
            if s.name in ENCRYPTION_SIGNAL_NAMES:
                p = pid_of(s)
                if p is not None:
                    enc_pids.add(p)

        buckets: dict = {}
        for s in sigs:
            trusted = ScoringEngine._trusted(s)
            contributes = s.weight
            if trusted:
                contributes = 0
            elif s.name in CORRELATION_GATED_NAMES and pid_of(s) not in enc_pids:
                contributes = 0
            pid = pid_of(s)
            key = pid if pid is not None else 0
            b = buckets.setdefault(key, {
                "pid": pid, "score": 0, "signals": [], "techniques": {},
                "process": "", "max_severity": "INFO", "trusted": trusted,
            })
            b["score"] += contributes
            if not b["process"]:
                b["process"] = (s.metadata or {}).get("process") or ""
            for t in attack_map.techniques_for(s.name):
                b["techniques"][t.tid] = t.to_dict()
            b["signals"].append({
                "name": s.name, "detector": s.detector, "weight": s.weight,
                "severity": s.severity.value, "contributes": contributes,
                "message": s.message, "timestamp": s.timestamp,
                "attack": attack_map.technique_dicts_for(s.name),
            })
            if _SEV_ORDER.get(s.severity.value, 0) > _SEV_ORDER.get(b["max_severity"], 0):
                b["max_severity"] = s.severity.value

        rows = []
        for b in buckets.values():
            b["techniques"] = list(b["techniques"].values())
            rows.append(b)
        rows.sort(key=lambda r: r["score"], reverse=True)
        return {
            "total_score": self.engine.current_score(),
            "level": self.engine.current_level().value,
            "threats": rows,
        }


def parse_args():
    p = argparse.ArgumentParser(description="RansomGuard EDR agent")
    p.add_argument(
        "--config", default=None,
        help="Path to a ransomguard.toml/.json policy file. If omitted, "
             "auto-detects ransomguard.toml/.json in the working directory. "
             "CLI flags override file values; file values override built-in "
             "defaults. Secrets (auth token, webhook url) can be injected via "
             "RANSOMGUARD_AUTH_TOKEN / RANSOMGUARD_WEBHOOK_URL / "
             "RANSOMGUARD_SYSLOG_HOST env vars (env wins over file).",
    )
    p.add_argument(
        "--watch", action="append", default=None,
        help="Directory to watch (repeatable). Defaults to ./test_watch_dir",
    )
    p.add_argument("--db", default=None, help="SQLite database path")
    p.add_argument(
        "--no-dashboard", action="store_true",
        help="Run agent only, without the web dashboard",
    )
    p.add_argument(
        "--port", type=int, default=None,
        help="Dashboard port (default 5000)",
    )
    p.add_argument(
        "--auth-token", default=None,
        help="Dashboard API token. Prefer the RANSOMGUARD_AUTH_TOKEN env var "
             "or the config file so the secret isn't visible in the process "
             "list. When set, mutating/admin endpoints require this token.",
    )
    p.add_argument(
        "--mode", default=None,
        choices=[m.value for m in ResponderMode],
        help="Responder mode: off | quarantine | kill (default kill)",
    )
    p.add_argument(
        "--no-minifilter", action="store_true",
        help="Disable the kernel minifilter bridge "
             "(falls back to user-mode-only detection)",
    )
    p.add_argument(
        "--reports-dir", default=None,
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
    p.add_argument(
        "--allowlist", default=None,
        help="JSON file of operator-trusted apps (name / path-prefix). "
             "Allowlisted processes are exempt from scoring and never killed.",
    )
    return p.parse_args()


def main():
    force_utf8()
    args = parse_args()

    # Policy precedence: CLI flag > config file > built-in default.  The config
    # file (auto-detected or via --config) lets a fleet ship one policy file;
    # CLI flags still win for one-off overrides on a single host.
    cfg = Config.load(args.config)

    watch = args.watch or cfg.watch_dirs or [str(Path.cwd() / "test_watch_dir")]
    for d in watch:
        Path(d).mkdir(parents=True, exist_ok=True)

    db_path = args.db or cfg.db_path
    reports_dir = args.reports_dir or cfg.reports_dir
    allowlist_path = args.allowlist or cfg.allowlist_path
    mode = args.mode or cfg.responder_mode
    port = args.port if args.port is not None else cfg.dashboard.port
    auth_token = args.auth_token or cfg.dashboard.auth_token
    # Boolean policies start from the config and a CLI "--no-*" flag turns off.
    enable_minifilter = cfg.enable_minifilter and not args.no_minifilter
    enable_tamper = cfg.enable_tamper_protection and not args.no_tamper_protection
    notify_user = cfg.notify_user and not args.no_notify

    forwarder = integrations.from_config(cfg)

    agent = Agent(
        watch,
        db_path=db_path,
        responder_mode=ResponderMode(mode),
        enable_minifilter=enable_minifilter,
        reports_dir=reports_dir,
        notify_user=notify_user,
        enable_tamper_protection=enable_tamper,
        watchdog_pid=args.watchdog_pid,
        allowlist_path=allowlist_path,
        auth_token=auth_token,
        auth_required_for_reads=cfg.dashboard.auth_required_for_reads,
        forwarder=forwarder,
    )
    if cfg.source_path:
        print(f"[agent] loaded config from {cfg.source_path}")
    if auth_token:
        print("[agent] dashboard authentication ENABLED (token required)")
    else:
        print("[agent] dashboard authentication DISABLED "
              "(set RANSOMGUARD_AUTH_TOKEN for production)")
    agent.start()

    if not args.no_dashboard:
        from dashboard.app import create_app
        import threading
        app = create_app(agent)
        threading.Thread(
            target=lambda: app.run(host=cfg.dashboard.host, port=port,
                                   debug=False, use_reloader=False),
            daemon=True,
        ).start()
        print(f"[agent] dashboard at http://{cfg.dashboard.host}:{port}")

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
