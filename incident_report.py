"""
Incident Reporter
-----------------
Hooks the ``ProcessResponder``'s ``on_action`` callback.  Every time the
responder actually does something to a process (quarantine or terminate),
we

  1. write a self-contained markdown incident report under ``reports/``
     so the operator has an audit trail they can hand to IR / legal /
     ticket the post-mortem against, and
  2. push a desktop notification so the user knows immediately, even
     when the dashboard isn't in focus.

No-ops (self-pid refusal, never-kill list hits, OFF-mode would-be kills)
are intentionally skipped — they didn't actually do anything to the
target, so there's nothing to report.

Notifications are best-effort and run in a background thread so a
blocking native dialog can't stall the responder.
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Deque, Dict, List, Optional

from scoring import ScoringEngine, Signal

# Native desktop notifications are *best effort* and purely advisory: the
# authoritative record is the markdown report + the dashboard.  When an
# incident storm hits (e.g. ransomware fanning out, or a browser spawning
# dozens of child processes the moment the operator opens the dashboard),
# firing one native popup per incident floods the screen and — with the
# blocking fallbacks — can wedge the desktop.  So we cap how many native
# popups we raise per rolling window; anything beyond the cap is still
# written to disk and surfaced in the dashboard, just not popped natively.
_NOTIFY_MAX_PER_WINDOW = 3
_NOTIFY_WINDOW_SECS = 30.0

# Reports are deduped per (pid, terminated, quarantined) state, but only for
# a rolling window — not forever.  A time window (rather than a permanent set)
# matters for live operation: it bounds memory on a long-running agent, lets a
# *persistent* attacker re-alert if it's still tripping after the window, and
# avoids permanently muzzling a reused PID or one the operator manually
# released and which later re-offends.
_REPORT_DEDUP_SECS = 60.0
_REPORT_DEDUP_MAX = 2048  # hard cap on tracked states; prune when exceeded


@dataclass
class IncidentRecord:
    timestamp: float
    pid: int
    process_name: str
    reason: str
    terminated: bool
    quarantined: bool
    filename: str
    path: str

    def to_dict(self) -> dict:
        return asdict(self)


class IncidentReporter:
    def __init__(self,
                 engine: ScoringEngine,
                 *,
                 reports_dir: str = "reports",
                 notify: bool = True):
        self.engine = engine
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.notify = notify
        self._lock = threading.Lock()
        self._records: List[IncidentRecord] = []
        # (pid, terminated, quarantined) -> last time we reported that state.
        # A pid that keeps tripping the same detector (very common with the
        # kernel minifilter on — it re-flags the encrypting pid on every file
        # op) is deduped within a rolling window so it doesn't spawn a fresh
        # report + popup each time.  A genuine escalation (quarantine → later
        # kill) is a different tuple and is still reported immediately.
        self._reported_states: Dict[tuple, float] = {}
        # Rolling timestamps of native popups we've raised, for rate limiting.
        self._notify_window: Deque[float] = deque()
        self._notify_lock = threading.Lock()

    # -------------------------------------------------------------- callback

    def on_action(self, action) -> None:
        """Wired into ``ProcessResponder(on_action=...)``."""
        # We only report when the responder actually did something to the
        # target.  Refusals, OFF-mode passes, and never-kill hits leave
        # both flags False and carry an error string explaining why.
        if not (action.terminated or action.quarantined):
            return

        # Suppress duplicate reports for a pid we've already reported in this
        # exact state within the dedup window.  Repeated identical signals for
        # the same pid (the norm under the kernel minifilter) otherwise pile up
        # reports + popups even though nothing new happened to the process.
        state = (action.pid, bool(action.terminated), bool(action.quarantined))
        now = time.time()
        with self._lock:
            last = self._reported_states.get(state)
            if last is not None and (now - last) < _REPORT_DEDUP_SECS:
                return
            self._reported_states[state] = now
            # Bound memory: when the map grows too large, drop entries whose
            # window has fully elapsed (they can only ever re-report anyway).
            if len(self._reported_states) > _REPORT_DEDUP_MAX:
                cutoff = now - _REPORT_DEDUP_SECS
                self._reported_states = {
                    k: v for k, v in self._reported_states.items() if v >= cutoff
                }

        content = self._build_markdown(action)
        path = self._write_file(content, action)

        record = IncidentRecord(
            timestamp=action.timestamp,
            pid=action.pid,
            process_name=action.process_name or "unknown",
            reason=action.reason,
            terminated=bool(action.terminated),
            quarantined=bool(action.quarantined),
            filename=path.name,
            path=str(path),
        )
        with self._lock:
            self._records.append(record)
            if len(self._records) > 500:
                self._records = self._records[-500:]

        print(f"[reporter] incident report written: {path}")

        if self.notify and self._notify_rate_ok():
            t = threading.Thread(
                target=self._notify_user,
                args=(action, path),
                daemon=True,
            )
            t.start()

    # ------------------------------------------------------------------ API

    def recent(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in reversed(self._records[-limit:])]

    def read_report(self, filename: str) -> Optional[str]:
        # Defence-in-depth: only allow plain filenames inside reports_dir.
        if not filename or "/" in filename or "\\" in filename or ".." in filename:
            return None
        p = self.reports_dir / filename
        try:
            p_resolved = p.resolve()
            if not str(p_resolved).startswith(str(self.reports_dir.resolve())):
                return None
            if not p_resolved.is_file():
                return None
            return p_resolved.read_text(encoding="utf-8")
        except OSError:
            return None

    # ------------------------------------------------------- markdown body

    def _build_markdown(self, action) -> str:
        ts_local = time.strftime(
            "%Y-%m-%d %H:%M:%S %Z", time.localtime(action.timestamp)
        )
        score = self.engine.current_score()
        level = self.engine.current_level().value
        recent = self.engine.recent_signals(limit=200)

        pid_signals = [s for s in recent if self._signal_pid(s) == action.pid]

        if action.terminated:
            status = "TERMINATED"
        elif action.quarantined:
            status = "QUARANTINED"
        else:
            status = "NO-OP"

        proc_name = action.process_name or "unknown"
        cmd = action.cmdline or "(unavailable)"

        lines: List[str] = []
        lines.append(f"# Incident Report — PID {action.pid} ({proc_name})")
        lines.append("")
        lines.append(f"- **Generated:** {ts_local}")
        lines.append(f"- **Reporter:** RansomGuard EDR")
        lines.append(f"- **Action:** {status}")
        lines.append(f"- **Responder mode:** `{action.mode}`")
        lines.append(f"- **Host:** `{platform.node()}` ({platform.system()} {platform.release()})")
        lines.append("")

        lines.append("## Process")
        lines.append("")
        lines.append(f"- **PID:** `{action.pid}`")
        lines.append(f"- **Name:** `{proc_name}`")
        lines.append(f"- **Trigger reason:** `{action.reason}`")
        lines.append("- **Command line:**")
        lines.append("")
        lines.append("  ```")
        lines.append(f"  {cmd}")
        lines.append("  ```")
        lines.append("")

        lines.append("## Response")
        lines.append("")
        lines.append(f"- **Quarantined (kernel block):** {'yes' if action.quarantined else 'no'}")
        lines.append(f"- **Terminated:** {'yes' if action.terminated else 'no'}")
        lines.append(f"- **Error:** {action.error or 'none'}")
        lines.append("")

        lines.append("## Threat Context")
        lines.append("")
        lines.append(f"- **Cumulative score (120s window):** {score}")
        lines.append(f"- **Threat level:** **{level}**")
        lines.append("")

        if pid_signals:
            lines.append(f"## Signals attributed to PID {action.pid}")
            lines.append("")
            lines.extend(self._signal_table(pid_signals[-30:]))
            lines.append("")

        if recent:
            lines.append("## Recent signals (active window)")
            lines.append("")
            lines.extend(self._signal_table(recent[-20:]))
            lines.append("")

        lines.append("## Raw action record")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(action.to_dict(), indent=2, default=str))
        lines.append("```")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _signal_table(signals: List[Signal]) -> List[str]:
        out = [
            "| time | detector | signal | severity | weight | message |",
            "|------|----------|--------|----------|--------|---------|",
        ]
        for s in signals:
            t = time.strftime("%H:%M:%S", time.localtime(s.timestamp))
            msg = (s.message or "").replace("|", "\\|").replace("\n", " ")
            if len(msg) > 140:
                msg = msg[:137] + "..."
            out.append(
                f"| {t} | {s.detector} | {s.name} | {s.severity.value} "
                f"| {s.weight} | {msg} |"
            )
        return out

    @staticmethod
    def _signal_pid(sig: Signal) -> Optional[int]:
        meta = sig.metadata or {}
        for key in ("pid", "ProcessId", "child_pid", "process_id"):
            val = meta.get(key)
            if isinstance(val, int) and val > 0:
                return val
        return None

    # ------------------------------------------------------- file output

    def _write_file(self, content: str, action) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(action.timestamp))
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_",
                           action.process_name or "unknown")
        fname = f"incident_{ts}_pid{action.pid}_{safe_name}.md"
        path = self.reports_dir / fname
        path.write_text(content, encoding="utf-8")
        return path

    # ---------------------------------------------- desktop notifications

    def _notify_rate_ok(self) -> bool:
        """True if we're under the native-popup budget for the window.

        Prevents an incident storm from flooding the desktop with popups
        (and, with blocking fallbacks, wedging it).  Suppressed popups are
        still recorded on disk and shown in the dashboard.
        """
        now = time.time()
        with self._notify_lock:
            cutoff = now - _NOTIFY_WINDOW_SECS
            while self._notify_window and self._notify_window[0] < cutoff:
                self._notify_window.popleft()
            if len(self._notify_window) >= _NOTIFY_MAX_PER_WINDOW:
                if len(self._notify_window) == _NOTIFY_MAX_PER_WINDOW:
                    # Log the throttle exactly once per saturated window.
                    print("[reporter] notification rate limit hit; "
                          "suppressing native popups (reports still written)")
                    self._notify_window.append(now)  # mark as logged
                return False
            self._notify_window.append(now)
            return True

    def _notify_user(self, action, path: Path) -> None:
        verb = "Killed" if action.terminated else "Quarantined"
        title = (f"RansomGuard: {verb} {action.process_name or '?'} "
                 f"(PID {action.pid})")
        body = f"Reason: {action.reason}\nReport: {path.name}"
        sysname = platform.system()
        try:
            if sysname == "Windows":
                self._notify_windows(title, body)
            elif sysname == "Linux":
                self._notify_linux(title, body)
            elif sysname == "Darwin":
                self._notify_macos(title, body)
            else:
                # Console bell as last-resort signal.
                print(f"\a[NOTIFY] {title}\n         {body}")
        except Exception as e:
            print(f"[reporter] notification failed: {e}")

    def _notify_linux(self, title: str, body: str) -> None:
        if shutil.which("notify-send"):
            subprocess.run(
                ["notify-send", "-u", "critical",
                 "-i", "dialog-warning", title, body],
                timeout=5, check=False,
            )
            return
        print(f"\a[NOTIFY] {title}\n         {body}")

    def _notify_macos(self, title: str, body: str) -> None:
        if shutil.which("osascript"):
            # Escape embedded double quotes for AppleScript.
            t = title.replace('"', '\\"')
            b = body.replace('"', '\\"').replace("\n", " — ")
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{b}" with title "{t}"'],
                timeout=5, check=False,
            )
            return
        print(f"\a[NOTIFY] {title}\n         {body}")

    def _notify_windows(self, title: str, body: str) -> None:
        # Preferred: win10toast (pure-python, uses pywin32 under the hood).
        try:
            from win10toast import ToastNotifier  # type: ignore
            ToastNotifier().show_toast(title, body, duration=8, threaded=True)
            return
        except Exception:
            pass
        # Fallback: PowerShell BurntToast module if the operator has it.
        try:
            ps = (
                "$ErrorActionPreference='Stop';"
                "Import-Module BurntToast;"
                f"New-BurntToastNotification -Text {self._psq(title)},"
                f"{self._psq(body)}"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                timeout=6, capture_output=True,
            )
            if r.returncode == 0:
                return
        except Exception:
            pass
        # Last resort: a non-blocking console line + bell.  We deliberately
        # do NOT pop a modal MessageBox here: a system-modal dialog steals
        # global input focus, and one per incident stacks into an
        # unclosable wall that wedges the desktop during an incident storm.
        # The report file and the dashboard remain the durable record.
        print(f"\a[NOTIFY] {title}\n         {body}")

    @staticmethod
    def _psq(s: str) -> str:
        """PowerShell single-quoted literal, with quotes escaped."""
        return "'" + s.replace("'", "''") + "'"
