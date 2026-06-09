"""
Process Kernel Detector
-----------------------
Subscribes to the kernel minifilter bridge's ProcessStart / ProcessExit
events (sourced from ``PsSetCreateProcessNotifyRoutineEx``) and applies
the same command-line rule set as ProcessCmdlineDetector — but without
WMI.

Why this exists (vs. process_cmdline.py):
  * WMI ExecNotificationQuery has 50–500 ms latency and is lossy under
    load; the kernel callback fires synchronously at process create
    time, before the new process runs a single instruction.
  * The command line comes from kernel memory, not from
    ``Win32_Process.CommandLine`` — so PEB tampering does not hide it.
  * Short-lived processes that exit faster than WMI's polling window
    used to be invisible; they aren't anymore.

This detector does not own a thread.  It registers with the bridge and
reacts on the bridge's receive thread, so it must keep its handler
fast.  The Signal it emits goes through the normal scoring engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Detector
from .process_cmdline import evaluate_cmdline
from scoring import Signal, Severity

if TYPE_CHECKING:
    from .minifilter_bridge import MinifilterBridge, RG_EVENT


class ProcessKernelDetector(Detector):
    """Replaces (or complements) ProcessCmdlineDetector when the
    minifilter is loaded.  If both are active the engine will see the
    same cmdline rule fire twice — once per source — which is harmless
    because scoring is keyed on the signal `name` plus weight."""

    name = "process_kernel"

    def __init__(self, engine, bridge: "MinifilterBridge"):
        super().__init__(engine)
        self._bridge = bridge
        bridge.subscribe_process(self._on_process_event)

    def run(self) -> None:
        # No polling loop — we are purely callback-driven.  Sit here
        # until asked to stop so the base class' thread join works.
        self._stop_event.wait()

    # -------------------------------------------------------------- handlers

    def _on_process_event(self, evt: "RG_EVENT") -> None:
        kind = int(evt.Kind)
        pid = int(evt.ProcessId)
        if pid == 0:
            return

        # ProcessExit: emit a low-weight informational signal so the
        # dashboard reflects process lifecycle.  Nothing to score on.
        if kind == 6:  # EVENT_PROCESS_EXIT
            return

        # ProcessStart
        image = evt.Path[:max(0, int(evt.PathLength) - 1)] if evt.PathLength else ""
        cmdline = evt.Extra[:max(0, int(evt.ExtraLength) - 1)] if evt.ExtraLength else ""
        ppid = int(evt.ParentProcessId)

        # process name = last path component
        proc_name = image.rsplit("\\", 1)[-1] if image else ""

        # Run the shared rule set.
        for sig in evaluate_cmdline(self.name, proc_name, cmdline, pid, ppid):
            self.emit(sig)

        # Emit a per-create informational signal so downstream consumers
        # (incident report, dashboard) can correlate.  Tiny weight.
        self.emit(Signal(
            detector=self.name,
            name="process_create",
            weight=1,
            severity=Severity.INFO,
            message=f"pid={pid} ppid={ppid} {proc_name}",
            metadata={
                "pid": pid,
                "ppid": ppid,
                "image": image,
                "cmdline": cmdline[:512],
            },
        ))
