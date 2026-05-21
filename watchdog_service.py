"""
RansomGuard Watchdog Service
----------------------------
Sidecar Windows service.  Its only job is to make sure the
RansomGuardAgent service is running and is actually responsive, and to
restart it if not.  Mutual: when the agent runs it asks the driver to
tamper-protect this watchdog process too, so killing the agent and the
watchdog both require either bug-checking the box (CRITICAL flag) or
calling the SCM (which the install scripts ACL away from non-admins).

What it checks every WATCHDOG_INTERVAL_SECS:

  1. RansomGuardAgent service current state via the SCM.
     If anything other than RUNNING or START_PENDING, ask the SCM
     to start it.
  2. (Optional, when enabled) the agent's /api/heartbeat dashboard
     endpoint.  A hung-but-alive agent — Python thread deadlock,
     listener wedge — won't be caught by (1) alone.  If the
     endpoint doesn't return 200 for three consecutive checks, stop
     the agent service so the SCM restarts it.

This service intentionally does NOT touch the driver.  All
quarantine / responder state lives in the agent.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

WATCHDOG_INTERVAL_SECS = 5
HEARTBEAT_MISS_THRESHOLD = 3

SERVICE_NAME         = "RansomGuardWatchdog"
SERVICE_DISPLAY_NAME = "RansomGuard EDR Watchdog"
SERVICE_DESCRIPTION  = ("Monitors the RansomGuard EDR agent and restarts "
                        "it on crash or hang.")

AGENT_SERVICE_NAME = "RansomGuardAgent"


try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:
    servicemanager = None  # type: ignore
    win32event = None      # type: ignore
    win32service = None    # type: ignore
    win32serviceutil = None  # type: ignore


def _query_state(name: str) -> int:
    """Return current SCM state for service ``name``, or 0 if missing."""
    try:
        status = win32serviceutil.QueryServiceStatus(name)
        # tuple: (svcType, currentState, ...)
        return int(status[1])
    except Exception:
        return 0


def _start_service(name: str) -> bool:
    try:
        win32serviceutil.StartService(name)
        return True
    except Exception as e:
        servicemanager.LogErrorMsg(f"watchdog: StartService({name}) failed: {e}")
        return False


def _stop_service(name: str) -> bool:
    try:
        win32serviceutil.StopService(name)
        return True
    except Exception:
        return False


def _heartbeat_ok(port: int, timeout: float = 2.0) -> bool:
    """Hit the agent's dashboard heartbeat endpoint.  Counts a non-200
    or any exception as a failure.  Bind is 127.0.0.1; no external
    network involved."""
    try:
        import urllib.request
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/api/heartbeat", timeout=timeout,
        ) as resp:
            return resp.status == 200
    except Exception:
        return False


def _load_watchdog_params() -> dict:
    defaults = {
        "DashboardPort":  5000,
        "HeartbeatCheck": 1,
    }
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}\Parameters",
            0, winreg.KEY_READ,
        )
        try:
            for name in defaults:
                try:
                    val, _ = winreg.QueryValueEx(key, name)
                    defaults[name] = val
                except FileNotFoundError:
                    pass
        finally:
            winreg.CloseKey(key)
    except FileNotFoundError:
        pass
    return defaults


if win32serviceutil is not None:

    class RansomGuardWatchdogService(win32serviceutil.ServiceFramework):
        _svc_name_         = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_  = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._stop_evt = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_evt)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                self._main()
            finally:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STOPPED,
                    (self._svc_name_, ""),
                )

        def _main(self) -> None:
            params = _load_watchdog_params()
            port = int(params["DashboardPort"])
            heartbeat = bool(int(params["HeartbeatCheck"]))
            misses = 0

            while True:
                # Wait either for the interval to elapse or for a stop.
                rc = win32event.WaitForSingleObject(
                    self._stop_evt, WATCHDOG_INTERVAL_SECS * 1000,
                )
                if rc == win32event.WAIT_OBJECT_0:
                    return

                state = _query_state(AGENT_SERVICE_NAME)
                # 4 = SERVICE_RUNNING, 2 = SERVICE_START_PENDING
                if state not in (2, 4):
                    servicemanager.LogWarningMsg(
                        f"watchdog: agent not running (state={state}); restarting"
                    )
                    _start_service(AGENT_SERVICE_NAME)
                    misses = 0
                    continue

                if heartbeat:
                    if _heartbeat_ok(port):
                        misses = 0
                    else:
                        misses += 1
                        if misses >= HEARTBEAT_MISS_THRESHOLD:
                            servicemanager.LogWarningMsg(
                                f"watchdog: agent heartbeat missed "
                                f"{misses} times; bouncing service"
                            )
                            _stop_service(AGENT_SERVICE_NAME)
                            # SCM recovery restarts it; if recovery is
                            # off, our next loop iteration will start it.
                            misses = 0


def main():
    if win32serviceutil is None:
        print("pywin32 is not installed; this entrypoint only runs on Windows.",
              file=sys.stderr)
        sys.exit(1)
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(RansomGuardWatchdogService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(RansomGuardWatchdogService)


if __name__ == "__main__":
    main()
