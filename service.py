"""
RansomGuard Agent Windows Service
---------------------------------
Hosts the Agent inside a Windows service so it survives logoff,
restarts on crash (via SCM recovery options), and runs under
LocalSystem with SeDebugPrivilege.

Install / start (elevated PowerShell):

    python service.py install
    python service.py start

Or use scripts\\install_services.ps1 which also configures recovery
and a sidecar watchdog.

The service writes its own config to HKLM\\SYSTEM\\CurrentControlSet\\
Services\\RansomGuardAgent\\Parameters so the SCM-spawned process
knows which directories to watch, where the DB lives, etc.  This
isolates service config from the dev CLI flags in agent.py.

This file is a no-op on non-Windows (pywin32 imports guard everything).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from console import force_utf8

# SCM 이 우리 main() 을 거치지 않고 서비스 클래스를 직접 호스팅할 수 있으므로
# 모듈 로드 시점에 한 번 stdout/stderr 를 UTF-8 로 맞춰 둔다. Agent.start()
# 의 비ASCII 출력이 cp949 Session 0 에서 죽는 것을 막는다.
force_utf8()

# Service constants
SERVICE_NAME         = "RansomGuardAgent"
SERVICE_DISPLAY_NAME = "RansomGuard EDR Agent"
SERVICE_DESCRIPTION  = ("RansomGuard endpoint detection and response agent. "
                        "Streams kernel minifilter events, scores them, and "
                        "responds to ransomware-like behaviour.")

WATCHDOG_SERVICE_NAME = "RansomGuardWatchdog"


def _load_params_from_registry() -> dict:
    """Read service parameters from HKLM\\...\\Services\\<svc>\\Parameters.

    Falls back to sensible defaults when keys are missing so the service
    can boot even before the install script has populated them.
    """
    defaults = {
        "WatchDirs":   r"C:\Users",
        "DbPath":      r"C:\ProgramData\RansomGuard\detector.db",
        "ReportsDir":  r"C:\ProgramData\RansomGuard\reports",
        "Mode":        "kill",
        "Dashboard":   1,
        "Port":        5000,
        "WatchdogPid": 0,
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
    except Exception as e:
        print(f"[service] registry read failed: {e}", file=sys.stderr)

    # Normalize.
    if isinstance(defaults["WatchDirs"], str):
        defaults["WatchDirs"] = [s.strip() for s in defaults["WatchDirs"].split(";") if s.strip()]
    return defaults


def _find_watchdog_pid() -> int:
    """Look up the RansomGuardWatchdog service PID so we can ask the
    driver to tamper-protect it too.  Returns 0 if not running."""
    try:
        import win32serviceutil
        import win32service
        status = win32serviceutil.QueryServiceStatus(WATCHDOG_SERVICE_NAME)
        # status is (serviceType, currentState, controlsAccepted,
        #            win32ExitCode, svcExitCode, checkPoint, waitHint)
        # PID is not in QueryServiceStatus; need EnumServicesStatusEx.
        # Use the SCM directly:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            svc = win32service.OpenService(scm, WATCHDOG_SERVICE_NAME,
                                           win32service.SERVICE_QUERY_STATUS)
            try:
                info = win32service.QueryServiceStatusEx(svc)
                return int(info.get("ProcessId", 0))
            finally:
                win32service.CloseServiceHandle(svc)
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception:
        return 0


# ----------------------------------------------------------------------------
# Service class — only defined when pywin32 is available.
# ----------------------------------------------------------------------------

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


if win32serviceutil is not None:

    class RansomGuardAgentService(win32serviceutil.ServiceFramework):
        _svc_name_         = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_  = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._stop_evt = win32event.CreateEvent(None, 0, 0, None)
            self._agent = None
            self._dashboard_thread: threading.Thread | None = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            # Drop the critical-process flag the instant a stop is
            # requested.  If the rest of shutdown hangs, raises, or the
            # process is force-terminated before agent.stop() runs, the
            # box must not bugcheck (CRITICAL_PROCESS_DIED -> reboot).
            # Idempotent — agent.stop() also clears it on the clean path.
            try:
                import tamper
                tamper.set_process_critical(False)
            except Exception:
                pass
            win32event.SetEvent(self._stop_evt)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                self._main()
            except Exception as e:
                servicemanager.LogErrorMsg(f"RansomGuard agent crashed: {e}")
                # Re-raise so the SCM marks the service as failed and
                # recovery kicks in (configure_recovery in the install
                # script sets restart-on-every-failure).
                raise
            finally:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STOPPED,
                    (self._svc_name_, ""),
                )

        def _main(self) -> None:
            # Imports are deferred so this module can be loaded on
            # non-Windows for editor type-checking.
            from agent import Agent
            from responder import ResponderMode

            params = _load_params_from_registry()
            for d in params["WatchDirs"]:
                Path(d).mkdir(parents=True, exist_ok=True)
            Path(params["DbPath"]).parent.mkdir(parents=True, exist_ok=True)
            Path(params["ReportsDir"]).mkdir(parents=True, exist_ok=True)

            watchdog_pid = int(params["WatchdogPid"]) or _find_watchdog_pid()

            self._agent = Agent(
                params["WatchDirs"],
                db_path=str(params["DbPath"]),
                responder_mode=ResponderMode(str(params["Mode"])),
                enable_minifilter=True,
                reports_dir=str(params["ReportsDir"]),
                notify_user=False,           # toast doesn't work on Session 0
                enable_tamper_protection=True,
                watchdog_pid=watchdog_pid,
            )
            self._agent.start()

            if int(params["Dashboard"]):
                self._start_dashboard(int(params["Port"]))

            # Wait until SCM asks us to stop.
            win32event.WaitForSingleObject(self._stop_evt, win32event.INFINITE)

            try:
                self._agent.stop()
            except Exception as e:
                servicemanager.LogErrorMsg(f"agent.stop failed: {e}")

        def _start_dashboard(self, port: int) -> None:
            try:
                from dashboard.app import create_app
                app = create_app(self._agent)
                self._dashboard_thread = threading.Thread(
                    target=lambda: app.run(
                        host="127.0.0.1", port=port,
                        debug=False, use_reloader=False,
                    ),
                    daemon=True,
                    name="ransomguard-dashboard",
                )
                self._dashboard_thread.start()
            except Exception as e:
                servicemanager.LogErrorMsg(f"dashboard failed to start: {e}")


def main():
    if win32serviceutil is None:
        print("pywin32 is not installed; this entrypoint only runs on Windows.",
              file=sys.stderr)
        sys.exit(1)
    # When the SCM launches us with no args it expects ServiceFramework
    # to take over; otherwise we're being invoked as the install CLI.
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(RansomGuardAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(RansomGuardAgentService)


if __name__ == "__main__":
    main()
