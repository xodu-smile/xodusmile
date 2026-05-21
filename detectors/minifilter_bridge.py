"""
Minifilter Bridge
-----------------
User-mode connector for the RansomGuard kernel minifilter.

The driver (minifilter/RansomGuard.sys) exposes a filter communication
port at ``\\RansomGuardPort``.  This module:

  - connects to that port via ``FilterConnectCommunicationPort``
  - blocks on ``FilterGetMessage`` to receive RG_EVENT records
  - converts each record into a Signal fed into the ScoringEngine
  - exposes ``quarantine_pid()`` / ``release_pid()`` so the responder
    can have the kernel block future file ops from a malicious PID

If the driver is not loaded (or we are not on Windows) the bridge logs a
warning and stays idle; the rest of the agent continues to work with the
user-mode-only detectors.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
import threading
import time
from collections import defaultdict, deque
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, Deque, Dict, List, Optional, Tuple

from .base import Detector
from scoring import Signal, Severity


# ---------------------------------------------------------------------------
# Constants (kept in sync with minifilter/RansomGuard.h)
# ---------------------------------------------------------------------------

PORT_NAME = r"\RansomGuardPort"
RG_PROTOCOL_VERSION = 2
RG_MAX_PATH_CHARS = 520
RG_MAX_EXTRA_CHARS = 1024

# RG_EVENT_KIND
EVENT_CREATE          = 1
EVENT_WRITE           = 2
EVENT_SETINFO         = 3
EVENT_BLOCKED         = 4
EVENT_PROCESS_START   = 5
EVENT_PROCESS_EXIT    = 6
EVENT_REGISTRY        = 7
EVENT_TAMPER_BLOCKED  = 8

# RG_SETINFO_KIND
SETINFO_OTHER  = 0
SETINFO_RENAME = 1
SETINFO_DELETE = 2

# RG_REGISTRY_KIND
REG_OTHER         = 0
REG_SET_VALUE     = 1
REG_DELETE_VALUE  = 2
REG_CREATE_KEY    = 3
REG_DELETE_KEY    = 4
REG_RENAME_KEY    = 5

# RG_TAMPER_KIND
TAMPER_PROCESS = 1
TAMPER_THREAD  = 2

# RG_COMMAND_KIND
CMD_QUARANTINE        = 1
CMD_RELEASE           = 2
CMD_PING              = 3
CMD_PROTECT_PID       = 4
CMD_UNPROTECT_PID     = 5
CMD_FLUSH_QUARANTINE  = 6

# Thresholds for write-burst detection at the driver level.  These are
# distinct from MassIODetector's path-based thresholds: we score per-PID,
# regardless of which directory was touched.
PID_WRITE_BURST_BYTES   = 75 * 1024 * 1024
PID_WRITE_BURST_WINDOW  = 4.0
PID_RENAME_BURST_COUNT  = 20
PID_RENAME_BURST_WINDOW = 5.0
# Paths that generate noise but aren't malicious - skip event processing
NOISY_PATHS = (
    "\\appdata\\local\\google\\chrome\\",
    "\\appdata\\local\\microsoft\\edge\\",
    "\\appdata\\local\\microsoft\\windows\\",
    "\\appdata\\roaming\\microsoft\\windows\\recent\\",
    "\\windows\\softwaredistribution\\",
    "\\windows\\system32\\config\\",
    "\\windows\\temp\\",
    "\\windows\\winsxs\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\indexeddb\\",
    "\\cache_data\\",
    "\\jumplisticons",
    "\\customdestinations",
)

# ---------------------------------------------------------------------------
# ctypes layout
# ---------------------------------------------------------------------------


class RG_EVENT(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ("Version",         wintypes.ULONG),
        ("Kind",            wintypes.ULONG),
        ("SubKind",         wintypes.ULONG),
        ("ProcessId",       wintypes.ULONG),
        ("ParentProcessId", wintypes.ULONG),
        ("ThreadId",        wintypes.ULONG),
        ("Status",          wintypes.ULONG),
        ("DesiredAccess",   wintypes.ULONG),
        ("WriteBytes",      ctypes.c_ulonglong),
        ("TimestampNs",     ctypes.c_ulonglong),
        ("PathLength",      wintypes.ULONG),
        ("ExtraLength",     wintypes.ULONG),
        ("Path",            wintypes.WCHAR * RG_MAX_PATH_CHARS),
        ("Extra",           wintypes.WCHAR * RG_MAX_EXTRA_CHARS),
    ]


class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [
        ("ReplyLength", wintypes.ULONG),
        ("MessageId",   ctypes.c_ulonglong),
    ]


class RG_MESSAGE(ctypes.Structure):
    """Header + payload as a single fixed-size buffer for FilterGetMessage."""
    _fields_ = [
        ("Header",  FILTER_MESSAGE_HEADER),
        ("Payload", RG_EVENT),
    ]


class RG_COMMAND(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ("Version",   wintypes.ULONG),
        ("Kind",      wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("Reserved",  wintypes.ULONG),
    ]


class RG_REPLY(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ("Status",   wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


# ---------------------------------------------------------------------------
# fltlib.dll bindings
# ---------------------------------------------------------------------------


def _load_fltlib() -> Optional[ctypes.WinDLL]:
    if platform.system() != "Windows":
        return None
    try:
        lib = ctypes.WinDLL("fltlib.dll")
    except OSError:
        return None

    lib.FilterConnectCommunicationPort.restype = ctypes.HRESULT
    lib.FilterConnectCommunicationPort.argtypes = [
        wintypes.LPCWSTR,                 # lpPortName
        wintypes.DWORD,                   # dwOptions
        ctypes.c_void_p,                  # lpContext
        wintypes.WORD,                    # wSizeOfContext
        ctypes.c_void_p,                  # lpSecurityAttributes
        ctypes.POINTER(wintypes.HANDLE),  # hPort
    ]

    lib.FilterGetMessage.restype = ctypes.HRESULT
    lib.FilterGetMessage.argtypes = [
        wintypes.HANDLE,                                  # hPort
        ctypes.POINTER(FILTER_MESSAGE_HEADER),            # lpMessageBuffer
        wintypes.DWORD,                                   # dwMessageBufferSize
        ctypes.c_void_p,                                  # lpOverlapped
    ]

    lib.FilterSendMessage.restype = ctypes.HRESULT
    lib.FilterSendMessage.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p, wintypes.DWORD,    # input buffer + length
        ctypes.c_void_p, wintypes.DWORD,    # output buffer + length
        ctypes.POINTER(wintypes.DWORD),     # bytes returned
    ]
    return lib


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


@dataclass
class _PidIoState:
    write_total: int = 0
    write_window_start: float = 0.0
    rename_times: Deque[float] = None    # type: ignore[assignment]


class MinifilterBridge(Detector):
    """Detector that consumes events from the RansomGuard kernel driver.

    Per-PID accounting:
      - Cumulative write bytes inside a rolling window → write-burst signal
      - Rename count inside a rolling window         → rename-burst signal
      - Any Blocked event                            → high-confidence signal
    """

    name = "minifilter"

    def __init__(self, engine, *, port_name: str = PORT_NAME):
        super().__init__(engine)
        self._port_name = port_name
        self._port: Optional[wintypes.HANDLE] = None
        self._lib = _load_fltlib()
        self._own_pid = os.getpid()
        self._pids: Dict[int, _PidIoState] = defaultdict(
            lambda: _PidIoState(rename_times=deque())
        )
        self._burst_alerted: Dict[int, float] = {}
        self._lock = threading.Lock()
        self._connected_event = threading.Event()
        self._known_paths: Dict[int, str] = {}     # pid → most recent path
        # Extra PIDs (besides our own) to tamper-protect on every connect.
        # The agent uses this so the watchdog process also gets protected
        # by the kernel ObCallback.
        self._extra_protected_pids: List[int] = []
        # Subscribers for non-file events.  Each receives an RG_EVENT.
        # The fan-out happens on the receive thread, so subscribers must
        # be fast and non-blocking.
        self._process_subs: List[Callable[[RG_EVENT], None]] = []
        self._registry_subs: List[Callable[[RG_EVENT], None]] = []
        self._tamper_subs: List[Callable[[RG_EVENT], None]] = []

    # ---------------------------------------------------------- subscribers

    def subscribe_process(self, fn: Callable[[RG_EVENT], None]) -> None:
        self._process_subs.append(fn)

    def subscribe_registry(self, fn: Callable[[RG_EVENT], None]) -> None:
        self._registry_subs.append(fn)

    def subscribe_tamper(self, fn: Callable[[RG_EVENT], None]) -> None:
        self._tamper_subs.append(fn)

    def add_protected_pid(self, pid: int) -> None:
        """Register an additional PID to be tamper-protected on every
        (re)connect.  Used by the agent for its watchdog companion."""
        if pid and pid not in self._extra_protected_pids:
            self._extra_protected_pids.append(pid)
        # If we're already connected, push it now too.
        if self.is_connected:
            self._send_command(CMD_PROTECT_PID, pid)

    # ------------------------------------------------------------------ API

    @property
    def is_connected(self) -> bool:
        return self._port is not None

    def quarantine_pid(self, pid: int) -> bool:
        """Ask the kernel to block subsequent file ops from ``pid``.

        Returns True on success, False if the driver is not loaded or the
        call fails.  Safe to call from any thread.
        """
        return self._send_command(CMD_QUARANTINE, pid)

    def release_pid(self, pid: int) -> bool:
        return self._send_command(CMD_RELEASE, pid)

    def ping(self) -> bool:
        return self._send_command(CMD_PING, 0)

    def protect_pid(self, pid: int) -> bool:
        """Ask the kernel to strip PROCESS_TERMINATE / PROCESS_VM_* from
        handles opened to ``pid`` by anyone except the process itself.
        """
        return self._send_command(CMD_PROTECT_PID, pid)

    def unprotect_pid(self, pid: int) -> bool:
        return self._send_command(CMD_UNPROTECT_PID, pid)

    def flush_quarantine(self) -> bool:
        """Explicitly drop every quarantined PID.  Use during clean
        shutdown; the v2 driver does NOT auto-clear on disconnect."""
        return self._send_command(CMD_FLUSH_QUARANTINE, 0)

    # ---------------------------------------------------------- detector loop

    def run(self) -> None:
        if self._lib is None:
            print(f"[{self.name}] fltlib unavailable "
                  f"(platform={platform.system()}); bridge inactive")
            self._stop_event.wait()
            return

        backoff = 1.0
        while not self._stop_event.is_set():
            if not self._connect():
                # Sleep with exponential backoff up to 30s.
                self._stop_event.wait(min(backoff, 30.0))
                backoff = min(backoff * 2.0, 30.0)
                continue
            backoff = 1.0
            try:
                self._receive_loop()
            except Exception as e:
                print(f"[{self.name}] receive loop error: {e}")
            finally:
                self._close()

    def stop(self, *, flush_quarantine: bool = False) -> None:
        # A clean shutdown from the agent should release blocked PIDs so
        # they aren't stuck on next driver reload.  An emergency stop
        # (e.g. caught exception) should leave them blocked — that's the
        # whole point of "sticky" quarantine in v2.
        if flush_quarantine and self.is_connected:
            try:
                self.flush_quarantine()
            except Exception:
                pass
        super().stop()
        self._close()

    # --------------------------------------------------------------- internals

    def _connect(self) -> bool:
        if self._lib is None:
            return False
        handle = wintypes.HANDLE()
        try:
            hr = self._lib.FilterConnectCommunicationPort(
                self._port_name, 0, None, 0, None, ctypes.byref(handle)
            )
        except OSError as e:
            print(f"[{self.name}] connect raised: {e}")
            return False
        if hr != 0 or not handle.value:
            # 0x80070002 = ERROR_FILE_NOT_FOUND wrapped as HRESULT (driver not loaded)
            if hr & 0xFFFF != 2:
                print(f"[{self.name}] FilterConnectCommunicationPort hr=0x{hr & 0xFFFFFFFF:08X}")
            return False
        self._port = handle
        self._connected_event.set()
        print(f"[{self.name}] connected to {self._port_name}")
        # Tamper-protect our own PID (and any pre-registered companions)
        # on every reconnect.  The driver's protected-PID list is sticky
        # across our disconnects but not across driver reloads.
        self._send_command(CMD_PROTECT_PID, self._own_pid)
        for pid in self._extra_protected_pids:
            self._send_command(CMD_PROTECT_PID, pid)
        return True

    def _close(self) -> None:
        if self._port and self._port.value:
            try:
                ctypes.windll.kernel32.CloseHandle(self._port)
            except Exception:
                pass
        self._port = None
        self._connected_event.clear()

    def _receive_loop(self) -> None:
        assert self._lib is not None and self._port is not None
        buf = RG_MESSAGE()
        size = ctypes.sizeof(buf)
        while not self._stop_event.is_set():
            hr = self._lib.FilterGetMessage(
                self._port,
                ctypes.byref(buf.Header),
                size,
                None,
            )
            if hr != 0:
                # Driver unloaded mid-loop or port closed: exit and reconnect.
                if hr & 0xFFFF in (109, 1167):  # ERROR_BROKEN_PIPE / ERROR_DEVICE_NOT_CONNECTED
                    print(f"[{self.name}] driver port closed; will reconnect")
                else:
                    print(f"[{self.name}] FilterGetMessage hr=0x{hr & 0xFFFFFFFF:08X}")
                return
            evt = buf.Payload
            if evt.Version != RG_PROTOCOL_VERSION:
                # Skip unknown versions but keep listening.
                continue
            self._handle_event(evt)

    def _send_command(self, kind: int, pid: int) -> bool:
        if self._lib is None or self._port is None or not self._port.value:
            return False
        cmd = RG_COMMAND(Version=RG_PROTOCOL_VERSION, Kind=kind,
                         ProcessId=pid, Reserved=0)
        reply = RG_REPLY()
        returned = wintypes.DWORD(0)
        hr = self._lib.FilterSendMessage(
            self._port,
            ctypes.byref(cmd), ctypes.sizeof(cmd),
            ctypes.byref(reply), ctypes.sizeof(reply),
            ctypes.byref(returned),
        )
        if hr != 0:
            print(f"[{self.name}] FilterSendMessage hr=0x{hr & 0xFFFFFFFF:08X}")
            return False
        if reply.Status != 0:
            print(f"[{self.name}] driver rejected cmd {kind} pid={pid} "
                  f"status=0x{reply.Status:08X}")
            return False
        return True

    # ---- event handling ----

    def _handle_event(self, evt: RG_EVENT) -> None:
        kind = int(evt.Kind)
        pid = int(evt.ProcessId)

        # Fan out non-file events to subscribers before any of the
        # file-centric noise filtering below kicks in.  Subscribers see
        # events from every PID, including our own (so they can ignore
        # self-events if they want).
        if kind == EVENT_PROCESS_START or kind == EVENT_PROCESS_EXIT:
            for sub in self._process_subs:
                try:
                    sub(evt)
                except Exception as e:
                    print(f"[{self.name}] process subscriber error: {e}")
            return
        if kind == EVENT_REGISTRY:
            for sub in self._registry_subs:
                try:
                    sub(evt)
                except Exception as e:
                    print(f"[{self.name}] registry subscriber error: {e}")
            return
        if kind == EVENT_TAMPER_BLOCKED:
            for sub in self._tamper_subs:
                try:
                    sub(evt)
                except Exception as e:
                    print(f"[{self.name}] tamper subscriber error: {e}")
            # Also emit a Signal directly so it shows up on the dashboard
            # even when no detector wraps it.
            self.emit(Signal(
                detector=self.name,
                name="tamper_attempt",
                weight=50,
                severity=Severity.HIGH,
                message=(f"pid={int(evt.ParentProcessId)} tried to open "
                         f"handle to protected pid={pid} "
                         f"(access=0x{int(evt.DesiredAccess):08X}, "
                         f"stripped=0x{int(evt.Status):08X})"),
                metadata={
                    "target_pid": pid,
                    "requester_pid": int(evt.ParentProcessId),
                    "desired_access": int(evt.DesiredAccess),
                    "stripped": int(evt.Status),
                    "subkind": int(evt.SubKind),
                },
            ))
            return

        # ---- file events (the original v1 set) ----
        if pid == self._own_pid or pid == 0:
            return

        path = evt.Path[:max(0, evt.PathLength - 1)] if evt.PathLength else ""
        if path:
            self._known_paths[pid] = path
        now = time.time()
        # Skip noisy system paths (browser caches, Windows internals, etc.)
        if path:
            path_lower = path.lower()
            for noisy in NOISY_PATHS:
                if noisy in path_lower:
                    return

        if evt.Kind == EVENT_BLOCKED:
            self.emit(Signal(
                detector=self.name,
                name="kernel_blocked_op",
                weight=60,
                severity=Severity.HIGH,
                message=f"Kernel blocked operation from pid={pid} on {path or '?'}",
                metadata={"pid": pid, "path": path, "subkind": int(evt.SubKind)},
            ))
            return

        if evt.Kind == EVENT_WRITE:
            self._account_write(pid, int(evt.WriteBytes), path, now)
            return

        if evt.Kind == EVENT_SETINFO:
            if int(evt.SubKind) == SETINFO_RENAME:
                self._account_rename(pid, path, now)
            elif int(evt.SubKind) == SETINFO_DELETE:
                # Single deletes are noisy; we emit only at LOW severity so
                # the scoring engine can fold them in alongside other signals.
                self.emit(Signal(
                    detector=self.name,
                    name="file_delete",
                    weight=3,
                    severity=Severity.LOW,
                    message=f"pid={pid} deleted {path or '?'}",
                    metadata={"pid": pid, "path": path},
                ))
            return

        # EVENT_CREATE is currently informational only; we keep the most
        # recent path so downstream signals can quote it, but do not emit.

    def _account_write(self, pid: int, bytes_written: int, path: str,
                       now: float) -> None:
        state = self._pids[pid]
        if state.write_window_start == 0.0 or \
                now - state.write_window_start > PID_WRITE_BURST_WINDOW:
            state.write_window_start = now
            state.write_total = 0
        state.write_total += bytes_written

        if state.write_total < PID_WRITE_BURST_BYTES:
            return

        # Debounce per-PID so we don't fire on every IRP after the threshold.
        last = self._burst_alerted.get(pid, 0.0)
        if now - last < PID_WRITE_BURST_WINDOW:
            return
        self._burst_alerted[pid] = now

        self.emit(Signal(
            detector=self.name,
            name="kernel_write_burst",
            weight=35,
            severity=Severity.HIGH,
            message=(f"pid={pid} wrote "
                     f"{state.write_total / (1024 * 1024):.1f} MB in "
                     f"{PID_WRITE_BURST_WINDOW:.0f}s (kernel-observed)"),
            metadata={
                "pid": pid,
                "bytes": state.write_total,
                "window_sec": PID_WRITE_BURST_WINDOW,
                "last_path": path or self._known_paths.get(pid, ""),
            },
        ))
        # Reset so the next burst is independently judged.
        state.write_total = 0
        state.write_window_start = now

    def _account_rename(self, pid: int, path: str, now: float) -> None:
        state = self._pids[pid]
        if state.rename_times is None:
            state.rename_times = deque()
        state.rename_times.append(now)
        cutoff = now - PID_RENAME_BURST_WINDOW
        while state.rename_times and state.rename_times[0] < cutoff:
            state.rename_times.popleft()

        if len(state.rename_times) < PID_RENAME_BURST_COUNT:
            return

        last = self._burst_alerted.get((pid, "rename"), 0.0)  # type: ignore[arg-type]
        if now - last < PID_RENAME_BURST_WINDOW:
            return
        self._burst_alerted[(pid, "rename")] = now  # type: ignore[assignment]

        self.emit(Signal(
            detector=self.name,
            name="kernel_rename_burst",
            weight=40,
            severity=Severity.HIGH,
            message=(f"pid={pid} performed {len(state.rename_times)} renames "
                     f"in {PID_RENAME_BURST_WINDOW:.0f}s (kernel-observed)"),
            metadata={
                "pid": pid,
                "count": len(state.rename_times),
                "window_sec": PID_RENAME_BURST_WINDOW,
                "last_path": path or self._known_paths.get(pid, ""),
            },
        ))
        state.rename_times.clear()
