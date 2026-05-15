"""
Minifilter user-mode bridge (Windows 11).

Talks to the RmDetectorFlt kernel driver over a FltMgr communication port.
The driver delivers EDR-grade telemetry — file events with PID + parent
PID, process start / exit, image loads, in-kernel entropy spikes, and
notifications of autonomous process termination. This module translates
those into Signal objects for the ScoringEngine and pushes config
(watch paths, canary paths, suspicious extensions, policy, thresholds,
block / terminate commands) down to the driver.

If fltlib.dll is missing or the port can't be opened (driver not loaded),
self.connected stays False — agent.py falls back to the user-mode
watchdog detector in that case.
"""

import ctypes
import ctypes.wintypes as wt
import os
import re
import sys
import threading
from pathlib import Path
from typing import Iterable, List, Optional

from .base import Detector
from scoring import Signal, Severity


# ----- contract mirror (must match kmod/RmDetectorFlt/RmDetectorFlt.h) ----

RM_PORT_NAME = r"\RmDetectorPort"
RM_PROTOCOL_VERSION = 2
RM_MAX_PATH_CHARS = 520
RM_MAX_WATCH_PATHS = 16
RM_MAX_CANARY_PATHS = 128
RM_MAX_SUSP_EXTS = 64

# RM_EVENT_TYPE
EVT_CREATE          = 1
EVT_WRITE           = 2
EVT_RENAME          = 3
EVT_DELETE          = 4
EVT_CLEANUP         = 5
EVT_BLOCKED_CANARY  = 10
EVT_BLOCKED_PID     = 11
EVT_BLOCKED_SUSP_EXT = 12
EVT_PROCESS_START   = 20
EVT_PROCESS_EXIT    = 21
EVT_IMAGE_LOAD      = 22
EVT_ENTROPY_SPIKE   = 30
EVT_SCORE_CRITICAL  = 31
EVT_AUTO_TERMINATED = 32

# Flags
F_CREATE_NEW    = 0x0001
F_WRITE_ACCESS  = 0x0002
F_DELETE_ACCESS = 0x0004
F_CANARY        = 0x0010
F_WATCHED       = 0x0020
F_HIGH_ENTROPY  = 0x0040
F_HEADER_CHANGED = 0x0080
F_SYSTEM_PROC   = 0x0100
F_SUSP_EXT      = 0x0200

# RM_COMMAND_TYPE
CMD_SET_WATCH       = 1
CMD_SET_CANARY      = 2
CMD_BLOCK_PID       = 3
CMD_UNBLOCK_PID     = 4
CMD_CLEAR_BLOCKED   = 5
CMD_SET_POLICY      = 6
CMD_PING            = 7
CMD_SET_SUSP_EXTS   = 8
CMD_TERMINATE_PID   = 9
CMD_SET_THRESHOLDS  = 10
CMD_RESET_PID_STATS = 11

# Policy bits
POL_BLOCK_CANARY    = 0x0001
POL_BLOCK_PIDS      = 0x0002
POL_EMIT_WRITES     = 0x0004
POL_EMIT_CREATES    = 0x0008
POL_EMIT_CLEANUPS   = 0x0010
POL_TRACK_PROCESSES = 0x0020
POL_ENTROPY_GUARD   = 0x0040
POL_BLOCK_SUSP_EXT  = 0x0080
POL_AUTO_TERMINATE  = 0x0100
POL_EMIT_IMAGE_LOADS = 0x0200

POL_DEFAULT = (
    POL_BLOCK_CANARY
    | POL_BLOCK_PIDS
    | POL_EMIT_CREATES
    | POL_EMIT_CLEANUPS
    | POL_TRACK_PROCESSES
    | POL_ENTROPY_GUARD
    | POL_BLOCK_SUSP_EXT
    | POL_AUTO_TERMINATE
)


# Common ransomware extension list. User-mode can override with
# set_suspicious_extensions().
DEFAULT_SUSP_EXTS = (
    ".locked", ".encrypted", ".crypt", ".crypto", ".enc",
    ".ryk", ".lockbit", ".lockbit3", ".conti", ".revil",
    ".sodinokibi", ".clop", ".dharma", ".phobos", ".djvu",
    ".wcry", ".wncry", ".wannacry", ".cerber", ".zepto",
    ".thor", ".aes256", ".cryp1", ".onion", ".rapid",
    ".pay2me", ".ranzy", ".magniber", ".babuk", ".darkside",
    ".blackcat", ".alphv", ".rorschach",
)


# Event struct — keep in lock-step with RM_EVENT in RmDetectorFlt.h.
class _RmEvent(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProtocolVersion",  ctypes.c_uint32),
        ("EventType",        ctypes.c_uint32),
        ("TimestampUtc",     ctypes.c_int64),
        ("ProcessId",        ctypes.c_uint32),
        ("ParentProcessId",  ctypes.c_uint32),
        ("ThreadId",         ctypes.c_uint32),
        ("Flags",            ctypes.c_uint32),
        ("WriteSize",        ctypes.c_uint32),
        ("PidWriteCount",    ctypes.c_uint32),
        ("PidDistinctExts",  ctypes.c_uint32),
        ("PidEntropyHits",   ctypes.c_uint32),
        ("PidScore",         ctypes.c_uint32),
        ("EntropyX100",      ctypes.c_uint32),
        ("PathLength",       ctypes.c_uint32),
        ("ExtraLength",      ctypes.c_uint32),
        ("Path",             ctypes.c_wchar * RM_MAX_PATH_CHARS),
        ("Extra",            ctypes.c_wchar * RM_MAX_PATH_CHARS),
    ]


class _FilterMessageHeader(ctypes.Structure):
    _fields_ = [
        ("ReplyLength", ctypes.c_uint32),
        ("MessageId",   ctypes.c_uint64),
    ]


class _RmMessage(ctypes.Structure):
    _fields_ = [
        ("Header", _FilterMessageHeader),
        ("Event",  _RmEvent),
    ]


_PATH_BUFFER_CHARS = RM_MAX_PATH_CHARS * 8


class _RmCommand(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProtocolVersion",   ctypes.c_uint32),
        ("CommandType",       ctypes.c_uint32),
        ("PathCount",         ctypes.c_uint32),
        ("PathBufferChars",   ctypes.c_uint32),
        ("Pid",               ctypes.c_uint32),
        ("Policy",            ctypes.c_uint32),
        ("ScoreCritical",     ctypes.c_uint32),
        ("EntropyThreshold",  ctypes.c_uint32),
        ("DistinctExtAlert",  ctypes.c_uint32),
        ("WriteBurstBytes",   ctypes.c_uint32),
        ("Paths",             ctypes.c_wchar * _PATH_BUFFER_CHARS),
    ]


class _RmReply(ctypes.Structure):
    _fields_ = [
        ("Status",  ctypes.c_int32),
        ("Detail",  ctypes.c_uint32),
    ]


# ----- ctypes import / loading ------------------------------------------

_HAS_FLTLIB = False
_fltlib = None
_kernel32 = None

if sys.platform == "win32":
    try:
        _fltlib = ctypes.WinDLL("fltlib.dll", use_last_error=True)
        _kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

        _fltlib.FilterConnectCommunicationPort.restype = ctypes.c_long  # HRESULT
        _fltlib.FilterConnectCommunicationPort.argtypes = [
            wt.LPCWSTR, wt.DWORD, ctypes.c_void_p, wt.WORD,
            ctypes.c_void_p, ctypes.POINTER(wt.HANDLE),
        ]
        _fltlib.FilterSendMessage.restype = ctypes.c_long
        _fltlib.FilterSendMessage.argtypes = [
            wt.HANDLE, ctypes.c_void_p, wt.DWORD,
            ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
        ]
        _fltlib.FilterGetMessage.restype = ctypes.c_long
        _fltlib.FilterGetMessage.argtypes = [
            wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p,
        ]
        _kernel32.CloseHandle.restype = wt.BOOL
        _kernel32.CloseHandle.argtypes = [wt.HANDLE]
        _kernel32.QueryDosDeviceW.restype = wt.DWORD
        _kernel32.QueryDosDeviceW.argtypes = [
            wt.LPCWSTR, wt.LPWSTR, wt.DWORD,
        ]
        _HAS_FLTLIB = True
    except OSError:
        _HAS_FLTLIB = False


# ----- path normalization -----------------------------------------------

_DRIVE_RE = re.compile(r"^([A-Za-z]):(.*)$")
_NT_DEVICE_CACHE: dict[str, str] = {}


def _nt_device_for_drive(drive_letter: str) -> Optional[str]:
    key = drive_letter.upper()
    if key in _NT_DEVICE_CACHE:
        return _NT_DEVICE_CACHE[key]
    if not _HAS_FLTLIB:
        return None
    buf = ctypes.create_unicode_buffer(1024)
    n = _kernel32.QueryDosDeviceW(key, buf, 1024)
    if n == 0:
        return None
    result = buf.value.lower()
    _NT_DEVICE_CACHE[key] = result
    return result


def normalize_path(path: str) -> Optional[str]:
    """Convert a Win32 path to the lowercased NT form the driver expects."""
    if not path:
        return None
    abs_path = os.path.abspath(path)
    m = _DRIVE_RE.match(abs_path)
    if not m:
        return abs_path.lower()
    drive, rest = m.group(1), m.group(2)
    dev = _nt_device_for_drive(f"{drive}:")
    if dev is None:
        return None
    return f"{dev}{rest}".lower().replace("/", "\\")


# ----- weights for kernel-sourced signals -------------------------------

EVENT_TYPE_NAMES = {
    EVT_CREATE:           "create",
    EVT_WRITE:            "write",
    EVT_RENAME:           "rename",
    EVT_DELETE:           "delete",
    EVT_CLEANUP:          "cleanup",
    EVT_BLOCKED_CANARY:   "canary_blocked",
    EVT_BLOCKED_PID:      "blocked_pid_write",
    EVT_BLOCKED_SUSP_EXT: "blocked_susp_ext",
    EVT_PROCESS_START:    "process_start",
    EVT_PROCESS_EXIT:     "process_exit",
    EVT_IMAGE_LOAD:       "image_load",
    EVT_ENTROPY_SPIKE:    "entropy_spike",
    EVT_SCORE_CRITICAL:   "kernel_score_critical",
    EVT_AUTO_TERMINATED:  "auto_terminated",
}

# These mirror the kernel's view: weight values are tuned so that several
# kernel signals from a single PID push the engine into HIGH/CRITICAL well
# before a process can finish encrypting a watch directory.
W_BLOCKED_CANARY    = 95
W_BLOCKED_PID       = 70
W_BLOCKED_SUSP_EXT  = 80
W_ENTROPY_SPIKE     = 18
W_SCORE_CRITICAL    = 90
W_AUTO_TERMINATED   = 100
W_DELETE_WATCHED    = 12
W_RENAME_WATCHED    = 12
W_HEAVY_WRITE       = 15
W_CANARY_KERNEL     = 90
WRITE_BURST_BYTES   = 50 * 1024 * 1024


class MinifilterDetector(Detector):
    """Kernel-sourced EDR-grade file-system + process telemetry.

    Tries to connect to RmDetectorFlt. If the driver isn't loaded,
    self.connected stays False after start() and the detector idles —
    agent.py keys the watchdog fallback off self.connected.
    """

    name = "minifilter"

    def __init__(
        self,
        engine,
        watch_dirs: List[str],
        canary_paths: Optional[List[str]] = None,
        policy: int = POL_DEFAULT,
        suspicious_extensions: Optional[Iterable[str]] = None,
    ):
        super().__init__(engine)
        self.watch_dirs = [str(Path(d)) for d in watch_dirs]
        self.canary_paths = [str(Path(p)) for p in (canary_paths or [])]
        self.policy = policy
        self.suspicious_extensions = list(
            suspicious_extensions if suspicious_extensions is not None
            else DEFAULT_SUSP_EXTS
        )
        # Default thresholds matching the driver's RM_DEFAULT_* constants.
        self.score_critical = 100
        self.entropy_threshold_x100 = 750
        self.distinct_ext_alert = 6
        self.write_burst_bytes = WRITE_BURST_BYTES
        self.connected = False
        self._handle: Optional[int] = None
        self._lock = threading.Lock()

    # --- public API used by agent / scoring callback ----------------

    def set_canary_paths(self, paths: Iterable[str]) -> None:
        self.canary_paths = [str(Path(p)) for p in paths]
        if self.connected:
            self._push_paths(CMD_SET_CANARY, self.canary_paths,
                             RM_MAX_CANARY_PATHS)

    def set_watch_paths(self, paths: Iterable[str]) -> None:
        self.watch_dirs = [str(Path(p)) for p in paths]
        if self.connected:
            self._push_paths(CMD_SET_WATCH, self.watch_dirs,
                             RM_MAX_WATCH_PATHS)

    def set_suspicious_extensions(self, exts: Iterable[str]) -> None:
        """Push the ransomware-extension list to the kernel."""
        self.suspicious_extensions = [e.lower() for e in exts]
        if self.connected:
            self._push_extensions(self.suspicious_extensions)

    def set_thresholds(
        self,
        score_critical: Optional[int] = None,
        entropy_threshold_x100: Optional[int] = None,
        distinct_ext_alert: Optional[int] = None,
        write_burst_bytes: Optional[int] = None,
    ) -> bool:
        """Update one or more in-kernel scoring thresholds. None = leave alone."""
        if score_critical is not None:
            self.score_critical = score_critical
        if entropy_threshold_x100 is not None:
            self.entropy_threshold_x100 = entropy_threshold_x100
        if distinct_ext_alert is not None:
            self.distinct_ext_alert = distinct_ext_alert
        if write_burst_bytes is not None:
            self.write_burst_bytes = write_burst_bytes
        if not self.connected:
            return False
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = CMD_SET_THRESHOLDS
        cmd.ScoreCritical = score_critical or 0
        cmd.EntropyThreshold = entropy_threshold_x100 or 0
        cmd.DistinctExtAlert = distinct_ext_alert or 0
        cmd.WriteBurstBytes = write_burst_bytes or 0
        return self._send_command(cmd) >= 0

    def block_pid(self, pid: int) -> bool:
        """Tell the kernel to deny writes from this PID. Idempotent."""
        if not self.connected:
            return False
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = CMD_BLOCK_PID
        cmd.Pid = pid
        return self._send_command(cmd) >= 0

    def unblock_pid(self, pid: int) -> bool:
        if not self.connected:
            return False
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = CMD_UNBLOCK_PID
        cmd.Pid = pid
        return self._send_command(cmd) >= 0

    def terminate_pid(self, pid: int) -> bool:
        """Ask the driver to call ZwTerminateProcess on this PID."""
        if not self.connected:
            return False
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = CMD_TERMINATE_PID
        cmd.Pid = pid
        return self._send_command(cmd) >= 0

    def reset_pid_stats(self) -> bool:
        if not self.connected:
            return False
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = CMD_RESET_PID_STATS
        return self._send_command(cmd) >= 0

    # --- detector lifecycle ----------------------------------------

    def run(self) -> None:
        if not _HAS_FLTLIB:
            print(f"[{self.name}] fltlib.dll unavailable; "
                  f"requires Windows + WDK port libraries")
            self._stop_event.wait()
            return

        if not self._connect():
            print(f"[{self.name}] could not open {RM_PORT_NAME}; "
                  f"driver not loaded? falling back to user-mode watchers")
            self._stop_event.wait()
            return

        try:
            self._push_initial_config()
            self._receive_loop()
        finally:
            self._disconnect()

    def stop(self) -> None:
        super().stop()
        self._disconnect()

    # --- connection -------------------------------------------------

    def _connect(self) -> bool:
        handle = wt.HANDLE()
        hr = _fltlib.FilterConnectCommunicationPort(
            RM_PORT_NAME, 0, None, 0, None, ctypes.byref(handle))
        if hr != 0:
            return False
        self._handle = handle.value
        self.connected = True
        return True

    def _disconnect(self) -> None:
        with self._lock:
            if self._handle is not None:
                _kernel32.CloseHandle(self._handle)
                self._handle = None
            self.connected = False

    def _push_initial_config(self) -> None:
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = CMD_SET_POLICY
        cmd.Policy = self.policy
        self._send_command(cmd)

        # Thresholds before paths so policy + thresholds are live as soon as
        # the driver sees the first file event.
        self.set_thresholds(
            score_critical=self.score_critical,
            entropy_threshold_x100=self.entropy_threshold_x100,
            distinct_ext_alert=self.distinct_ext_alert,
            write_burst_bytes=self.write_burst_bytes,
        )

        self._push_paths(CMD_SET_WATCH, self.watch_dirs, RM_MAX_WATCH_PATHS)
        if self.canary_paths:
            self._push_paths(CMD_SET_CANARY, self.canary_paths,
                             RM_MAX_CANARY_PATHS)
        if self.suspicious_extensions:
            self._push_extensions(self.suspicious_extensions)

    def _push_paths(self, cmd_type: int, paths: List[str], max_paths: int) -> bool:
        norm: List[str] = []
        for p in paths:
            n = normalize_path(p)
            if n:
                norm.append(n)
        if len(norm) > max_paths:
            print(f"[{self.name}] truncating path list from {len(norm)} "
                  f"to {max_paths}")
            norm = norm[:max_paths]
        joined = "\x00".join(norm) + "\x00\x00"
        if len(joined) > _PATH_BUFFER_CHARS:
            print(f"[{self.name}] path buffer overflow "
                  f"({len(joined)} > {_PATH_BUFFER_CHARS} chars)")
            return False
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = cmd_type
        cmd.PathCount = len(norm)
        cmd.PathBufferChars = len(joined)
        ctypes.memmove(cmd.Paths, joined, len(joined) * ctypes.sizeof(ctypes.c_wchar))
        return self._send_command(cmd) >= 0

    def _push_extensions(self, exts: List[str]) -> bool:
        norm = [e.lower() for e in exts if e]
        if len(norm) > RM_MAX_SUSP_EXTS:
            print(f"[{self.name}] truncating suspicious-extension list from "
                  f"{len(norm)} to {RM_MAX_SUSP_EXTS}")
            norm = norm[:RM_MAX_SUSP_EXTS]
        joined = "\x00".join(norm) + "\x00\x00"
        if len(joined) > _PATH_BUFFER_CHARS:
            print(f"[{self.name}] suspicious-extension buffer overflow")
            return False
        cmd = _RmCommand()
        cmd.ProtocolVersion = RM_PROTOCOL_VERSION
        cmd.CommandType = CMD_SET_SUSP_EXTS
        cmd.PathCount = len(norm)
        cmd.PathBufferChars = len(joined)
        ctypes.memmove(cmd.Paths, joined, len(joined) * ctypes.sizeof(ctypes.c_wchar))
        return self._send_command(cmd) >= 0

    def _send_command(self, cmd: _RmCommand) -> int:
        with self._lock:
            if self._handle is None:
                return -1
            reply = _RmReply()
            written = wt.DWORD(0)
            hr = _fltlib.FilterSendMessage(
                self._handle,
                ctypes.byref(cmd), ctypes.sizeof(cmd),
                ctypes.byref(reply), ctypes.sizeof(reply),
                ctypes.byref(written))
        if hr != 0:
            print(f"[{self.name}] FilterSendMessage hr=0x{hr & 0xffffffff:08x}")
            return -1
        if reply.Status != 0:
            return -1
        return reply.Detail

    # --- receive loop ----------------------------------------------

    def _receive_loop(self) -> None:
        msg = _RmMessage()
        size = ctypes.sizeof(msg)
        print(f"[{self.name}] connected, listening for kernel events")
        while not self._stop_event.is_set():
            ctypes.memset(ctypes.byref(msg), 0, size)
            hr = _fltlib.FilterGetMessage(
                self._handle, ctypes.byref(msg), size, None)
            if hr != 0:
                if self._stop_event.is_set():
                    return
                print(f"[{self.name}] FilterGetMessage hr=0x{hr & 0xffffffff:08x}; "
                      f"closing")
                return
            try:
                self._handle_event(msg.Event)
            except Exception as e:
                print(f"[{self.name}] event handler error: {e}")

    def _event_meta(self, ev: _RmEvent, path: str, extra: str) -> dict:
        return {
            "path": path,
            "pid": ev.ProcessId,
            "parent_pid": ev.ParentProcessId,
            "tid": ev.ThreadId,
            "flags": ev.Flags,
            "write_size": ev.WriteSize,
            "pid_writes": ev.PidWriteCount,
            "pid_distinct_exts": ev.PidDistinctExts,
            "pid_entropy_hits": ev.PidEntropyHits,
            "pid_kscore": ev.PidScore,
            "entropy_x100": ev.EntropyX100,
            "extra": extra,
        }

    def _handle_event(self, ev: _RmEvent) -> None:
        if ev.ProtocolVersion != RM_PROTOCOL_VERSION:
            return

        path = ev.Path[:ev.PathLength] if ev.PathLength else ""
        extra = ev.Extra[:ev.ExtraLength] if ev.ExtraLength else ""

        etype = ev.EventType
        meta = self._event_meta(ev, path, extra)

        if etype == EVT_AUTO_TERMINATED:
            self.emit(Signal(
                detector=self.name, name="auto_terminated",
                weight=W_AUTO_TERMINATED,
                severity=Severity.CRITICAL,
                message=f"Driver auto-terminated pid={ev.ProcessId} "
                        f"(kernel score={ev.PidScore}, "
                        f"entropy hits={ev.PidEntropyHits})",
                metadata=meta,
            ))
            return

        if etype == EVT_SCORE_CRITICAL:
            self.emit(Signal(
                detector=self.name, name="kernel_score_critical",
                weight=W_SCORE_CRITICAL,
                severity=Severity.CRITICAL,
                message=f"In-kernel per-PID score crossed threshold "
                        f"(pid={ev.ProcessId}, kscore={ev.PidScore})",
                metadata=meta,
            ))
            return

        if etype == EVT_BLOCKED_CANARY:
            self.emit(Signal(
                detector=self.name, name="canary_blocked",
                weight=W_BLOCKED_CANARY,
                severity=Severity.CRITICAL,
                message=f"Driver blocked canary write/rename/delete: {path}",
                metadata=meta,
            ))
            return

        if etype == EVT_BLOCKED_SUSP_EXT:
            self.emit(Signal(
                detector=self.name, name="blocked_susp_ext",
                weight=W_BLOCKED_SUSP_EXT,
                severity=Severity.CRITICAL,
                message=f"Driver blocked rename into suspicious extension: "
                        f"{path} -> {extra}",
                metadata=meta,
            ))
            return

        if etype == EVT_BLOCKED_PID:
            self.emit(Signal(
                detector=self.name, name="blocked_pid_write",
                weight=W_BLOCKED_PID,
                severity=Severity.HIGH,
                message=f"Driver denied write from pid={ev.ProcessId}: {path}",
                metadata=meta,
            ))
            return

        if etype == EVT_ENTROPY_SPIKE:
            self.emit(Signal(
                detector=self.name, name="entropy_spike",
                weight=W_ENTROPY_SPIKE,
                severity=Severity.MEDIUM,
                message=f"High-entropy write (entropy={ev.EntropyX100/100:.2f}/8.00) "
                        f"by pid={ev.ProcessId}: {path}",
                metadata=meta,
            ))
            return

        if etype == EVT_PROCESS_START:
            # Observational by itself; surface as INFO so the dashboard
            # gets the process tree without inflating the score.
            self.emit(Signal(
                detector=self.name, name="process_start",
                weight=0,
                severity=Severity.INFO,
                message=f"Process started pid={ev.ProcessId} "
                        f"parent={ev.ParentProcessId}: {path or '<unknown>'}",
                metadata=meta,
            ))
            return

        if etype == EVT_PROCESS_EXIT:
            self.emit(Signal(
                detector=self.name, name="process_exit",
                weight=0,
                severity=Severity.INFO,
                message=f"Process exited pid={ev.ProcessId}",
                metadata=meta,
            ))
            return

        if etype == EVT_IMAGE_LOAD:
            self.emit(Signal(
                detector=self.name, name="image_load",
                weight=0,
                severity=Severity.INFO,
                message=f"Image loaded into pid={ev.ProcessId}: {path}",
                metadata=meta,
            ))
            return

        if etype == EVT_DELETE:
            self.emit(Signal(
                detector=self.name, name="watched_delete",
                weight=W_CANARY_KERNEL if (ev.Flags & F_CANARY) else W_DELETE_WATCHED,
                severity=Severity.CRITICAL if (ev.Flags & F_CANARY) else Severity.MEDIUM,
                message=f"File deleted by pid={ev.ProcessId}: {path}",
                metadata=meta,
            ))
            return

        if etype == EVT_RENAME:
            is_canary = bool(ev.Flags & F_CANARY)
            self.emit(Signal(
                detector=self.name, name="watched_rename",
                weight=W_CANARY_KERNEL if is_canary else W_RENAME_WATCHED,
                severity=Severity.CRITICAL if is_canary else Severity.MEDIUM,
                message=f"File renamed by pid={ev.ProcessId}: {path} -> {extra}",
                metadata=meta,
            ))
            return

        if etype == EVT_CLEANUP and ev.WriteSize >= WRITE_BURST_BYTES:
            self.emit(Signal(
                detector=self.name, name="heavy_write_close",
                weight=W_HEAVY_WRITE,
                severity=Severity.MEDIUM,
                message=f"pid={ev.ProcessId} wrote "
                        f"{ev.WriteSize / (1024*1024):.1f} MB to {path}",
                metadata=meta,
            ))
            return

        # CREATE and ordinary CLEANUP are observational.
