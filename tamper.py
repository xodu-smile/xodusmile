"""
User-mode tamper hardening helpers.

These are best-effort defences run by the agent at startup.  None of
them is sufficient on its own — together they raise the cost of an
attacker terminating the agent or corrupting its on-disk state.

Layers, weakest to strongest:

  1. Restrictive DACL on the SQLite event store and reports directory.
     Limits damage from a non-administrator attacker; an attacker who
     already holds SYSTEM can override DACLs.

  2. RtlSetProcessIsCritical (only when running as a service or with
     SeDebugPrivilege).  A "critical" process cannot be terminated
     without bug-checking the box — this turns "kill the EDR" into
     "bluescreen the machine," which is loud and recoverable but at
     least is not silent loss of protection.

  3. Kernel-side ObCallback (registered separately by the minifilter
     driver via ``MinifilterBridge.protect_pid``) strips
     PROCESS_TERMINATE/VM_WRITE access from non-self callers.  That
     is the strongest of the three because it works against attackers
     who hold SYSTEM but aren't a Protected Process Light.

The functions below are no-ops on non-Windows or when the required
APIs are unavailable; the caller does not need to gate on platform.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Iterable


def is_windows() -> bool:
    return platform.system() == "Windows"


def set_process_critical(enable: bool = True) -> bool:
    """Mark the current process as critical.  Returns True on success.

    Requires SeDebugPrivilege.  When running as a Windows service under
    LocalSystem this is granted automatically; running as a normal user
    will fail and we return False without raising.
    """
    if not is_windows():
        return False
    try:
        import ctypes
        ntdll = ctypes.WinDLL("ntdll.dll", use_last_error=True)
        # NTSTATUS RtlSetProcessIsCritical(BOOLEAN NewValue,
        #                                  PBOOLEAN OldValue OPTIONAL,
        #                                  BOOLEAN CheckFlag);
        ntdll.RtlSetProcessIsCritical.argtypes = [
            ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ubyte,
        ]
        ntdll.RtlSetProcessIsCritical.restype = ctypes.c_long
        # Enable SeDebugPrivilege first (best-effort; ignored on failure).
        _enable_privilege("SeDebugPrivilege")
        status = ntdll.RtlSetProcessIsCritical(1 if enable else 0, None, 0)
        return status == 0
    except Exception as e:
        print(f"[tamper] set_process_critical failed: {e}")
        return False


def _enable_privilege(name: str) -> bool:
    """Enable a privilege on the current process token."""
    if not is_windows():
        return False
    try:
        import ctypes
        from ctypes import wintypes

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        ):
            return False
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                return False
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            ok = advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(tp), 0, None, None
            )
            return bool(ok) and ctypes.get_last_error() == 0
        finally:
            kernel32.CloseHandle(token)
    except Exception:
        return False


# SDDL granting full control to SYSTEM and BUILTIN\Administrators,
# inheritable.  Nothing else can read, list, or modify the path.
_LOCKED_DOWN_SDDL = (
    "D:PAI"                                    # discretionary, protected (no inheritance from parent)
    "(A;OICI;FA;;;SY)"                         # SYSTEM: full, inherited by children
    "(A;OICI;FA;;;BA)"                         # Administrators: full, inherited
)


def lock_down_path(path: str | os.PathLike) -> bool:
    """Apply a restrictive DACL (SYSTEM + Admins only) to ``path``.

    The path can be a file or a directory; if a directory, the DACL
    inherits to children.  Returns True on success.  Silently no-ops
    on non-Windows.
    """
    if not is_windows():
        return False
    p = Path(path)
    if not p.exists():
        return False
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)

        # ConvertStringSecurityDescriptorToSecurityDescriptorW
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

        # SetFileSecurityW
        advapi32.SetFileSecurityW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
        ]
        advapi32.SetFileSecurityW.restype = wintypes.BOOL

        DACL_SECURITY_INFORMATION = 0x00000004
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

        sd_ptr = ctypes.c_void_p()
        sd_size = wintypes.DWORD(0)
        ok = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _LOCKED_DOWN_SDDL, 1,  # SDDL_REVISION_1
            ctypes.byref(sd_ptr), ctypes.byref(sd_size),
        )
        if not ok:
            return False
        try:
            res = advapi32.SetFileSecurityW(
                str(p),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd_ptr,
            )
            return bool(res)
        finally:
            ctypes.WinDLL("kernel32.dll").LocalFree(sd_ptr)
    except Exception as e:
        print(f"[tamper] lock_down_path({p}) failed: {e}")
        return False


def harden_paths(paths: Iterable[str | os.PathLike]) -> None:
    """Best-effort: apply lock_down_path to each path, log failures."""
    if not is_windows():
        return
    for path in paths:
        ok = lock_down_path(path)
        if ok:
            print(f"[tamper] locked DACL on {path}")
        else:
            print(f"[tamper] could not lock DACL on {path} "
                  f"(not admin? path missing?)")
