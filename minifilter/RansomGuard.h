/*
 * RansomGuard.h
 *
 * Shared definitions between the kernel-mode minifilter and the user-mode
 * bridge.  Both sides include this file so the message layout stays in sync.
 *
 * The user-mode side accesses these structures through ctypes; the field
 * order and packing must therefore match a fixed-size, little-endian layout
 * on Windows x64.
 *
 * Protocol history:
 *   v1 — file IRP events only.
 *   v2 — adds process-create/exit, registry, and self-protection events;
 *        adds ParentProcessId and a secondary Extra buffer (used for
 *        command line and registry value name); adds ProtectPid command
 *        and a "sticky quarantine" model (the driver no longer flushes
 *        the quarantine list when the user-mode bridge disconnects).
 */

#pragma once

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#else
#include <windows.h>
#endif

#define RG_PORT_NAME            L"\\RansomGuardPort"
#define RG_DRIVER_NAME          L"RansomGuard"
#define RG_INSTANCE_NAME        L"RansomGuard Instance"
#define RG_ALTITUDE             L"385201"
#define RG_MAX_PATH_CHARS       520
#define RG_MAX_EXTRA_CHARS      1024
#define RG_PROTOCOL_VERSION     2

/*
 * Event kinds that the driver reports up to user mode.  Stored as a 32-bit
 * value so the layout is stable across the port boundary.
 */
typedef enum _RG_EVENT_KIND {
    RgEventCreate        = 1,   // file opened (post-create)
    RgEventWrite         = 2,   // write completed
    RgEventSetInfo       = 3,   // rename / delete / set-info
    RgEventBlocked       = 4,   // we blocked a file op for a quarantined PID
    RgEventProcessStart  = 5,   // PsSetCreateProcessNotifyRoutineEx — create
    RgEventProcessExit   = 6,   // PsSetCreateProcessNotifyRoutineEx — exit
    RgEventRegistry      = 7,   // CmRegisterCallbackEx — interesting key op
    RgEventTamperBlocked = 8,   // ObCallback stripped dangerous rights
} RG_EVENT_KIND;

/*
 * Sub-kinds for SetInformation so user mode does not have to keep its own
 * copy of FileInformationClass values.
 */
typedef enum _RG_SETINFO_KIND {
    RgSetInfoOther   = 0,
    RgSetInfoRename  = 1,
    RgSetInfoDelete  = 2,
} RG_SETINFO_KIND;

/*
 * Sub-kinds for registry events.  Mirrors the Cm REG_NOTIFY_CLASS values
 * but compressed to the ones we actually act on.
 */
typedef enum _RG_REGISTRY_KIND {
    RgRegOther        = 0,
    RgRegSetValue     = 1,
    RgRegDeleteValue  = 2,
    RgRegCreateKey    = 3,
    RgRegDeleteKey    = 4,
    RgRegRenameKey    = 5,
} RG_REGISTRY_KIND;

/*
 * Sub-kinds for the tamper-blocked event.  Lets user mode log which
 * access right was stripped (terminate vs. memory write etc.).
 */
typedef enum _RG_TAMPER_KIND {
    RgTamperProcess = 1,
    RgTamperThread  = 2,
} RG_TAMPER_KIND;

/*
 * The packet that travels through the filter port.  Fixed size so both
 * sides can ProbeForRead a flat buffer.  Path and Extra are NUL-
 * terminated WCHAR strings; ExtraLength is in WCHARs including the
 * terminator (0 if unused for the event kind).
 *
 * Field usage by kind:
 *   File* (1..4):  Path = file path,     Extra unused
 *   ProcessStart:  Path = image path,    Extra = command line
 *   ProcessExit:   Path = image path,    Extra unused
 *   Registry:      Path = key path,      Extra = value name (or empty)
 *   TamperBlocked: Path = requester img, Extra = stripped-access string
 */
#pragma pack(push, 4)
typedef struct _RG_EVENT {
    ULONG     Version;          // = RG_PROTOCOL_VERSION
    ULONG     Kind;             // RG_EVENT_KIND
    ULONG     SubKind;          // RG_SETINFO_KIND / RG_REGISTRY_KIND / RG_TAMPER_KIND
    ULONG     ProcessId;        // requesting / subject PID
    ULONG     ParentProcessId;  // parent PID (ProcessStart) or requester PID (Tamper)
    ULONG     ThreadId;
    ULONG     Status;           // NTSTATUS the operation completed with
    ULONG     DesiredAccess;    // for TamperBlocked (or 0)
    ULONGLONG WriteBytes;       // bytes written (RgEventWrite only)
    ULONGLONG TimestampNs;      // KeQueryPerformanceCounter normalized
    ULONG     PathLength;       // WCHARs in Path, including terminator
    ULONG     ExtraLength;      // WCHARs in Extra, including terminator (or 0)
    WCHAR     Path[RG_MAX_PATH_CHARS];
    WCHAR     Extra[RG_MAX_EXTRA_CHARS];
} RG_EVENT, *PRG_EVENT;
#pragma pack(pop)

/*
 * Commands that user mode sends back to the driver.
 *
 *   QuarantinePid / ReleasePid — file-op block list (existing).
 *   Ping                        — liveness check (existing).
 *   ProtectPid / UnprotectPid   — register the agent's own PID for
 *                                 handle-rights stripping by ObCallback.
 *                                 Multiple PIDs supported so the agent
 *                                 and watchdog can both be protected.
 *   FlushQuarantine             — user-mode opt-in to clear all
 *                                 quarantined PIDs (e.g. during clean
 *                                 service stop).  Without this command
 *                                 the kernel keeps the list across
 *                                 user-mode disconnects, which is the
 *                                 anti-tamper default in v2.
 */
typedef enum _RG_COMMAND_KIND {
    RgCmdQuarantinePid    = 1,
    RgCmdReleasePid       = 2,
    RgCmdPing             = 3,
    RgCmdProtectPid       = 4,
    RgCmdUnprotectPid     = 5,
    RgCmdFlushQuarantine  = 6,
} RG_COMMAND_KIND;

#pragma pack(push, 4)
typedef struct _RG_COMMAND {
    ULONG  Version;
    ULONG  Kind;
    ULONG  ProcessId;
    ULONG  Reserved;
} RG_COMMAND, *PRG_COMMAND;

typedef struct _RG_REPLY {
    ULONG  Status;     // 0 on success, non-zero on failure
    ULONG  Reserved;
} RG_REPLY, *PRG_REPLY;
#pragma pack(pop)
