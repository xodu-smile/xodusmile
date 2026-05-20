/*
 * RansomGuard.h
 *
 * Shared definitions between the kernel-mode minifilter and the user-mode
 * bridge.  Both sides include this file so the message layout stays in sync.
 *
 * The user-mode side accesses these structures through ctypes; the field
 * order and packing must therefore match a fixed-size, little-endian layout
 * on Windows x64.
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
#define RG_PROTOCOL_VERSION     1

/*
 * Event kinds that the driver reports up to user mode.  Stored as a 32-bit
 * value so the layout is stable across the port boundary.
 */
typedef enum _RG_EVENT_KIND {
    RgEventCreate    = 1,   // file opened (post-create)
    RgEventWrite     = 2,   // write completed
    RgEventSetInfo   = 3,   // rename / delete / set-info
    RgEventBlocked   = 4,   // we blocked an operation for a quarantined PID
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
 * The packet that travels through the filter port.  All paths are NUL-
 * terminated, in WCHAR, capped at RG_MAX_PATH_CHARS.  Numeric fields are
 * little-endian (Windows x64 only target).
 */
#pragma pack(push, 4)
typedef struct _RG_EVENT {
    ULONG    Version;        // = RG_PROTOCOL_VERSION
    ULONG    Kind;           // RG_EVENT_KIND
    ULONG    SubKind;        // RG_SETINFO_KIND when Kind == RgEventSetInfo
    ULONG    ProcessId;      // requesting PID
    ULONG    ThreadId;       // requesting TID
    ULONG    Status;         // NTSTATUS the operation completed with
    ULONGLONG WriteBytes;    // bytes written (RgEventWrite only)
    ULONGLONG TimestampNs;   // KeQueryPerformanceCounter normalized
    ULONG    PathLength;     // WCHARs in Path, including terminator
    WCHAR    Path[RG_MAX_PATH_CHARS];
} RG_EVENT, *PRG_EVENT;
#pragma pack(pop)

/*
 * Commands that user mode sends back to the driver.  Used to quarantine
 * a suspicious PID so subsequent file writes/renames from it are blocked.
 */
typedef enum _RG_COMMAND_KIND {
    RgCmdQuarantinePid  = 1,
    RgCmdReleasePid     = 2,
    RgCmdPing           = 3,
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
