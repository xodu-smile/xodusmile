/*++

RmDetectorFlt.h

Shared contract between the kernel-mode minifilter and user-mode Python
agent. Both sides include / mirror this layout.

Communication uses a single FltMgr port. Messages are fixed-size records
so user-mode (ctypes) can parse them with struct.unpack().

This contract supports an EDR-grade workload: per-PID process telemetry,
image-load tracking, in-kernel entropy heuristics, suspicious-extension
rename guard, and autonomous process termination.

--*/

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#endif

/* ----- port + limits ------------------------------------------------ */

#define RM_PORT_NAME            L"\\RmDetectorPort"

/*
 * Path buffer length in WCHARs. NTFS supports paths up to ~32K but
 * realistic user paths sit well under this. We truncate above.
 */
#define RM_MAX_PATH_CHARS       520

/* How many watch roots / canary paths user-mode may push. */
#define RM_MAX_WATCH_PATHS      16
#define RM_MAX_CANARY_PATHS     128

/* How many ransomware-style extensions the kernel will reject on rename. */
#define RM_MAX_SUSP_EXTS        64

/* Longest individual suspicious extension (including dot). */
#define RM_MAX_EXT_CHARS        24

/* How many blocked / terminated PIDs the driver tracks. */
#define RM_MAX_BLOCKED_PIDS     256

/* How many live processes the driver tracks per-PID stats for. */
#define RM_MAX_TRACKED_PIDS     1024

/* Protocol version - bump if the structs below change. */
#define RM_PROTOCOL_VERSION     2

/* ----- event types (kernel -> user) -------------------------------- */

typedef enum _RM_EVENT_TYPE
{
    RmEventCreate           = 1,    /* file opened/created */
    RmEventWrite            = 2,    /* IRP_MJ_WRITE seen */
    RmEventRename           = 3,    /* SetInformation: rename */
    RmEventDelete           = 4,    /* SetInformation: delete-on-close */
    RmEventCleanup          = 5,    /* last handle closing */

    RmEventBlockedCanary    = 10,   /* driver vetoed a canary write/rename/delete */
    RmEventBlockedPid       = 11,   /* driver vetoed a write from a blocked PID */
    RmEventBlockedSuspExt   = 12,   /* rename into a suspicious extension */

    RmEventProcessStart     = 20,   /* PsSetCreateProcessNotifyRoutineEx: spawn */
    RmEventProcessExit      = 21,   /* process termination notify */
    RmEventImageLoad        = 22,   /* PsSetLoadImageNotifyRoutine */

    RmEventEntropySpike     = 30,   /* high-entropy write seen on watched path */
    RmEventScoreCritical    = 31,   /* in-kernel per-PID score crossed threshold */
    RmEventAutoTerminated   = 32,   /* driver called ZwTerminateProcess */
} RM_EVENT_TYPE;

/*
 * Bitflags on RM_EVENT.Flags
 */
#define RM_EVENT_FLAG_CREATE_NEW    0x0001  /* FILE_CREATE / SUPERSEDE / OVERWRITE */
#define RM_EVENT_FLAG_WRITE_ACCESS  0x0002  /* opened with write access */
#define RM_EVENT_FLAG_DELETE_ACCESS 0x0004  /* opened with delete access */
#define RM_EVENT_FLAG_CANARY        0x0010  /* path matched canary list */
#define RM_EVENT_FLAG_WATCHED       0x0020  /* path matched watch root */
#define RM_EVENT_FLAG_HIGH_ENTROPY  0x0040  /* sampled buffer entropy >= threshold */
#define RM_EVENT_FLAG_HEADER_CHANGED 0x0080 /* file magic bytes mutated */
#define RM_EVENT_FLAG_SYSTEM_PROC   0x0100  /* parent or image is a system process */
#define RM_EVENT_FLAG_SUSP_EXT      0x0200  /* path/new-name ends in a flagged extension */

#pragma pack(push, 8)

typedef struct _RM_EVENT
{
    ULONG               ProtocolVersion;    /* always RM_PROTOCOL_VERSION */
    ULONG               EventType;          /* RM_EVENT_TYPE */
    LONGLONG            TimestampUtc;       /* 100ns since 1601 (FILETIME) */

    /* Process identity. ParentProcessId is meaningful for ProcessStart
     * and is the spawning process; for file events it is the cached
     * parent of ProcessId (or 0 if not tracked). */
    ULONG               ProcessId;
    ULONG               ParentProcessId;
    ULONG               ThreadId;

    ULONG               Flags;              /* RM_EVENT_FLAG_* */
    ULONG               WriteSize;          /* bytes (write events only) */

    /* Per-PID rolling counters at the time of this event. Useful for
     * the dashboard and for explaining auto-terminate decisions. */
    ULONG               PidWriteCount;
    ULONG               PidDistinctExts;
    ULONG               PidEntropyHits;
    ULONG               PidScore;           /* in-kernel score */

    /* Shannon entropy of the sampled write buffer, x100 (so 7.85 -> 785).
     * 0 when not a write event. */
    ULONG               EntropyX100;

    ULONG               PathLength;         /* WCHARs in Path, no NUL */
    ULONG               ExtraLength;        /* WCHARs in Extra, no NUL */
    WCHAR               Path[RM_MAX_PATH_CHARS];
    WCHAR               Extra[RM_MAX_PATH_CHARS];   /* new name / image path / command line */
} RM_EVENT, *PRM_EVENT;

#pragma pack(pop)

/* ----- commands (user -> kernel) ----------------------------------- */

typedef enum _RM_COMMAND_TYPE
{
    RmCmdSetWatchPaths      = 1,    /* replace watch root list */
    RmCmdSetCanaryPaths     = 2,    /* replace canary file list */
    RmCmdBlockPid           = 3,    /* add PID to write deny list */
    RmCmdUnblockPid         = 4,    /* remove PID from deny list */
    RmCmdClearBlockedPids   = 5,    /* clear all blocked PIDs */
    RmCmdSetPolicy          = 6,    /* policy bitmask */
    RmCmdPing               = 7,    /* roundtrip / heartbeat */

    RmCmdSetSuspExts        = 8,    /* replace suspicious extension list */
    RmCmdTerminatePid       = 9,    /* ZwTerminateProcess by PID */
    RmCmdSetThresholds      = 10,   /* in-kernel scoring thresholds */
    RmCmdResetPidStats      = 11,   /* clear per-PID rolling stats */
} RM_COMMAND_TYPE;

/*
 * Policy bitmask. User-mode picks what behavior the driver enforces.
 * Default after connect: BLOCK_CANARY | EMIT_CREATES | EMIT_CLEANUPS |
 *                        TRACK_PROCESSES | ENTROPY_GUARD | BLOCK_SUSP_EXT |
 *                        AUTO_TERMINATE.
 */
#define RM_POLICY_BLOCK_CANARY      0x0001
#define RM_POLICY_BLOCK_PIDS        0x0002
#define RM_POLICY_EMIT_WRITES       0x0004
#define RM_POLICY_EMIT_CREATES      0x0008
#define RM_POLICY_EMIT_CLEANUPS     0x0010
#define RM_POLICY_TRACK_PROCESSES   0x0020  /* process / image notify callbacks */
#define RM_POLICY_ENTROPY_GUARD     0x0040  /* sample entropy on writes */
#define RM_POLICY_BLOCK_SUSP_EXT    0x0080  /* deny renames into flagged extensions */
#define RM_POLICY_AUTO_TERMINATE    0x0100  /* ZwTerminateProcess on score breach */
#define RM_POLICY_EMIT_IMAGE_LOADS  0x0200  /* image-load events upcalled */

#pragma pack(push, 8)

typedef struct _RM_COMMAND
{
    ULONG               ProtocolVersion;
    ULONG               CommandType;        /* RM_COMMAND_TYPE */

    /* Payload is interpreted per CommandType: */

    /* For RmCmdSetWatchPaths / RmCmdSetCanaryPaths / RmCmdSetSuspExts:
     *   PathCount = number of entries; Paths is a NUL-separated,
     *   double-NUL terminated buffer of lowercase NT-style paths or
     *   extensions (".locked\0.encrypted\0..." for SuspExts).
     */
    ULONG               PathCount;
    ULONG               PathBufferChars;    /* WCHARs in Paths, including NULs */

    /* For RmCmdBlockPid / RmCmdUnblockPid / RmCmdTerminatePid: single PID. */
    ULONG               Pid;

    /* For RmCmdSetPolicy: bitmask in Policy. */
    ULONG               Policy;

    /* For RmCmdSetThresholds. All four are in-kernel knobs:
     *   ScoreCritical    - per-PID kernel score that triggers auto-terminate
     *   EntropyThreshold - Shannon entropy x100 above which a write is
     *                      counted as "high entropy" (e.g. 750 ~ 7.50)
     *   DistinctExtAlert - distinct extensions touched before alert
     *   WriteBurstBytes  - total bytes a single PID may write across
     *                      watched paths before MEDIUM is emitted
     */
    ULONG               ScoreCritical;
    ULONG               EntropyThreshold;
    ULONG               DistinctExtAlert;
    ULONG               WriteBurstBytes;

    /* Inline path/ext buffer. */
    WCHAR               Paths[RM_MAX_PATH_CHARS * 8];
} RM_COMMAND, *PRM_COMMAND;

typedef struct _RM_REPLY
{
    LONG                Status;             /* NTSTATUS-ish; 0 = OK */
    ULONG               Detail;             /* command-specific echo */
} RM_REPLY, *PRM_REPLY;

#pragma pack(pop)
