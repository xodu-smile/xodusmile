/*++

RmDetectorFlt.c

Ransomware detection minifilter (EDR-grade PoC).

Pipeline:
  PsSetCreateProcessNotifyRoutineEx
                 -> emit RmEventProcessStart with parent PID, image, cmdline
                 -> allocate per-PID stats slot
                 -> emit RmEventProcessExit on termination, free slot

  PsSetLoadImageNotifyRoutine
                 -> emit RmEventImageLoad (DLL / EXE images)

  PostCreate     -> resolve normalized path, set StreamHandle context,
                    emit RmEventCreate, classify watched / canary

  PreWrite       -> if PID is blocked OR canary path -> STATUS_ACCESS_DENIED
                    else sample first 256 bytes -> Shannon-equivalent entropy
                          (distinct-byte heuristic). High entropy bumps the
                          per-PID score and emits RmEventEntropySpike.
                    accumulate distinct extensions per PID. Cross-thresholds
                    -> RmEventScoreCritical + (if AUTO_TERMINATE) async
                    ZwTerminateProcess.

  PreSetInfo     -> rename / delete-disposition on a canary path -> deny.
                    rename whose new name matches a suspicious extension
                    -> RmEventBlockedSuspExt + deny.

  PostCleanup    -> emit RmEventCleanup with aggregate write totals,
                    free StreamHandle context

Single FltMgr communication port (RM_PORT_NAME). User-mode pushes config
(watch roots, canary paths, suspicious extensions, block PIDs, policy,
thresholds) and receives events.

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include "RmDetectorFlt.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not applicable to kernel mode drivers")

/* ----- pool tag ----------------------------------------------------- */

#define RM_POOL_TAG     'tDmR'   /* 'RmDt' */

#define RM_DBG(_fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RmDetFlt] " _fmt "\n", ##__VA_ARGS__)

/* ----- in-kernel score model --------------------------------------- */

#define RM_SCORE_ENTROPY_HIT        5    /* one high-entropy write */
#define RM_SCORE_NEW_EXTENSION      3    /* first time seeing an ext for a PID */
#define RM_SCORE_SUSP_EXT_RENAME    30   /* renamed into .locked / .crypt / etc */
#define RM_SCORE_CANARY_BLOCK       60   /* canary file write / rename / delete */
#define RM_SCORE_BURST              15   /* cumulative bytes over threshold */

#define RM_DEFAULT_SCORE_CRITICAL   100
#define RM_DEFAULT_ENTROPY_X100     750   /* ~7.50 bits/byte */
#define RM_DEFAULT_DISTINCT_EXT     6
#define RM_DEFAULT_WRITE_BURST      (50 * 1024 * 1024)   /* 50 MB */

/* Bytes sampled per write to estimate entropy. */
#define RM_ENTROPY_SAMPLE_BYTES     256
/* Minimum distinct-byte count in a 256-byte sample to flag high entropy. */
#define RM_HIGH_ENTROPY_DISTINCT    192

/* ----- per-PID stats table ---------------------------------------- */

typedef struct _RM_PID_CTX
{
    ULONG       Pid;                /* 0 == free slot */
    ULONG       ParentPid;
    ULONG       WriteCount;
    ULONG       EntropyHits;
    ULONG       SuspRenameCount;
    ULONG       DistinctExtCount;
    ULONG64     TotalBytes;
    ULONG       Score;              /* in-kernel rolling score */
    BOOLEAN     BurstReported;
    BOOLEAN     TerminationQueued;
    BOOLEAN     IsSystemProc;
    /* 256-bit bitmap of seen extension hashes (FNV-1a 8-bit truncated). */
    UCHAR       ExtBitmap[32];
} RM_PID_CTX, *PRM_PID_CTX;

/* ----- globals ------------------------------------------------------ */

typedef struct _RM_GLOBALS
{
    PDRIVER_OBJECT      DriverObject;
    PFLT_FILTER         Filter;
    PFLT_PORT           ServerPort;
    PFLT_PORT           ClientPort;
    BOOLEAN             Connected;

    /* Config (guarded by ConfigLock) */
    EX_PUSH_LOCK        ConfigLock;
    ULONG               Policy;
    ULONG               WatchCount;
    UNICODE_STRING      WatchRoots[RM_MAX_WATCH_PATHS];
    PWCH                WatchRootBuffers[RM_MAX_WATCH_PATHS];
    ULONG               CanaryCount;
    UNICODE_STRING      CanaryPaths[RM_MAX_CANARY_PATHS];
    PWCH                CanaryPathBuffers[RM_MAX_CANARY_PATHS];
    ULONG               SuspExtCount;
    WCHAR               SuspExts[RM_MAX_SUSP_EXTS][RM_MAX_EXT_CHARS];

    /* Tunable thresholds (also guarded by ConfigLock for the writer side;
     * readers do a relaxed load -- these are ULONGs and the impact of a
     * torn read is benign). */
    ULONG               ScoreCritical;
    ULONG               EntropyThreshold;   /* x100 */
    ULONG               DistinctExtAlert;
    ULONG               WriteBurstBytes;

    /* Blocked PIDs (write deny list) */
    KSPIN_LOCK          PidLock;
    ULONG               BlockedPidCount;
    ULONG               BlockedPids[RM_MAX_BLOCKED_PIDS];

    /* Per-PID stats table (open-addressed, guarded by PidStatsLock) */
    KSPIN_LOCK          PidStatsLock;
    RM_PID_CTX          PidStats[RM_MAX_TRACKED_PIDS];

    /* Process notify state */
    BOOLEAN             ProcessNotifyArmed;
    BOOLEAN             ImageNotifyArmed;
} RM_GLOBALS;

static RM_GLOBALS g_Data;

/* ----- StreamHandle context ---------------------------------------- */

typedef struct _RM_STREAM_HANDLE_CTX
{
    BOOLEAN             IsWatched;
    BOOLEAN             IsCanary;
    BOOLEAN             CreatedNew;
    BOOLEAN             WriteAccess;
    ULONG               OwnerPid;
    ULONG               WriteCount;
    LONGLONG            BytesWritten;
    UNICODE_STRING      FullPath;
} RM_STREAM_HANDLE_CTX, *PRM_STREAM_HANDLE_CTX;

#define RM_STREAM_HANDLE_CTX_SIZE   sizeof(RM_STREAM_HANDLE_CTX)

/* ----- forward decls ------------------------------------------------ */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

NTSTATUS RmUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS RmInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                         _In_ DEVICE_TYPE VolumeDeviceType,
                         _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

NTSTATUS RmInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                 _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID RmInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                             _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID RmInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS RmPostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                                        _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_opt_ PVOID CompletionContext,
                                        _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS RmPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
                                     _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                     _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS RmPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
                                              _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                              _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS RmPostCleanup(_Inout_ PFLT_CALLBACK_DATA Data,
                                         _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                         _In_opt_ PVOID CompletionContext,
                                         _In_ FLT_POST_OPERATION_FLAGS Flags);

VOID RmContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);

NTSTATUS RmPortConnect(_In_ PFLT_PORT ClientPort,
                       _In_opt_ PVOID ServerPortCookie,
                       _In_opt_ PVOID ConnectionContext,
                       _In_ ULONG SizeOfContext,
                       _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);

VOID RmPortDisconnect(_In_opt_ PVOID ConnectionCookie);

NTSTATUS RmPortMessage(_In_opt_ PVOID PortCookie,
                       _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                       _In_ ULONG InputBufferLength,
                       _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
                       _In_ ULONG OutputBufferLength,
                       _Out_ PULONG ReturnOutputBufferLength);

VOID RmProcessNotifyEx(_Inout_ PEPROCESS Process,
                       _In_ HANDLE ProcessId,
                       _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID RmImageNotify(_In_opt_ PUNICODE_STRING FullImageName,
                   _In_ HANDLE ProcessId,
                   _In_ PIMAGE_INFO ImageInfo);

/* ----- registration ------------------------------------------------- */

CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, RmContextCleanup, RM_STREAM_HANDLE_CTX_SIZE, RM_POOL_TAG },
    { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,            0, NULL,                  RmPostCreate },
    { IRP_MJ_WRITE,             0, RmPreWrite,            NULL },
    { IRP_MJ_SET_INFORMATION,   0, RmPreSetInformation,   NULL },
    { IRP_MJ_CLEANUP,           0, NULL,                  RmPostCleanup },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration,
    Callbacks,
    RmUnload,
    RmInstanceSetup,
    RmInstanceQueryTeardown,
    RmInstanceTeardownStart,
    RmInstanceTeardownComplete,
    NULL, NULL, NULL, NULL
};

/* ----- small helpers ----------------------------------------------- */

static VOID
RmFreeUnicodeBuffer(_Inout_ PWCH *Buffer)
{
    if (*Buffer != NULL) {
        ExFreePoolWithTag(*Buffer, RM_POOL_TAG);
        *Buffer = NULL;
    }
}

static NTSTATUS
RmCopyDowncasedPath(
    _In_ PCWCH Src, _In_ USHORT SrcChars,
    _Out_ PUNICODE_STRING Dest, _Out_ PWCH *Buffer)
{
    PWCH buf;
    USHORT bytes;
    USHORT i;

    *Buffer = NULL;
    RtlZeroMemory(Dest, sizeof(*Dest));

    if (SrcChars == 0 || SrcChars > RM_MAX_PATH_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }
    bytes = (USHORT)(SrcChars * sizeof(WCHAR));
    buf = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, bytes, RM_POOL_TAG);
    if (buf == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    for (i = 0; i < SrcChars; ++i) {
        buf[i] = RtlDowncaseUnicodeChar(Src[i]);
    }
    Dest->Buffer = buf;
    Dest->Length = bytes;
    Dest->MaximumLength = bytes;
    *Buffer = buf;
    return STATUS_SUCCESS;
}

static BOOLEAN
RmPathStartsWith(_In_ PCUNICODE_STRING Path, _In_ PCUNICODE_STRING Prefix)
{
    UNICODE_STRING head;
    if (Path->Length < Prefix->Length || Prefix->Length == 0) return FALSE;
    head.Buffer = Path->Buffer;
    head.Length = Prefix->Length;
    head.MaximumLength = Prefix->Length;
    return RtlEqualUnicodeString(&head, Prefix, TRUE);
}

static BOOLEAN
RmIsWatched_Locked(_In_ PCUNICODE_STRING Path)
{
    ULONG i;
    for (i = 0; i < g_Data.WatchCount; ++i) {
        if (RmPathStartsWith(Path, &g_Data.WatchRoots[i])) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
RmIsCanary_Locked(_In_ PCUNICODE_STRING Path)
{
    ULONG i;
    for (i = 0; i < g_Data.CanaryCount; ++i) {
        if (RtlEqualUnicodeString(Path, &g_Data.CanaryPaths[i], TRUE)) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
RmIsPidBlocked(_In_ ULONG Pid)
{
    KIRQL irql;
    ULONG i;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_Data.PidLock, &irql);
    for (i = 0; i < g_Data.BlockedPidCount; ++i) {
        if (g_Data.BlockedPids[i] == Pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_Data.PidLock, irql);
    return found;
}

static VOID
RmClearWatchPaths_Locked(VOID)
{
    ULONG i;
    for (i = 0; i < RM_MAX_WATCH_PATHS; ++i) {
        RmFreeUnicodeBuffer(&g_Data.WatchRootBuffers[i]);
        RtlZeroMemory(&g_Data.WatchRoots[i], sizeof(UNICODE_STRING));
    }
    g_Data.WatchCount = 0;
}

static VOID
RmClearCanaryPaths_Locked(VOID)
{
    ULONG i;
    for (i = 0; i < RM_MAX_CANARY_PATHS; ++i) {
        RmFreeUnicodeBuffer(&g_Data.CanaryPathBuffers[i]);
        RtlZeroMemory(&g_Data.CanaryPaths[i], sizeof(UNICODE_STRING));
    }
    g_Data.CanaryCount = 0;
}

static NTSTATUS
RmLoadPathList_Locked(
    _In_ PCWCH Buffer, _In_ ULONG BufferChars, _In_ ULONG PathCount,
    _In_ ULONG MaxPaths,
    _Out_writes_(MaxPaths) PUNICODE_STRING Dest,
    _Out_writes_(MaxPaths) PWCH *DestBuffers,
    _Out_ PULONG OutCount)
{
    NTSTATUS status;
    ULONG i = 0;
    ULONG idx = 0;
    USHORT run;

    *OutCount = 0;
    if (PathCount > MaxPaths) return STATUS_BUFFER_OVERFLOW;

    while (i < PathCount && idx < BufferChars) {
        run = 0;
        while (idx + run < BufferChars && Buffer[idx + run] != L'\0' && run < RM_MAX_PATH_CHARS) {
            run++;
        }
        if (run == 0) { idx++; continue; }
        if (idx + run >= BufferChars || Buffer[idx + run] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
        status = RmCopyDowncasedPath(&Buffer[idx], run, &Dest[i], &DestBuffers[i]);
        if (!NT_SUCCESS(status)) return status;
        idx += run + 1;
        i++;
    }
    *OutCount = i;
    return STATUS_SUCCESS;
}

static NTSTATUS
RmLoadSuspExts_Locked(
    _In_ PCWCH Buffer, _In_ ULONG BufferChars, _In_ ULONG PathCount)
{
    ULONG i = 0;
    ULONG idx = 0;
    USHORT run;
    USHORT k;

    g_Data.SuspExtCount = 0;
    if (PathCount > RM_MAX_SUSP_EXTS) return STATUS_BUFFER_OVERFLOW;
    RtlZeroMemory(g_Data.SuspExts, sizeof(g_Data.SuspExts));

    while (i < PathCount && idx < BufferChars) {
        run = 0;
        while (idx + run < BufferChars && Buffer[idx + run] != L'\0' && run < RM_MAX_EXT_CHARS - 1) {
            run++;
        }
        if (run == 0) { idx++; continue; }
        if (idx + run >= BufferChars || Buffer[idx + run] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
        for (k = 0; k < run; ++k) {
            g_Data.SuspExts[i][k] = RtlDowncaseUnicodeChar(Buffer[idx + k]);
        }
        g_Data.SuspExts[i][run] = L'\0';
        idx += run + 1;
        i++;
    }
    g_Data.SuspExtCount = i;
    return STATUS_SUCCESS;
}

/*
 * Match the suffix of (lowercased) `Name` against the suspicious extension
 * list. Returns TRUE on hit. Caller holds ConfigLock shared.
 */
static BOOLEAN
RmEndsWithSuspExt_Locked(_In_ PCUNICODE_STRING Name)
{
    ULONG i;
    USHORT extLen;
    USHORT nameLen = (USHORT)(Name->Length / sizeof(WCHAR));
    PCWCH tail;

    for (i = 0; i < g_Data.SuspExtCount; ++i) {
        const WCHAR *ext = g_Data.SuspExts[i];
        for (extLen = 0; extLen < RM_MAX_EXT_CHARS && ext[extLen] != L'\0'; ++extLen) {}
        if (extLen == 0 || extLen > nameLen) continue;
        tail = &Name->Buffer[nameLen - extLen];
        {
            USHORT k;
            BOOLEAN eq = TRUE;
            for (k = 0; k < extLen; ++k) {
                if (RtlDowncaseUnicodeChar(tail[k]) != ext[k]) { eq = FALSE; break; }
            }
            if (eq) return TRUE;
        }
    }
    return FALSE;
}

/* ----- per-PID stats ------------------------------------------------ */

static __forceinline ULONG
RmHashPid(_In_ ULONG Pid)
{
    ULONG h = Pid * 2654435761u;
    return h % RM_MAX_TRACKED_PIDS;
}

/*
 * Find an existing slot for Pid or claim a free one. Returns NULL if the
 * table is full (very unlikely with RM_MAX_TRACKED_PIDS = 1024). Caller
 * holds PidStatsLock.
 */
static PRM_PID_CTX
RmPidCtxLookup_Locked(_In_ ULONG Pid, _In_ BOOLEAN Create)
{
    ULONG idx = RmHashPid(Pid);
    ULONG probes = 0;

    if (Pid == 0) return NULL;

    while (probes < RM_MAX_TRACKED_PIDS) {
        PRM_PID_CTX slot = &g_Data.PidStats[idx];
        if (slot->Pid == Pid) return slot;
        if (slot->Pid == 0) {
            if (!Create) return NULL;
            RtlZeroMemory(slot, sizeof(*slot));
            slot->Pid = Pid;
            return slot;
        }
        idx = (idx + 1) % RM_MAX_TRACKED_PIDS;
        probes++;
    }
    return NULL;
}

static VOID
RmPidCtxRelease_Locked(_In_ ULONG Pid)
{
    PRM_PID_CTX slot = RmPidCtxLookup_Locked(Pid, FALSE);
    if (slot != NULL) {
        RtlZeroMemory(slot, sizeof(*slot));
    }
}

/* FNV-1a 32-bit truncated to 8 bits, for the per-PID extension bitmap. */
static UCHAR
RmExtHash(_In_ PCWCH Ext, _In_ USHORT Chars)
{
    ULONG h = 2166136261u;
    USHORT i;
    for (i = 0; i < Chars; ++i) {
        WCHAR c = RtlDowncaseUnicodeChar(Ext[i]);
        h ^= (UCHAR)(c & 0xff);
        h *= 16777619u;
        h ^= (UCHAR)((c >> 8) & 0xff);
        h *= 16777619u;
    }
    return (UCHAR)(h & 0xff);
}

/* Returns TRUE if the bit was newly set (first time seeing this extension). */
static BOOLEAN
RmPidMarkExt_Locked(_Inout_ PRM_PID_CTX Ctx, _In_ UCHAR ExtHash)
{
    UCHAR mask = (UCHAR)(1u << (ExtHash & 7));
    UCHAR *byte = &Ctx->ExtBitmap[ExtHash >> 3];
    if ((*byte & mask) == 0) {
        *byte |= mask;
        Ctx->DistinctExtCount++;
        return TRUE;
    }
    return FALSE;
}

/* Extract the last "." segment of a normalized path. Returns 0 if none. */
static USHORT
RmPathExtension(_In_ PCUNICODE_STRING Path, _Out_ PCWCH *Out)
{
    USHORT chars = (USHORT)(Path->Length / sizeof(WCHAR));
    USHORT i;
    *Out = NULL;
    if (chars < 2) return 0;
    for (i = chars; i > 0; --i) {
        WCHAR c = Path->Buffer[i - 1];
        if (c == L'\\' || c == L'/') return 0;
        if (c == L'.') {
            if (i == chars) return 0;
            *Out = &Path->Buffer[i - 1];
            return (USHORT)(chars - (i - 1));
        }
    }
    return 0;
}

/* ----- event emission ---------------------------------------------- */

static VOID
RmFillCommonEvent(
    _Out_ PRM_EVENT Event, _In_ RM_EVENT_TYPE Type, _In_ ULONG Flags,
    _In_opt_ PCUNICODE_STRING Path, _In_opt_ PCUNICODE_STRING Extra)
{
    LARGE_INTEGER now;
    USHORT len;

    RtlZeroMemory(Event, sizeof(*Event));
    Event->ProtocolVersion = RM_PROTOCOL_VERSION;
    Event->EventType = (ULONG)Type;
    Event->Flags = Flags;

    KeQuerySystemTimePrecise(&now);
    Event->TimestampUtc = now.QuadPart;

    Event->ProcessId = HandleToULong(PsGetCurrentProcessId());
    Event->ThreadId  = HandleToULong(PsGetCurrentThreadId());

    if (Path != NULL && Path->Length > 0) {
        len = Path->Length;
        if (len > RM_MAX_PATH_CHARS * sizeof(WCHAR)) len = RM_MAX_PATH_CHARS * sizeof(WCHAR);
        RtlCopyMemory(Event->Path, Path->Buffer, len);
        Event->PathLength = len / sizeof(WCHAR);
    }
    if (Extra != NULL && Extra->Length > 0) {
        len = Extra->Length;
        if (len > RM_MAX_PATH_CHARS * sizeof(WCHAR)) len = RM_MAX_PATH_CHARS * sizeof(WCHAR);
        RtlCopyMemory(Event->Extra, Extra->Buffer, len);
        Event->ExtraLength = len / sizeof(WCHAR);
    }
}

static VOID
RmSendEvent(_In_ PRM_EVENT Event)
{
    NTSTATUS status;
    LARGE_INTEGER timeout;

    if (!g_Data.Connected || g_Data.ClientPort == NULL) return;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return;

    timeout.QuadPart = -(LONGLONG)50 * 10000;   /* 50 ms */
    status = FltSendMessage(
        g_Data.Filter, &g_Data.ClientPort,
        Event, sizeof(*Event),
        NULL, NULL, &timeout);
    if (!NT_SUCCESS(status) && status != STATUS_TIMEOUT) {
        RM_DBG("FltSendMessage failed 0x%x", status);
    }
}

/*
 * Decorate an event with per-PID stats. Caller has already filled the
 * common fields. The decorate step takes the PidStatsLock so it is safe
 * from IRQL <= DISPATCH.
 */
static VOID
RmEventDecorateWithPid(_Inout_ PRM_EVENT Event, _In_ ULONG Pid)
{
    KIRQL irql;
    PRM_PID_CTX slot;

    KeAcquireSpinLock(&g_Data.PidStatsLock, &irql);
    slot = RmPidCtxLookup_Locked(Pid, FALSE);
    if (slot != NULL) {
        Event->ParentProcessId  = slot->ParentPid;
        Event->PidWriteCount    = slot->WriteCount;
        Event->PidDistinctExts  = slot->DistinctExtCount;
        Event->PidEntropyHits   = slot->EntropyHits;
        Event->PidScore         = slot->Score;
        if (slot->IsSystemProc) Event->Flags |= RM_EVENT_FLAG_SYSTEM_PROC;
    }
    KeReleaseSpinLock(&g_Data.PidStatsLock, irql);
}

/* ----- async terminate work item ----------------------------------- */

typedef struct _RM_TERMINATE_WORK
{
    PIO_WORKITEM    WorkItem;
    ULONG           Pid;
} RM_TERMINATE_WORK, *PRM_TERMINATE_WORK;

static VOID
RmTerminateWorker(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    PRM_TERMINATE_WORK work = (PRM_TERMINATE_WORK)Context;
    HANDLE hProc = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);
    if (work == NULL) return;

    cid.UniqueProcess = ULongToHandle(work->Pid);
    cid.UniqueThread = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid);
    if (NT_SUCCESS(status)) {
        /* STATUS_UNSUCCESSFUL == 0xC0000001 -- visible to Event Viewer as
         * the termination reason without needing ntstatus.h here. */
        ZwTerminateProcess(hProc, STATUS_UNSUCCESSFUL);
        ZwClose(hProc);
        RM_DBG("auto-terminated pid=%lu", work->Pid);
    } else {
        RM_DBG("ZwOpenProcess(pid=%lu) failed 0x%x", work->Pid, status);
    }

    IoFreeWorkItem(work->WorkItem);
    ExFreePoolWithTag(work, RM_POOL_TAG);
}

static VOID
RmQueueTerminate(_In_ ULONG Pid)
{
    PRM_TERMINATE_WORK work;

    if (Pid == 0 || g_Data.DriverObject == NULL) return;
    if (g_Data.DriverObject->DeviceObject == NULL) return;

    work = (PRM_TERMINATE_WORK)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*work), RM_POOL_TAG);
    if (work == NULL) return;

    work->WorkItem = IoAllocateWorkItem(g_Data.DriverObject->DeviceObject);
    if (work->WorkItem == NULL) {
        ExFreePoolWithTag(work, RM_POOL_TAG);
        return;
    }
    work->Pid = Pid;
    IoQueueWorkItem(work->WorkItem, RmTerminateWorker, DelayedWorkQueue, work);
}

/*
 * Apply a score delta. If the new score crosses ScoreCritical and the
 * PID hasn't already been queued for termination, emit RmEventScoreCritical
 * and (if AUTO_TERMINATE policy is on) queue ZwTerminateProcess.
 * Caller does NOT hold PidStatsLock.
 *
 * Returns the new score for convenience.
 */
static ULONG
RmPidApplyScore(
    _In_ ULONG Pid, _In_ ULONG Delta,
    _In_opt_ PCUNICODE_STRING Path)
{
    KIRQL irql;
    PRM_PID_CTX slot;
    ULONG newScore = 0;
    BOOLEAN crossed = FALSE;
    BOOLEAN queueTerm = FALSE;
    RM_EVENT evt;

    KeAcquireSpinLock(&g_Data.PidStatsLock, &irql);
    slot = RmPidCtxLookup_Locked(Pid, TRUE);
    if (slot != NULL) {
        slot->Score += Delta;
        newScore = slot->Score;
        if (newScore >= g_Data.ScoreCritical && !slot->TerminationQueued) {
            crossed = TRUE;
            slot->TerminationQueued = TRUE;
            queueTerm = (g_Data.Policy & RM_POLICY_AUTO_TERMINATE) != 0;
        }
    }
    KeReleaseSpinLock(&g_Data.PidStatsLock, irql);

    if (crossed && KeGetCurrentIrql() <= PASSIVE_LEVEL) {
        RmFillCommonEvent(&evt, RmEventScoreCritical, 0, Path, NULL);
        evt.ProcessId = Pid;
        RmEventDecorateWithPid(&evt, Pid);
        RmSendEvent(&evt);

        if (queueTerm) {
            RmFillCommonEvent(&evt, RmEventAutoTerminated, 0, Path, NULL);
            evt.ProcessId = Pid;
            RmEventDecorateWithPid(&evt, Pid);
            RmSendEvent(&evt);
        }
    }
    if (queueTerm) {
        RmQueueTerminate(Pid);
    }
    return newScore;
}

/* ----- entropy sampling -------------------------------------------- */

/*
 * Crude byte-distinctness heuristic. Returns an entropy-equivalent value
 * scaled x100 (0..800), where ~800 corresponds to maximum diversity
 * (Shannon ~8 bits/byte). Avoids floating-point in kernel.
 */
static ULONG
RmSampleEntropyX100(_In_reads_bytes_(Len) const UCHAR *Buf, _In_ ULONG Len)
{
    UCHAR hist[256];
    ULONG distinct = 0;
    ULONG i;

    if (Len == 0) return 0;
    if (Len > RM_ENTROPY_SAMPLE_BYTES) Len = RM_ENTROPY_SAMPLE_BYTES;

    RtlZeroMemory(hist, sizeof(hist));
    for (i = 0; i < Len; ++i) {
        if (hist[Buf[i]] == 0) {
            hist[Buf[i]] = 1;
            distinct++;
        }
    }
    return (distinct * 800) / 256;
}

/*
 * Try to map the first N bytes of the IRP_MJ_WRITE buffer. Returns NULL
 * if not safe to read.
 */
static const UCHAR *
RmMapWritePrefix(
    _In_ PFLT_CALLBACK_DATA Data, _In_ ULONG MaxLen, _Out_ PULONG OutLen)
{
    PVOID buf = NULL;
    ULONG len = Data->Iopb->Parameters.Write.Length;

    if (len == 0) { *OutLen = 0; return NULL; }
    if (len > MaxLen) len = MaxLen;

    if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
        buf = MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
    } else {
        buf = Data->Iopb->Parameters.Write.WriteBuffer;
    }
    if (buf == NULL) { *OutLen = 0; return NULL; }

    *OutLen = len;
    return (const UCHAR *)buf;
}

/* ----- path resolution ---------------------------------------------- */

static NTSTATUS
RmGetNormalizedPath(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING Out, _Out_ PWCH *Buffer)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION fni = NULL;

    *Buffer = NULL;
    RtlZeroMemory(Out, sizeof(*Out));

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fni);
    if (!NT_SUCCESS(status)) return status;

    status = RmCopyDowncasedPath(
        fni->Name.Buffer, fni->Name.Length / sizeof(WCHAR), Out, Buffer);
    FltReleaseFileNameInformation(fni);
    return status;
}

/* ----- IRP callbacks ----------------------------------------------- */

FLT_POSTOP_CALLBACK_STATUS
RmPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    NTSTATUS status;
    UNICODE_STRING path;
    PWCH pathBuf = NULL;
    PRM_STREAM_HANDLE_CTX ctx = NULL;
    BOOLEAN isWatched, isCanary;
    ULONG createOpts, disposition, desiredAccess;
    ULONG eventFlags = 0;
    RM_EVENT evt;
    BOOLEAN ctxAttached = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_POSTOP_FINISHED_PROCESSING;

    status = RmGetNormalizedPath(Data, &path, &pathBuf);
    if (!NT_SUCCESS(status)) return FLT_POSTOP_FINISHED_PROCESSING;

    FltAcquirePushLockShared(&g_Data.ConfigLock);
    isWatched = RmIsWatched_Locked(&path);
    isCanary  = isWatched ? RmIsCanary_Locked(&path) : FALSE;
    FltReleasePushLock(&g_Data.ConfigLock);

    if (!isWatched && !isCanary) {
        RmFreeUnicodeBuffer(&pathBuf);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    createOpts    = Data->Iopb->Parameters.Create.Options;
    disposition   = (createOpts >> 24) & 0x000000ff;
    /* SecurityContext can be NULL for some kernel-initiated opens. */
    desiredAccess = (Data->Iopb->Parameters.Create.SecurityContext != NULL)
        ? Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess
        : 0;

    if (disposition == FILE_CREATE || disposition == FILE_SUPERSEDE ||
        disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF) {
        eventFlags |= RM_EVENT_FLAG_CREATE_NEW;
    }
    if (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) {
        eventFlags |= RM_EVENT_FLAG_WRITE_ACCESS;
    }
    if (desiredAccess & (DELETE | FILE_WRITE_ATTRIBUTES)) {
        eventFlags |= RM_EVENT_FLAG_DELETE_ACCESS;
    }
    if (isCanary)  eventFlags |= RM_EVENT_FLAG_CANARY;
    if (isWatched) eventFlags |= RM_EVENT_FLAG_WATCHED;

    status = FltAllocateContext(g_Data.Filter, FLT_STREAMHANDLE_CONTEXT,
        RM_STREAM_HANDLE_CTX_SIZE, PagedPool, (PFLT_CONTEXT *)&ctx);
    if (NT_SUCCESS(status)) {
        RtlZeroMemory(ctx, RM_STREAM_HANDLE_CTX_SIZE);
        ctx->IsWatched   = isWatched;
        ctx->IsCanary    = isCanary;
        ctx->CreatedNew  = (eventFlags & RM_EVENT_FLAG_CREATE_NEW) != 0;
        ctx->WriteAccess = (eventFlags & RM_EVENT_FLAG_WRITE_ACCESS) != 0;
        ctx->OwnerPid    = HandleToULong(PsGetCurrentProcessId());
        ctx->FullPath = path;
        pathBuf = NULL;

        status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
        if (NT_SUCCESS(status) || status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            ctxAttached = TRUE;
        } else {
            RmFreeUnicodeBuffer(&ctx->FullPath.Buffer);
        }
        FltReleaseContext(ctx);
    }

    FltAcquirePushLockShared(&g_Data.ConfigLock);
    if (g_Data.Policy & RM_POLICY_EMIT_CREATES) {
        RmFillCommonEvent(&evt, RmEventCreate, eventFlags, &path, NULL);
        FltReleasePushLock(&g_Data.ConfigLock);
        RmEventDecorateWithPid(&evt, evt.ProcessId);
        RmSendEvent(&evt);
    } else {
        FltReleasePushLock(&g_Data.ConfigLock);
    }

    if (!ctxAttached) RmFreeUnicodeBuffer(&pathBuf);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
RmPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    NTSTATUS status;
    PRM_STREAM_HANDLE_CTX ctx = NULL;
    ULONG pid;
    ULONG writeLen;
    BOOLEAN block = FALSE;
    RM_EVENT evt;
    ULONG entropyX100 = 0;
    BOOLEAN highEntropy = FALSE;
    ULONG policy;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                       (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status) || ctx == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!ctx->IsWatched && !ctx->IsCanary) {
        FltReleaseContext(ctx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = HandleToULong(PsGetCurrentProcessId());
    writeLen = Data->Iopb->Parameters.Write.Length;
    policy = g_Data.Policy;

    /* Canary block */
    if (ctx->IsCanary && (policy & RM_POLICY_BLOCK_CANARY)) {
        block = TRUE;
        RmFillCommonEvent(&evt, RmEventBlockedCanary,
                          RM_EVENT_FLAG_CANARY | RM_EVENT_FLAG_WRITE_ACCESS,
                          &ctx->FullPath, NULL);
        evt.WriteSize = writeLen;
    }
    /* PID block */
    else if ((policy & RM_POLICY_BLOCK_PIDS) && RmIsPidBlocked(pid)) {
        block = TRUE;
        RmFillCommonEvent(&evt, RmEventBlockedPid,
                          RM_EVENT_FLAG_WRITE_ACCESS,
                          &ctx->FullPath, NULL);
        evt.WriteSize = writeLen;
    }

    if (block) {
        RmEventDecorateWithPid(&evt, pid);
        RmSendEvent(&evt);
        if (evt.EventType == RmEventBlockedCanary) {
            RmPidApplyScore(pid, RM_SCORE_CANARY_BLOCK, &ctx->FullPath);
        }
        FltReleaseContext(ctx);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    InterlockedIncrement((volatile LONG *)&ctx->WriteCount);
    InterlockedExchangeAdd64(&ctx->BytesWritten, writeLen);

    /* Entropy sampling */
    if ((policy & RM_POLICY_ENTROPY_GUARD) && ctx->IsWatched && writeLen >= 64) {
        ULONG sampled = 0;
        const UCHAR *prefix;
        __try {
            prefix = RmMapWritePrefix(Data, RM_ENTROPY_SAMPLE_BYTES, &sampled);
            if (prefix != NULL && sampled >= 64) {
                entropyX100 = RmSampleEntropyX100(prefix, sampled);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            entropyX100 = 0;
        }
        if (entropyX100 >= g_Data.EntropyThreshold) {
            highEntropy = TRUE;
        }
    }

    /* Per-PID stats update */
    {
        KIRQL irql;
        PRM_PID_CTX slot;
        PCWCH ext;
        USHORT extChars;
        BOOLEAN newExt = FALSE;
        BOOLEAN burstNow = FALSE;
        ULONG scoreDelta = 0;

        extChars = RmPathExtension(&ctx->FullPath, &ext);

        KeAcquireSpinLock(&g_Data.PidStatsLock, &irql);
        slot = RmPidCtxLookup_Locked(pid, TRUE);
        if (slot != NULL) {
            slot->WriteCount++;
            slot->TotalBytes += writeLen;
            if (highEntropy) slot->EntropyHits++;
            if (extChars > 0) {
                UCHAR h = RmExtHash(ext, extChars);
                if (RmPidMarkExt_Locked(slot, h)) newExt = TRUE;
            }
            if (!slot->BurstReported && slot->TotalBytes >= g_Data.WriteBurstBytes) {
                slot->BurstReported = TRUE;
                burstNow = TRUE;
            }
        }
        KeReleaseSpinLock(&g_Data.PidStatsLock, irql);

        if (highEntropy) scoreDelta += RM_SCORE_ENTROPY_HIT;
        if (newExt)      scoreDelta += RM_SCORE_NEW_EXTENSION;
        if (burstNow)    scoreDelta += RM_SCORE_BURST;

        if (highEntropy && KeGetCurrentIrql() <= PASSIVE_LEVEL) {
            RmFillCommonEvent(&evt, RmEventEntropySpike,
                              RM_EVENT_FLAG_WATCHED | RM_EVENT_FLAG_WRITE_ACCESS |
                              RM_EVENT_FLAG_HIGH_ENTROPY,
                              &ctx->FullPath, NULL);
            evt.WriteSize = writeLen;
            evt.EntropyX100 = entropyX100;
            evt.ProcessId = pid;
            RmEventDecorateWithPid(&evt, pid);
            RmSendEvent(&evt);
        }

        if (scoreDelta > 0) {
            RmPidApplyScore(pid, scoreDelta, &ctx->FullPath);
        }
    }

    FltReleaseContext(ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
RmPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    NTSTATUS status;
    PRM_STREAM_HANDLE_CTX ctx = NULL;
    FILE_INFORMATION_CLASS infoClass;
    PFILE_RENAME_INFORMATION rename;
    UNICODE_STRING newName;
    BOOLEAN isDelete = FALSE, isRename = FALSE;
    BOOLEAN deleteOn = FALSE;
    BOOLEAN block = FALSE;
    BOOLEAN suspExtHit = FALSE;
    RM_EVENT evt;
    ULONG eventFlags = 0;
    ULONG pid;

    UNREFERENCED_PARAMETER(CompletionContext);

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        isRename = TRUE;
    } else if (infoClass == FileDispositionInformation) {
        isDelete = TRUE;
        deleteOn = ((PFILE_DISPOSITION_INFORMATION)
                    Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile != FALSE;
    } else if (infoClass == FileDispositionInformationEx) {
        isDelete = TRUE;
        deleteOn = (((PFILE_DISPOSITION_INFORMATION_EX)
                     Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->Flags
                    & FILE_DISPOSITION_DELETE) != 0;
    } else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (isDelete && !deleteOn) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                       (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status) || ctx == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!ctx->IsWatched && !ctx->IsCanary) {
        FltReleaseContext(ctx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = HandleToULong(PsGetCurrentProcessId());
    eventFlags = ctx->IsCanary ? RM_EVENT_FLAG_CANARY : RM_EVENT_FLAG_WATCHED;

    /* Canary rename/delete -> deny unconditionally if policy enabled. */
    if (ctx->IsCanary && (g_Data.Policy & RM_POLICY_BLOCK_CANARY)) {
        block = TRUE;
    }

    if (isRename) {
        ULONG fnameBytes;
        rename = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        fnameBytes = rename->FileNameLength;
        if (fnameBytes > MAXUSHORT) fnameBytes = MAXUSHORT & ~1u;
        newName.Buffer = rename->FileName;
        newName.Length = (USHORT)fnameBytes;
        newName.MaximumLength = newName.Length;

        if ((g_Data.Policy & RM_POLICY_BLOCK_SUSP_EXT) && ctx->IsWatched) {
            FltAcquirePushLockShared(&g_Data.ConfigLock);
            suspExtHit = RmEndsWithSuspExt_Locked(&newName);
            FltReleasePushLock(&g_Data.ConfigLock);
            if (suspExtHit) {
                block = TRUE;
                eventFlags |= RM_EVENT_FLAG_SUSP_EXT;
            }
        }

        RmFillCommonEvent(&evt,
            suspExtHit ? RmEventBlockedSuspExt :
                         (block ? RmEventBlockedCanary : RmEventRename),
            eventFlags, &ctx->FullPath, &newName);
    } else {
        RmFillCommonEvent(&evt,
            block ? RmEventBlockedCanary : RmEventDelete,
            eventFlags, &ctx->FullPath, NULL);
    }

    evt.ProcessId = pid;
    RmEventDecorateWithPid(&evt, pid);
    RmSendEvent(&evt);

    if (suspExtHit) {
        RmPidApplyScore(pid, RM_SCORE_SUSP_EXT_RENAME, &ctx->FullPath);
    } else if (block) {
        RmPidApplyScore(pid, RM_SCORE_CANARY_BLOCK, &ctx->FullPath);
    }
    FltReleaseContext(ctx);

    if (block) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
RmPostCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    NTSTATUS status;
    PRM_STREAM_HANDLE_CTX ctx = NULL;
    RM_EVENT evt;
    BOOLEAN emit;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_POSTOP_FINISHED_PROCESSING;

    status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                       (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status) || ctx == NULL) return FLT_POSTOP_FINISHED_PROCESSING;

    FltAcquirePushLockShared(&g_Data.ConfigLock);
    emit = (g_Data.Policy & RM_POLICY_EMIT_CLEANUPS) != 0;
    FltReleasePushLock(&g_Data.ConfigLock);

    if (emit && (ctx->WriteCount > 0 || ctx->CreatedNew)) {
        ULONG flags = 0;
        if (ctx->IsCanary)     flags |= RM_EVENT_FLAG_CANARY;
        if (ctx->IsWatched)    flags |= RM_EVENT_FLAG_WATCHED;
        if (ctx->CreatedNew)   flags |= RM_EVENT_FLAG_CREATE_NEW;
        if (ctx->WriteAccess)  flags |= RM_EVENT_FLAG_WRITE_ACCESS;

        RmFillCommonEvent(&evt, RmEventCleanup, flags, &ctx->FullPath, NULL);
        evt.WriteSize = (ULONG)ctx->BytesWritten;
        evt.ProcessId = ctx->OwnerPid;
        RmEventDecorateWithPid(&evt, ctx->OwnerPid);
        RmSendEvent(&evt);
    }

    FltReleaseContext(ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID
RmContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    PRM_STREAM_HANDLE_CTX ctx = (PRM_STREAM_HANDLE_CTX)Context;
    if (ContextType != FLT_STREAMHANDLE_CONTEXT) return;
    if (ctx->FullPath.Buffer != NULL) {
        ExFreePoolWithTag(ctx->FullPath.Buffer, RM_POOL_TAG);
        ctx->FullPath.Buffer = NULL;
    }
}

/* ----- process / image notify callbacks ----------------------------- */

VOID
RmProcessNotifyEx(
    _Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid = HandleToULong(ProcessId);
    RM_EVENT evt;
    KIRQL irql;
    PRM_PID_CTX slot;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        /* Process start */
        ULONG parent = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
        UNICODE_STRING image = { 0 };
        UNICODE_STRING cmdline = { 0 };

        if (CreateInfo->ImageFileName != NULL) image = *CreateInfo->ImageFileName;
        if (CreateInfo->CommandLine != NULL)    cmdline = *CreateInfo->CommandLine;

        KeAcquireSpinLock(&g_Data.PidStatsLock, &irql);
        slot = RmPidCtxLookup_Locked(pid, TRUE);
        if (slot != NULL) {
            slot->ParentPid = parent;
            /* Heuristic: image path under \windows\system32 / syswow64 -> system */
            if (image.Length > 0) {
                UNICODE_STRING sys32 = RTL_CONSTANT_STRING(L"\\windows\\system32\\");
                slot->IsSystemProc = RmPathStartsWith(&image, &sys32);
            }
        }
        KeReleaseSpinLock(&g_Data.PidStatsLock, irql);

        if (g_Data.Policy & RM_POLICY_TRACK_PROCESSES) {
            RmFillCommonEvent(&evt, RmEventProcessStart, 0, &image, &cmdline);
            evt.ProcessId = pid;
            evt.ParentProcessId = parent;
            RmSendEvent(&evt);
        }
    } else {
        /* Process exit */
        if (g_Data.Policy & RM_POLICY_TRACK_PROCESSES) {
            RmFillCommonEvent(&evt, RmEventProcessExit, 0, NULL, NULL);
            evt.ProcessId = pid;
            RmEventDecorateWithPid(&evt, pid);
            RmSendEvent(&evt);
        }
        KeAcquireSpinLock(&g_Data.PidStatsLock, &irql);
        RmPidCtxRelease_Locked(pid);
        KeReleaseSpinLock(&g_Data.PidStatsLock, irql);
    }
}

VOID
RmImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    RM_EVENT evt;
    UNICODE_STRING image = { 0 };
    ULONG pid = HandleToULong(ProcessId);

    UNREFERENCED_PARAMETER(ImageInfo);

    if (!(g_Data.Policy & RM_POLICY_EMIT_IMAGE_LOADS)) return;
    if (FullImageName != NULL) image = *FullImageName;

    RmFillCommonEvent(&evt, RmEventImageLoad, 0, &image, NULL);
    evt.ProcessId = pid;
    RmEventDecorateWithPid(&evt, pid);
    RmSendEvent(&evt);
}

/* ----- instance lifecycle ------------------------------------------ */

NTSTATUS
RmInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                _In_ DEVICE_TYPE VolumeDeviceType,
                _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) return STATUS_FLT_DO_NOT_ATTACH;
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS && VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
RmInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

VOID RmInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                             _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{ UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(Flags); }

VOID RmInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{ UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(Flags); }

/* ----- port: connect / disconnect / message ------------------------- */

NTSTATUS
RmPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_opt_ PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    PVOID prev;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    prev = InterlockedCompareExchangePointer((PVOID volatile *)&g_Data.ClientPort,
                                             ClientPort, NULL);
    if (prev != NULL) return STATUS_ALREADY_REGISTERED;

    g_Data.Connected = TRUE;
    *ConnectionPortCookie = NULL;
    RM_DBG("user-mode client connected");
    return STATUS_SUCCESS;
}

VOID
RmPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    KIRQL irql;
    PFLT_PORT port;

    UNREFERENCED_PARAMETER(ConnectionCookie);

    RM_DBG("user-mode client disconnected");
    g_Data.Connected = FALSE;
    port = (PFLT_PORT)InterlockedExchangePointer(
        (PVOID volatile *)&g_Data.ClientPort, NULL);
    if (port != NULL) {
        FltCloseClientPort(g_Data.Filter, &port);
    }

    KeAcquireSpinLock(&g_Data.PidLock, &irql);
    g_Data.BlockedPidCount = 0;
    RtlZeroMemory(g_Data.BlockedPids, sizeof(g_Data.BlockedPids));
    KeReleaseSpinLock(&g_Data.PidLock, irql);

    KeAcquireSpinLock(&g_Data.PidStatsLock, &irql);
    RtlZeroMemory(g_Data.PidStats, sizeof(g_Data.PidStats));
    KeReleaseSpinLock(&g_Data.PidStatsLock, irql);
}

static NTSTATUS
RmHandleSetPaths(_In_ PCRM_COMMAND Cmd, _In_ BOOLEAN Canary)
{
    NTSTATUS status;
    PUNICODE_STRING dst;
    PWCH *dstBuf;
    ULONG max;
    ULONG newCount = 0;

    if (Cmd->PathBufferChars > (sizeof(Cmd->Paths) / sizeof(WCHAR))) return STATUS_INVALID_PARAMETER;
    max = Canary ? RM_MAX_CANARY_PATHS : RM_MAX_WATCH_PATHS;
    if (Cmd->PathCount > max) return STATUS_INVALID_PARAMETER;

    FltAcquirePushLockExclusive(&g_Data.ConfigLock);
    if (Canary) {
        RmClearCanaryPaths_Locked();
        dst = g_Data.CanaryPaths;
        dstBuf = g_Data.CanaryPathBuffers;
    } else {
        RmClearWatchPaths_Locked();
        dst = g_Data.WatchRoots;
        dstBuf = g_Data.WatchRootBuffers;
    }
    status = RmLoadPathList_Locked(Cmd->Paths, Cmd->PathBufferChars, Cmd->PathCount,
                                   max, dst, dstBuf, &newCount);
    if (NT_SUCCESS(status)) {
        if (Canary) g_Data.CanaryCount = newCount;
        else        g_Data.WatchCount = newCount;
    } else {
        if (Canary) RmClearCanaryPaths_Locked();
        else        RmClearWatchPaths_Locked();
    }
    FltReleasePushLock(&g_Data.ConfigLock);
    return status;
}

static NTSTATUS
RmHandleSetSuspExts(_In_ PCRM_COMMAND Cmd)
{
    NTSTATUS status;
    if (Cmd->PathBufferChars > (sizeof(Cmd->Paths) / sizeof(WCHAR))) return STATUS_INVALID_PARAMETER;
    if (Cmd->PathCount > RM_MAX_SUSP_EXTS) return STATUS_INVALID_PARAMETER;

    FltAcquirePushLockExclusive(&g_Data.ConfigLock);
    status = RmLoadSuspExts_Locked(Cmd->Paths, Cmd->PathBufferChars, Cmd->PathCount);
    if (!NT_SUCCESS(status)) g_Data.SuspExtCount = 0;
    FltReleasePushLock(&g_Data.ConfigLock);
    return status;
}

static NTSTATUS
RmHandleBlockPid(_In_ ULONG Pid, _In_ BOOLEAN Add)
{
    KIRQL irql;
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;

    if (Pid == 0) return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&g_Data.PidLock, &irql);
    if (Add) {
        for (i = 0; i < g_Data.BlockedPidCount; ++i) {
            if (g_Data.BlockedPids[i] == Pid) { status = STATUS_OBJECT_NAME_COLLISION; goto done; }
        }
        if (g_Data.BlockedPidCount >= RM_MAX_BLOCKED_PIDS) {
            status = STATUS_INSUFFICIENT_RESOURCES; goto done;
        }
        g_Data.BlockedPids[g_Data.BlockedPidCount++] = Pid;
    } else {
        for (i = 0; i < g_Data.BlockedPidCount; ++i) {
            if (g_Data.BlockedPids[i] == Pid) {
                g_Data.BlockedPids[i] = g_Data.BlockedPids[g_Data.BlockedPidCount - 1];
                g_Data.BlockedPidCount--;
                goto done;
            }
        }
        status = STATUS_NOT_FOUND;
    }
done:
    KeReleaseSpinLock(&g_Data.PidLock, irql);
    return status;
}

NTSTATUS
RmPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    PCRM_COMMAND cmd;
    RM_COMMAND localCmd;
    RM_REPLY reply = { 0 };

    UNREFERENCED_PARAMETER(PortCookie);
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(RM_COMMAND)) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        RtlCopyMemory(&localCmd, InputBuffer, sizeof(RM_COMMAND));
    } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    cmd = &localCmd;

    if (cmd->ProtocolVersion != RM_PROTOCOL_VERSION) {
        reply.Status = (LONG)STATUS_REVISION_MISMATCH;
        goto reply;
    }

    switch (cmd->CommandType) {
    case RmCmdSetWatchPaths:
        status = RmHandleSetPaths(cmd, FALSE); break;
    case RmCmdSetCanaryPaths:
        status = RmHandleSetPaths(cmd, TRUE); break;
    case RmCmdSetSuspExts:
        status = RmHandleSetSuspExts(cmd); break;
    case RmCmdBlockPid:
        status = RmHandleBlockPid(cmd->Pid, TRUE); break;
    case RmCmdUnblockPid:
        status = RmHandleBlockPid(cmd->Pid, FALSE); break;
    case RmCmdTerminatePid:
        if (cmd->Pid == 0) { status = STATUS_INVALID_PARAMETER; break; }
        RmQueueTerminate(cmd->Pid);
        break;
    case RmCmdClearBlockedPids: {
        KIRQL irql;
        KeAcquireSpinLock(&g_Data.PidLock, &irql);
        g_Data.BlockedPidCount = 0;
        RtlZeroMemory(g_Data.BlockedPids, sizeof(g_Data.BlockedPids));
        KeReleaseSpinLock(&g_Data.PidLock, irql);
        break;
    }
    case RmCmdResetPidStats: {
        KIRQL irql;
        KeAcquireSpinLock(&g_Data.PidStatsLock, &irql);
        RtlZeroMemory(g_Data.PidStats, sizeof(g_Data.PidStats));
        KeReleaseSpinLock(&g_Data.PidStatsLock, irql);
        break;
    }
    case RmCmdSetPolicy:
        FltAcquirePushLockExclusive(&g_Data.ConfigLock);
        g_Data.Policy = cmd->Policy;
        FltReleasePushLock(&g_Data.ConfigLock);
        break;
    case RmCmdSetThresholds:
        FltAcquirePushLockExclusive(&g_Data.ConfigLock);
        if (cmd->ScoreCritical    > 0) g_Data.ScoreCritical    = cmd->ScoreCritical;
        if (cmd->EntropyThreshold > 0) g_Data.EntropyThreshold = cmd->EntropyThreshold;
        if (cmd->DistinctExtAlert > 0) g_Data.DistinctExtAlert = cmd->DistinctExtAlert;
        if (cmd->WriteBurstBytes  > 0) g_Data.WriteBurstBytes  = cmd->WriteBurstBytes;
        FltReleasePushLock(&g_Data.ConfigLock);
        reply.Detail = g_Data.ScoreCritical;
        break;
    case RmCmdPing:
        reply.Detail = RM_PROTOCOL_VERSION;
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    reply.Status = (LONG)status;

reply:
    if (OutputBuffer != NULL && OutputBufferLength >= sizeof(RM_REPLY)) {
        __try {
            RtlCopyMemory(OutputBuffer, &reply, sizeof(RM_REPLY));
            *ReturnOutputBufferLength = sizeof(RM_REPLY);
        } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    }
    return STATUS_SUCCESS;
}

/* ----- driver entry / unload --------------------------------------- */

static NTSTATUS
RmCreatePort(VOID)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    RtlInitUnicodeString(&portName, RM_PORT_NAME);
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) return status;

    InitializeObjectAttributes(&oa, &portName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, sd);
    status = FltCreateCommunicationPort(
        g_Data.Filter, &g_Data.ServerPort, &oa,
        NULL, RmPortConnect, RmPortDisconnect, RmPortMessage, 1);
    FltFreeSecurityDescriptor(sd);
    return status;
}

NTSTATUS
RmUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    RM_DBG("unloading");

    if (g_Data.ImageNotifyArmed) {
        PsRemoveLoadImageNotifyRoutine(RmImageNotify);
        g_Data.ImageNotifyArmed = FALSE;
    }
    if (g_Data.ProcessNotifyArmed) {
        PsSetCreateProcessNotifyRoutineEx(RmProcessNotifyEx, TRUE);
        g_Data.ProcessNotifyArmed = FALSE;
    }
    if (g_Data.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Data.ServerPort);
        g_Data.ServerPort = NULL;
    }
    if (g_Data.Filter != NULL) {
        FltUnregisterFilter(g_Data.Filter);
        g_Data.Filter = NULL;
    }

    FltAcquirePushLockExclusive(&g_Data.ConfigLock);
    RmClearWatchPaths_Locked();
    RmClearCanaryPaths_Locked();
    FltReleasePushLock(&g_Data.ConfigLock);
    FltDeletePushLock(&g_Data.ConfigLock);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    RM_DBG("DriverEntry (EDR mode)");

    RtlZeroMemory(&g_Data, sizeof(g_Data));
    g_Data.DriverObject = DriverObject;
    g_Data.Policy = RM_POLICY_BLOCK_CANARY | RM_POLICY_EMIT_CREATES |
                    RM_POLICY_EMIT_CLEANUPS | RM_POLICY_TRACK_PROCESSES |
                    RM_POLICY_ENTROPY_GUARD | RM_POLICY_BLOCK_SUSP_EXT |
                    RM_POLICY_AUTO_TERMINATE;
    g_Data.ScoreCritical    = RM_DEFAULT_SCORE_CRITICAL;
    g_Data.EntropyThreshold = RM_DEFAULT_ENTROPY_X100;
    g_Data.DistinctExtAlert = RM_DEFAULT_DISTINCT_EXT;
    g_Data.WriteBurstBytes  = RM_DEFAULT_WRITE_BURST;

    FltInitializePushLock(&g_Data.ConfigLock);
    KeInitializeSpinLock(&g_Data.PidLock);
    KeInitializeSpinLock(&g_Data.PidStatsLock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Data.Filter);
    if (!NT_SUCCESS(status)) { RM_DBG("FltRegisterFilter 0x%x", status); goto fail; }

    status = RmCreatePort();
    if (!NT_SUCCESS(status)) { RM_DBG("FltCreateCommunicationPort 0x%x", status); goto fail; }

    status = PsSetCreateProcessNotifyRoutineEx(RmProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        RM_DBG("PsSetCreateProcessNotifyRoutineEx 0x%x (continuing without process telemetry)", status);
    } else {
        g_Data.ProcessNotifyArmed = TRUE;
    }

    status = PsSetLoadImageNotifyRoutine(RmImageNotify);
    if (!NT_SUCCESS(status)) {
        RM_DBG("PsSetLoadImageNotifyRoutine 0x%x (continuing without image telemetry)", status);
    } else {
        g_Data.ImageNotifyArmed = TRUE;
    }

    status = FltStartFiltering(g_Data.Filter);
    if (!NT_SUCCESS(status)) { RM_DBG("FltStartFiltering 0x%x", status); goto fail; }

    RM_DBG("loaded ok (policy=0x%x score-crit=%lu entropy>=%lu/800)",
           g_Data.Policy, g_Data.ScoreCritical, g_Data.EntropyThreshold);
    return STATUS_SUCCESS;

fail:
    if (g_Data.ImageNotifyArmed) {
        PsRemoveLoadImageNotifyRoutine(RmImageNotify);
        g_Data.ImageNotifyArmed = FALSE;
    }
    if (g_Data.ProcessNotifyArmed) {
        PsSetCreateProcessNotifyRoutineEx(RmProcessNotifyEx, TRUE);
        g_Data.ProcessNotifyArmed = FALSE;
    }
    if (g_Data.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Data.ServerPort);
        g_Data.ServerPort = NULL;
    }
    if (g_Data.Filter != NULL) {
        FltUnregisterFilter(g_Data.Filter);
        g_Data.Filter = NULL;
    }
    FltDeletePushLock(&g_Data.ConfigLock);
    return status;
}
