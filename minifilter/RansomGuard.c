/*
 * RansomGuard.c
 *
 * Windows file-system minifilter that observes file create/write/rename
 * activity, forwards each event to a user-mode listener over a filter
 * communication port, and can block subsequent file mutations from a PID
 * that user mode has marked as quarantined.
 *
 * The driver is intentionally small: heavy logic lives in user mode.  The
 * kernel side does three things only:
 *   1. Stream events up (PID + path + op + bytes).
 *   2. Maintain a small bitmap of quarantined PIDs.
 *   3. Fail WRITE / SET_INFORMATION pre-ops for quarantined PIDs.
 *
 * Build with the Windows Driver Kit; the .vcxproj in this directory wires
 * the WDK targets in.  Test-sign or install on a machine with test signing
 * enabled before loading.
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "RansomGuard.h"

#define RG_TAG  'GnsR'

#define RG_MAX_QUARANTINED      256

/* -------------------------------------------------------------------------- */
/* Global state                                                                */
/* -------------------------------------------------------------------------- */

typedef struct _RG_GLOBALS {
    PFLT_FILTER       Filter;
    PFLT_PORT         ServerPort;
    PFLT_PORT         ClientPort;        // single connected client
    FAST_MUTEX        ClientLock;        // protects ClientPort
    EX_PUSH_LOCK      QuarantineLock;
    ULONG             QuarantinedPids[RG_MAX_QUARANTINED];
    ULONG             QuarantinedCount;
    LARGE_INTEGER     PerfFrequency;
} RG_GLOBALS;

static RG_GLOBALS g_Rg;

/* -------------------------------------------------------------------------- */
/* Forward declarations                                                        */
/* -------------------------------------------------------------------------- */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath);

static NTSTATUS RgUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static NTSTATUS RgInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                _In_ DEVICE_TYPE VolumeDeviceType,
                                _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

static NTSTATUS RgInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS RgPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS RgPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS RgPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS RgPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS RgPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS RgPostSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static NTSTATUS RgPortConnect(_In_ PFLT_PORT ClientPort,
                              _In_opt_ PVOID ServerPortCookie,
                              _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                              _In_ ULONG SizeOfContext,
                              _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);

static VOID RgPortDisconnect(_In_opt_ PVOID ConnectionCookie);

static NTSTATUS RgPortMessage(_In_opt_ PVOID PortCookie,
                              _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                              _In_ ULONG InputBufferLength,
                              _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
                              _In_ ULONG OutputBufferLength,
                              _Out_ PULONG ReturnOutputBufferLength);

static BOOLEAN RgIsQuarantined(_In_ ULONG ProcessId);
static NTSTATUS RgAddQuarantine(_In_ ULONG ProcessId);
static NTSTATUS RgRemoveQuarantine(_In_ ULONG ProcessId);

static VOID RgSendEvent(_In_ RG_EVENT_KIND Kind,
                        _In_ ULONG SubKind,
                        _In_ PFLT_CALLBACK_DATA Data,
                        _In_ PCFLT_RELATED_OBJECTS FltObjects,
                        _In_ ULONGLONG WriteBytes,
                        _In_ NTSTATUS OpStatus);

/* -------------------------------------------------------------------------- */
/* Callback registration                                                       */
/* -------------------------------------------------------------------------- */

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,            0, RgPreCreate,  RgPostCreate  },
    { IRP_MJ_WRITE,             0, RgPreWrite,   RgPostWrite   },
    { IRP_MJ_SET_INFORMATION,   0, RgPreSetInfo, RgPostSetInfo },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),       // Size
    FLT_REGISTRATION_VERSION,       // Version
    0,                              // Flags
    NULL,                           // ContextRegistration
    Callbacks,                      // OperationRegistration
    RgUnload,                       // FilterUnloadCallback
    RgInstanceSetup,                // InstanceSetupCallback
    RgInstanceQueryTeardown,        // InstanceQueryTeardownCallback
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL, NULL, NULL,               // Name provider callbacks
    NULL,                           // TransactionNotification
    NULL,                           // NormalizeNameComponent
    NULL,                           // NormalizeContextCleanup
    NULL,                           // TransactionNotification (Ex)
    NULL,                           // SectionNotificationCallback
};

/* -------------------------------------------------------------------------- */
/* DriverEntry / unload                                                        */
/* -------------------------------------------------------------------------- */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;

    RtlZeroMemory(&g_Rg, sizeof(g_Rg));
    ExInitializeFastMutex(&g_Rg.ClientLock);
    FltInitializePushLock(&g_Rg.QuarantineLock);
    KeQueryPerformanceCounter(&g_Rg.PerfFrequency);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Rg.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        goto fail_filter;
    }

    RtlInitUnicodeString(&portName, RG_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, sd);

    status = FltCreateCommunicationPort(g_Rg.Filter, &g_Rg.ServerPort, &oa,
                                        NULL,
                                        RgPortConnect, RgPortDisconnect,
                                        RgPortMessage, 1);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status)) {
        goto fail_filter;
    }

    status = FltStartFiltering(g_Rg.Filter);
    if (!NT_SUCCESS(status)) {
        goto fail_port;
    }

    return STATUS_SUCCESS;

fail_port:
    FltCloseCommunicationPort(g_Rg.ServerPort);
    g_Rg.ServerPort = NULL;
fail_filter:
    FltUnregisterFilter(g_Rg.Filter);
    g_Rg.Filter = NULL;
    return status;
}

static NTSTATUS RgUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_Rg.ServerPort) {
        FltCloseCommunicationPort(g_Rg.ServerPort);
        g_Rg.ServerPort = NULL;
    }
    if (g_Rg.Filter) {
        FltUnregisterFilter(g_Rg.Filter);
        g_Rg.Filter = NULL;
    }
    FltDeletePushLock(&g_Rg.QuarantineLock);
    return STATUS_SUCCESS;
}

static NTSTATUS RgInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                _In_ DEVICE_TYPE VolumeDeviceType,
                                _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

static NTSTATUS RgInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Quarantine bitmap                                                           */
/* -------------------------------------------------------------------------- */

static BOOLEAN RgIsQuarantined(_In_ ULONG ProcessId)
{
    BOOLEAN found = FALSE;
    ULONG i;

    FltAcquirePushLockShared(&g_Rg.QuarantineLock);
    for (i = 0; i < g_Rg.QuarantinedCount; ++i) {
        if (g_Rg.QuarantinedPids[i] == ProcessId) {
            found = TRUE;
            break;
        }
    }
    FltReleasePushLock(&g_Rg.QuarantineLock);
    return found;
}

static NTSTATUS RgAddQuarantine(_In_ ULONG ProcessId)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    BOOLEAN exists = FALSE;

    FltAcquirePushLockExclusive(&g_Rg.QuarantineLock);
    for (i = 0; i < g_Rg.QuarantinedCount; ++i) {
        if (g_Rg.QuarantinedPids[i] == ProcessId) {
            exists = TRUE;
            break;
        }
    }
    if (!exists) {
        if (g_Rg.QuarantinedCount >= RG_MAX_QUARANTINED) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            g_Rg.QuarantinedPids[g_Rg.QuarantinedCount++] = ProcessId;
        }
    }
    FltReleasePushLock(&g_Rg.QuarantineLock);
    return status;
}

static NTSTATUS RgRemoveQuarantine(_In_ ULONG ProcessId)
{
    ULONG i;

    FltAcquirePushLockExclusive(&g_Rg.QuarantineLock);
    for (i = 0; i < g_Rg.QuarantinedCount; ++i) {
        if (g_Rg.QuarantinedPids[i] == ProcessId) {
            g_Rg.QuarantinedPids[i] =
                g_Rg.QuarantinedPids[--g_Rg.QuarantinedCount];
            break;
        }
    }
    FltReleasePushLock(&g_Rg.QuarantineLock);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Communication port                                                          */
/* -------------------------------------------------------------------------- */

static NTSTATUS RgPortConnect(_In_ PFLT_PORT ClientPort,
                              _In_opt_ PVOID ServerPortCookie,
                              _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                              _In_ ULONG SizeOfContext,
                              _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    ExAcquireFastMutex(&g_Rg.ClientLock);
    if (g_Rg.ClientPort != NULL) {
        ExReleaseFastMutex(&g_Rg.ClientLock);
        return STATUS_ALREADY_REGISTERED;
    }
    g_Rg.ClientPort = ClientPort;
    ExReleaseFastMutex(&g_Rg.ClientLock);

    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

static VOID RgPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ExAcquireFastMutex(&g_Rg.ClientLock);
    if (g_Rg.ClientPort) {
        FltCloseClientPort(g_Rg.Filter, &g_Rg.ClientPort);
        g_Rg.ClientPort = NULL;
    }
    ExReleaseFastMutex(&g_Rg.ClientLock);

    // Releasing the listener means no one is consuming events; drop the
    // quarantine list so user mode rebuilds it on reconnect.
    FltAcquirePushLockExclusive(&g_Rg.QuarantineLock);
    g_Rg.QuarantinedCount = 0;
    FltReleasePushLock(&g_Rg.QuarantineLock);
}

static NTSTATUS RgPortMessage(_In_opt_ PVOID PortCookie,
                              _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                              _In_ ULONG InputBufferLength,
                              _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
                              _In_ ULONG OutputBufferLength,
                              _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);

    RG_COMMAND cmd;
    RG_REPLY reply = { 0 };

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(RG_COMMAND)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        ProbeForRead(InputBuffer, sizeof(RG_COMMAND), sizeof(ULONG));
        RtlCopyMemory(&cmd, InputBuffer, sizeof(RG_COMMAND));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (cmd.Version != RG_PROTOCOL_VERSION) {
        reply.Status = STATUS_REVISION_MISMATCH;
        goto write_reply;
    }

    switch (cmd.Kind) {
    case RgCmdQuarantinePid:
        reply.Status = RgAddQuarantine(cmd.ProcessId);
        break;
    case RgCmdReleasePid:
        reply.Status = RgRemoveQuarantine(cmd.ProcessId);
        break;
    case RgCmdPing:
        reply.Status = STATUS_SUCCESS;
        break;
    default:
        reply.Status = STATUS_INVALID_PARAMETER;
        break;
    }

write_reply:
    if (OutputBuffer && OutputBufferLength >= sizeof(RG_REPLY)) {
        __try {
            ProbeForWrite(OutputBuffer, sizeof(RG_REPLY), sizeof(ULONG));
            RtlCopyMemory(OutputBuffer, &reply, sizeof(RG_REPLY));
            *ReturnOutputBufferLength = sizeof(RG_REPLY);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

static ULONGLONG RgTimestampNs(VOID)
{
    LARGE_INTEGER counter = KeQueryPerformanceCounter(NULL);
    // Convert to nanoseconds: (counter * 1e9) / freq.  Use 64-bit math.
    if (g_Rg.PerfFrequency.QuadPart == 0) {
        return 0;
    }
    return (ULONGLONG)((counter.QuadPart * 1000000000ULL) /
                       (ULONGLONG)g_Rg.PerfFrequency.QuadPart);
}

/*
 * Resolve the requested file name into a normalized DOS path string and
 * copy it (up to RG_MAX_PATH_CHARS) into the event.  Returns the number of
 * WCHARs written including the terminator.
 */
static ULONG RgCopyFileName(_In_ PFLT_CALLBACK_DATA Data,
                            _In_ PCFLT_RELATED_OBJECTS FltObjects,
                            _Out_writes_z_(RG_MAX_PATH_CHARS) PWCHAR Dest)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG copied = 0;

    Dest[0] = L'\0';

    status = FltGetFileNameInformation(Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return 0;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return 0;
    }

    {
        USHORT bytes = nameInfo->Name.Length;
        USHORT chars = (USHORT)(bytes / sizeof(WCHAR));
        if (chars >= RG_MAX_PATH_CHARS) {
            chars = RG_MAX_PATH_CHARS - 1;
        }
        if (chars > 0) {
            RtlCopyMemory(Dest, nameInfo->Name.Buffer, chars * sizeof(WCHAR));
        }
        Dest[chars] = L'\0';
        copied = chars + 1;
    }

    FltReleaseFileNameInformation(nameInfo);
    UNREFERENCED_PARAMETER(FltObjects);
    return copied;
}

static VOID RgSendEvent(_In_ RG_EVENT_KIND Kind,
                        _In_ ULONG SubKind,
                        _In_ PFLT_CALLBACK_DATA Data,
                        _In_ PCFLT_RELATED_OBJECTS FltObjects,
                        _In_ ULONGLONG WriteBytes,
                        _In_ NTSTATUS OpStatus)
{
    PFLT_PORT clientPort;
    PRG_EVENT evt;
    NTSTATUS status;
    LARGE_INTEGER timeout;

    ExAcquireFastMutex(&g_Rg.ClientLock);
    clientPort = g_Rg.ClientPort;
    ExReleaseFastMutex(&g_Rg.ClientLock);
    if (clientPort == NULL) {
        return;
    }

    evt = (PRG_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RG_EVENT), RG_TAG);
    if (evt == NULL) {
        return;
    }

    RtlZeroMemory(evt, sizeof(RG_EVENT));
    evt->Version    = RG_PROTOCOL_VERSION;
    evt->Kind       = (ULONG)Kind;
    evt->SubKind    = SubKind;
    evt->ProcessId  = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt->ThreadId   = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    evt->Status     = (ULONG)OpStatus;
    evt->WriteBytes = WriteBytes;
    evt->TimestampNs = RgTimestampNs();
    evt->PathLength = RgCopyFileName(Data, FltObjects, evt->Path);

    // 50 ms cap; if user mode is wedged we drop the event rather than stall I/O.
    timeout.QuadPart = -((LONGLONG)50 * 10 * 1000);
    status = FltSendMessage(g_Rg.Filter, &clientPort, evt, sizeof(RG_EVENT),
                            NULL, NULL, &timeout);
    UNREFERENCED_PARAMETER(status);

    ExFreePoolWithTag(evt, RG_TAG);
}

/* -------------------------------------------------------------------------- */
/* Callbacks                                                                   */
/* -------------------------------------------------------------------------- */

static FLT_PREOP_CALLBACK_STATUS RgPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS RgPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (Data->RequestorMode == KernelMode) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RgSendEvent(RgEventCreate, 0, Data, FltObjects, 0, Data->IoStatus.Status);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS RgPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (RgIsQuarantined(pid)) {
        // Tell user mode why this got blocked, then fail the IRP.
        RgSendEvent(RgEventBlocked, RgEventWrite, Data, FltObjects, 0,
                    STATUS_ACCESS_DENIED);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS RgPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    ULONGLONG bytes = (ULONGLONG)Data->IoStatus.Information;
    // Throttle: skip sub-page writes to keep the user-mode queue small.
    if (bytes < 4096) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RgSendEvent(RgEventWrite, 0, Data, FltObjects, bytes,
                Data->IoStatus.Status);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static ULONG RgClassifySetInfo(_In_ FILE_INFORMATION_CLASS InfoClass)
{
    switch (InfoClass) {
    case FileRenameInformation:
    case FileRenameInformationEx:
        return RgSetInfoRename;
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        return RgSetInfoDelete;
    default:
        return RgSetInfoOther;
    }
}

static FLT_PREOP_CALLBACK_STATUS RgPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG sub = RgClassifySetInfo(
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass);

    // We only care about rename/delete here.
    if (sub == RgSetInfoOther) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (RgIsQuarantined(pid)) {
        RgSendEvent(RgEventBlocked, sub, Data, FltObjects, 0,
                    STATUS_ACCESS_DENIED);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    *CompletionContext = (PVOID)(ULONG_PTR)sub;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS RgPostSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    ULONG sub = (ULONG)(ULONG_PTR)CompletionContext;
    RgSendEvent(RgEventSetInfo, sub, Data, FltObjects, 0,
                Data->IoStatus.Status);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
