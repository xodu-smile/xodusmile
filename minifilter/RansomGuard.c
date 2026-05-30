/*
 * RansomGuard.c
 *
 * Windows file-system minifilter + process / registry / handle telemetry
 * driver.  Streams events to user mode over a filter communication port
 * and can:
 *   - block file mutations from a quarantined PID  (v1)
 *   - tamper-protect a user-mode agent PID by stripping dangerous handle
 *     access rights from non-self callers                (v2)
 *   - report process creation with command line          (v2)
 *   - report writes/deletes against sensitive reg keys   (v2)
 *
 * Heavy logic still lives in user mode.  The driver does:
 *   1. Stream file / process / registry / tamper events up
 *   2. Maintain three small bitmaps:
 *        QuarantinedPids   — blocked from file mutations
 *        ProtectedPids     — handle-access stripped by ObCallback
 *   3. Fail WRITE / SET_INFORMATION pre-ops for quarantined PIDs
 *   4. Strip PROCESS_TERMINATE, PROCESS_VM_*, etc. from handles opened
 *      to protected PIDs by callers other than themselves
 *
 * Build with the Windows Driver Kit; the .vcxproj in this directory wires
 * the WDK targets in.  Test-sign or install on a machine with test signing
 * enabled before loading.
 */

#include <fltKernel.h>
#include <ntddk.h>
#include <dontuse.h>
#include <suppress.h>
#include "RansomGuard.h"

/* Process/thread access rights not defined in WDK kernel headers (wdm.h
 * does not include winnt.h).  Values are the canonical Windows constants. */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE         (0x0001)
#define PROCESS_CREATE_THREAD     (0x0002)
#define PROCESS_VM_OPERATION      (0x0008)
#define PROCESS_VM_READ           (0x0010)
#define PROCESS_VM_WRITE          (0x0020)
#define PROCESS_DUP_HANDLE        (0x0040)
#define PROCESS_SET_QUOTA         (0x0100)
#define PROCESS_SET_INFORMATION   (0x0200)
#define PROCESS_SUSPEND_RESUME    (0x0800)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN   (0x0080)
#define THREAD_IMPERSONATE        (0x0100)
#define THREAD_DIRECT_IMPERSONATION (0x0200)
#endif

#define RG_TAG  'GnsR'

#define RG_MAX_QUARANTINED      256
#define RG_MAX_PROTECTED        16

/* Access mask bits we strip from handles opened to a protected PID. */
#define RG_DENY_PROCESS_ACCESS  (PROCESS_TERMINATE          | \
                                 PROCESS_VM_WRITE           | \
                                 PROCESS_VM_READ            | \
                                 PROCESS_VM_OPERATION       | \
                                 PROCESS_CREATE_THREAD      | \
                                 PROCESS_DUP_HANDLE         | \
                                 PROCESS_SUSPEND_RESUME     | \
                                 PROCESS_SET_INFORMATION    | \
                                 PROCESS_SET_QUOTA)

#define RG_DENY_THREAD_ACCESS   (THREAD_TERMINATE           | \
                                 THREAD_SUSPEND_RESUME      | \
                                 THREAD_SET_CONTEXT         | \
                                 THREAD_SET_INFORMATION     | \
                                 THREAD_SET_THREAD_TOKEN    | \
                                 THREAD_IMPERSONATE         | \
                                 THREAD_DIRECT_IMPERSONATION)

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
    EX_PUSH_LOCK      ProtectedLock;
    ULONG             ProtectedPids[RG_MAX_PROTECTED];
    ULONG             ProtectedCount;
    LARGE_INTEGER     PerfFrequency;
    LARGE_INTEGER     CmCookie;          // CmRegisterCallbackEx cookie
    PVOID             ObCallbackHandle;  // ObRegisterCallbacks registration
    BOOLEAN           ProcessCallbackRegistered;
    BOOLEAN           CmCallbackRegistered;
} RG_GLOBALS;

static RG_GLOBALS g_Rg;

/* Registry paths we watch.  Stored lowercased; we compare with a case-
 * insensitive prefix match.  Kept tiny on purpose: a real EDR would push
 * this from user mode, but here the list of "things ransomware tampers
 * with" is well-bounded and fits in source. */
static const PCWSTR kRgWatchedRegPrefixes[] = {
    L"\\registry\\machine\\software\\microsoft\\windows defender",
    L"\\registry\\machine\\software\\policies\\microsoft\\windows defender",
    L"\\registry\\machine\\system\\currentcontrolset\\services\\windefend",
    L"\\registry\\machine\\system\\currentcontrolset\\services\\wdfilter",
    L"\\registry\\machine\\system\\currentcontrolset\\services\\wdboot",
    L"\\registry\\machine\\system\\currentcontrolset\\services\\sense",
    L"\\registry\\machine\\system\\currentcontrolset\\services\\ransomguard",
    L"\\registry\\machine\\system\\currentcontrolset\\control\\safeboot",
    L"\\registry\\machine\\software\\microsoft\\windows\\currentversion\\run",
    L"\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce",
    L"\\registry\\user\\",   // catches HKCU\Software\...\Run when joined with suffix check below
};

/* HKCU value-name suffixes we care about (lower-case).  An HKCU key path
 * starts with \registry\user\<sid>\..., so we accept the user prefix
 * above and then verify the rest of the path contains one of these. */
static const PCWSTR kRgWatchedRegSuffixes[] = {
    L"\\software\\microsoft\\windows\\currentversion\\run",
    L"\\software\\microsoft\\windows\\currentversion\\runonce",
    L"\\software\\microsoft\\windows\\currentversion\\policies\\system",
    L"\\software\\policies\\microsoft\\windows defender",
};

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
static VOID     RgFlushQuarantine(VOID);

static BOOLEAN RgIsProtected(_In_ ULONG ProcessId);
static NTSTATUS RgAddProtected(_In_ ULONG ProcessId);
static NTSTATUS RgRemoveProtected(_In_ ULONG ProcessId);

static VOID RgSendFileEvent(_In_ RG_EVENT_KIND Kind,
                            _In_ ULONG SubKind,
                            _In_ PFLT_CALLBACK_DATA Data,
                            _In_ PCFLT_RELATED_OBJECTS FltObjects,
                            _In_ ULONGLONG WriteBytes,
                            _In_ NTSTATUS OpStatus);

static VOID RgSendRawEvent(_In_ PRG_EVENT Event);

static VOID RgProcessNotifyEx(_Inout_ PEPROCESS Process,
                              _In_ HANDLE ProcessId,
                              _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

static NTSTATUS RgRegistryCallback(_In_ PVOID CallbackContext,
                                   _In_opt_ PVOID Argument1,
                                   _In_opt_ PVOID Argument2);

static OB_PREOP_CALLBACK_STATUS RgObPreOperation(_In_ PVOID RegistrationContext,
                                                 _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

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
    NULL,                           // GenerateFileNameCallback
    NULL,                           // NormalizeNameComponentCallback
    NULL,                           // NormalizeContextCleanupCallback
    NULL,                           // TransactionNotificationCallback
    NULL,                           // NormalizeNameComponentExCallback
    NULL                            // SectionNotificationCallback
};

static OB_OPERATION_REGISTRATION g_ObOperations[2];
static OB_CALLBACK_REGISTRATION  g_ObRegistration;

/* -------------------------------------------------------------------------- */
/* DriverEntry / unload                                                        */
/* -------------------------------------------------------------------------- */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING portName;
    UNICODE_STRING cmAltitude;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RansomGuard: DriverEntry called\n");

    RtlZeroMemory(&g_Rg, sizeof(g_Rg));
    ExInitializeFastMutex(&g_Rg.ClientLock);
    FltInitializePushLock(&g_Rg.QuarantineLock);
    FltInitializePushLock(&g_Rg.ProtectedLock);
    KeQueryPerformanceCounter(&g_Rg.PerfFrequency);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Rg.Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RansomGuard: FltRegisterFilter FAILED 0x%X\n", status);
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RansomGuard: FltBuildDefaultSecurityDescriptor FAILED 0x%X\n", status);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RansomGuard: FltCreateCommunicationPort FAILED 0x%X\n", status);
        goto fail_filter;
    }

    /* Process create/exit kernel callback.  Reported on the same port as
     * file events so user mode has one queue. */
    status = PsSetCreateProcessNotifyRoutineEx(RgProcessNotifyEx, FALSE);
    if (NT_SUCCESS(status)) {
        g_Rg.ProcessCallbackRegistered = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RansomGuard: PsSetCreateProcessNotifyRoutineEx FAILED 0x%X\n", status);
        /* Non-fatal: file telemetry still works. */
    }

    /* Registry callback.  Altitude must be a unique string; we pick one
     * adjacent to the filter altitude. */
    RtlInitUnicodeString(&cmAltitude, L"385202");
    status = CmRegisterCallbackEx(RgRegistryCallback, &cmAltitude,
                                  DriverObject, NULL, &g_Rg.CmCookie, NULL);
    if (NT_SUCCESS(status)) {
        g_Rg.CmCallbackRegistered = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RansomGuard: CmRegisterCallbackEx FAILED 0x%X\n", status);
        /* Non-fatal. */
    }

    /* Object-manager callbacks for tamper protection.  Only registers
     * the operations table; pre-operation does the actual access strip. */
    RtlZeroMemory(g_ObOperations, sizeof(g_ObOperations));
    g_ObOperations[0].ObjectType = PsProcessType;
    g_ObOperations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOperations[0].PreOperation = RgObPreOperation;
    g_ObOperations[1].ObjectType = PsThreadType;
    g_ObOperations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOperations[1].PreOperation = RgObPreOperation;

    RtlZeroMemory(&g_ObRegistration, sizeof(g_ObRegistration));
    g_ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    g_ObRegistration.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&g_ObRegistration.Altitude, L"385203");
    g_ObRegistration.RegistrationContext = NULL;
    g_ObRegistration.OperationRegistration = g_ObOperations;

    status = ObRegisterCallbacks(&g_ObRegistration, &g_Rg.ObCallbackHandle);
    if (!NT_SUCCESS(status)) {
        /* ObRegisterCallbacks requires a properly signed driver in
         * production.  Under test-signing it works; log and continue. */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RansomGuard: ObRegisterCallbacks FAILED 0x%X (tamper protection off)\n",
            status);
        g_Rg.ObCallbackHandle = NULL;
    }

    status = FltStartFiltering(g_Rg.Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RansomGuard: FltStartFiltering FAILED 0x%X\n", status);
        goto fail_callbacks;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "RansomGuard: ready (proc=%u reg=%u ob=%u)\n",
        g_Rg.ProcessCallbackRegistered,
        g_Rg.CmCallbackRegistered,
        g_Rg.ObCallbackHandle != NULL);
    return STATUS_SUCCESS;

fail_callbacks:
    if (g_Rg.ObCallbackHandle) {
        ObUnRegisterCallbacks(g_Rg.ObCallbackHandle);
        g_Rg.ObCallbackHandle = NULL;
    }
    if (g_Rg.CmCallbackRegistered) {
        CmUnRegisterCallback(g_Rg.CmCookie);
        g_Rg.CmCallbackRegistered = FALSE;
    }
    if (g_Rg.ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(RgProcessNotifyEx, TRUE);
        g_Rg.ProcessCallbackRegistered = FALSE;
    }
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

    /* Unregister in reverse order of registration.  Each of these
     * unregister calls is synchronous and drains pending callbacks. */
    if (g_Rg.ObCallbackHandle) {
        ObUnRegisterCallbacks(g_Rg.ObCallbackHandle);
        g_Rg.ObCallbackHandle = NULL;
    }
    if (g_Rg.CmCallbackRegistered) {
        CmUnRegisterCallback(g_Rg.CmCookie);
        g_Rg.CmCallbackRegistered = FALSE;
    }
    if (g_Rg.ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(RgProcessNotifyEx, TRUE);
        g_Rg.ProcessCallbackRegistered = FALSE;
    }
    if (g_Rg.ServerPort) {
        FltCloseCommunicationPort(g_Rg.ServerPort);
        g_Rg.ServerPort = NULL;
    }
    if (g_Rg.Filter) {
        FltUnregisterFilter(g_Rg.Filter);
        g_Rg.Filter = NULL;
    }
    FltDeletePushLock(&g_Rg.QuarantineLock);
    FltDeletePushLock(&g_Rg.ProtectedLock);
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

static VOID RgFlushQuarantine(VOID)
{
    FltAcquirePushLockExclusive(&g_Rg.QuarantineLock);
    g_Rg.QuarantinedCount = 0;
    FltReleasePushLock(&g_Rg.QuarantineLock);
}

/* -------------------------------------------------------------------------- */
/* Protected-PID bitmap (tamper protection target set)                         */
/* -------------------------------------------------------------------------- */

static BOOLEAN RgIsProtected(_In_ ULONG ProcessId)
{
    BOOLEAN found = FALSE;
    ULONG i;

    FltAcquirePushLockShared(&g_Rg.ProtectedLock);
    for (i = 0; i < g_Rg.ProtectedCount; ++i) {
        if (g_Rg.ProtectedPids[i] == ProcessId) {
            found = TRUE;
            break;
        }
    }
    FltReleasePushLock(&g_Rg.ProtectedLock);
    return found;
}

static NTSTATUS RgAddProtected(_In_ ULONG ProcessId)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    BOOLEAN exists = FALSE;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    FltAcquirePushLockExclusive(&g_Rg.ProtectedLock);
    for (i = 0; i < g_Rg.ProtectedCount; ++i) {
        if (g_Rg.ProtectedPids[i] == ProcessId) {
            exists = TRUE;
            break;
        }
    }
    if (!exists) {
        if (g_Rg.ProtectedCount >= RG_MAX_PROTECTED) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            g_Rg.ProtectedPids[g_Rg.ProtectedCount++] = ProcessId;
        }
    }
    FltReleasePushLock(&g_Rg.ProtectedLock);
    return status;
}

static NTSTATUS RgRemoveProtected(_In_ ULONG ProcessId)
{
    ULONG i;

    FltAcquirePushLockExclusive(&g_Rg.ProtectedLock);
    for (i = 0; i < g_Rg.ProtectedCount; ++i) {
        if (g_Rg.ProtectedPids[i] == ProcessId) {
            g_Rg.ProtectedPids[i] =
                g_Rg.ProtectedPids[--g_Rg.ProtectedCount];
            break;
        }
    }
    FltReleasePushLock(&g_Rg.ProtectedLock);
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

    /* v2: do NOT clear the quarantine list on disconnect.  Earlier
     * versions flushed it here, which meant an attacker who killed the
     * user-mode bridge for one second would release every blocked PID.
     * The agent must now send RgCmdFlushQuarantine explicitly during a
     * clean shutdown if it wants the list cleared.  Protected PIDs are
     * likewise sticky for the same reason. */
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
        reply.Status = (ULONG)STATUS_REVISION_MISMATCH;
        goto write_reply;
    }

    switch (cmd.Kind) {
    case RgCmdQuarantinePid:
        reply.Status = (ULONG)RgAddQuarantine(cmd.ProcessId);
        break;
    case RgCmdReleasePid:
        reply.Status = (ULONG)RgRemoveQuarantine(cmd.ProcessId);
        break;
    case RgCmdProtectPid:
        reply.Status = (ULONG)RgAddProtected(cmd.ProcessId);
        break;
    case RgCmdUnprotectPid:
        reply.Status = (ULONG)RgRemoveProtected(cmd.ProcessId);
        break;
    case RgCmdFlushQuarantine:
        RgFlushQuarantine();
        reply.Status = STATUS_SUCCESS;
        break;
    case RgCmdPing:
        reply.Status = STATUS_SUCCESS;
        break;
    default:
        reply.Status = (ULONG)STATUS_INVALID_PARAMETER;
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
    if (g_Rg.PerfFrequency.QuadPart == 0) {
        return 0;
    }
    return (ULONGLONG)((counter.QuadPart * 1000000000ULL) /
                       (ULONGLONG)g_Rg.PerfFrequency.QuadPart);
}

/* Copy a UNICODE_STRING into the event's fixed-WCHAR buffer.  Returns the
 * number of WCHARs written, including the terminator (0 on empty). */
static ULONG RgCopyUnicode(_In_opt_ PUNICODE_STRING Src,
                           _Out_writes_z_(MaxChars) PWCHAR Dest,
                           _In_ ULONG MaxChars)
{
    USHORT chars;

    if (MaxChars == 0) {
        return 0;
    }
    Dest[0] = L'\0';

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        return 0;
    }

    chars = (USHORT)(Src->Length / sizeof(WCHAR));
    if (chars >= MaxChars) {
        chars = (USHORT)(MaxChars - 1);
    }
    RtlCopyMemory(Dest, Src->Buffer, chars * sizeof(WCHAR));
    Dest[chars] = L'\0';
    return chars + 1u;
}

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
    if (NT_SUCCESS(status)) {
        copied = RgCopyUnicode(&nameInfo->Name, Dest, RG_MAX_PATH_CHARS);
    }

    FltReleaseFileNameInformation(nameInfo);
    UNREFERENCED_PARAMETER(FltObjects);
    return copied;
}

/* Send a fully-populated event structure up the port.  Used by the
 * non-file event sources (process / registry / tamper) which build the
 * RG_EVENT themselves. */
static VOID RgSendRawEvent(_In_ PRG_EVENT Event)
{
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    ExAcquireFastMutex(&g_Rg.ClientLock);
    clientPort = g_Rg.ClientPort;
    ExReleaseFastMutex(&g_Rg.ClientLock);
    if (clientPort == NULL) {
        return;
    }

    Event->Version = RG_PROTOCOL_VERSION;
    if (Event->TimestampNs == 0) {
        Event->TimestampNs = RgTimestampNs();
    }

    /* 50 ms cap; if user mode is wedged we drop the event rather than
     * stall a kernel callback path. */
    timeout.QuadPart = -((LONGLONG)50 * 10 * 1000);
    status = FltSendMessage(g_Rg.Filter, &clientPort, Event, sizeof(RG_EVENT),
                            NULL, NULL, &timeout);
    UNREFERENCED_PARAMETER(status);
}

static VOID RgSendFileEvent(_In_ RG_EVENT_KIND Kind,
                            _In_ ULONG SubKind,
                            _In_ PFLT_CALLBACK_DATA Data,
                            _In_ PCFLT_RELATED_OBJECTS FltObjects,
                            _In_ ULONGLONG WriteBytes,
                            _In_ NTSTATUS OpStatus)
{
    PFLT_PORT clientPort;
    PRG_EVENT evt;
    LARGE_INTEGER timeout;
    NTSTATUS status;

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
    evt->Version     = RG_PROTOCOL_VERSION;
    evt->Kind        = (ULONG)Kind;
    evt->SubKind     = SubKind;
    evt->ProcessId   = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt->ThreadId    = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    evt->Status      = (ULONG)OpStatus;
    evt->WriteBytes  = WriteBytes;
    evt->TimestampNs = RgTimestampNs();
    evt->PathLength  = RgCopyFileName(Data, FltObjects, evt->Path);

    timeout.QuadPart = -((LONGLONG)50 * 10 * 1000);
    status = FltSendMessage(g_Rg.Filter, &clientPort, evt, sizeof(RG_EVENT),
                            NULL, NULL, &timeout);
    UNREFERENCED_PARAMETER(status);

    ExFreePoolWithTag(evt, RG_TAG);
}

/* -------------------------------------------------------------------------- */
/* File callbacks                                                              */
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

    RgSendFileEvent(RgEventCreate, 0, Data, FltObjects, 0, Data->IoStatus.Status);
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
        RgSendFileEvent(RgEventBlocked, RgEventWrite, Data, FltObjects, 0,
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
    if (bytes < 4096) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RgSendFileEvent(RgEventWrite, 0, Data, FltObjects, bytes,
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

    if (sub == RgSetInfoOther) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (RgIsQuarantined(pid)) {
        RgSendFileEvent(RgEventBlocked, sub, Data, FltObjects, 0,
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
    RgSendFileEvent(RgEventSetInfo, sub, Data, FltObjects, 0,
                    Data->IoStatus.Status);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* -------------------------------------------------------------------------- */
/* Process create/exit callback                                                */
/* -------------------------------------------------------------------------- */

static VOID RgProcessNotifyEx(_Inout_ PEPROCESS Process,
                              _In_ HANDLE ProcessId,
                              _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PRG_EVENT evt;

    UNREFERENCED_PARAMETER(Process);

    /* Allocate from non-paged: this callback can be invoked at <= APC_LEVEL
     * and we must not page-fault inside it. */
    evt = (PRG_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RG_EVENT), RG_TAG);
    if (evt == NULL) {
        return;
    }
    RtlZeroMemory(evt, sizeof(RG_EVENT));

    evt->ProcessId   = (ULONG)(ULONG_PTR)ProcessId;
    evt->TimestampNs = RgTimestampNs();

    if (CreateInfo != NULL) {
        evt->Kind            = (ULONG)RgEventProcessStart;
        evt->ParentProcessId = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        evt->Status          = (ULONG)CreateInfo->CreationStatus;
        evt->PathLength      = RgCopyUnicode(
            (PUNICODE_STRING)CreateInfo->ImageFileName,
            evt->Path, RG_MAX_PATH_CHARS);
        evt->ExtraLength     = RgCopyUnicode(
            (PUNICODE_STRING)CreateInfo->CommandLine,
            evt->Extra, RG_MAX_EXTRA_CHARS);
    } else {
        evt->Kind = (ULONG)RgEventProcessExit;
    }

    RgSendRawEvent(evt);
    ExFreePoolWithTag(evt, RG_TAG);
}

/* -------------------------------------------------------------------------- */
/* Registry callback                                                           */
/* -------------------------------------------------------------------------- */

/* Case-insensitive prefix match: does Haystack begin with Needle?  Both
 * inputs are NUL-terminated lower-case WCHAR strings. */
static BOOLEAN RgIciStartsWith(_In_ PCWSTR Haystack, _In_ PCWSTR Needle)
{
    while (*Needle) {
        WCHAR a = *Haystack;
        WCHAR b = *Needle;
        if (a == L'\0') {
            return FALSE;
        }
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
        if (a != b) {
            return FALSE;
        }
        ++Haystack;
        ++Needle;
    }
    return TRUE;
}

/* Case-insensitive substring match. */
static BOOLEAN RgIciContains(_In_ PCWSTR Haystack, _In_ PCWSTR Needle)
{
    if (*Needle == L'\0') {
        return TRUE;
    }
    for (PCWSTR p = Haystack; *p; ++p) {
        if (RgIciStartsWith(p, Needle)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN RgPathIsWatched(_In_ PCWSTR Path)
{
    SIZE_T i;
    BOOLEAN isUserHive;

    for (i = 0; i < RTL_NUMBER_OF(kRgWatchedRegPrefixes); ++i) {
        if (RgIciStartsWith(Path, kRgWatchedRegPrefixes[i])) {
            isUserHive = RgIciStartsWith(Path, L"\\registry\\user\\");
            if (!isUserHive) {
                return TRUE;
            }
            /* For HKCU we also require one of the suffix patterns to hit,
             * otherwise every per-user explorer write would fire. */
            for (SIZE_T j = 0; j < RTL_NUMBER_OF(kRgWatchedRegSuffixes); ++j) {
                if (RgIciContains(Path, kRgWatchedRegSuffixes[j])) {
                    return TRUE;
                }
            }
            return FALSE;
        }
    }
    return FALSE;
}

/* Map REG_NOTIFY_CLASS pre-operation classes to our compressed subkind. */
static ULONG RgClassifyRegOp(_In_ REG_NOTIFY_CLASS Class)
{
    switch (Class) {
    case RegNtPreSetValueKey:    return RgRegSetValue;
    case RegNtPreDeleteValueKey: return RgRegDeleteValue;
    case RegNtPreCreateKeyEx:    return RgRegCreateKey;
    case RegNtPreDeleteKey:      return RgRegDeleteKey;
    case RegNtPreRenameKey:      return RgRegRenameKey;
    default:                     return RgRegOther;
    }
}

static NTSTATUS RgRegistryCallback(_In_ PVOID CallbackContext,
                                   _In_opt_ PVOID Argument1,
                                   _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    ULONG sub;
    PCUNICODE_STRING keyName = NULL;
    PUNICODE_STRING valueName = NULL;
    PVOID keyObject = NULL;
    NTSTATUS status;
    PRG_EVENT evt;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL || Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    sub = RgClassifyRegOp(notifyClass);
    if (sub == RgRegOther) {
        return STATUS_SUCCESS;
    }

    switch (notifyClass) {
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        keyObject = info->Object;
        valueName = info->ValueName;
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        keyObject = info->Object;
        valueName = info->ValueName;
        break;
    }
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        /* CreateKey pre-op gives us a complete path string, not an
         * object pointer.  Send it directly. */
        if (info->CompleteName == NULL || info->CompleteName->Length == 0) {
            return STATUS_SUCCESS;
        }
        /* Quick filter against watched prefixes before allocating. */
        if (info->CompleteName->Buffer[0] != L'\\' ||
            !RgPathIsWatched(info->CompleteName->Buffer)) {
            return STATUS_SUCCESS;
        }
        evt = (PRG_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RG_EVENT), RG_TAG);
        if (evt == NULL) return STATUS_SUCCESS;
        RtlZeroMemory(evt, sizeof(RG_EVENT));
        evt->Kind        = (ULONG)RgEventRegistry;
        evt->SubKind     = sub;
        evt->ProcessId   = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        evt->ThreadId    = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
        evt->PathLength  = RgCopyUnicode((PUNICODE_STRING)info->CompleteName,
                                         evt->Path, RG_MAX_PATH_CHARS);
        RgSendRawEvent(evt);
        ExFreePoolWithTag(evt, RG_TAG);
        return STATUS_SUCCESS;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        keyObject = info->Object;
        break;
    }
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        keyObject = info->Object;
        break;
    }
    default:
        return STATUS_SUCCESS;
    }

    if (keyObject == NULL) {
        return STATUS_SUCCESS;
    }

    /* Resolve the key object to its full registry path. */
    status = CmCallbackGetKeyObjectIDEx(&g_Rg.CmCookie, keyObject, NULL,
                                        &keyName, 0);
    if (!NT_SUCCESS(status) || keyName == NULL) {
        return STATUS_SUCCESS;
    }

    if (keyName->Length == 0 || keyName->Buffer == NULL ||
        !RgPathIsWatched(keyName->Buffer)) {
        CmCallbackReleaseKeyObjectIDEx(keyName);
        return STATUS_SUCCESS;
    }

    evt = (PRG_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RG_EVENT), RG_TAG);
    if (evt == NULL) {
        CmCallbackReleaseKeyObjectIDEx(keyName);
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(evt, sizeof(RG_EVENT));
    evt->Kind       = (ULONG)RgEventRegistry;
    evt->SubKind    = sub;
    evt->ProcessId  = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt->ThreadId   = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    evt->PathLength = RgCopyUnicode((PUNICODE_STRING)keyName,
                                    evt->Path, RG_MAX_PATH_CHARS);
    if (valueName != NULL) {
        evt->ExtraLength = RgCopyUnicode(valueName,
                                         evt->Extra, RG_MAX_EXTRA_CHARS);
    }
    RgSendRawEvent(evt);
    ExFreePoolWithTag(evt, RG_TAG);

    CmCallbackReleaseKeyObjectIDEx(keyName);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Object-manager callback (tamper protection)                                 */
/* -------------------------------------------------------------------------- */

static OB_PREOP_CALLBACK_STATUS RgObPreOperation(_In_ PVOID RegistrationContext,
                                                 _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    PEPROCESS target;
    HANDLE targetPidH;
    ULONG targetPid;
    ULONG requesterPid;
    ACCESS_MASK *desired;
    ACCESS_MASK before;
    ACCESS_MASK stripped;
    BOOLEAN isThread;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    isThread = (OperationInformation->ObjectType == *PsThreadType);
    if (isThread) {
        PETHREAD t = (PETHREAD)OperationInformation->Object;
        target = IoThreadToProcess(t);
    } else {
        target = (PEPROCESS)OperationInformation->Object;
    }
    if (target == NULL) {
        return OB_PREOP_SUCCESS;
    }

    targetPidH = PsGetProcessId(target);
    targetPid  = (ULONG)(ULONG_PTR)targetPidH;
    if (targetPid == 0 || !RgIsProtected(targetPid)) {
        return OB_PREOP_SUCCESS;
    }

    requesterPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (requesterPid == targetPid) {
        return OB_PREOP_SUCCESS;   // self-access is always allowed
    }

    /* Select pre-op vs duplicate access mask. */
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else {
        desired = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    before  = *desired;
    stripped = isThread ? (before & RG_DENY_THREAD_ACCESS)
                        : (before & RG_DENY_PROCESS_ACCESS);
    if (stripped == 0) {
        return OB_PREOP_SUCCESS;
    }
    *desired = before & ~stripped;

    /* Notify user mode best-effort.  Keep the event payload tiny — we are
     * inside an Ob pre-op and must not block. */
    {
        PRG_EVENT evt = (PRG_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                   sizeof(RG_EVENT), RG_TAG);
        if (evt != NULL) {
            RtlZeroMemory(evt, sizeof(RG_EVENT));
            evt->Kind            = (ULONG)RgEventTamperBlocked;
            evt->SubKind         = isThread ? (ULONG)RgTamperThread
                                            : (ULONG)RgTamperProcess;
            evt->ProcessId       = targetPid;
            evt->ParentProcessId = requesterPid;
            evt->DesiredAccess   = (ULONG)before;
            evt->Status          = (ULONG)stripped;
            evt->TimestampNs     = RgTimestampNs();
            RgSendRawEvent(evt);
            ExFreePoolWithTag(evt, RG_TAG);
        }
    }

    return OB_PREOP_SUCCESS;
}
