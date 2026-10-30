/*
 * scanu_flt.sys: Scanu kernel component (minifilter + process notify + Ob callbacks).
 *
 * Deliberately small (ADR 0001): it intercepts and forwards, and never parses
 * file contents. All analysis and policy live in the Rust service, which
 * connects to \ScanuPort as LocalSystem.
 *
 *   - Ransomware canaries: deny write/rename/delete in pre-op, notify service (Tier-1 freeze).
 *   - Protected paths (install dir, vault, spool): deny modification by anyone but the sensor.
 *   - Pre-exec gate: ask the service for a verdict on every new process image (200 ms, fail open).
 *   - Self-protection: strip terminate/inject/suspend rights to the sensor process and threads.
 *   - Refuses non-mandatory unload unless the sensor sent ScanuCmdAllowUnload.
 *
 * Build: WDK "Filter Driver: Filesystem Mini-Filter" project, link with /INTEGRITYCHECK
 * (required by ObRegisterCallbacks and PsSetCreateProcessNotifyRoutineEx).
 */

#include <fltKernel.h>
#include <ntstrsafe.h>
#include "scanu_proto.h"

#define TAG              'unaS'
#define MAX_CANARIES     256
#define MAX_PROTECTED    16
#define PREEXEC_TIMEOUT  (-2000000LL)   /* 200 ms, relative, 100 ns units */
#define NOTIFY_TIMEOUT   (-500000LL)    /*  50 ms */

#define PROCESS_TERMINATE_        0x0001
#define PROCESS_CREATE_THREAD_    0x0002
#define PROCESS_VM_OPERATION_     0x0008
#define PROCESS_VM_WRITE_         0x0020
#define PROCESS_SET_INFORMATION_  0x0200
#define PROCESS_SUSPEND_RESUME_   0x0800
#define THREAD_TERMINATE_         0x0001
#define THREAD_SUSPEND_RESUME_    0x0002
#define THREAD_SET_CONTEXT_       0x0010

NTKERNELAPI LONGLONG PsGetProcessCreateTimeQuadPart(_In_ PEPROCESS Process);

typedef struct _SCANU_GLOBALS {
    PFLT_FILTER   Filter;
    PFLT_PORT     ServerPort;
    PFLT_PORT     ClientPort;
    EX_PUSH_LOCK  Lock;                     /* guards lists + sensor identity */
    UNICODE_STRING Canaries[MAX_CANARIES];
    ULONG         CanaryCount;
    UNICODE_STRING Protected[MAX_PROTECTED];
    ULONG         ProtectedCount;
    PEPROCESS     SensorProcess;            /* referenced */
    HANDLE        SensorPid;
    BOOLEAN       AllowUnload;
    BOOLEAN       ProcessNotifyRegistered;
    PVOID         ObHandle;
    LARGE_INTEGER QpcFrequency;
    volatile LONG PreExecTimeouts;
} SCANU_GLOBALS;

static SCANU_GLOBALS g;

DRIVER_INITIALIZE DriverEntry;
static NTSTATUS ScanuUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static FLT_PREOP_CALLBACK_STATUS ScanuPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *Ctx);
static FLT_PREOP_CALLBACK_STATUS ScanuPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *Ctx);
static FLT_PREOP_CALLBACK_STATUS ScanuPreSetInfo(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *Ctx);

/* ------------------------------------------------------------------ helpers */

static BOOLEAN IsSensorCaller(VOID)
{
    return g.SensorPid != NULL && PsGetCurrentProcessId() == g.SensorPid;
}

static VOID FreeList(_Inout_ UNICODE_STRING *List, _Inout_ ULONG *Count)
{
    for (ULONG i = 0; i < *Count; i++) {
        if (List[i].Buffer) ExFreePoolWithTag(List[i].Buffer, TAG);
        RtlZeroMemory(&List[i], sizeof(UNICODE_STRING));
    }
    *Count = 0;
}

static NTSTATUS AppendPath(_Inout_ UNICODE_STRING *List, _Inout_ ULONG *Count, ULONG Max, _In_reads_(Len) PCWCH Path, ULONG Len)
{
    if (*Count >= Max || Len == 0 || Len > SCANU_MAX_PATH) return STATUS_INVALID_PARAMETER;
    USHORT bytes = (USHORT)(Len * sizeof(WCHAR));
    PWCH buf = ExAllocatePool2(POOL_FLAG_PAGED, bytes, TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(buf, Path, bytes);
    List[*Count].Buffer = buf;
    List[*Count].Length = List[*Count].MaximumLength = bytes;
    (*Count)++;
    return STATUS_SUCCESS;
}

/* Caller holds g.Lock shared. */
static BOOLEAN MatchCanary(_In_ PCUNICODE_STRING Name)
{
    for (ULONG i = 0; i < g.CanaryCount; i++)
        if (RtlEqualUnicodeString(Name, &g.Canaries[i], TRUE)) return TRUE;
    return FALSE;
}

static BOOLEAN MatchProtected(_In_ PCUNICODE_STRING Name)
{
    for (ULONG i = 0; i < g.ProtectedCount; i++)
        if (RtlPrefixUnicodeString(&g.Protected[i], Name, TRUE)) return TRUE;
    return FALSE;
}

typedef enum { HitNone, HitCanary, HitProtected } HIT;

static HIT Classify(_In_ PFLT_CALLBACK_DATA Data, _Out_ PFLT_FILE_NAME_INFORMATION *NameOut)
{
    *NameOut = NULL;
    if (g.CanaryCount == 0 && g.ProtectedCount == 0) return HitNone;
    PFLT_FILE_NAME_INFORMATION ni = NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &ni)))
        return HitNone;
    HIT hit = HitNone;
    FltAcquirePushLockShared(&g.Lock);
    if (MatchCanary(&ni->Name)) hit = HitCanary;
    else if (MatchProtected(&ni->Name)) hit = HitProtected;
    FltReleasePushLock(&g.Lock);
    if (hit == HitNone) { FltReleaseFileNameInformation(ni); return HitNone; }
    *NameOut = ni;
    return hit;
}

/* Fire-and-forget notification (short timeout; never blocks I/O for long). */
static VOID Notify(SCANU_MSG_TYPE Type, ULONG Op, _In_opt_ PCUNICODE_STRING Path)
{
    if (!g.ClientPort) return;
    SCANU_NOTIFICATION *n = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*n), TAG);
    if (!n) return;
    PEPROCESS proc = PsGetCurrentProcess();
    n->Version = SCANU_PROTO_VERSION;
    n->Type = Type;
    n->Pid = HandleToULong(PsGetCurrentProcessId());
    n->ProcessCreateTime = (UINT64)PsGetProcessCreateTimeQuadPart(proc);
    n->Qpc = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
    n->QpcFrequency = (UINT64)g.QpcFrequency.QuadPart;
    n->Op = Op;
    if (Path) {
        n->PathLen = min(Path->Length / sizeof(WCHAR), SCANU_MAX_PATH);
        RtlCopyMemory(n->Path, Path->Buffer, n->PathLen * sizeof(WCHAR));
    }
    LARGE_INTEGER timeout = { .QuadPart = NOTIFY_TIMEOUT };
    (VOID)FltSendMessage(g.Filter, &g.ClientPort, n, sizeof(*n), NULL, NULL, &timeout);
    ExFreePoolWithTag(n, TAG);
}

static FLT_PREOP_CALLBACK_STATUS Deny(_Inout_ PFLT_CALLBACK_DATA Data, HIT Hit, ULONG Op, _In_ PFLT_FILE_NAME_INFORMATION Ni)
{
    Notify(Hit == HitCanary ? ScanuMsgCanaryTrip : ScanuMsgTamper, Op, &Ni->Name);
    FltReleaseFileNameInformation(Ni);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* --------------------------------------------------------- file callbacks */

static FLT_PREOP_CALLBACK_STATUS ScanuPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, PVOID *Ctx)
{
    UNREFERENCED_PARAMETER(Objects);
    *Ctx = NULL;
    if (IsSensorCaller() || Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    ACCESS_MASK access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    BOOLEAN writes = (access & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES)) ||
                     disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF ||
                     (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE);
    if (!writes) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PFLT_FILE_NAME_INFORMATION ni;
    HIT hit = Classify(Data, &ni);
    return hit == HitNone ? FLT_PREOP_SUCCESS_NO_CALLBACK : Deny(Data, hit, ScanuOpOpenForWrite, ni);
}

static FLT_PREOP_CALLBACK_STATUS ScanuPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, PVOID *Ctx)
{
    UNREFERENCED_PARAMETER(Objects);
    *Ctx = NULL;
    /* Paging writes come from the cache manager in System context; the user write was seen earlier. */
    if (IsSensorCaller() || FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PFLT_FILE_NAME_INFORMATION ni;
    HIT hit = Classify(Data, &ni);
    return hit == HitNone ? FLT_PREOP_SUCCESS_NO_CALLBACK : Deny(Data, hit, ScanuOpWrite, ni);
}

static FLT_PREOP_CALLBACK_STATUS ScanuPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, PVOID *Ctx)
{
    UNREFERENCED_PARAMETER(Objects);
    *Ctx = NULL;
    if (IsSensorCaller()) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG op;
    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
    case FileRenameInformation:
    case FileRenameInformationEx:        op = ScanuOpRename; break;
    case FileDispositionInformation:
    case FileDispositionInformationEx:   op = ScanuOpDelete; break;
    case FileBasicInformation:
    case FileEndOfFileInformation:
    case FileAllocationInformation:      op = ScanuOpSetInfo; break;
    default:                             return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    PFLT_FILE_NAME_INFORMATION ni;
    HIT hit = Classify(Data, &ni);
    return hit == HitNone ? FLT_PREOP_SUCCESS_NO_CALLBACK : Deny(Data, hit, op, ni);
}

/* ------------------------------------------------------ pre-exec gate */

static VOID CreateProcessNotifyEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO Info)
{
    if (!Info) {
        /* Exit: forget the sensor identity if it was the sensor. */
        if (ProcessId == g.SensorPid) {
            FltAcquirePushLockExclusive(&g.Lock);
            if (g.SensorProcess) ObDereferenceObject(g.SensorProcess);
            g.SensorProcess = NULL;
            g.SensorPid = NULL;
            FltReleasePushLock(&g.Lock);
        }
        return;
    }
    if (!g.ClientPort || !Info->ImageFileName || Info->ParentProcessId == g.SensorPid) return;

    SCANU_NOTIFICATION *n = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*n), TAG);
    if (!n) return;
    n->Version = SCANU_PROTO_VERSION;
    n->Type = ScanuMsgPreExec;
    n->Pid = HandleToULong(ProcessId);
    n->ParentPid = HandleToULong(Info->ParentProcessId);
    n->ProcessCreateTime = (UINT64)PsGetProcessCreateTimeQuadPart(Process);
    n->Qpc = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
    n->QpcFrequency = (UINT64)g.QpcFrequency.QuadPart;
    n->PathLen = min(Info->ImageFileName->Length / sizeof(WCHAR), SCANU_MAX_PATH);
    RtlCopyMemory(n->Path, Info->ImageFileName->Buffer, n->PathLen * sizeof(WCHAR));

    SCANU_REPLY reply = { 0 };
    ULONG replyLen = sizeof(reply);
    LARGE_INTEGER timeout = { .QuadPart = PREEXEC_TIMEOUT };
    NTSTATUS st = FltSendMessage(g.Filter, &g.ClientPort, n, sizeof(*n), &reply, &replyLen, &timeout);
    ExFreePoolWithTag(n, TAG);
    if (st == STATUS_TIMEOUT) {
        InterlockedIncrement(&g.PreExecTimeouts);   /* fail open, counted */
        return;
    }
    if (NT_SUCCESS(st) && replyLen >= sizeof(reply) && reply.Verdict == 1)
        Info->CreationStatus = STATUS_ACCESS_DENIED;
}

/* ------------------------------------------------------ self-protection */

static OB_PREOP_CALLBACK_STATUS ObPre(_In_ PVOID Ctx, _Inout_ POB_PRE_OPERATION_INFORMATION Op)
{
    UNREFERENCED_PARAMETER(Ctx);
    if (Op->KernelHandle || !g.SensorProcess || PsGetCurrentProcess() == g.SensorProcess) return OB_PREOP_SUCCESS;
    ACCESS_MASK strip;
    if (Op->ObjectType == *PsProcessType) {
        if (Op->Object != g.SensorProcess) return OB_PREOP_SUCCESS;
        strip = PROCESS_TERMINATE_ | PROCESS_CREATE_THREAD_ | PROCESS_VM_OPERATION_ | PROCESS_VM_WRITE_ |
                PROCESS_SET_INFORMATION_ | PROCESS_SUSPEND_RESUME_;
    } else {
        if (IoThreadToProcess((PETHREAD)Op->Object) != g.SensorProcess) return OB_PREOP_SUCCESS;
        strip = THREAD_TERMINATE_ | THREAD_SUSPEND_RESUME_ | THREAD_SET_CONTEXT_;
    }
    if (Op->Operation == OB_OPERATION_HANDLE_CREATE)
        Op->Parameters->CreateHandleInformation.DesiredAccess &= ~strip;
    else
        Op->Parameters->DuplicateHandleInformation.DesiredAccess &= ~strip;
    return OB_PREOP_SUCCESS;
}

static NTSTATUS RegisterObCallbacks(VOID)
{
    OB_OPERATION_REGISTRATION ops[2] = {
        { PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, ObPre, NULL },
        { PsThreadType,  OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, ObPre, NULL },
    };
    OB_CALLBACK_REGISTRATION reg = { OB_FLT_REGISTRATION_VERSION, 2, RTL_CONSTANT_STRING(L"328010.Scanu"), NULL, ops };
    return ObRegisterCallbacks(&reg, &g.ObHandle);
}

/* ----------------------------------------------------- communication port */

static BOOLEAN CallerIsLocalSystem(VOID)
{
    BOOLEAN result = FALSE;
    PACCESS_TOKEN tok = PsReferencePrimaryToken(PsGetCurrentProcess());
    PTOKEN_USER user = NULL;
    if (NT_SUCCESS(SeQueryInformationToken(tok, TokenUser, (PVOID *)&user)) && user) {
        result = RtlEqualSid(user->User.Sid, SeExports->SeLocalSystemSid);
        ExFreePool(user);
    }
    PsDereferencePrimaryToken(tok);
    return result;
}

static NTSTATUS PortConnect(PFLT_PORT Client, PVOID Cookie, PVOID Ctx, ULONG CtxLen, PVOID *ConnCookie)
{
    UNREFERENCED_PARAMETER(Cookie); UNREFERENCED_PARAMETER(Ctx); UNREFERENCED_PARAMETER(CtxLen);
    *ConnCookie = NULL;
    if (!CallerIsLocalSystem()) return STATUS_ACCESS_DENIED;
    g.ClientPort = Client;
    return STATUS_SUCCESS;
}

static VOID PortDisconnect(PVOID ConnCookie)
{
    UNREFERENCED_PARAMETER(ConnCookie);
    FltCloseClientPort(g.Filter, &g.ClientPort);
}

static NTSTATUS PortMessage(PVOID Cookie, PVOID In, ULONG InLen, PVOID Out, ULONG OutLen, PULONG Returned)
{
    UNREFERENCED_PARAMETER(Cookie); UNREFERENCED_PARAMETER(Out); UNREFERENCED_PARAMETER(OutLen);
    *Returned = 0;
    if (!In || InLen < sizeof(SCANU_COMMAND)) return STATUS_INVALID_PARAMETER;
    SCANU_COMMAND *cmd = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*cmd), TAG);
    if (!cmd) return STATUS_INSUFFICIENT_RESOURCES;
    NTSTATUS st = STATUS_SUCCESS;
    __try {
        ProbeForRead(In, sizeof(*cmd), sizeof(UINT32));      /* user buffer: probe + copy */
        RtlCopyMemory(cmd, In, sizeof(*cmd));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    if (NT_SUCCESS(st) && (cmd->Version != SCANU_PROTO_VERSION || cmd->PathLen > SCANU_MAX_PATH)) st = STATUS_INVALID_PARAMETER;
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(cmd, TAG); return st; }

    FltAcquirePushLockExclusive(&g.Lock);
    switch (cmd->Type) {
    case ScanuCmdRegisterSensor:
        if (g.SensorPid && g.SensorPid != PsGetCurrentProcessId()) { st = STATUS_ACCESS_DENIED; break; }
        if (!g.SensorProcess) {
            g.SensorProcess = PsGetCurrentProcess();
            ObReferenceObject(g.SensorProcess);
            g.SensorPid = PsGetCurrentProcessId();
        }
        break;
    case ScanuCmdClearCanaries:
        if (!IsSensorCaller()) { st = STATUS_ACCESS_DENIED; break; }
        FreeList(g.Canaries, &g.CanaryCount);
        break;
    case ScanuCmdAddCanary:
        st = IsSensorCaller() ? AppendPath(g.Canaries, &g.CanaryCount, MAX_CANARIES, cmd->Path, cmd->PathLen) : STATUS_ACCESS_DENIED;
        break;
    case ScanuCmdAddProtectedPath:
        st = IsSensorCaller() ? AppendPath(g.Protected, &g.ProtectedCount, MAX_PROTECTED, cmd->Path, cmd->PathLen) : STATUS_ACCESS_DENIED;
        break;
    case ScanuCmdAllowUnload:
        /* The sensor only sends this after verifying a cloud-signed uninstall. */
        if (IsSensorCaller()) g.AllowUnload = TRUE; else st = STATUS_ACCESS_DENIED;
        break;
    default:
        st = STATUS_INVALID_PARAMETER;
    }
    FltReleasePushLock(&g.Lock);
    ExFreePoolWithTag(cmd, TAG);
    return st;
}

/* ------------------------------------------------------------- lifecycle */

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,          0, ScanuPreCreate,  NULL },
    { IRP_MJ_WRITE,           0, ScanuPreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION, 0, ScanuPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0,
    NULL, Callbacks, ScanuUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static VOID Cleanup(VOID)
{
    if (g.ServerPort) { FltCloseCommunicationPort(g.ServerPort); g.ServerPort = NULL; }
    if (g.ProcessNotifyRegistered) { PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE); g.ProcessNotifyRegistered = FALSE; }
    if (g.ObHandle) { ObUnRegisterCallbacks(g.ObHandle); g.ObHandle = NULL; }
    FltAcquirePushLockExclusive(&g.Lock);
    FreeList(g.Canaries, &g.CanaryCount);
    FreeList(g.Protected, &g.ProtectedCount);
    if (g.SensorProcess) { ObDereferenceObject(g.SensorProcess); g.SensorProcess = NULL; g.SensorPid = NULL; }
    FltReleasePushLock(&g.Lock);
    if (g.Filter) { FltUnregisterFilter(g.Filter); g.Filter = NULL; }
}

static NTSTATUS ScanuUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    if (!g.AllowUnload && !FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY)) return STATUS_FLT_DO_NOT_DETACH;
    Cleanup();
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    RtlZeroMemory(&g, sizeof(g));
    FltInitializePushLock(&g.Lock);
    KeQueryPerformanceCounter(&g.QpcFrequency);

    NTSTATUS st = FltRegisterFilter(DriverObject, &Registration, &g.Filter);
    if (!NT_SUCCESS(st)) return st;

    PSECURITY_DESCRIPTOR sd = NULL;
    st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);   /* SYSTEM + Admins; PortConnect narrows to SYSTEM */
    if (NT_SUCCESS(st)) {
        UNICODE_STRING name = RTL_CONSTANT_STRING(SCANU_PORT_NAME);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        st = FltCreateCommunicationPort(g.Filter, &g.ServerPort, &oa, NULL, PortConnect, PortDisconnect, PortMessage, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (NT_SUCCESS(st)) {
        st = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
        g.ProcessNotifyRegistered = NT_SUCCESS(st);
    }
    if (NT_SUCCESS(st)) st = RegisterObCallbacks();
    if (NT_SUCCESS(st)) st = FltStartFiltering(g.Filter);
    if (!NT_SUCCESS(st)) Cleanup();
    return st;
}
