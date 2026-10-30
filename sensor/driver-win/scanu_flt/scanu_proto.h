/*
 * Kernel <-> user wire protocol for the Scanu minifilter.
 * Mirrored by sensor/crates/sensor-win/src/driver.rs (repr(C)); change both together.
 *
 * Every message is fixed-size, carries no pointers, and is length-checked on
 * both sides. Paths are NT-normalized (\Device\HarddiskVolumeN\...), UTF-16,
 * not NUL-terminated (PathLen is in WCHARs).
 */
#pragma once

#define SCANU_PORT_NAME        L"\\ScanuPort"
#define SCANU_MAX_PATH         520
#define SCANU_PROTO_VERSION    1

/* kernel -> user (FltSendMessage) */
typedef enum _SCANU_MSG_TYPE {
    ScanuMsgCanaryTrip   = 1,   /* I/O already denied; freeze the process   */
    ScanuMsgPreExec      = 2,   /* reply SCANU_REPLY within 200 ms or allow */
    ScanuMsgTamper       = 3,   /* denied access to protected path/process  */
    ScanuMsgHeartbeat    = 4
} SCANU_MSG_TYPE;

typedef enum _SCANU_FILE_OP {
    ScanuOpWrite   = 1,
    ScanuOpRename  = 2,
    ScanuOpDelete  = 3,
    ScanuOpSetInfo = 4,
    ScanuOpOpenForWrite = 5
} SCANU_FILE_OP;

typedef struct _SCANU_NOTIFICATION {
    UINT32 Version;              /* SCANU_PROTO_VERSION                      */
    UINT32 Type;                 /* SCANU_MSG_TYPE                           */
    UINT32 Pid;
    UINT32 ParentPid;
    UINT64 ProcessCreateTime;    /* FILETIME (100 ns since 1601)             */
    UINT64 Qpc;                  /* KeQueryPerformanceCounter at detection   */
    UINT64 QpcFrequency;
    UINT32 Op;                   /* SCANU_FILE_OP (CanaryTrip / Tamper)      */
    UINT32 PathLen;              /* WCHARs used in Path                      */
    WCHAR  Path[SCANU_MAX_PATH]; /* target file, or image for PreExec        */
} SCANU_NOTIFICATION;

typedef struct _SCANU_REPLY {
    UINT32 Verdict;              /* 0 = allow, 1 = block                     */
} SCANU_REPLY;

/* user -> kernel (FilterSendMessage) */
typedef enum _SCANU_CMD_TYPE {
    ScanuCmdRegisterSensor   = 1,  /* caller PID becomes the protected sensor */
    ScanuCmdClearCanaries    = 2,
    ScanuCmdAddCanary        = 3,
    ScanuCmdAddProtectedPath = 4,  /* prefix: install dir, vault, spool       */
    ScanuCmdAllowUnload      = 5   /* only honoured from the registered sensor */
} SCANU_CMD_TYPE;

typedef struct _SCANU_COMMAND {
    UINT32 Version;
    UINT32 Type;                 /* SCANU_CMD_TYPE                           */
    UINT32 PathLen;
    WCHAR  Path[SCANU_MAX_PATH];
} SCANU_COMMAND;
