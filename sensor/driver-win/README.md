# scanu_flt: Windows kernel component

The kernel side is small, written in C (see [ADR 0001](../../docs/adr/0001-windows-kernel-in-c.md)).
All analysis happens in `scanu-sensor.exe`.

| Feature | Mechanism | Tier |
|---|---|---|
| Ransomware canaries | Minifilter pre-create/write/set-info **denies** the I/O, then notifies the service, which suspends the process and adds a WFP block | Tier-1 |
| Self-protection of install dir, vault, spool | Minifilter denies modification by any process except the registered sensor | — |
| Pre-exec verdict | `PsSetCreateProcessNotifyRoutineEx` asks the service (200 ms timeout, fail open, timeouts counted) and sets `CreationStatus = STATUS_ACCESS_DENIED` on block | Tier-1 |
| Sensor anti-kill | `ObRegisterCallbacks` strips TERMINATE / VM_WRITE / VM_OPERATION / CREATE_THREAD / SUSPEND_RESUME / SET_INFORMATION from every non-kernel handle to the sensor's process and threads | — |
| Anti-unload | `FilterUnload` returns `STATUS_FLT_DO_NOT_DETACH` unless the sensor sent `ScanuCmdAllowUnload` (issued only after a cloud-signed uninstall) | — |
| Port hardening | Port SD = SYSTEM + Admins, `PortConnect` requires a LocalSystem token, `MaxConnections = 1`, user buffers probed and copied, fixed-size messages | — |

File/network/process **telemetry** comes from user-mode ETW (`sensor-win/src/etw.rs`), not from this driver.
That keeps the driver's attack surface and CPU cost minimal.

## Build (Windows 11 x64 VM)

1. Install Visual Studio 2022 with the **Desktop development with C++** workload, plus the matching **Windows SDK and WDK**.
2. Create a project from the **Filter Driver: Filesystem Mini-Filter** template named `scanu_flt`. Replace its sources with `scanu_flt.c`, `scanu_proto.h`, and `scanu_flt.inf`.
3. Project properties:
   - Linker → Command Line: `/INTEGRITYCHECK` (required for ObRegisterCallbacks and process notify).
   - Linker → Input: add `fltMgr.lib`.
   - C/C++ → Treat warnings as errors: **Yes**. Driver Signing → Test Sign.
4. Build **x64 / Release**.

## Load (test-signing)

```powershell
bcdedit /set testsigning on           # reboot afterwards
# optional kernel debugging: bcdedit /debug on ; bcdedit /dbgsettings net hostip:<host> port:50000
pnputil /add-driver scanu_flt.inf /install
fltmc load scanu_flt
fltmc                                  # expect scanu_flt at altitude 328010
```

Then start the sensor (`scanu-sensor.exe --console` as SYSTEM, e.g. `psexec -s -i`). It logs
`minifilter connected: kernel canary + pre-exec + self-protection active`.

## Verify

```powershell
# Driver Verifier on the driver (CI on the VM): standard flags + I/O verification
verifier /standard /driver scanu_flt.sys
# Self-protection: both must fail with Access denied
taskkill /f /im scanu-sensor.exe
fltmc unload scanu_flt                 # STATUS_FLT_DO_NOT_DETACH
# Canary + latency: see tests/perf/canary.ps1
```

## Production gates (not available to the MVP)

- **Attestation/WHQL signing** through the Hardware Dev Center (EV certificate) to load without test-signing.
- **Altitude allocation** from Microsoft.
- **ELAM + PPL (AntimalwareLight)**: requires Microsoft Virus Initiative membership and an ELAM-signed resource in the service binary. Then the sensor runs as PPL, so even admins can't inject into it or kill it, and the kill-stripping above becomes defense in depth.
