import { PageHeader } from "@/components/shell";
import { Card } from "@/components/ui";

type Status = "active" | "dev" | "planned" | "gated";
const PILL: Record<Status, [string, string]> = {
  active: ["pill-good", "Active"],
  dev: ["pill-ok", "Dev / test-signed"],
  planned: ["pill-info", "Planned"],
  gated: ["pill-warn", "External gate"],
};

const SUBSYSTEMS: { name: string; status: Status; what: string; detail: string }[] = [
  { name: "WFP per-process isolation", status: "active", what: "Blocks one executable's traffic (ALE connect/accept, app-id match) without taking the machine offline.", detail: "User-mode WFP API · dynamic session" },
  { name: "Minifilter · canaries & protected paths", status: "dev", what: "Denies writes, renames, and deletes of ransomware canaries and the sensor's own files in kernel, then freezes the writer.", detail: "scanu_flt.sys · altitude placeholder 328010" },
  { name: "Pre-execution verdict", status: "dev", what: "Every new process image is hashed, bloom-checked, and scored offline before its first thread runs.", detail: "PsSetCreateProcessNotifyRoutineEx · 200 ms fail-open" },
  { name: "Self-protection (handle stripping)", status: "dev", what: "Terminate, inject, and suspend rights to the sensor are stripped for every non-kernel caller, admins included.", detail: "ObRegisterCallbacks" },
  { name: "Signed remediation commands", status: "active", what: "The device runs only closed-set commands, Ed25519-signed by the pinned cloud key, bound to this device, unexpired, unreplayed, and human-approved.", detail: "enforcer::verify" },
  { name: "mTLS with pinned CA", status: "active", what: "Device identity comes from its certificate (SPIFFE URI), never from payloads. OS trust stores are not used.", detail: "TLS 1.3 · rustls" },
  { name: "TPM-backed device key", status: "planned", what: "The device private key becomes non-exportable via the NCrypt Platform Crypto Provider.", detail: "Milestone M4" },
  { name: "PPL + ELAM", status: "gated", what: "Runs the sensor as a Protected Process Light (Antimalware), so even admins can't open it for write.", detail: "Requires Microsoft Virus Initiative membership" },
];

const PARITY = [
  ["Blocking file intercept", "Minifilter", "fanotify / eBPF LSM", "EndpointSecurity AUTH*"],
  ["Pre-exec verdict", "Process notify", "FAN_OPEN_EXEC_PERM", "ES AUTH_EXEC"],
  ["Per-process network block", "WFP ALE", "cgroup + eBPF", "NE content filter"],
  ["Script telemetry", "ETW 4104 / WMI / CLR", "eBPF uprobes (best effort)", "exec args only"],
  ["Anti-tamper", "ObCallbacks → PPL", "lockdown + LSM", "System Extension + SIP"],
  ["Status", "MVP", "Post-MVP", "Post-MVP"],
];

export default function Rules() {
  return (
    <>
      <PageHeader kicker="Kernel hooks · zero-trust permission matrix" title="Subsystem & Privilege Control">
        <p className="max-w-md text-sm text-muted">What protects this endpoint today, and what's still gated. These are the real statuses, not marketing.</p>
      </PageHeader>
      <div className="grid gap-4 lg:grid-cols-2">
        {SUBSYSTEMS.map((s) => (
          <Card key={s.name}>
            <div className="mb-2 flex items-start justify-between gap-3">
              <h2 className="font-display text-lg font-medium">{s.name}</h2>
              <span className={`pill ${PILL[s.status][0]}`}>{PILL[s.status][1]}</span>
            </div>
            <p className="text-sm leading-relaxed text-muted">{s.what}</p>
            <div className="mt-4 rounded-lg border border-stroke bg-void px-3 py-2 font-mono text-[11px] text-faint">{s.detail}</div>
          </Card>
        ))}
      </div>
      <Card className="mt-6" kicker="Cross-platform" title="Platform parity">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead>
              <tr className="border-b border-stroke">
                {["Capability", "Windows", "Linux", "macOS"].map((h) => <th key={h} className="label-caps px-3 py-2">{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-stroke">
              {PARITY.map((r) => (
                <tr key={r[0]}>
                  {r.map((c, i) => <td key={i} className={`px-3 py-2.5 ${i ? "font-mono text-xs text-muted" : "text-ink"}`}>{c}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
