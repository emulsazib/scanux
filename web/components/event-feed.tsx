"use client";

import { baseName, type EventRow, fmtTime } from "@/lib/api";

const CLASS: Record<number, [string, string]> = {
  1001: ["File", "pill-info"],
  1007: ["Process", "pill-ok"],
  2004: ["Detection", "pill-crit"],
  3002: ["Auth", "pill-warn"],
  4001: ["Network", "pill-info"],
  4003: ["DNS", "pill-info"],
};
const FILE_OP: Record<number, string> = { 1: "create", 2: "read", 3: "write", 4: "delete", 5: "rename", 6: "set-info" };

/** One-line summary from the OCSF event. Rendered as text only (telemetry is untrusted). */
export function summarize(e: EventRow): string {
  let o: Record<string, any>;
  try {
    o = JSON.parse(e.ocsf);
  } catch {
    return "";
  }
  const actor = baseName(o.actor?.process?.file?.path) || `pid ${o.actor?.process?.pid ?? "?"}`;
  switch (e.class_uid) {
    case 1007:
      if (o.activity_id === 1) return `${baseName(o.process?.file?.path)} started (pid ${o.process?.pid})`;
      if (o.activity_id === 2) return `pid ${o.process?.pid} exited`;
      return `${baseName(o.process?.file?.path)} ${o.unmapped?.scanu?.script ? "script block" : "activity"}`;
    case 1001:
      return `${actor} ${FILE_OP[o.activity_id] ?? "touched"} ${baseName(o.file?.path)}`;
    case 4001:
      return `${actor} → ${o.dst_endpoint?.ip}:${o.dst_endpoint?.port}`;
    case 4003:
      return `${actor} resolved ${o.query?.hostname}`;
    case 2004:
      return `finding: ${o.finding_info?.title}`;
    case 3002:
      return `logon ${o.status_id === 1 ? "success" : "failure"} ${o.user?.name ?? ""}`;
    default:
      return `class ${e.class_uid}`;
  }
}

export function EventFeed({ events }: { events: EventRow[] }) {
  return (
    <ol className="max-h-[420px] divide-y divide-stroke overflow-y-auto rounded-xl border border-stroke bg-void">
      {events.map((e) => {
        const [label, cls] = CLASS[e.class_uid] ?? [String(e.class_uid), ""];
        return (
          <li key={e.event_id} className="flex min-w-0 items-center gap-3 px-4 py-2.5">
            <time className="w-[88px] shrink-0 font-mono text-[11px] text-faint">{fmtTime(e.time).split(", ").pop()}</time>
            <span className={`pill ${cls} w-[92px] shrink-0 justify-center`}>{label}</span>
            <span className="truncate font-mono text-xs text-ink">{summarize(e)}</span>
          </li>
        );
      })}
    </ol>
  );
}
