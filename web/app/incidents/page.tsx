"use client";

import Link from "next/link";
import { PageHeader } from "@/components/shell";
import { Card, Empty, ErrorNote, SeverityPill, StatePill } from "@/components/ui";
import { fmtTime, type IncidentRow, usePoll } from "@/lib/api";

export default function Incidents() {
  const { data, error } = usePoll<IncidentRow[]>("/v1/incidents?limit=200", 4000);
  return (
    <>
      <PageHeader kicker="Incident telemetry · OCSF audit" title="Security Intelligence & Incidents" />
      <ErrorNote error={error} />
      <Card>
        {!data?.length ? (
          <Empty>No incidents yet.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-sm">
              <thead>
                <tr className="border-b border-stroke">
                  {["Time", "Incident", "Device", "Techniques", "Severity", "Resolution", "By"].map((h) => (
                    <th key={h} className="label-caps px-3 py-3 font-semibold">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-stroke">
                {data.map((i) => (
                  <tr key={i.incident_id} className="hover:bg-white/[0.02]">
                    <td className="whitespace-nowrap px-3 py-3 font-mono text-xs text-muted">{fmtTime(i.created_at)}</td>
                    <td className="px-3 py-3">
                      <Link href={`/incidents/${i.incident_id}`} className="font-display text-ink hover:text-primary">{i.title}</Link>
                      <div className="font-mono text-[11px] text-faint">{i.incident_id.slice(0, 16)}…</div>
                    </td>
                    <td className="px-3 py-3 font-mono text-xs text-muted">{i.device_id}</td>
                    <td className="px-3 py-3">
                      <div className="flex max-w-[260px] flex-wrap gap-1">
                        {i.attack_techniques.map((t) => (
                          <a key={t} href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noreferrer" className="pill hover:text-ink">{t}</a>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-3"><SeverityPill s={i.severity} /></td>
                    <td className="px-3 py-3"><StatePill s={i.action_state} /></td>
                    <td className="px-3 py-3 font-mono text-[11px] text-faint">{i.produced_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
