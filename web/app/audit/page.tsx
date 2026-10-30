"use client";

import { PageHeader } from "@/components/shell";
import { Card, Empty, ErrorNote } from "@/components/ui";
import { fmtTime, usePoll } from "@/lib/api";

interface Row { id: number; at: string; actor: string; kind: string; subject: string; payload: Record<string, unknown>; hash: string }

export default function Audit() {
  const rows = usePoll<Row[]>("/v1/audit?limit=200", 5000);
  const verify = usePoll<{ ok: boolean; rows: number; first_bad_index: number | null }>("/v1/audit/verify", 10000);
  const v = verify.data;
  return (
    <>
      <PageHeader kicker="Append-only · SHA-256 hash chain" title="Incident Audit Log">
        {v && (
          <span className={`pill ${v.ok ? "pill-good" : "pill-crit"}`}>
            {v.ok ? `Chain verified · ${v.rows} rows` : `Chain broken at row ${v.first_bad_index}`}
          </span>
        )}
      </PageHeader>
      <ErrorNote error={rows.error} />
      <Card>
        {!rows.data?.length ? (
          <Empty>No audit entries.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead>
                <tr className="border-b border-stroke">
                  {["#", "Time", "Actor", "Event", "Subject", "Hash"].map((h) => <th key={h} className="label-caps px-3 py-2">{h}</th>)}
                </tr>
              </thead>
              <tbody className="divide-y divide-stroke font-mono text-xs">
                {rows.data.map((r) => (
                  <tr key={r.id} className="align-top">
                    <td className="px-3 py-2 text-faint">{r.id}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted">{fmtTime(r.at)}</td>
                    <td className="px-3 py-2 text-ink">{r.actor}</td>
                    <td className="px-3 py-2 text-primary">{r.kind}</td>
                    <td className="max-w-[260px] truncate px-3 py-2 text-muted" title={JSON.stringify(r.payload)}>{r.subject}</td>
                    <td className="px-3 py-2 text-faint">{r.hash.slice(0, 12)}…</td>
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
