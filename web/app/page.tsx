"use client";

import Link from "next/link";
import { EventFeed } from "@/components/event-feed";
import { ScanPanel } from "@/components/scan-panel";
import { PageHeader } from "@/components/shell";
import { Card, Empty, ErrorNote, SeverityPill, Stat, StatePill } from "@/components/ui";
import { type AlertRow, alertKind, alertSubject, type EventRow, fmtTime, type IncidentRow, type Stats, usePoll } from "@/lib/api";

export default function Diagnostics() {
  const stats = usePoll<Stats>("/v1/stats", 4000);
  const events = usePoll<EventRow[]>("/v1/events?limit=80", 3000);
  const alerts = usePoll<AlertRow[]>("/v1/alerts?limit=12", 3000);
  const incidents = usePoll<IncidentRow[]>("/v1/incidents?limit=6", 4000);
  const s = stats.data;
  const pending = incidents.data?.filter((i) => i.action_state === "PROPOSED") ?? [];

  return (
    <>
      <PageHeader kicker="Edge sensors · OCSF stream" title="System Diagnostics">
        <p className="max-w-md text-sm text-muted">
          Tier-1 freezes happen on the device in microseconds. Everything destructive waits for you.
        </p>
      </PageHeader>
      <ErrorNote error={stats.error} />

      {pending.length > 0 && (
        <div className="mb-6 flex flex-col gap-3 rounded-2xl border border-warning/40 bg-warning/10 p-4 md:flex-row md:items-center">
          <span className="pill pill-warn"><span className="pulse" /> Decision needed</span>
          <span className="text-sm text-ink">
            {pending.length} incident{pending.length > 1 ? "s" : ""} waiting for your approval: <b>{pending[0].title}</b>
          </span>
          <Link href={`/incidents/${pending[0].incident_id}`} className="btn btn-primary md:ml-auto">Review</Link>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Alerts · 7 days" value={s?.alerts_7d ?? "–"} hint="raised by edge detectors" tone="warning" />
        <Stat label="Tier-1 freezes" value={s?.frozen_7d ?? "–"} hint="suspended + network-blocked" tone="critical" />
        <Stat label="Awaiting decision" value={s?.pending_actions ?? "–"} hint={`${s?.incidents ?? 0} incidents total`} />
        <Stat label="Verified actions" value={s?.verified_actions ?? "–"} hint={`${s?.devices ?? 0} protected device(s)`} tone="secondary" />
      </div>

      <div className="mt-6">
        <ScanPanel />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_420px]">
        <Card kicker="ClickHouse · raw" title="OCSF Normalized Event Feed" right={<span className="pill pill-good">Auto-refresh</span>}>
          {events.data?.length ? <EventFeed events={events.data} /> : <Empty>No telemetry yet. Run <code className="font-mono">make sim-cred</code>.</Empty>}
        </Card>
        <Card kicker="Edge detections" title="Latest Alerts">
          {alerts.data?.length ? (
            <ul className="space-y-2">
              {alerts.data.map((a) => (
                <li key={a.alert_id} className="flex items-center gap-3 rounded-lg border border-stroke bg-void px-3 py-2">
                  <SeverityPill s={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-xs text-ink">{alertKind(a)}</div>
                    <div className="truncate text-[11px] text-faint">{alertSubject(a)} · {fmtTime(a.received_at)}</div>
                  </div>
                  {a.tier1 !== "none" && <span className="pill pill-crit" title={a.tier1}>Frozen</span>}
                </li>
              ))}
            </ul>
          ) : (
            <Empty>Quiet. No alerts.</Empty>
          )}
        </Card>
      </div>

      <Card className="mt-6" kicker="Multi-agent correlation" title="Recent Incidents" right={<Link href="/incidents" className="btn">All incidents</Link>}>
        {incidents.data?.length ? (
          <ul className="divide-y divide-stroke">
            {incidents.data.map((i) => (
              <li key={i.incident_id}>
                <Link href={`/incidents/${i.incident_id}`} className="flex flex-wrap items-center gap-3 py-3 hover:bg-white/[0.02]">
                  <SeverityPill s={i.severity} />
                  <span className="min-w-0 flex-1 truncate font-display text-ink">{i.title}</span>
                  <StatePill s={i.action_state} />
                  <span className="font-mono text-[11px] text-faint">{fmtTime(i.created_at)}</span>
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>No incidents.</Empty>
        )}
      </Card>
    </>
  );
}
