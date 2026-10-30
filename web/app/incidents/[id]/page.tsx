"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { IncidentGraph } from "@/components/incident-graph";
import { Card, ErrorNote, SeverityPill, StatePill } from "@/components/ui";
import { alertKind, alertSubject, api, baseName, fmtTime, type GraphNode, type IncidentDetail, usePoll } from "@/lib/api";

const CHOICES = [
  { id: "terminate_and_quarantine", label: "Terminate & Quarantine", hint: "Stop the process tree and move its files into the encrypted vault (reversible)." },
  { id: "isolate_network_only", label: "Isolate Network Only", hint: "Keep it running but cut it off from the network." },
  { id: "allow_and_whitelist", label: "Allow & Whitelist", hint: "It's a false positive: resume, reconnect, and trust this hash." },
] as const;

const TOOL_VERB: Record<string, string> = {
  terminate: "Terminate", quarantine: "Quarantine", net_block: "Block network", suspend: "Suspend", allowlist: "Allowlist",
  resume: "Resume", net_unblock: "Unblock network", restore: "Restore from vault",
};

function describe(nodes: GraphNode[], id: string): string {
  const n = nodes.find((x) => x.id === id);
  if (!n) return id.slice(0, 14);
  return n.kind === "process" ? `${n.name || baseName(n.image)} (pid ${n.pid})` : baseName(n.path) || n.id.slice(0, 14);
}

export default function IncidentPage() {
  const { id } = useParams<{ id: string }>();
  const { data, error, refresh } = usePoll<IncidentDetail>(`/v1/incidents/${id}`, 2000);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  if (!data) return <ErrorNote error={error} />;
  const { incident: inc, actions, commands, alerts } = data;
  const action = actions[actions.length - 1];
  const nodes = inc.graph.nodes;

  async function decide(choice: string) {
    if (!action) return;
    setBusy(choice);
    setMsg(null);
    try {
      const r = await api<{ state: string; commands: string[] }>(`/v1/actions/${action.action_id}/decision`, {
        method: "POST",
        body: JSON.stringify({ choice, channel: "web" }),
      });
      setMsg(`Decision recorded → ${r.state}. ${r.commands.length} signed command(s) sent to the device.`);
      refresh();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function rollback() {
    if (!action) return;
    setBusy("rollback");
    try {
      const r = await api<{ commands: string[] }>(`/v1/actions/${action.action_id}/rollback`, { method: "POST" });
      setMsg(`Rollback sent (${r.commands.length} command(s)).`);
      refresh();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <Link href="/incidents" className="label-caps hover:text-ink">← Incidents</Link>
      <div className="mb-6 mt-3 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityPill s={inc.severity} />
            <StatePill s={action?.state} />
            <span className="pill">{inc.device_id}</span>
            <span className="pill" title="Who produced the correlation">{inc.produced_by === "llm" ? "AI correlated" : "Rule correlated"}</span>
          </div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">{inc.title}</h1>
          <div className="mt-1 font-mono text-[11px] text-faint">{inc.incident_id} · {fmtTime(inc.created_at)}</div>
        </div>
        <div className="flex flex-wrap gap-1">
          {inc.attack_techniques.map((t) => (
            <a key={t} className="pill pill-info" href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noreferrer">{t}</a>
          ))}
        </div>
      </div>
      <ErrorNote error={error} />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_440px]">
        <div className="min-w-0 space-y-6">
          <Card kicker="Plain-language explanation" title="What happened">
            <p className="max-w-[72ch] leading-relaxed text-ink/90">{inc.narrative}</p>
          </Card>
          <Card kicker={`${nodes.length} entities · ${inc.graph.edges.length} relations`} title="Incident graph">
            <IncidentGraph nodes={nodes} edges={inc.graph.edges} />
          </Card>
          <Card kicker="Edge detections" title="Alerts in this incident">
            <ul className="space-y-2">
              {alerts.map((a) => (
                <li key={a.alert_id} className="flex flex-wrap items-center gap-3 rounded-lg border border-stroke bg-void px-3 py-2">
                  <SeverityPill s={a.severity} />
                  <span className="font-mono text-xs">{alertKind(a)}</span>
                  <span className="text-xs text-faint">{alertSubject(a)}</span>
                  {a.tier1 !== "none" && (
                    <span className="pill pill-crit ml-auto">
                      Tier-1 frozen{typeof a.payload.reason.frozen_us === "number" ? ` · ${a.payload.reason.frozen_us}µs` : ""}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </Card>
        </div>

        <div className="order-first space-y-6 xl:order-none">
          <Card kicker="Remediation agent · human in the loop" title="Your decision">
            {action ? (
              <>
                <p className="mb-4 text-sm leading-relaxed text-muted">{action.explanation}</p>
                <div className="label-caps mb-2">Proposed targets</div>
                <ul className="mb-5 space-y-1">
                  {action.proposal.steps.map((s, i) => (
                    <li key={i} className="font-mono text-xs text-ink">
                      <span className="text-primary">{TOOL_VERB[s.tool] ?? s.tool}</span> {describe(nodes, s.target_entity_id)}
                    </li>
                  ))}
                </ul>
                {action.state === "PROPOSED" ? (
                  <div className="space-y-2">
                    {CHOICES.map((c) => (
                      <button
                        key={c.id}
                        onClick={() => decide(c.id)}
                        disabled={!!busy}
                        className={`btn w-full !h-auto flex-col !items-start py-2.5 text-left ${c.id === action.recommended_choice ? "btn-primary" : ""}`}
                      >
                        <span>{c.label}{c.id === action.recommended_choice ? " · recommended" : ""}</span>
                        <span className="font-sans text-[11px] font-normal opacity-80">{c.hint}</span>
                      </button>
                    ))}
                    <button onClick={() => decide("reject")} disabled={!!busy} className="btn btn-danger w-full">Reject proposal</button>
                  </div>
                ) : action.state === "VERIFIED" && !action.rollback_pending ? (
                  <button onClick={rollback} disabled={!!busy} className="btn w-full">Roll back (restore from vault)</button>
                ) : (
                  <div className="text-sm text-muted">State: {action.state}{action.rollback_pending ? " · rollback in progress" : ""}</div>
                )}
                {msg && <div role="status" className="mt-3 rounded-lg border border-stroke bg-void px-3 py-2 font-mono text-xs text-muted">{msg}</div>}
              </>
            ) : (
              <p className="text-sm text-muted">No action proposed.</p>
            )}
          </Card>

          <Card kicker="Signed · Ed25519 · verified on device" title="Command trail">
            {commands.length ? (
              <ol className="space-y-2">
                {commands.map((c) => (
                  <li key={c.command_id} className="rounded-lg border border-stroke bg-void px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-ink">{TOOL_VERB[c.tool] ?? c.tool}</span>
                      <span className={`pill ml-auto ${c.status === "executed" ? "pill-good" : c.status === "sent" ? "pill-info" : "pill-crit"}`}>{c.status}</span>
                    </div>
                    <div className="mt-1 truncate font-mono text-[10px] text-faint">
                      {c.command_id}{c.reason ? ` · ${c.reason}` : ""}{c.vault_id ? ` · ${c.vault_id}` : ""}
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-sm text-muted">Nothing has been sent to the device.</p>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
