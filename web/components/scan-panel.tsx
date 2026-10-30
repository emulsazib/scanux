"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui";
import { api, baseName, type Device, fmtTime, type Scan, usePoll } from "@/lib/api";

const ACTIVE = new Set(["queued", "running"]);
const STATE_PILL: Record<string, string> = { queued: "pill-info", running: "pill-ok", completed: "pill-good", cancelled: "", failed: "pill-crit" };

function ts(s: string | null): number {
  return s ? new Date(s).getTime() : 0;
}

function duration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

function bytes(n: number): string {
  if (n < 1 << 20) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${(n / (1 << 30)).toFixed(2)} GB`;
}

export function ScanPanel() {
  const devices = usePoll<Device[]>("/v1/devices", 5000).data ?? [];
  const [device, setDevice] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!device && devices.length) setDevice((devices.find((d) => d.online) ?? devices[0]).device_id);
  }, [devices, device]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const scans = usePoll<Scan[]>(device ? `/v1/scans?device_id=${encodeURIComponent(device)}&limit=6` : null, 1500);
  const list = scans.data ?? [];
  const active = list.find((s) => ACTIVE.has(s.state));
  const last = list.find((s) => !ACTIVE.has(s.state));
  const dev = useMemo(() => devices.find((d) => d.device_id === device), [devices, device]);

  async function start(scope: "quick" | "full") {
    setBusy(true);
    setError(null);
    try {
      await api(`/v1/devices/${encodeURIComponent(device)}/scans`, { method: "POST", body: JSON.stringify({ scope }) });
      await scans.refresh();
    } catch (e) {
      const m = String(e);
      setError(m.includes("409") ? "A scan is already running on this device." : m.includes("403") ? "Your role can't start scans." : m);
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    if (!active) return;
    setBusy(true);
    try {
      await api(`/v1/scans/${active.scan_id}/cancel`, { method: "POST" });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const elapsed = active ? now - (ts(active.started_at) || ts(active.created_at)) : 0;
  const rate = active && elapsed > 1000 ? Math.round(active.files_seen / (elapsed / 1000)) : 0;

  return (
    <Card
      kicker="On-demand · read-only · findings go to you for a decision"
      title="Scan now"
      right={
        devices.length > 0 && (
          <select
            aria-label="Device to scan"
            value={device}
            onChange={(e) => setDevice(e.target.value)}
            className="h-9 rounded-lg border border-stroke bg-void px-3 font-mono text-xs text-ink focus:border-primary focus:outline-none"
          >
            {devices.map((d) => (
              <option key={d.device_id} value={d.device_id}>
                {d.online ? "● " : "○ "}{d.device_id}
              </option>
            ))}
          </select>
        )
      }
    >
      {devices.length === 0 ? (
        <p className="text-sm text-muted">No protected devices yet. Install the sensor (or run <code className="font-mono">make sim-cred</code>) and it appears here.</p>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <button className="btn btn-primary !h-auto flex-col !items-start py-3 text-left" disabled={busy || !!active || !dev?.online} onClick={() => start("quick")}>
              <span>Quick scan</span>
              <span className="font-sans text-[11px] font-normal opacity-80">Downloads, Desktop, Temp, AppData, Startup: where threats usually land.</span>
            </button>
            <button className="btn !h-auto flex-col !items-start py-3 text-left" disabled={busy || !!active || !dev?.online} onClick={() => start("full")}>
              <span>Full system scan</span>
              <span className="font-sans text-[11px] font-normal text-muted">Every file on every fixed drive. Takes longer and runs in the background.</span>
            </button>
          </div>
          {dev && !dev.online && <p className="mt-3 text-xs text-warning">This device is offline. Scans start once it reconnects to Scanu.</p>}
          {error && <p role="alert" className="mt-3 font-mono text-xs text-critical">{error}</p>}

          {active && (
            <div className="mt-5 rounded-xl border border-primary/30 bg-primary/[0.04] p-4" aria-live="polite">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`pill ${STATE_PILL[active.state]}`}><span className="pulse" /> {active.state === "queued" ? "Starting" : "Scanning"}</span>
                <span className="font-display text-ink">{active.scope === "full" ? "Full system scan" : "Quick scan"}</span>
                <span className="font-mono text-xs text-muted">{duration(elapsed)}</span>
                <button className="btn btn-danger ml-auto !h-8" onClick={cancel} disabled={busy}>Cancel</button>
              </div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-stroke" role="progressbar" aria-label="Scan in progress">
                <div className="h-full w-1/3 animate-[scan-sweep_1.4s_ease-in-out_infinite] rounded-full bg-primary motion-reduce:animate-none" />
              </div>
              <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                {[
                  ["Files examined", active.files_seen.toLocaleString()],
                  ["Analyzed", active.files_analyzed.toLocaleString()],
                  ["Threats found", active.findings.toLocaleString()],
                  ["Speed", rate ? `${rate.toLocaleString()}/s` : "—"],
                ].map(([k, v]) => (
                  <div key={k}>
                    <dt className="label-caps">{k}</dt>
                    <dd className={`mt-1 font-mono text-xl tabular-nums ${k === "Threats found" && active.findings > 0 ? "text-critical" : "text-ink"}`}>{v}</dd>
                  </div>
                ))}
              </dl>
              {active.current_path && <div className="mt-3 truncate font-mono text-[11px] text-faint" title={active.current_path}>{active.current_path}</div>}
            </div>
          )}

          {!active && last && (
            <div className={`mt-5 flex flex-wrap items-center gap-3 rounded-xl border p-4 ${last.findings > 0 ? "border-critical/40 bg-critical/[0.06]" : "border-stroke bg-void"}`}>
              <span className={`pill ${last.findings > 0 ? "pill-crit" : STATE_PILL[last.state]}`}>
                {last.state === "completed" ? (last.findings > 0 ? `${last.findings} threat${last.findings > 1 ? "s" : ""} found` : "Clean") : last.state}
              </span>
              <span className="text-sm text-ink">
                Last {last.scope} scan · {last.files_seen.toLocaleString()} files, {last.files_analyzed.toLocaleString()} analyzed ({bytes(last.bytes_analyzed)})
                {last.started_at && last.finished_at ? ` in ${duration(ts(last.finished_at) - ts(last.started_at))}` : ""}
              </span>
              {last.error && <span className="font-mono text-xs text-critical">{last.error}</span>}
              {last.findings > 0 && <Link href="/incidents" className="btn ml-auto">Review findings</Link>}
            </div>
          )}

          {list.length > 1 && (
            <details className="mt-4">
              <summary className="label-caps cursor-pointer hover:text-ink">Scan history</summary>
              <ul className="mt-2 divide-y divide-stroke">
                {list.map((s) => (
                  <li key={s.scan_id} className="flex flex-wrap items-center gap-3 py-2 font-mono text-xs">
                    <span className={`pill ${STATE_PILL[s.state] ?? ""}`}>{s.state}</span>
                    <span className="text-ink">{s.scope}</span>
                    <span className="text-muted">{s.files_seen.toLocaleString()} files · {s.findings} findings</span>
                    <span className="text-faint">by {s.requested_by === "device" ? "device" : baseName(s.requested_by)}</span>
                    <span className="ml-auto text-faint">{fmtTime(s.created_at)}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </Card>
  );
}
