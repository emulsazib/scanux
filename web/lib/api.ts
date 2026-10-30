"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export const DEFAULT_API = process.env.NEXT_PUBLIC_SCANU_API ?? "http://127.0.0.1:8000";
export const DEFAULT_TOKEN = "dev-owner-token";

function read(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
}

/** Connection settings live only in this browser (Settings → Connection). */
export function connection(): { api: string; token: string } {
  return { api: read("scanu.api", DEFAULT_API).replace(/\/+$/, ""), token: read("scanu.token", DEFAULT_TOKEN) };
}

export function saveConnection(api: string, token: string): void {
  try {
    localStorage.setItem("scanu.api", api.trim().replace(/\/+$/, ""));
    localStorage.setItem("scanu.token", token);
    window.dispatchEvent(new Event("scanu:connection"));
  } catch {
    /* storage blocked: settings apply for this tab only */
  }
}

export async function api<T>(path: string, init?: RequestInit, conn = connection()): Promise<T> {
  const { api: base, token } = conn;
  const r = await fetch(`${base}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.json() as Promise<T>;
}

/** Polls `path` every `ms`; returns data, error and a manual refresh. */
export function usePoll<T>(path: string | null, ms = 3000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  const load = useCallback(async () => {
    if (!path) return;
    try {
      const d = await api<T>(path);
      if (alive.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (alive.current) setError(String(e));
    }
  }, [path]);
  useEffect(() => {
    alive.current = true;
    load();
    const t = setInterval(load, ms);
    window.addEventListener("scanu:connection", load);
    return () => {
      alive.current = false;
      clearInterval(t);
      window.removeEventListener("scanu:connection", load);
    };
  }, [load, ms]);
  return { data, error, refresh: load };
}

export type Severity = "low" | "medium" | "high" | "critical";
export type ActionState = "PROPOSED" | "APPROVED" | "REJECTED" | "EXECUTED" | "VERIFIED" | "FAILED" | "ROLLED_BACK";

export interface Stats {
  alerts_7d: number;
  frozen_7d: number;
  incidents: number;
  pending_actions: number;
  verified_actions: number;
  devices: number;
}

export interface IncidentRow {
  incident_id: string;
  device_id: string;
  title: string;
  severity: Severity;
  attack_techniques: string[];
  created_at: string;
  produced_by: string;
  action_id: string | null;
  action_state: ActionState | null;
  recommended_choice: string | null;
}

export interface GraphNode {
  id: string;
  kind: "process" | "file" | "domain" | "endpoint" | "host";
  name?: string;
  image?: string;
  path?: string;
  pid?: number;
  ip?: string;
  sha256?: string;
  alerts?: string[];
  cmdline?: string;
}
export interface GraphEdge {
  src: string;
  dst: string;
  type: string;
  count?: number;
  mean_interval_s?: number;
}

export interface Action {
  action_id: string;
  state: ActionState;
  recommended_choice: string;
  explanation: string;
  proposal: { steps: { tool: string; target_entity_id: string }[] };
  rollback_pending: boolean;
  updated_at: string;
}

export interface Command {
  command_id: string;
  action_id: string;
  tool: string;
  status: string;
  reason: string;
  vault_id: string;
  created_at: string;
  completed_at: string | null;
}

export interface AlertRow {
  alert_id: string;
  device_id?: string;
  severity: Severity;
  kind: string;
  tier1: string;
  received_at: string;
  incident_id?: string | null;
  payload: {
    reason: Record<string, unknown>;
    process?: { image_path: string; pid: number } | null;
    confidence: number;
    file_path?: string;
    scan_id?: string;
  };
}

export interface IncidentDetail {
  incident: {
    incident_id: string;
    device_id: string;
    title: string;
    severity: Severity;
    narrative: string;
    attack_techniques: string[];
    graph: { nodes: GraphNode[]; edges: GraphEdge[] };
    produced_by: string;
    created_at: string;
  };
  actions: Action[];
  commands: Command[];
  alerts: AlertRow[];
}

export interface EventRow {
  event_id: string;
  device_id: string;
  seq: number;
  class_uid: number;
  time: string;
  ocsf: string;
}

export function fmtTime(s: string | null | undefined): string {
  if (!s) return "—";
  const d = new Date(s.includes("T") || s.includes("Z") ? s : s.replace(" ", "T") + "Z");
  return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function baseName(p?: string): string {
  if (!p) return "";
  return p.split(/[\\/]/).pop() ?? p;
}

export interface Device {
  device_id: string;
  online: boolean;
  sensor_version: string;
  os: string;
  first_seen: string;
  last_seen: string;
}

export type ScanState = "queued" | "running" | "completed" | "cancelled" | "failed";

export interface Scan {
  scan_id: string;
  device_id: string;
  scope: "quick" | "full";
  state: ScanState;
  requested_by: string;
  files_seen: number;
  files_analyzed: number;
  bytes_analyzed: number;
  findings: number;
  current_path: string;
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Profile {
  user_id: string;
  role: "owner" | "analyst" | "viewer";
  tenant_id: string;
  tenant_name: string;
  display_name: string;
  email: string;
  notify_desktop: boolean;
  notify_email_critical: boolean;
  updated_at: string;
}

export function initials(name: string): string {
  return name.split(/[\s._-]+/).filter(Boolean).slice(0, 2).map((w) => w[0]!.toUpperCase()).join("") || "?";
}

/** What an alert is about: the process image, or the file for scan findings. */
export function alertSubject(a: AlertRow): string {
  return baseName(a.payload.process?.image_path) || baseName(a.payload.file_path) || "unknown";
}

const KIND_LABEL: Record<string, string> = { bloom: "known malware", ml: "suspicious executable", canary: "ransomware canary" };
export function alertKind(a: AlertRow): string {
  return (KIND_LABEL[a.kind] ?? a.kind.replaceAll("_", " ")) + (a.payload.scan_id ? " · scan" : "");
}
