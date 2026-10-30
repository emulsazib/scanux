"use client";

import { baseName, type GraphEdge, type GraphNode } from "@/lib/api";

const COL_W = 210;
const ROW_H = 64;

function label(n: GraphNode): string {
  if (n.kind === "process") return n.name || baseName(n.image) || "process";
  if (n.kind === "file") return n.name || baseName(n.path);
  if (n.kind === "endpoint") return n.ip ?? "endpoint";
  return n.name ?? n.id.slice(0, 10);
}

/**
 * Layered layout: processes by spawn depth (left → right), then the files,
 * domains, and endpoints they touched in the last column. Labels are text nodes
 * (telemetry is never rendered as HTML).
 */
export function IncidentGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const procs = nodes.filter((n) => n.kind === "process");
  const parent = new Map(edges.filter((e) => e.type === "SPAWNED").map((e) => [e.dst, e.src]));
  const depth = (id: string, seen = new Set<string>()): number => {
    const p = parent.get(id);
    return p && !seen.has(p) ? 1 + depth(p, seen.add(id)) : 0;
  };
  const pos = new Map<string, { x: number; y: number }>();
  const perCol = new Map<number, number>();
  for (const p of [...procs].sort((a, b) => depth(a.id) - depth(b.id))) {
    const d = depth(p.id);
    const row = perCol.get(d) ?? 0;
    perCol.set(d, row + 1);
    pos.set(p.id, { x: 24 + d * COL_W, y: 28 + row * ROW_H });
  }
  const lastCol = Math.max(0, ...[...perCol.keys()]) + 1;
  nodes
    .filter((n) => n.kind !== "process" && n.kind !== "host")
    .forEach((n, i) => pos.set(n.id, { x: 24 + lastCol * COL_W, y: 28 + i * ROW_H * 0.8 }));
  const width = 24 + (lastCol + 1) * COL_W;
  const height = Math.max(...[...pos.values()].map((p) => p.y), 0) + 60;
  const color = (n: GraphNode) =>
    n.alerts?.length ? "var(--color-critical)" : n.kind === "process" ? "var(--color-primary)" : "var(--color-tertiary)";

  return (
    <div className="overflow-x-auto rounded-xl border border-stroke bg-void">
      <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img" aria-label="Incident graph">
        <defs>
          <marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L8,4 L0,8 z" fill="var(--color-faint)" />
          </marker>
        </defs>
        {edges.map((e, i) => {
          // Stack labels of edges that share a target so they don't overprint.
          const nth = edges.slice(0, i).filter((o) => o.dst === e.dst && o.type !== "SPAWNED").length;
          const a = pos.get(e.src);
          const b = pos.get(e.dst);
          if (!a || !b) return null;
          const x1 = a.x + 160;
          const y1 = a.y + 14;
          const x2 = b.x - 4;
          const y2 = b.y + 14;
          const mx = (x1 + x2) / 2;
          return (
            <g key={i}>
              <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke="var(--color-stroke-strong)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              {/* Spawn labels sit mid-edge; fan-in labels sit beside their target to avoid collisions. */}
              <text
                x={e.type === "SPAWNED" ? mx : x2 - 8}
                y={e.type === "SPAWNED" ? y1 - 6 : y2 - 5 - nth * 10}
                textAnchor={e.type === "SPAWNED" ? "middle" : "end"}
                className="fill-faint font-mono"
                fontSize="9"
              >
                {e.type.toLowerCase().replace("_", " ")}
                {e.mean_interval_s ? ` · every ${e.mean_interval_s}s` : ""}
              </text>
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <title>{`${n.kind} ${n.image || n.path || n.ip || n.name || ""}${n.pid ? ` (pid ${n.pid})` : ""}`}</title>
              <rect width="160" height="28" rx="8" fill="var(--color-surface)" stroke={color(n)} strokeOpacity="0.7" />
              <circle cx="12" cy="14" r="3.5" fill={color(n)} />
              <text x="22" y="18" className="fill-ink font-mono" fontSize="11">
                {label(n).length > 20 ? label(n).slice(0, 19) + "…" : label(n)}
              </text>
              {n.alerts?.length ? (
                <text x="0" y="42" className="font-mono" fontSize="9" fill="var(--color-critical)">
                  {n.alerts.join(" · ").replaceAll("_", " ").slice(0, 34)}
                </text>
              ) : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
