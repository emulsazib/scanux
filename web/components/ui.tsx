import type { ReactNode } from "react";
import type { ActionState, Severity } from "@/lib/api";

export function Card({ title, kicker, right, children, className = "" }: {
  title?: ReactNode; kicker?: ReactNode; right?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card p-5 md:p-6 min-w-0 ${className}`}>
      {(title || right) && (
        <header className="mb-4 flex items-start justify-between gap-4">
          <div className="min-w-0">
            {kicker && <div className="label-caps mb-1">{kicker}</div>}
            {title && <h2 className="font-display text-lg font-medium text-ink">{title}</h2>}
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

const SEV: Record<string, string> = { critical: "pill-crit", high: "pill-warn", medium: "pill-info", low: "" };

export function SeverityPill({ s }: { s: Severity | string }) {
  return <span className={`pill ${SEV[s] ?? ""}`}>{s}</span>;
}

const STATE: Record<string, [string, string]> = {
  PROPOSED: ["pill-warn", "Awaiting decision"],
  APPROVED: ["pill-info", "Approved · executing"],
  EXECUTED: ["pill-info", "Executed"],
  VERIFIED: ["pill-good", "Verified"],
  REJECTED: ["", "Rejected"],
  FAILED: ["pill-crit", "Failed"],
  ROLLED_BACK: ["", "Rolled back"],
};

export function StatePill({ s }: { s: ActionState | null | undefined }) {
  if (!s) return <span className="pill">No action</span>;
  const [cls, label] = STATE[s] ?? ["", s];
  return <span className={`pill ${cls}`}>{label}</span>;
}

export function Stat({ label, value, hint, tone = "primary" }: {
  label: string; value: ReactNode; hint?: ReactNode; tone?: "primary" | "critical" | "warning" | "secondary" | "tertiary";
}) {
  const color = { primary: "text-primary", critical: "text-critical", warning: "text-warning", secondary: "text-secondary", tertiary: "text-tertiary" }[tone];
  return (
    <div className="card p-5">
      <div className="label-caps">{label}</div>
      <div className={`mt-3 font-mono text-4xl font-semibold tabular-nums ${color}`}>{value}</div>
      {hint && <div className="mt-2 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-stroke px-4 py-8 text-center text-sm text-muted">{children}</div>;
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div role="alert" className="mb-4 rounded-lg border border-critical/40 bg-critical/10 px-4 py-3 font-mono text-xs text-critical">
      API unreachable: {error}
    </div>
  );
}
