"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/shell";
import { Card } from "@/components/ui";
import { api, connection, DEFAULT_API, fmtTime, initials, type Profile, saveConnection } from "@/lib/api";

type Test = { state: "idle" | "testing" | "ok" | "error"; detail?: string };

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="label-caps">{label}</span>
      <div className="mt-2">{children}</div>
      {hint && <span className="mt-1.5 block text-xs text-faint">{hint}</span>}
    </label>
  );
}

const input =
  "h-10 w-full rounded-lg border border-stroke bg-void px-3 font-mono text-[13px] text-ink placeholder:text-faint focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-60";

function Toggle({ checked, onChange, label, hint }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint: string }) {
  return (
    <div className="flex items-start justify-between gap-6 py-3">
      <div>
        <div className="text-sm text-ink">{label}</div>
        <div className="text-xs text-muted">{hint}</div>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 shrink-0 rounded-full border transition-colors ${checked ? "border-primary bg-primary/25" : "border-stroke bg-stroke"}`}
      >
        <span className={`absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all ${checked ? "left-[18px] bg-primary" : "left-0.5 bg-faint"}`} />
      </button>
    </div>
  );
}

export default function Settings() {
  const [apiUrl, setApiUrl] = useState("");
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [test, setTest] = useState<Test>({ state: "idle" });
  const [profile, setProfile] = useState<Profile | null>(null);
  const [draft, setDraft] = useState({ display_name: "", email: "", notify_desktop: true, notify_email_critical: false });
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function loadProfile() {
    try {
      const p = await api<Profile>("/v1/me");
      setProfile(p);
      setDraft({ display_name: p.display_name, email: p.email, notify_desktop: p.notify_desktop, notify_email_critical: p.notify_email_critical });
    } catch {
      setProfile(null);
    }
  }

  useEffect(() => {
    const c = connection();
    setApiUrl(c.api);
    setToken(c.token);
    loadProfile();
  }, []);

  async function testConnection(e?: React.FormEvent) {
    e?.preventDefault();
    let url: URL;
    try {
      url = new URL(apiUrl);
      if (!["http:", "https:"].includes(url.protocol)) throw new Error();
    } catch {
      setTest({ state: "error", detail: "Enter a full http(s):// URL." });
      return false;
    }
    setTest({ state: "testing" });
    const conn = { api: apiUrl.trim().replace(/\/+$/, ""), token };
    try {
      const health = await api<{ ok: boolean; signer: string | null }>("/healthz", undefined, conn);
      const me = await api<Profile>("/v1/me", undefined, conn);
      setTest({ state: "ok", detail: `Signed in as ${me.display_name} (${me.role}) · ${me.tenant_name} · signer ${health.signer ?? "missing"}` });
      return true;
    } catch (err) {
      const msg = String(err);
      setTest({ state: "error", detail: msg.includes("401") ? "The API rejected this token." : `Can't reach the API: ${msg}` });
      return false;
    }
  }

  async function saveConn(e: React.FormEvent) {
    e.preventDefault();
    if (await testConnection()) {
      saveConnection(apiUrl, token);
      loadProfile();
    }
  }

  async function saveProfile(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setSaveMsg(null);
    try {
      const p = await api<Profile>("/v1/me", { method: "PATCH", body: JSON.stringify(draft) });
      setProfile(p);
      setSaveMsg("Profile saved.");
      window.dispatchEvent(new Event("scanu:connection"));
    } catch (err) {
      setSaveMsg(String(err).includes("422") ? "Check the name and email format." : `Couldn't save: ${err}`);
    } finally {
      setSaving(false);
    }
  }

  const dirty =
    profile !== null &&
    (draft.display_name !== profile.display_name || draft.email !== profile.email ||
      draft.notify_desktop !== profile.notify_desktop || draft.notify_email_critical !== profile.notify_email_critical);

  return (
    <>
      <PageHeader kicker="Console · account" title="Settings" />
      <div className="grid gap-6 xl:grid-cols-2">
        <Card kicker="Stored in this browser only" title="API connection">
          <form onSubmit={saveConn} className="space-y-5">
            <Field label="API URL" hint={`Your Scanu cloud endpoint. Default: ${DEFAULT_API}`}>
              <input className={input} value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} placeholder="https://api.example.com" inputMode="url" spellCheck={false} />
            </Field>
            <Field label="Access token" hint="A personal API token. Never share it: it can approve actions for your tenant.">
              <div className="flex gap-2">
                <input className={input} type={showToken ? "text" : "password"} value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" spellCheck={false} />
                <button type="button" className="btn shrink-0" onClick={() => setShowToken((v) => !v)}>{showToken ? "Hide" : "Show"}</button>
              </div>
            </Field>
            <div className="flex flex-wrap items-center gap-2">
              <button type="submit" className="btn btn-primary" disabled={test.state === "testing"}>Save connection</button>
              <button type="button" className="btn" onClick={() => testConnection()} disabled={test.state === "testing"}>
                {test.state === "testing" ? "Testing…" : "Test connection"}
              </button>
            </div>
            {test.state !== "idle" && test.state !== "testing" && (
              <div role="status" className={`rounded-lg border px-3 py-2 font-mono text-xs ${test.state === "ok" ? "border-secondary/40 bg-secondary/10 text-secondary" : "border-critical/40 bg-critical/10 text-critical"}`}>
                {test.state === "ok" ? "✓ " : "✕ "}{test.detail}
              </div>
            )}
          </form>
        </Card>

        <Card kicker="Your account" title="Profile">
          {!profile ? (
            <p className="text-sm text-muted">Connect to the API to load your profile.</p>
          ) : (
            <form onSubmit={saveProfile} className="space-y-5">
              <div className="flex items-center gap-4">
                <div className="grid h-14 w-14 place-items-center rounded-full bg-primary font-display text-lg font-semibold text-void" aria-hidden>
                  {initials(draft.display_name || profile.user_id)}
                </div>
                <div className="min-w-0">
                  <div className="truncate font-display text-lg">{draft.display_name || profile.user_id}</div>
                  <div className="flex flex-wrap gap-2 pt-1">
                    <span className="pill pill-ok">{profile.role}</span>
                    <span className="pill">{profile.tenant_name}</span>
                  </div>
                </div>
              </div>
              <Field label="Display name">
                <input className={input} value={draft.display_name} maxLength={80} required onChange={(e) => setDraft({ ...draft, display_name: e.target.value })} />
              </Field>
              <Field label="Email" hint="Used for critical-incident emails if you turn them on below.">
                <input className={input} type="email" value={draft.email} maxLength={254} placeholder="you@example.com" onChange={(e) => setDraft({ ...draft, email: e.target.value })} />
              </Field>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="User ID"><input className={input} value={profile.user_id} disabled /></Field>
                <Field label="Tenant ID"><input className={input} value={profile.tenant_id} disabled /></Field>
              </div>
              <div>
                <div className="label-caps">Notifications</div>
                <div className="divide-y divide-stroke">
                  <Toggle
                    label="Desktop prompts"
                    hint="Show Tier-2 decisions and freeze alerts in the Scanu desktop app."
                    checked={draft.notify_desktop}
                    onChange={(v) => setDraft({ ...draft, notify_desktop: v })}
                  />
                  <Toggle
                    label="Email on critical incidents"
                    hint={draft.email ? `Send to ${draft.email}.` : "Add an email address first."}
                    checked={draft.notify_email_critical}
                    onChange={(v) => setDraft({ ...draft, notify_email_critical: v && !!draft.email })}
                  />
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <button type="submit" className="btn btn-primary" disabled={!dirty || saving}>{saving ? "Saving…" : "Save profile"}</button>
                <span role="status" className="text-xs text-muted">{saveMsg ?? `Last updated ${fmtTime(profile.updated_at)}`}</span>
              </div>
            </form>
          )}
        </Card>
      </div>
    </>
  );
}
