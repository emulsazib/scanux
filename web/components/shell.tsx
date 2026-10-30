"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { initials, type Profile, usePoll } from "@/lib/api";

const NAV = [
  { href: "/", label: "Diagnostics" },
  { href: "/incidents", label: "Incidents" },
  { href: "/rules", label: "Security Rules" },
  { href: "/audit", label: "Audit Log" },
  { href: "/settings", label: "Settings" },
];

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const me = usePoll<Profile>("/v1/me", 30000).data;
  const active = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));
  return (
    <div className="min-h-dvh">
      <header className="sticky top-0 z-20 border-b border-stroke bg-[rgba(18,23,21,0.75)] backdrop-blur-xl">
        <div className="mx-auto flex h-14 max-w-[1600px] items-center gap-6 px-4 md:px-7">
          <Link href="/" className="flex items-center gap-2 font-mono text-sm font-bold tracking-[0.12em] text-ink">
            <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden className="text-primary">
              <path fill="currentColor" d="M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6l-9-4Zm0 4.2 5 2.2V12c0 3-2.1 5.8-5 6.6-2.9-.8-5-3.6-5-6.6V8.4l5-2.2Z" />
            </svg>
            SCANU
          </Link>
          <nav className="hidden gap-1 md:flex" aria-label="Primary">
            {NAV.map((n) => (
              <Link
                key={n.href}
                href={n.href}
                aria-current={active(n.href) ? "page" : undefined}
                className={`rounded-md px-3 py-1.5 text-sm transition-colors ${active(n.href) ? "bg-primary/10 text-primary" : "text-muted hover:text-ink"}`}
              >
                {n.label}
              </Link>
            ))}
          </nav>
          <span className="pill pill-ok ml-auto hidden sm:inline-flex">
            <span className="pulse" /> Live feed
          </span>
          <Link
            href="/settings"
            title={me ? `${me.display_name} · ${me.role}` : "Settings"}
            aria-label="Profile and settings"
            className="ml-auto grid h-9 w-9 place-items-center rounded-full bg-primary font-display text-sm font-semibold text-void transition-shadow hover:shadow-[var(--shadow-glow)] sm:ml-0"
          >
            {me ? initials(me.display_name) : "?"}
          </Link>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-4 pb-2 md:hidden" aria-label="Primary mobile">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} className={`whitespace-nowrap rounded-md px-3 py-1 text-sm ${active(n.href) ? "bg-primary/10 text-primary" : "text-muted"}`}>
              {n.label}
            </Link>
          ))}
        </nav>
      </header>
      <main className="mx-auto max-w-[1600px] px-4 py-6 md:px-7 md:py-8">{children}</main>
    </div>
  );
}

export function PageHeader({ kicker, title, children }: { kicker: string; title: string; children?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-4 md:mb-8 md:flex-row md:items-end md:justify-between">
      <div>
        <div className="pill pill-ok mb-3"><span className="pulse" /> {kicker}</div>
        <h1 className="font-display text-3xl font-semibold tracking-tight text-ink md:text-[2.5rem] md:leading-[1.15]">{title}</h1>
      </div>
      {children}
    </div>
  );
}
