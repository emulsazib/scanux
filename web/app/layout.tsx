import type { Metadata } from "next";
import { Geist, JetBrains_Mono, Space_Grotesk } from "next/font/google";
import { Shell } from "@/components/shell";
import "./globals.css";

const display = Space_Grotesk({ subsets: ["latin"], variable: "--font-display-loaded" });
const sans = Geist({ subsets: ["latin"], variable: "--font-sans-loaded" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono-loaded" });

export const metadata: Metadata = {
  title: "Scanu Console",
  description: "Hybrid EDR + AI-SIEM: incidents, decisions, and telemetry",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${display.variable} ${sans.variable} ${mono.variable}`}>
      <body
        style={{
          ["--font-display" as string]: "var(--font-display-loaded), ui-sans-serif, system-ui",
          ["--font-sans" as string]: "var(--font-sans-loaded), ui-sans-serif, system-ui",
          ["--font-mono" as string]: "var(--font-mono-loaded), ui-monospace, monospace",
        }}
      >
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
