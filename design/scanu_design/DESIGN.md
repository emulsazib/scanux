---
name: Obsidian Telemetry
colors:
  surface: '#121413'
  surface-dim: '#121413'
  surface-bright: '#383a38'
  surface-container-lowest: '#0d0f0e'
  surface-container-low: '#1a1c1b'
  surface-container: '#1e201f'
  surface-container-high: '#282a29'
  surface-container-highest: '#333534'
  on-surface: '#e2e3e0'
  on-surface-variant: '#c5c9af'
  inverse-surface: '#e2e3e0'
  inverse-on-surface: '#2f312f'
  outline: '#8f937c'
  outline-variant: '#454935'
  surface-tint: '#afd528'
  primary: '#c4eb40'
  on-primary: '#293500'
  primary-container: '#a9ce20'
  on-primary-container: '#435500'
  inverse-primary: '#516600'
  secondary: '#4de082'
  on-secondary: '#003919'
  secondary-container: '#00b55d'
  on-secondary-container: '#003e1c'
  tertiary: '#5af3dd'
  on-tertiary: '#003731'
  tertiary-container: '#31d6c1'
  on-tertiary-container: '#00584f'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#caf246'
  primary-fixed-dim: '#afd528'
  on-primary-fixed: '#171e00'
  on-primary-fixed-variant: '#3d4d00'
  secondary-fixed: '#6dfe9c'
  secondary-fixed-dim: '#4de082'
  on-secondary-fixed: '#00210c'
  on-secondary-fixed-variant: '#005227'
  tertiary-fixed: '#62fae3'
  tertiary-fixed-dim: '#3cddc7'
  on-tertiary-fixed: '#00201c'
  on-tertiary-fixed-variant: '#005047'
  background: '#121413'
  on-background: '#e2e3e0'
  surface-variant: '#333534'
typography:
  display:
    fontFamily: Space Grotesk
    fontSize: 48px
    fontWeight: '600'
    lineHeight: 56px
    letterSpacing: -0.03em
  headline-lg:
    fontFamily: Space Grotesk
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Space Grotesk
    fontSize: 24px
    fontWeight: '500'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Space Grotesk
    fontSize: 18px
    fontWeight: '500'
    lineHeight: 26px
    letterSpacing: 0em
  body-lg:
    fontFamily: Geist
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0em
  body-sm:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: 0.01em
  mono-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: -0.02em
  mono-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: -0.01em
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.08em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-desktop: 1.25rem
  margin: 1rem
  margin-desktop: 1.75rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
---

## Brand & Style

This design system blends developer-grade cyber-diagnostics with tranquil, precision-engineered wellness telemetry. The interface delivers deep focus, acute visual triage, and effortless analytical comprehension.

### Target Audience & Persona
Engineered for SecOps engineers, security architects, and systems analysts monitoring high-frequency biometric streams, telemetry nodes, and system vitals. Users require zero-glare immersion during sustained, high-cognitive-load monitoring sessions.

### Aesthetic Movement
**Bio-Cyber Minimal with Glass & Luminescent Accents.** A hybrid of technical command HUD and clinical calm. It merges obsidian-tier low-luminance surfaces with bioluminescent sage-green indicators, micro-grid alignments, and refined tactical status modules.

### Emotional Response
Calm mastery, analytical clarity, surgical precision, and unshakeable operational stability under crisis conditions.

## Colors

The palette balances profound dark-spectrum absorption with surgical luminescent feedback.

### Palette Architecture
- **Canvas Base (`#0A0C0B`):** Deep obsidian ground minimizing eye strain during prolonged monitoring.
- **Card / Surface (`#121715`):** Subtly tinted, desaturated emerald-charcoal providing organic separation from the background void.
- **Structural Stroke (`#1E2623`):** Low-attenuation borders maintaining strict structural definition without visual noise.
- **Active Primary (`#A9CE20`):** Electric sage green. Dictates real-time operational states, biometric gauges, progress arcs, and decisive interactions.
- **Secondary Telemetry (`#4ADE80`):** Vibrant cyber mint. Reserved for normal threshold vectors, verified certificates, and positive operational trends.
- **Tertiary Resonance (`#2DD4BF`):** Cyan-teal. Utilized for data stream packet inspection, auxiliary network tunnels, and concurrent query streams.
- **Critical Diagnostics:**
  - Alert / Breach: `#EF4444` (Vivid Crimson)
  - Degraded / Warning: `#F59E0B` (Amber Flash)
  - Neutral Reading / Inactive: `#4B5E55` (Subdued Forest Slate)

## Typography

Typographic scale is structured into three clear disciplines:

1. **Space Grotesk (Structural Headings):** Geometric, precise sans-serif providing authoritative hierarchy and technical posture across dashboards, viewport modules, and metric cards.
2. **Geist (Body & Explanatory Copy):** Ultra-neutral, legible grotesk engineered specifically for dense interfaces and screen-based technical reading.
3. **JetBrains Mono (Data, Logs & Telemetry Metrics):** Tabular, highly visible monospaced type used for timestamps, hash outputs, hardware addresses, gauge indicators, and status pill badges.

### Typographic Rules
- All numeric readouts, system paths, addresses, and status badges must use `JetBrains Mono`.
- Sub-headers, parameter keys, and system categories must be rendered in `label-caps` with uppercase transformation (`text-transform: uppercase`).
- Display sizes are restrained to maximize viewport density for multi-panel desktop telemetry.

## Layout & Spacing

The layout is built for high-density, multi-monitor telemetry workstations.

### Grid Architecture
- **Desktop (>= 1440px):** 12-column dynamic grid, `margin-desktop` (1.75rem / 28px), `gutter-desktop` (1.25rem / 20px). Panels can span 3, 4, 6, 8, or 12 units.
- **Compact Desktop / Tablet Landscape (1024px - 1439px):** 8-column layout, `gutter` (1rem / 16px), collateral feeds collapse into side drawers or tabbed stacks.
- **Viewport Canvas:** Fixed-height viewport with modular, independently scrolling telemetry panels; main analytics viewport defaults to full-bleed workspace constraints.

### Spacing Philosophy
- Use `space-xs` (4px) for inline status indicator gap offsets and micro icon-to-label separation.
- Use `space-sm` (8px) for badge internals, input vertical padding, and closely bound telemetry tuples.
- Use `space-md` (16px) for module internal container padding, list item gaps, and standard metric cards.
- Use `space-lg` (24px) for primary layout section headers, metric splitters, and master card internal bounds.
- Use `space-xl` (32px) strictly for macro dashboard section partitions.

## Elevation & Depth

This system avoids heavy drop shadows, instead using **tonal layering, calibrated luminescent halos, and crisp ghost borders**.

### Hierarchy of Depth

1. **Ground Void (Level 0):** `#0A0C0B` base canvas. Completely matte, absorbs background noise.
2. **Floating Modules (Level 1):** `#121715` surface, 1px solid `#1E2623` outline. Elevated by an ultra-diffused atmospheric shadow: `0 8px 32px -4px rgba(0, 0, 0, 0.6)`.
3. **Elevated Drawers & Flyouts (Level 2):** `#171E1B` surface, 1px solid `#28332F` outline, with directional shadow `0 16px 48px -8px rgba(0, 0, 0, 0.8)`.
4. **Active/Focused Telemetry Elements (Level 3):** Layered with a luminous ambient sage glow: `0 0 16px -2px rgba(169, 206, 32, 0.25)` and border transition to `#A9CE20` at 60% opacity.

### Translucency & Glassmorphism
Header bars, command pallets, and hovering telemetry tooltips apply subtle backdrop blurs (`backdrop-filter: blur(16px)`) with semi-transparent tinted obsidian backgrounds (`rgba(18, 23, 21, 0.75)`).

## Shapes

The design uses a balanced radius paradigm with 16px corner geometry as the anchor.

- **Primary Cards & Containers:** Fixed `16px` border-radius (`rounded-lg` per scale) to establish the calm, organic, soft-edged aesthetic inspired by modern wellness tech.
- **Interactive Controls (Buttons, Inputs, Selectors):** `8px` (`rounded`) for compact tactical responsiveness.
- **Pills, Nodes & Micro-Badges:** Full pill-shaped geometry (`9999px`) to immediately signal real-time telemetry state, node connectivity, and operational tags.
- **Biometric Gauges & Ring Charts:** Circular sweeps with curved terminus caps (`stroke-linecap: round`) contrasting against rigid rectangular matrices.

## Components

### Buttons
- **Primary:** Background `#A9CE20`, text `#0A0C0B` (JetBrains Mono bold, 12px), border `none`, corner radius `8px`. Hover: `#BDE42B` with a soft ambient aura `0 0 12px rgba(169, 206, 32, 0.35)`.
- **Secondary / Ghost:** Background `transparent`, border `1px solid #1E2623`, text `#A9CE20`. Hover: background `rgba(169, 206, 32, 0.08)`, border `#A9CE20`.
- **Tactical Action:** Monospaced label, icon prepended, height 36px, horizontal padding 14px.

### Cards & Telemetry Panels
- Surface: `#121715`.
- Border: `1px solid #1E2623`.
- Corner Radius: `16px`.
- Padding: `20px` to `24px`.
- Header: Incorporates title in `Space Grotesk`, paired with a live status indicator (pulsing dot) and numeric node ID.

### Status Pills & Diagnostics Badges
- Structural capsule (`border-radius: 9999px`), height `22px`, padding `0 10px`.
- Typography: `label-caps` (`JetBrains Mono`, 11px).
- **Nominal / Active:** Background `rgba(169, 206, 32, 0.12)`, border `1px solid rgba(169, 206, 32, 0.35)`, text `#A9CE20`.
- **Standby / Idle:** Background `rgba(75, 94, 85, 0.15)`, border `1px solid #1E2623`, text `#8A9E94`.
- **Breach / Critical:** Background `rgba(239, 68, 68, 0.12)`, border `1px solid rgba(239, 68, 68, 0.4)`, text `#EF4444`.

### Pulse Indicators
- Circular micro-dot (6px) with an expanding radial pseudo-element ping (`animation: pulse 2s cubic-bezier(0, 0, 0.2, 1) infinite`).
- Used alongside node telemetry, network interface health, and real-time heartbeat monitors.

### Biometric & Telemetry Gauges
- SVG-based circular and horizontal meters with `#1E2623` base tracks and `#A9CE20` animated fills.
- Center typography displays numeric value in `JetBrains Mono` with the metric unit in muted `#8A9E94`.

### Input Fields & Terminal Prompts
- Background: `#0A0C0B`.
- Border: `1px solid #1E2623`. Focus state: `1px solid #A9CE20`, shadow `0 0 0 1px #A9CE20`.
- Typography: `JetBrains Mono` 13px, text color `#E1E8E4`. Placeholder: `#4B5E55`.
- Affixes: Monospaced prompt symbol (`>`, `~`, or `$`) tinted `#A9CE20`.

### Checkboxes & Toggle Switches
- Checkbox: `16px x 16px`, radius `4px`, unselected border `1px solid #1E2623`, checked state `#A9CE20` with obsidian `#0A0C0B` check glyph.
- Switch: Track `36px x 20px`, pill-shaped, base color `#1E2623`; active state background `rgba(169, 206, 32, 0.25)` with border `1px solid #A9CE20`; thumb `#A9CE20` (14px).

### Data Tables & Event Logs
- Alternating row styling: transparent to `#121715` hover state.
- Dividers: `1px solid #1E2623`.
- Cell alignment: Monospaced numerical values right-aligned; timestamps and hashes formatted in `JetBrains Mono`.