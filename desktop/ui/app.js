// Scanu desktop UI.
// Local sensor link (Windows named pipe via Tauri): scans, threats, local actions.
// Optional Scanu cloud (Settings): Tier-2/3 decisions signed by the cloud.
// All telemetry-derived strings are inserted with textContent, never HTML.

const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};
const tauri = window.__TAURI__;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
const fileName = (p) => String(p || "").split(/[\\/]/).pop();

// ------------------------------------------------------------ sensor link
let sensor = { linked: false, status: null };
async function sensorRequest(request) {
  if (!tauri?.core) throw new Error("Not running in the Scanu app");
  return tauri.core.invoke("sensor_request", { request });
}

function renderStatus() {
  const pill = $("status");
  const label = pill.lastElementChild;
  if (!tauri?.core) { pill.className = "pill"; label.textContent = "Browser preview"; return; }
  if (!sensor.linked) { pill.className = "pill warn"; label.textContent = "Sensor not running"; return; }
  const s = sensor.status;
  pill.className = "pill ok";
  label.textContent = s?.cloud ? "Protected · cloud linked" : "Protected";
  if (s) $("sensor-info").textContent =
    `Device ${s.device_id} · sensor ${s.version} · ${s.driver ? "kernel driver active" : "ETW mode (no kernel driver)"} · ${s.cloud ? "linked to cloud" : "standalone"}`;
}

// Threats the sensor flagged (scan findings, frozen processes).
const threats = new Map();
function renderThreats() {
  const box = $("threats");
  box.replaceChildren(...[...threats.values()].map((t) => {
    const card = el("article", "card threat");
    const head = el("div", "row");
    head.append(el("span", `pill ${t.severity >= 4 ? "crit" : "high"}`, t.severity >= 4 ? "critical" : "high"),
                el("span", "title", fileName(t.path) || "Unknown program"));
    const what = { known_malware: "Matches known malware", suspicious_executable: "Looks like malware to the on-device model",
                   ransomware_canary: "Behaved like ransomware: it was paused and cut off from the network" }[t.summary] || t.summary;
    const actions = el("div", "actions");
    const result = el("div", "muted");
    const act = (label, action, primary) => {
      const b = el("button", `btn ${primary ? "primary" : ""}`, label);
      b.addEventListener("click", async () => {
        actions.querySelectorAll("button").forEach((x) => (x.disabled = true));
        result.textContent = "Working…";
        try { await sensorRequest({ cmd: action, alert_id: t.alert_id }); }
        catch (e) { result.textContent = String(e); actions.querySelectorAll("button").forEach((x) => (x.disabled = false)); }
      });
      return b;
    };
    if (t.can_terminate) actions.append(act("Stop program", "terminate", !t.can_quarantine));
    if (t.can_quarantine) actions.append(act("Quarantine file", "quarantine", true));
    card.append(head, el("div", "muted", what), el("div", "path", t.path || ""), actions, result);
    t.resultEl = result;
    return card;
  }));
  $("threats-section").hidden = threats.size === 0;
}

let localScan = null;
function renderScan(s) {
  localScan = s && s.state === "running" ? s : null;
  document.querySelectorAll("button[data-scope]").forEach((b) => (b.disabled = !!localScan));
  $("scan-status").hidden = !localScan;
  if (localScan) {
    $("scan-label").textContent = "Scanning…";
    $("scan-stats").replaceChildren(...[["Files", s.files_seen], ["Threats", s.findings]].map(([k, v]) => {
      const d = el("div"); const b = el("b", k === "Threats" && v > 0 ? "crit" : "", Number(v).toLocaleString()); d.append(b, k); return d;
    }));
  } else if (s) {
    $("scan-last").textContent = s.state === "completed"
      ? `Last scan: ${Number(s.files_seen).toLocaleString()} files checked, ${s.findings ? `${s.findings} threat(s) found` : "no threats found"}.`
      : `Last scan ${s.state}.`;
  }
}

function onNotice(v) {
  switch (v.type) {
    case "status": sensor.status = v; renderStatus(); break;
    case "scan": renderScan(v); break;
    case "scan_started": renderScan({ state: "running", files_seen: 0, findings: 0, scan_id: v.scan_id }); break;
    case "finding": threats.set(v.alert_id, v); renderThreats(); break;
    case "findings": threats.clear(); for (const f of v.findings) threats.set(f.alert_id, f); renderThreats(); break;
    case "action": {
      const t = threats.get(v.alert_id);
      if (v.ok) { threats.delete(v.alert_id); renderThreats(); toast(v.message); }
      else if (t?.resultEl) t.resultEl.textContent = `Could not complete: ${v.message}`;
      break;
    }
    case "frozen": case "blocked":
      toast(v.type === "frozen" ? `${fileName(v.image)} was paused in ${v.elapsed_us} µs (${v.reason}).` : `${fileName(v.image)} was blocked.`, true);
      break;
    case "error": $("scan-last").textContent = v.error === "SCAN_ALREADY_RUNNING" ? "A scan is already running." : `Sensor: ${v.error}`; break;
  }
}

function toast(text, danger) {
  const n = el("div", "notice", text);
  if (!danger) n.style.borderColor = "rgba(169,206,32,.4)", n.style.background = "rgba(169,206,32,.08)";
  $("notices").prepend(n);
  setTimeout(() => n.remove(), 15000);
}

if (tauri?.event) {
  tauri.event.listen("sensor-notice", ({ payload }) => onNotice(payload));
  tauri.event.listen("sensor-link", ({ payload }) => { sensor.linked = payload; renderStatus(); });
}

document.querySelectorAll("button[data-scope]").forEach((b) => b.addEventListener("click", async () => {
  if (tauri?.core) {
    try { await sensorRequest({ cmd: "scan", scope: b.dataset.scope }); }
    catch (e) { $("scan-last").textContent = String(e); }
  } else {
    cloudScan(b.dataset.scope);
  }
}));
$("scan-cancel").addEventListener("click", () => {
  if (localScan?.scan_id) sensorRequest({ cmd: "cancel_scan", scan_id: localScan.scan_id }).catch(() => {});
});

// ------------------------------------------------------------- cloud (optional)
const cfg = () => ({ api: store.get("scanu.api", ""), token: store.get("scanu.token", "") });
async function call(path, init = {}, conn = cfg()) {
  if (!conn.api) throw new Error("not linked");
  const r = await fetch(conn.api + path, { ...init, headers: { Authorization: `Bearer ${conn.token}`, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

const rendered = new Map();
function renderPrompt(action) {
  const node = $("prompt-tpl").content.firstElementChild.cloneNode(true);
  node.querySelector(".sev").textContent = action.severity;
  node.querySelector(".sev").classList.add(action.severity);
  node.querySelector(".title").textContent = action.title;
  node.querySelector(".why").textContent = action.explanation;
  for (const b of node.querySelectorAll("button[data-choice]")) {
    b.classList.toggle("primary", b.dataset.choice === action.recommended_choice);
    b.addEventListener("click", async () => {
      node.querySelectorAll("button").forEach((x) => (x.disabled = true));
      const out = node.querySelector(".result");
      try {
        const r = await call(`/v1/actions/${action.action_id}/decision`, { method: "POST", body: JSON.stringify({ choice: b.dataset.choice, channel: "desktop" }) });
        out.textContent = `Done: ${r.commands.length} signed command(s) sent to this device.`;
      } catch (e) {
        out.textContent = `Could not reach Scanu cloud (${e.message}). This PC stays protected; try again.`;
        node.querySelectorAll("button").forEach((x) => (x.disabled = false));
      }
    });
  }
  return node;
}

async function refreshCloud() {
  if (!cfg().api) { $("cloud-section").hidden = true; return; }
  $("cloud-section").hidden = false;
  try {
    const list = await call("/v1/actions?state=PROPOSED");
    const ids = new Set(list.map((a) => a.action_id));
    for (const [id, n] of rendered) if (!ids.has(id) && !n.querySelector("button:disabled")) { n.remove(); rendered.delete(id); }
    for (const a of list) if (!rendered.has(a.action_id)) { const n = renderPrompt(a); $("prompts").prepend(n); rendered.set(a.action_id, n); }
    $("empty").hidden = rendered.size > 0;
  } catch { $("empty").hidden = false; $("empty").textContent = "Scanu cloud unreachable. Local protection is unaffected."; }
}

// Browser preview only: scan through the cloud API.
async function cloudScan(scope) {
  const dev = $("device").value;
  try { await call(`/v1/devices/${encodeURIComponent(dev)}/scans`, { method: "POST", body: JSON.stringify({ scope }) }); $("scan-last").textContent = "Scan requested."; }
  catch (e) { $("scan-last").textContent = `Could not start the scan (${e.message}).`; }
}
async function loadDevices() {
  if (tauri?.core || !cfg().api) return;
  try {
    const list = await call("/v1/devices");
    $("device").hidden = false;
    $("device").replaceChildren(...list.map((d) => { const o = el("option", "", `${d.online ? "●" : "○"} ${d.device_id}`); o.value = d.device_id; return o; }));
  } catch {}
}

$("api").value = cfg().api;
$("token").value = cfg().token;
async function loadWho(conn = cfg()) {
  const me = await call("/v1/me", {}, conn);
  $("who").textContent = `Signed in as ${me.display_name} (${me.role}) · ${me.tenant_name}`;
}
$("save").addEventListener("click", async () => {
  const conn = { api: $("api").value.trim().replace(/\/+$/, ""), token: $("token").value };
  if (!/^https?:\/\//.test(conn.api)) { $("conn-msg").textContent = "Enter a full http(s):// URL."; return; }
  try {
    await loadWho(conn);
    store.set("scanu.api", conn.api); store.set("scanu.token", conn.token);
    $("conn-msg").textContent = "Linked.";
    refreshCloud(); loadDevices();
  } catch (e) { $("conn-msg").textContent = e.message === "401" ? "Token rejected." : "Can't reach that API."; }
});
$("unlink").addEventListener("click", () => {
  store.del("scanu.api"); store.del("scanu.token");
  $("api").value = ""; $("token").value = ""; $("conn-msg").textContent = "Unlinked.";
  $("who").textContent = "Not linked."; refreshCloud();
});

renderStatus();
if (cfg().api) loadWho().catch(() => {});
loadDevices();
refreshCloud();
setInterval(refreshCloud, 5000);
setInterval(() => { if (sensor.linked) sensorRequest({ cmd: "status" }).catch(() => {}); }, 15000);
