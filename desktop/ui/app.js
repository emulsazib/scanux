// Scanu desktop UI: polls the API for PROPOSED actions and records the user's
// Tier-2 choice. All telemetry-derived strings are inserted with textContent.
const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};
const cfg = () => ({ api: store.get("scanu.api", "http://127.0.0.1:8000"), token: store.get("scanu.token", "dev-owner-token") });

async function call(path, init = {}, conn = cfg()) {
  const { api, token } = conn;
  const r = await fetch(api + path, { ...init, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

const prompts = document.getElementById("prompts");
const empty = document.getElementById("empty");
const status = document.getElementById("status");
const tpl = document.getElementById("prompt-tpl");
const rendered = new Map();

function render(action) {
  const node = tpl.content.firstElementChild.cloneNode(true);
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
        const r = await call(`/v1/actions/${action.action_id}/decision`, {
          method: "POST",
          body: JSON.stringify({ choice: b.dataset.choice, channel: "desktop" }),
        });
        out.textContent = `Done: ${r.commands.length} signed command(s) sent to this device.`;
      } catch (e) {
        out.textContent = `Could not reach Scanu cloud (${e.message}). Your device stays protected; try again.`;
        node.querySelectorAll("button").forEach((x) => (x.disabled = false));
      }
    });
  }
  return node;
}

async function refresh() {
  try {
    const list = await call("/v1/actions?state=PROPOSED");
    status.className = "pill ok";
    status.lastChild.textContent = "Protected";
    const ids = new Set(list.map((a) => a.action_id));
    for (const [id, el] of rendered) if (!ids.has(id) && !el.querySelector("button:disabled")) { el.remove(); rendered.delete(id); }
    for (const a of list) if (!rendered.has(a.action_id)) { const el = render(a); prompts.prepend(el); rendered.set(a.action_id, el); }
    empty.hidden = rendered.size > 0;
  } catch {
    status.className = "pill high";
    status.lastChild.textContent = "Offline · local protection on";
  }
}

// Instant notices from the sensor (Windows named pipe → Rust → this event).
if (window.__TAURI__?.event) {
  window.__TAURI__.event.listen("sensor-notice", ({ payload }) => {
    if (payload.type === "scan") { refreshScan(); return; }
    if (payload.type !== "frozen" && payload.type !== "blocked") return;
    const n = document.createElement("div");
    n.className = "notice";
    const name = String(payload.image || "a program").split("\\").pop();
    n.textContent = payload.type === "frozen"
      ? `${name} was paused in ${payload.elapsed_us} µs (${payload.reason}). Decide below once the analysis arrives.`
      : `${name} was blocked before it started.`;
    document.getElementById("notices").prepend(n);
    refresh();
  });
}

// ------------------------------------------------------------- scans
const deviceSel = document.getElementById("device");
const scanStatus = document.getElementById("scan-status");
const scanLast = document.getElementById("scan-last");
let activeScan = null;

async function loadDevices() {
  try {
    const list = await call("/v1/devices");
    const keep = deviceSel.value || store.get("scanu.device", "");
    deviceSel.replaceChildren(...list.map((d) => {
      const o = document.createElement("option");
      o.value = d.device_id;
      o.textContent = `${d.online ? "●" : "○"} ${d.device_id}`;
      return o;
    }));
    if (list.some((d) => d.device_id === keep)) deviceSel.value = keep;
  } catch { /* offline: keep previous list */ }
}
deviceSel.addEventListener("change", () => { store.set("scanu.device", deviceSel.value); refreshScan(); });

async function refreshScan() {
  if (!deviceSel.value) return;
  try {
    const scans = await call(`/v1/scans?device_id=${encodeURIComponent(deviceSel.value)}&limit=3`);
    activeScan = scans.find((s) => s.state === "queued" || s.state === "running") || null;
    const last = scans.find((s) => s !== activeScan);
    document.querySelectorAll("button[data-scope]").forEach((b) => (b.disabled = !!activeScan));
    scanStatus.hidden = !activeScan;
    if (activeScan) {
      document.getElementById("scan-label").textContent = `${activeScan.scope} scan · ${activeScan.state}`;
      const stats = document.getElementById("scan-stats");
      stats.replaceChildren(...[["Files", activeScan.files_seen], ["Analyzed", activeScan.files_analyzed], ["Threats", activeScan.findings]].map(([k, v]) => {
        const d = document.createElement("div");
        const b = document.createElement("b");
        b.textContent = Number(v).toLocaleString();
        if (k === "Threats" && v > 0) b.className = "crit";
        d.append(b, k);
        return d;
      }));
    }
    scanLast.textContent = last
      ? `Last ${last.scope} scan: ${last.state}, ${last.files_seen.toLocaleString()} files, ${last.findings} threat(s).`
      : "";
  } catch { /* offline */ }
}

document.querySelectorAll("button[data-scope]").forEach((b) => b.addEventListener("click", async () => {
  b.disabled = true;
  try {
    await call(`/v1/devices/${encodeURIComponent(deviceSel.value)}/scans`, { method: "POST", body: JSON.stringify({ scope: b.dataset.scope }) });
  } catch (e) {
    scanLast.textContent = e.message === "409" ? "A scan is already running." : `Could not start the scan (${e.message}).`;
  }
  refreshScan();
}));
document.getElementById("scan-cancel").addEventListener("click", async () => {
  if (activeScan) await call(`/v1/scans/${activeScan.scan_id}/cancel`, { method: "POST" }).catch(() => {});
  refreshScan();
});

// ----------------------------------------------------------- settings
const apiIn = document.getElementById("api");
const tokIn = document.getElementById("token");
const connMsg = document.getElementById("conn-msg");
const who = document.getElementById("who");
apiIn.value = cfg().api;
tokIn.value = cfg().token;

async function loadWho(conn = cfg()) {
  const me = await call("/v1/me", {}, conn);
  who.textContent = `Signed in as ${me.display_name} (${me.role}) · ${me.tenant_name}`;
  return me;
}

document.getElementById("save").addEventListener("click", async () => {
  const conn = { api: apiIn.value.trim().replace(/\/+$/, ""), token: tokIn.value };
  if (!/^https?:\/\//.test(conn.api)) { connMsg.textContent = "Enter a full http(s):// URL."; return; }
  try {
    await loadWho(conn);
    store.set("scanu.api", conn.api);
    store.set("scanu.token", conn.token);
    connMsg.textContent = "Connected.";
    loadDevices().then(refreshScan);
    refresh();
  } catch (e) {
    connMsg.textContent = e.message === "401" ? "Token rejected." : "Can't reach the API.";
  }
});

loadWho().catch(() => {});
loadDevices().then(refreshScan);
refresh();
setInterval(refresh, 4000);
setInterval(refreshScan, 1500);
setInterval(loadDevices, 10000);
