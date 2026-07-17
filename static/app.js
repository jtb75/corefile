// corefile.io — scripted forensic workbench.
// The trace is deterministic on purpose: a reliable path to click through
// during a live pitch, while still feeling like a real investigation.

const INCIDENTS = [
  { id: "CF-4211", title: "SIGSEGV in prod-checkout-api", org: "acme-checkout",
    region: "us-east-1", at: "03:17:04 UTC", mttc: "37s", live: true },
  { id: "flight-501", title: "Unhandled conversion, 37s after launch", org: "esa-launch",
    region: "kourou-1", at: "launch+37s", mttc: "37s", live: false },
  { id: "CF-1988", title: "Stack smash in fingerd", org: "internet",
    region: "arpanet", at: "1988", mttc: "hours", live: false },
  { id: "CF-0009", title: "Null deref in session loader", org: "acme-checkout",
    region: "us-east-1", at: "02:54:11 UTC", mttc: "1964", live: false },
];

// Six stages: cloud resource -> code line. Terminal node is a real planted vuln.
const TRACE = [
  { kind: "cloud resource", title: 'aws_ecs_service.<span class="hl">checkout-prod</span>',
    kv: { Region: "us-east-1", Cluster: "acme-prod", "Desired / running": "6 / 5",
          "IaC": "terraform · modules/ecs/service.tf:88" } },
  { kind: "running task", title: 'ecs/task <span class="hl">a91f…d0</span>',
    kv: { "Image digest": "sha256:9f2c…be1a", "Task role": "checkout-task-role",
          "Env": "SENTRY_DSN, DB_HOST, REGISTRY_TOKEN", "Exit": "139 (128+SIGSEGV)" } },
  { kind: "image / registry", title: 'checkout-api:<span class="hl">2.14.0</span>',
    kv: { "Registry": "acme.dkr.ecr.us-east-1", "Layers": "11",
          "Flagged layer": "#7 — COPY tools/ (adds symbolicate helper)",
          "Provenance": "SLSA L2 · cosign verified" } },
  { kind: "Dockerfile", title: 'Dockerfile <span class="hl">ARG REGISTRY_TOKEN</span>',
    kv: { "Line": "7", "Issue": "GitHub PAT baked into image history",
          "Introduced by": "layer #7" },
    finding: "GitHub Classic PAT · Dockerfile:7" },
  { kind: "commit / PR", title: 'PR #613 <span class="hl">“faster symbolication”</span>',
    kv: { "Commit": "4d1f0e2", "Author": "j.rivera", "CI": "unit ✓  sast ✗ (overridden)",
          "Merged": "2 days ago" },
    diff: [
      { t: "ctx", s: "  def symbolicate_request():" },
      { t: "del", s: '-     return check_output([ADDR2LINE, "-f", "-e", binary, addr])' },
      { t: "add", s: '+     cmd = "addr2line -f -e " + binary + " " + addr' },
      { t: "add", s: "+     return check_output(cmd, shell=True)" },
    ] },
  { kind: "source line", terminal: true, title: 'symbolicate.py:<span class="hl">42</span>',
    kv: { "Function": "symbolicate_request()", "Input": "binary, addr — from query string",
          "Sink": "subprocess.check_output(cmd, shell=True)",
          "Rule": "WS-I013-PYTHON-00193 · CWE-78" },
    finding: "os-command-injection · symbolicate.py:42" },
];

// Mirrors `wizcli scan dir` output 1:1 — same rule IDs, CWEs, file:line, severity.
const FINDINGS = [
  { kind: "SAST", wiz: "WS-I013-PYTHON-00193", cwe: "CWE-78", loc: "symbolicate.py:42",
    feature: "Symbolicate corefile", note: "addr2line run via shell with query-string input" },
  { kind: "SAST", wiz: "WS-PYTHON-00330", cwe: "CWE-89", loc: "app.py:130",
    feature: "Crash-signature search", note: "query string concatenated into SQL" },
  { kind: "SAST", wiz: "WS-I013-PYTHON-00054", cwe: "CWE-95", loc: "app.py:166",
    feature: "Derived metric", note: "eval() of a user-supplied expression" },
  { kind: "Secret", wiz: "GitHub Classic PAT", cwe: "config file", loc: "config.py:15",
    feature: "Integration config", note: "GitHub PAT committed to source" },
  { kind: "Secret", wiz: "GitHub Classic PAT", cwe: "IaC", loc: "Dockerfile:7",
    feature: "Image build ARG", note: "token baked into image history" },
];

// ---------- render incident rail ----------
const rail = document.getElementById("incidents");
INCIDENTS.forEach((inc, i) => {
  const li = document.createElement("li");
  li.className = "inc" + (i === 0 ? " is-active" : "");
  li.innerHTML =
    `<div class="inc-top">${inc.live ? '<span class="dot"></span>' : ""}` +
    `<span class="inc-title">${inc.title}</span></div>` +
    `<span class="inc-sub">${inc.org} · ${inc.region} · ${inc.id}</span>`;
  li.onclick = () => selectIncident(i, li);
  rail.appendChild(li);
});

function selectIncident(i, el) {
  document.querySelectorAll(".inc").forEach((n) => n.classList.remove("is-active"));
  el.classList.add("is-active");
  const inc = INCIDENTS[i];
  document.getElementById("inc-title").textContent = inc.title;
  document.getElementById("inc-meta").textContent =
    `${inc.org} · ${inc.region} · ${inc.at} · case ${inc.id}`;
  document.getElementById("mttc").textContent = inc.mttc;
  resetTrace();
}

// ---------- trace ----------
const traceEl = document.getElementById("trace");
const runBtn = document.getElementById("run");
let timers = [];

function resetTrace() {
  timers.forEach(clearTimeout);
  timers = [];
  traceEl.innerHTML = "";
  runBtn.disabled = false;
  runBtn.textContent = "▶ Run trace";
}

function renderNode(stage) {
  const li = document.createElement("li");
  li.className = "node" + (stage.terminal ? " terminal" : "");
  const kv = Object.entries(stage.kv)
    .map(([k, v]) => `<span>${k}</span><code>${v}</code>`).join("");
  const diff = stage.diff
    ? `<div class="diff">${stage.diff.map((d) => `<div class="${d.t}">${d.s}</div>`).join("")}</div>`
    : "";
  const finding = stage.finding ? `<span class="finding-tag">⚑ ${stage.finding}</span>` : "";
  li.innerHTML =
    `<span class="pin"></span>` +
    `<div class="card"><div class="card-top">` +
    `<span class="kind">${stage.kind}</span>` +
    `<span class="card-title">${stage.title}</span>` +
    `<span class="chev">›</span></div>` +
    `<div class="card-body"><div class="kv">${kv}</div>${diff}${finding}</div></div>`;
  const card = li.querySelector(".card");
  card.onclick = () => card.classList.toggle("open");
  traceEl.appendChild(li);
  requestAnimationFrame(() => li.classList.add("show"));
  return li;
}

runBtn.onclick = () => {
  resetTrace();
  runBtn.disabled = true;
  runBtn.textContent = "◴ tracing…";
  TRACE.forEach((stage, idx) => {
    timers.push(setTimeout(() => {
      const li = renderNode(stage);
      if (stage.terminal) li.querySelector(".card").classList.add("open");
      if (idx === TRACE.length - 1) {
        runBtn.textContent = "✓ traced";
        const cta = document.createElement("div");
        cta.className = "to-findings";
        cta.innerHTML = "<button>View security findings for this line →</button>";
        cta.querySelector("button").onclick = () => switchView("findings");
        traceEl.appendChild(cta);
      }
    }, 520 * (idx + 1)));
  });
};

// ---------- findings table ----------
const findingsTable = document.getElementById("findings");
findingsTable.innerHTML =
  "<tr><th>Sev</th><th>Type</th><th>Rule</th><th>Weakness</th><th>Location</th><th>Feature</th></tr>" +
  FINDINGS.map((f) =>
    `<tr><td><span class="sev sev-high">HIGH</span></td>` +
    `<td>${f.kind}</td><td><code>${f.wiz}</code></td><td>${f.cwe}</td>` +
    `<td><code>${f.loc}</code></td><td>${f.feature}<div class="fnote">${f.note}</div></td></tr>`
  ).join("");

// ---------- view switching ----------
function switchView(name) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("is-active", t.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) =>
    v.classList.toggle("is-active", v.id === "view-" + name));
}
document.querySelectorAll(".tab").forEach((t) => (t.onclick = () => switchView(t.dataset.view)));

// ---------- ulimit easter egg ----------
const ulimit = document.getElementById("ulimit");
const uhint = document.getElementById("ulimit-hint");
ulimit.onchange = () => {
  uhint.textContent = ulimit.checked
    ? "deep analysis on — core size: unlimited"
    : "deep analysis off";
  document.querySelector(".glyph").style.animationDuration = ulimit.checked ? "1s" : "2.6s";
};

// ---------- clock (UTC, ticking) ----------
function tick() {
  const d = new Date();
  document.getElementById("clock").innerHTML =
    d.toISOString().slice(11, 19) + "&nbsp;UTC";
}
setInterval(tick, 1000);
tick();
