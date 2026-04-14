const sessionId = `ui-${Date.now()}`;

const chatWindow = document.getElementById("chat-window");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const btnSummary = document.getElementById("btn-summary");
const btnEscalations = document.getElementById("btn-escalations");
const btnAudit = document.getElementById("btn-audit");
const triageOriginForm = document.getElementById("triage-origin-form");
const originInput = document.getElementById("origin-input");
const originLimit = document.getElementById("origin-limit");
const singleTriageForm = document.getElementById("single-triage-form");
const rawLogInput = document.getElementById("raw-log-input");
const auditStats = document.getElementById("audit-stats");
const auditList = document.getElementById("audit-list");

function appendMessage(role, text) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.textContent = text;
  chatWindow.appendChild(div);
  chatWindow.scrollTop = chatWindow.scrollHeight;
}

async function initializeSession() {
  try {
    const resp = await fetch(`/assistant/welcome/${sessionId}`);
    const data = await resp.json();
    appendMessage("agent", data.message || "Session ready.");
  } catch {
    appendMessage("agent", "Could not initialize assistant session.");
  }
}

async function askAssistant(prompt) {
  appendMessage("user", prompt);
  try {
    const resp = await fetch("/assistant/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId, prompt }),
    });
    const data = await resp.json();
    appendMessage("agent", data.message || "No response.");
    await loadAudit();
  } catch {
    appendMessage("agent", "Assistant request failed.");
  }
}

function renderAudit(data) {
  const changed = Number(data.changed_records || 0);
  const classified = Number(data.classified_non_unknown || 0);
  const updated = Number(data.updated_at_count || 0);
  auditStats.textContent = `Changed records: ${changed} | Classified: ${classified} | Updated timestamps: ${updated}`;

  auditList.innerHTML = "";
  const samples = Array.isArray(data.samples) ? data.samples : [];
  if (samples.length === 0) {
    auditList.innerHTML = '<div class="audit-item">No changes from baseline yet.</div>';
    return;
  }

  for (const sample of samples) {
    const item = document.createElement("div");
    item.className = "audit-item";
    const eventId = sample.event_id || "unknown";
    const changes = sample.changes || {};
    const fields = Object.keys(changes);
    const details = fields
      .map((field) => {
        const before = JSON.stringify(changes[field].before);
        const after = JSON.stringify(changes[field].after);
        return `${field}: ${before} → ${after}`;
      })
      .join("\n");

    item.innerHTML = `<strong>${eventId}</strong><br/><span>${details.replace(/\n/g, "<br/>")}</span>`;
    auditList.appendChild(item);
  }
}

async function loadAudit() {
  try {
    const resp = await fetch("/assistant/audit?limit=10");
    const data = await resp.json();
    renderAudit(data);
  } catch {
    auditStats.textContent = "Could not load audit.";
    auditList.innerHTML = '<div class="audit-item">Audit request failed.</div>';
  }
}

chatForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const prompt = chatInput.value.trim();
  if (!prompt) return;
  chatInput.value = "";
  await askAssistant(prompt);
});

btnSummary.addEventListener("click", async () => {
  try {
    const resp = await fetch("/analysis/summary");
    const data = await resp.json();
    appendMessage("agent", `Summary:\n${JSON.stringify(data, null, 2)}`);
    await loadAudit();
  } catch {
    appendMessage("agent", "Could not fetch summary.");
  }
});

btnEscalations.addEventListener("click", async () => {
  await askAssistant("How many cases are escalated and what should I prioritize now?");
});

btnAudit.addEventListener("click", async () => {
  await loadAudit();
});

triageOriginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const origin = originInput.value.trim();
  const limit = Number(originLimit.value || 50);
  if (!origin) return;

  appendMessage("user", `Run triage by origin: ${origin} (limit=${limit})`);

  try {
    const resp = await fetch(`/triage/by-origin/${encodeURIComponent(origin)}?limit=${encodeURIComponent(limit)}`, {
      method: "POST",
    });
    const data = await resp.json();
    const report = `Triage by origin result:\nMatched: ${data.matched}\nProcessed: ${data.processed}\nEscalated: ${data.escalated}`;
    appendMessage("agent", report);
    await loadAudit();
  } catch {
    appendMessage("agent", "Origin-based triage failed.");
  }
});

singleTriageForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const rawLog = rawLogInput.value.trim();
  if (!rawLog) return;

  appendMessage("user", "Triage this raw log.");

  try {
    const resp = await fetch("/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_log: rawLog, enrich_threat_intel: false }),
    });
    const data = await resp.json();
    const analysis = data.analysis || {};
    appendMessage(
      "agent",
      `Classification: ${analysis.classification}\nPriority: ${analysis.priority}\nRisk Score: ${analysis.risk_score}`,
    );
    await loadAudit();
  } catch {
    appendMessage("agent", "Single log triage failed.");
  }
});

initializeSession();
loadAudit();
