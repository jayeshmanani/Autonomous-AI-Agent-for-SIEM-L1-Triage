const sessionId = `ui-${Date.now()}`;

const chatWindow = document.getElementById("chat-window");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const btnSummary = document.getElementById("btn-summary");
const btnEscalations = document.getElementById("btn-escalations");
const btnAudit = document.getElementById("btn-audit");
const btnAuditRefresh = document.getElementById("btn-audit-refresh");
const triageOriginForm = document.getElementById("triage-origin-form");
const originInput = document.getElementById("origin-input");
const originLimit = document.getElementById("origin-limit");
const singleTriageForm = document.getElementById("single-triage-form");
const rawLogInput = document.getElementById("raw-log-input");
const auditStats = document.getElementById("audit-stats");
const auditList = document.getElementById("audit-list");
const auditLimitInput = document.getElementById("audit-limit");

function getAuditLimit() {
  const raw = Number(auditLimitInput.value || 50);
  if (!Number.isFinite(raw)) {
    return 50;
  }
  return Math.max(1, Math.min(Math.trunc(raw), 1000));
}

function appendMessage(role, text) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.textContent = text;
  chatWindow.appendChild(div);
  chatWindow.scrollTop = chatWindow.scrollHeight;
}

function _percent(count, total) {
  if (!total) return "0.0%";
  return `${((Number(count || 0) / total) * 100).toFixed(1)}%`;
}

function formatDatasetSummary(data) {
  const total = Number(data.total_events || 0);
  const avgRisk = Number(data.average_metadata_risk || 0);
  const severity = data.severity_distribution || {};
  const eventTypes = data.event_type_distribution || {};
  const topSources = Array.isArray(data.top_sources) ? data.top_sources : [];

  const sevEntries = Object.entries(severity).sort((a, b) => Number(b[1]) - Number(a[1]));
  const eventEntries = Object.entries(eventTypes).sort((a, b) => Number(b[1]) - Number(a[1]));

  const highCriticalEmergency = Number(severity.high || 0) + Number(severity.critical || 0) + Number(severity.emergency || 0);
  const highRiskShare = _percent(highCriticalEmergency, total);

  const sevLines = sevEntries
    .map(([name, count]) => `${name}: ${count} (${_percent(Number(count), total)})`)
    .join("\n");

  const eventLines = eventEntries
    .slice(0, 5)
    .map(([name, count]) => `${name}: ${count} (${_percent(Number(count), total)})`)
    .join("\n");

  const sourceLines = topSources
    .slice(0, 5)
    .map((item, index) => `${index + 1}. ${item[0]}: ${item[1]}`)
    .join("\n");

  let riskBand = "normal";
  if (avgRisk >= 70) riskBand = "high";
  else if (avgRisk >= 50) riskBand = "elevated";

  return [
    "Dataset Summary",
    "",
    `Total events analyzed: ${total}`,
    `Average metadata risk score: ${avgRisk.toFixed(2)} (${riskBand})`,
    `High+Critical+Emergency share: ${highCriticalEmergency} (${highRiskShare})`,
    "",
    "Severity breakdown:",
    sevLines || "No severity data available.",
    "",
    "Top event types:",
    eventLines || "No event type data available.",
    "",
    "Top sources:",
    sourceLines || "No source data available.",
    "",
    "What this means:",
    "- Prioritize High/Critical/Emergency queue first.",
    "- Focus tuning on the top event types and top log sources.",
    "- Use origin-based triage on the busiest source/event type to reduce backlog faster.",
  ].join("\n");
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
    let text = data.message || "No response.";
    if (Array.isArray(data.reasoning) && data.reasoning.length > 0) {
      text += `\n\nReasoning:\n- ${data.reasoning.join("\n- ")}`;
    }
    if (data.top_threat_identified) {
      text += `\n\nTop threat: ${data.top_threat_identified}`;
    }
    if (Array.isArray(data.escalation_actions_queued) && data.escalation_actions_queued.length > 0) {
      const actions = data.escalation_actions_queued
        .map((item) => `${item.event_id}: ${item.action}`)
        .join("\n");
      text += `\n\nQueued actions:\n${actions}`;
    }
    appendMessage("agent", text);
    await loadAudit();
  } catch {
    appendMessage("agent", "Assistant request failed.");
  }
}

function renderAudit(data) {
  const changed = Number(data.changed_records || 0);
  const classified = Number(data.classified_non_unknown || 0);
  const updated = Number(data.updated_at_count || 0);
  const seedCount = Number(data.seed_count || 0);
  const currentCount = Number(data.current_count || 0);
  const requestedLimit = getAuditLimit();
  const showing = Math.min(changed, requestedLimit);
  auditStats.textContent = `DB records: ${currentCount} (baseline: ${seedCount}) | Changed: ${changed} | Showing: ${showing} | Classified: ${classified} | Updated timestamps: ${updated}`;

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
    const requestedLimit = getAuditLimit();
    const resp = await fetch(`/assistant/audit?limit=${encodeURIComponent(requestedLimit)}`);
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
    appendMessage("agent", formatDatasetSummary(data));
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

btnAuditRefresh.addEventListener("click", async () => {
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
    const examples = Array.isArray(data.results) ? data.results.slice(0, 2) : [];
    const reasonLines = examples
      .map((item) => {
        const topReason = Array.isArray(item.reasoning) && item.reasoning.length > 0 ? item.reasoning[0] : "No reasoning available.";
        return `${item.event_id}: ${topReason}`;
      })
      .join("\n");
    const report = `Triage by origin result:\nMatched: ${data.matched}\nEligible New: ${data.eligible_new}\nAlready Processed: ${data.already_processed}\nProcessed Now: ${data.processed}\nEscalated: ${data.escalated}\nRemaining New: ${data.remaining_new}${reasonLines ? `\n\nSample reasoning:\n${reasonLines}` : ""}`;
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
    const reasons = Array.isArray(analysis.decision_reasoning) ? analysis.decision_reasoning : [];
    const fieldsUsed = Array.isArray(analysis.decision_fields_used) ? analysis.decision_fields_used : [];
    appendMessage(
      "agent",
      `Classification: ${analysis.classification}\nPriority: ${analysis.priority}\nRisk Score: ${analysis.risk_score}\nSummary: ${analysis.summary || "n/a"}${reasons.length ? `\n\nReasoning:\n- ${reasons.join("\n- ")}` : ""}${fieldsUsed.length ? `\n\nFields used: ${fieldsUsed.join(", ")}` : ""}`,
    );
    await loadAudit();
  } catch {
    appendMessage("agent", "Single log triage failed.");
  }
});

initializeSession();
loadAudit();
