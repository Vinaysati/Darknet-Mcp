"use strict";

const $ = (id) => document.getElementById(id);
const sourceCategories = [
  ["ransomware", "Ransomware listings"], ["threatfox", "ThreatFox"], ["urlhaus", "URLhaus"],
  ["otx", "AlienVault OTX"], ["stealer", "Hudson Rock"], ["hibp", "Have I Been Pwned"],
  ["intelx", "IntelligenceX"], ["abuseipdb", "AbuseIPDB"], ["greynoise", "GreyNoise"],
  ["bazaar", "MalwareBazaar"], ["hybrid", "Hybrid Analysis"],
  ["ransomlook", "RansomLook"], ["tor", "Tor onion access"], ["onionlookup", "CIRCL onion lookup"],
  ["blockchain", "Bitcoin blockchain"], ["chainabuse", "ChainAbuse"], ["vulners", "Vulners"],
  ["phishing", "Phishing lookups"], ["pulsedive", "Pulsedive"],
];
const statusLabels = {
  match: "Matches reported", no_match: "No match reported", skipped: "Skipped",
  error: "Provider error", timeout: "Timed out", inconclusive: "Inconclusive",
};
let currentReport = null;
let running = false;
let investigationController = null;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}
function readableDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Time unavailable" : date.toLocaleString();
}
function safeSourceUrl(value) {
  if (typeof value !== "string" || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch { return null; }
}
function onionTarget() {
  const selected = $("target-type").value;
  if (selected !== "onion" && selected !== "auto") return false;
  try {
    const raw = $("target").value.trim();
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`);
    return ['http:', 'https:'].includes(url.protocol) && /^[a-z2-7]{56}\.onion$/.test(url.hostname);
  } catch { return false; }
}
function updateOnionOption() {
  const eligible = onionTarget();
  $("onion-options").hidden = $("target-type").value !== "onion" && !eligible;
  $("fetch-onion").disabled = !eligible;
  if (!eligible) $("fetch-onion").checked = false;
}
function showPage(page) {
  $("investigate-panel").hidden = page !== "investigate";
  $("sources-panel").hidden = page !== "sources";
  document.querySelectorAll("[data-page]").forEach((button) => {
    const active = button.dataset.page === page;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
}
document.querySelectorAll("[data-page]").forEach((button) => button.addEventListener("click", () => showPage(button.dataset.page)));

sourceCategories.forEach(([value, name]) => {
  const label = element("label", "checkbox-label");
  const checkbox = element("input");
  checkbox.type = "checkbox";
  checkbox.value = value;
  checkbox.name = "source";
  checkbox.checked = true;
  label.append(checkbox, document.createTextNode(name));
  $("source-options").append(label);
});
$("automatic-sources").addEventListener("change", () => {
  $("source-options").hidden = $("automatic-sources").checked;
});
$("target-type").addEventListener("change", () => {
  const placeholders = { auto: "e.g. example.com", domain: "e.g. example.com", email: "name@example.com", ip: "e.g. 192.0.2.10", hash: "MD5, SHA-1, or SHA-256 hash", url: "https://example.com/path", onion: "A v3 .onion address or URL", bitcoin: "Bitcoin address (mainnet)", cve: "e.g. CVE-2024-12345" };
  $("target").placeholder = placeholders[$("target-type").value];
  updateOnionOption();
});
$("target").addEventListener("input", updateOnionOption);
$("max-results").addEventListener("invalid", () => {
  // Keep native form validation able to focus an invalid field inside collapsed options.
  $("max-results").closest("details").open = true;
});

async function loadSources() {
  try {
    const response = await fetch("/api/sources", { cache: "no-store" });
    if (!response.ok) throw new Error();
    const { sources } = await response.json();
    if (!Array.isArray(sources)) throw new Error();
    $("source-count").textContent = sources.length;
    $("source-list").replaceChildren();
    sources.forEach((source) => {
      const card = element("article", "source-card");
      card.append(element("h3", "", source.name));
      const keyPresent = Boolean(source.keyPresent);
      const blockedCount = Array.isArray(source.blockedTools) ? source.blockedTools.length : 0;
      const needsKey = source.authRequired && !keyPresent;
      const status = source.requiresTor ? "Tor connection not checked" : needsKey ? "Required key missing" : blockedCount ? "Some tools need a key" : keyPresent ? "Key configured" : "Public access";
      card.append(element("span", `status-badge ${needsKey || blockedCount ? "status-skipped" : source.requiresTor ? "" : "status-match"}`, status));
      const info = element("p", "source-details");
      const toolCount = Array.isArray(source.tools) ? source.tools.length : 0;
      info.append(document.createTextNode(`${toolCount} tools${blockedCount ? ` · ${blockedCount} require a missing key` : ""}`));
      if (source.envVar) {
        info.append(document.createTextNode(" · "), element("code", "", source.envVar));
        if (!keyPresent) info.append(document.createTextNode(blockedCount ? " (not configured)" : " (optional key not configured)"));
      }
      card.append(info);
      $("source-list").append(card);
    });
  } catch {
    $("source-list").replaceChildren(element("p", "error-banner", "Source configuration could not be loaded. Check that the local server is running, then reload this page."));
  }
}

function renderReadiness(report) {
  if (!Array.isArray(report.checks) || !report.tor) throw new Error("Unexpected readiness report.");
  $("readiness-date").textContent = `Checked ${readableDate(report.checked_at)} · Cached for up to one minute`;
  $("readiness-status").textContent = report.tor.socksAvailable
    ? `Tor SOCKS proxy is reachable at ${report.tor.socksHost}:${report.tor.socksPort}. This confirms the proxy handshake, not onion reachability. Provider account access has not been checked.`
    : `Tor SOCKS proxy is unavailable at ${report.tor.socksHost}:${report.tor.socksPort}. Onion fetching will need a working proxy. Provider account access has not been checked.`;
  const configurationLabels = { configured: "Key configured", partial: "Some tools blocked", missing_key: "Required key missing", available_without_key: "No key required" };
  const healthLabels = { not_checked: "Provider health not checked", reachable: "Local connection reachable", unavailable: "Local connection unavailable" };
  $("readiness-checks").replaceChildren();
  report.checks.forEach((check) => {
    const card = element("article", "source-card");
    card.append(element("h3", "", check.name));
    const configuration = configurationLabels[check.configuration_status] || "Configuration unknown";
    const connection = check.requires_tor ? (healthLabels[check.health_status] || "Connection not checked") : "Provider health not checked";
    card.append(element("span", `status-badge ${['missing_key', 'partial'].includes(check.configuration_status) || check.health_status === "unavailable" ? "status-skipped" : ""}`, configuration));
    card.append(element("p", "source-details", `${connection} · ${check.detail || ""}${check.missing_env ? ` · Configure ${check.missing_env}` : ""}`));
    $("readiness-checks").append(card);
  });
}

async function loadReadiness(refresh = false) {
  $("refresh-readiness").disabled = true;
  try {
    const response = await fetch("/api/readiness", refresh
      ? { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}", cache: "no-store" }
      : { cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : "Local readiness checks are unavailable.");
    renderReadiness(data.readiness);
  } catch (error) {
    $("readiness-status").textContent = error instanceof TypeError ? "Could not reach the local server. Check that it is running." : error.message;
    $("readiness-date").textContent = "Readiness refresh did not complete; earlier checks may be stale.";
  } finally {
    $("refresh-readiness").disabled = false;
  }
}
$("refresh-readiness").addEventListener("click", () => loadReadiness(true));

function renderReport(report) {
  currentReport = report;
  $("empty-state").hidden = true;
  $("report-panel").hidden = false;
  $("report-title").textContent = report.target?.value || "Investigation";
  $("report-date").textContent = `${report.target?.type || "Indicator"} · Completed ${readableDate(report.finished_at)}`;
  const coverage = report.coverage || {};
  const issues = (coverage.errors || 0) + (coverage.timeouts || 0) + (coverage.inconclusive || 0);
  $("coverage-metrics").replaceChildren();
  [
    [coverage.completed || 0, "Completed checks", ""],
    [coverage.matches || 0, "Checks with matches", "match"],
    [coverage.skipped || 0, "Skipped checks", ""],
    [issues, "Errors / incomplete", "issue"],
  ].forEach(([value, label, className]) => {
    const card = element("div", `metric ${className}`);
    card.append(element("strong", "", value), element("span", "", label));
    $("coverage-metrics").append(card);
  });
  $("coverage-note").textContent = coverage.partial
    ? "Coverage is partial. Review skipped and incomplete checks below; an unchecked source cannot rule out exposure."
    : "A completed lookup with no reported match does not rule out exposure. Matches are source reports and need analyst review.";
  $("coverage-note").append(document.createTextNode(` ${coverage.selected || 0} selected checks; coverage depends on indicator type, provider permissions, and available records.`));
  const correlations = Array.isArray(report.correlations) ? report.correlations : [];
  $("correlations-panel").hidden = correlations.length === 0;
  $("correlations").replaceChildren();
  correlations.forEach((item) => {
    const row = element("div", "correlation");
    const indicator = element("div", "correlation-value", item.indicator?.value || "Indicator");
    indicator.append(element("span", "correlation-type", item.indicator?.type || ""));
    row.append(indicator, element("span", "correlation-sources", (item.sources || []).join(" · ")));
    $("correlations").append(row);
  });
  const checks = Array.isArray(report.checks) ? report.checks : [];
  const evidenceById = new Map((Array.isArray(report.evidence) ? report.evidence : []).map((item) => [item.id, item]));
  const followups = checks.filter((check) => ["error", "timeout", "inconclusive", "skipped"].includes(check.status) || check.partial_results || check.truncated);
  $("followups-panel").hidden = followups.length === 0;
  $("followups").replaceChildren();
  followups.forEach((check) => {
    const action = check.status === "skipped" ? "Review configuration or applicability"
      : check.status === "error" || check.status === "timeout" ? "Review provider access and retry"
      : "Review incomplete or capped results";
    $("followups").append(element("li", "", `${check.source}: ${action}. ${check.summary || ""}`));
  });
  $("checks-caption").textContent = `${checks.length} CHECKS · EVIDENCE REDACTED`;
  $("checks").replaceChildren();
  checks.forEach((check) => {
    const card = element("article", "check");
    const heading = element("div", "check-heading");
    const knownStatus = Object.hasOwn(statusLabels, check.status) ? check.status : "inconclusive";
    heading.append(element("h4", "", check.source || "Source"), element("span", `status-badge status-${knownStatus}`, statusLabels[knownStatus]));
    card.append(heading, element("p", "check-summary", check.summary || "No summary was returned."));
    const meta = [check.tool, `Checked ${readableDate(check.finished_at)}`];
    if (check.match_count !== null && check.match_count !== undefined) meta.push(`${check.match_count} reported matches`);
    if (check.partial_results) meta.push("Partial results; follow-up required");
    if (check.truncated) meta.push("Evidence limited by report settings");
    card.append(element("p", "check-meta", meta.filter(Boolean).join(" · ")));
    const records = (check.evidence_ids || []).map((id) => evidenceById.get(id)).filter(Boolean);
    if (records.length) {
      const details = element("details", "evidence");
      details.append(element("summary", "", `View redacted evidence (${records.length})`));
      records.forEach((record) => {
        const item = element("div", "evidence-item");
        const provenance = record.provenance?.kind === "local_configuration" ? "Local configuration" : "Unverified source claim";
        const meta = element("p", "evidence-meta", `${record.id} · Observed ${readableDate(record.observed_at)} · ${provenance}`);
        if (record.original_event_at) meta.append(document.createTextNode(` · Source event ${readableDate(record.original_event_at)}`));
        const sourceUrl = safeSourceUrl(record.source_url);
        if (sourceUrl) {
          const link = element("a", "evidence-link", "Open source evidence ↗");
          link.href = sourceUrl;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          meta.append(document.createTextNode(" · "), link);
        }
        item.append(meta);
        item.append(element("pre", "", JSON.stringify(record.data, null, 2)));
        details.append(item);
      });
      card.append(details);
    }
    $("checks").append(card);
  });
  $("limitations").replaceChildren();
  const limitations = Array.isArray(report.limitations) ? report.limitations : [];
  $("limitations-panel").hidden = limitations.length === 0;
  limitations.forEach((item) => $("limitations").append(element("li", "", item)));
}

$("investigation-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (running) return;
  const args = { target: $("target").value.trim(), target_type: $("target-type").value, max_results: Number($("max-results").value), fetch_onion: onionTarget() && $("fetch-onion").checked };
  if (!$("automatic-sources").checked) {
    args.sources = [...document.querySelectorAll('input[name="source"]:checked')].map((item) => item.value);
    if (args.sources.length === 0) {
      $("run-error").textContent = "Select at least one source, or use automatic source coverage.";
      $("run-error").hidden = false;
      return;
    }
  }
  running = true;
  investigationController = new AbortController();
  $("investigate-button").disabled = true;
  $("investigate-button").textContent = "Investigating…";
  $("investigation-form").setAttribute("aria-busy", "true");
  $("run-error").hidden = true;
  $("report-panel").hidden = true;
  $("empty-state").hidden = true;
  $("run-status").hidden = false;
  $("stop-investigation").hidden = false;
  $("run-status").replaceChildren(element("span", "spinner"), element("span", "", "Checking relevant intelligence sources. Provider results will appear together when the report is ready."));
  try {
    const response = await fetch("/api/investigate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(args), signal: investigationController.signal });
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : "The investigation could not complete.");
    if (!data.report || typeof data.report !== "object" || !Array.isArray(data.report.checks)) throw new Error("The server returned an unexpected report. Reload the page and try again.");
    renderReport(data.report);
    $("run-status").replaceChildren(element("span", "live-dot"), element("span", "", "Investigation complete. Review coverage and source evidence below."));
  } catch (error) {
    if (investigationController.signal.aborted) {
      $("run-status").replaceChildren(element("span", "", "Investigation stopped. No completed report was saved for this run."));
    } else {
      $("run-status").hidden = true;
      $("run-error").textContent = error instanceof TypeError ? "Could not reach the local server. Check that it is running and try again." : error.message;
      $("run-error").hidden = false;
    }
    if (currentReport) $("report-panel").hidden = false;
    else $("empty-state").hidden = false;
  } finally {
    running = false;
    investigationController = null;
    $("stop-investigation").hidden = true;
    $("stop-investigation").disabled = false;
    $("investigate-button").disabled = false;
    $("investigate-button").replaceChildren(document.createTextNode("Start investigation "), element("span", "", "↗"));
    $("investigation-form").removeAttribute("aria-busy");
  }
});

$("stop-investigation").addEventListener("click", () => {
  if (!investigationController) return;
  $("stop-investigation").disabled = true;
  investigationController.abort();
});

$("download-report").addEventListener("click", () => {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = element("a");
  link.href = url;
  // Avoid embedding personal target values in filenames.
  link.download = `darknet-investigation-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

loadSources();
loadReadiness();
updateOnionOption();
