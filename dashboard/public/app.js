"use strict";

const POLL_INTERVAL_MS = 3_000;

const elements = {
  authFlagCount: document.querySelector("#auth-flag-count"),
  connectionStatus: document.querySelector("#connection-status"),
  detectionCount: document.querySelector("#detection-count"),
  emptyState: document.querySelector("#empty-state"),
  error: document.querySelector("#dashboard-error"),
  highRiskCount: document.querySelector("#high-risk-count"),
  messageCount: document.querySelector("#message-count"),
  reportList: document.querySelector("#report-list"),
  scanTime: document.querySelector("#scan-time"),
};

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = String(text);
  return element;
}

function formatDate(value) {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Time unavailable"
    : new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function statusPill(label, status) {
  const pill = node("span", `pill pill--${status === "pass" ? "pass" : "fail"}`);
  pill.append(node("span", "pill__label", label), document.createTextNode(` ${status.toUpperCase()}`));
  return pill;
}

function renderUrls(report) {
  const block = node("div", "detail-block");
  block.append(node("h4", null, `Sanitised URLs · ${report.url_analysis.sanitised_count}`));
  if (!report.url_analysis.sanitised_urls.length) {
    block.append(node("p", "muted", "No external destinations identified."));
    return block;
  }

  const list = node("ul", "url-list");
  report.url_analysis.sanitised_urls.forEach((url) => list.append(node("li", null, url)));
  block.append(list);
  return block;
}

function renderVirusTotal(report) {
  const block = node("div", "detail-block");
  block.append(node("h4", null, "VirusTotal"));
  if (!report.virus_total.verdicts.length) {
    block.append(node("p", "muted", "No URL lookups required."));
    return block;
  }

  const list = node("ul", "verdict-list");
  report.virus_total.verdicts.forEach((verdict) => {
    const item = node("li");
    if (verdict.lookup_status === "complete") {
      item.append(
        node("strong", null, `${verdict.malicious_count} malicious`),
        document.createTextNode(` · ${verdict.suspicious_count} suspicious`),
      );
    } else {
      item.append(node("strong", "warning-text", verdict.lookup_status.replaceAll("_", " ")));
    }
    item.append(node("span", "verdict-url", verdict.sanitised_url));
    list.append(item);
  });
  block.append(list);
  return block;
}

function renderReport(report) {
  const card = node("article", `report-card report-card--${report.overall_risk.classification}`);
  const header = node("header", "report-card__header");
  const identity = node("div", "report-card__identity");
  identity.append(
    node("span", `risk-badge risk-badge--${report.overall_risk.classification}`, report.overall_risk.classification),
    node("h3", null, report.subject || "(No Subject)"),
    node("p", "sender", report.sender || "Sender unavailable"),
  );

  const score = node("div", "risk-score");
  score.append(node("strong", null, report.overall_risk.score), node("span", null, "risk score"));
  header.append(identity, score);

  const statusRow = node("div", "status-row");
  statusRow.append(
    statusPill("SPF", report.authentication.spf),
    statusPill("DKIM", report.authentication.dkim),
    statusPill("DMARC", report.authentication.dmarc),
    node(
      "span",
      `pill pill--${report.scan_status === "complete" ? "pass" : "partial"}`,
      report.scan_status,
    ),
  );

  const facts = node("div", "facts-grid");
  const urgency = node("div", "fact");
  urgency.append(
    node("span", "fact__label", "Urgency"),
    node("strong", null, `${report.social_engineering.score} · ${report.social_engineering.severity}`),
  );
  const flags = node("div", "fact");
  flags.append(
    node("span", "fact__label", "Spoofing flags"),
    node("strong", null, report.spoofing_flags.length),
  );
  const received = node("div", "fact");
  received.append(node("span", "fact__label", "Received"), node("strong", null, formatDate(report.received_at)));
  facts.append(urgency, flags, received);

  const details = node("div", "report-card__details");
  details.append(renderUrls(report), renderVirusTotal(report));
  card.append(header, statusRow, facts, details);

  const failures = [...report.analysis_errors, ...report.virus_total.lookup_errors.map((item) => item.error)].filter(Boolean);
  if (failures.length) {
    const notice = node("div", "inline-notice");
    notice.append(node("strong", null, "Partial analysis"), node("span", null, failures.join(" · ")));
    card.append(notice);
  }
  return card;
}

function renderLatestScan(scan) {
  const reports = scan.reports;
  elements.messageCount.textContent = scan.message_count;
  elements.highRiskCount.textContent = reports.filter(
    (report) => report.overall_risk.classification === "high",
  ).length;
  elements.authFlagCount.textContent = reports.reduce(
    (total, report) => total + report.spoofing_flags.length,
    0,
  );
  elements.detectionCount.textContent = reports.reduce(
    (total, report) =>
      total +
      report.virus_total.verdicts.reduce(
        (subtotal, verdict) => subtotal + (verdict.malicious_count || 0) + (verdict.suspicious_count || 0),
        0,
      ),
    0,
  );
  elements.scanTime.textContent = `Completed ${formatDate(scan.scan_completed_at)}`;
  elements.emptyState.hidden = reports.length > 0;
  elements.reportList.replaceChildren(...reports.map(renderReport));
}

async function refresh() {
  try {
    const response = await fetch("/api/reports", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`Report request returned ${response.status}`);
    const payload = await response.json();
    elements.connectionStatus.textContent = "Live";
    elements.error.hidden = true;
    if (payload.reports.length) renderLatestScan(payload.reports[0]);
  } catch (error) {
    elements.connectionStatus.textContent = "Disconnected";
    elements.error.textContent = "The dashboard cannot reach the local report service.";
    elements.error.hidden = false;
  }
}

refresh();
window.setInterval(refresh, POLL_INTERVAL_MS);
