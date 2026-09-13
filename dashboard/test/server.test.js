"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createReportStore, validateScanPayload } = require("../server");

function validReport(overrides = {}) {
  return {
    message_id: "message-1",
    thread_id: "thread-1",
    received_at: "2026-01-01T00:00:00Z",
    subject: "Security update",
    sender: "sender@example.com",
    reply_to: "",
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass" },
    spoofing_flags: [],
    url_analysis: {
      extracted_count: 0,
      sanitised_count: 0,
      sanitised_urls: [],
      url_records: [],
    },
    social_engineering: {
      score: 0,
      severity: "low",
      matched_indicators: [],
      explanations: ["No pressure detected"],
    },
    virus_total: { verdicts: [], lookup_errors: [] },
    overall_risk: { score: 0, classification: "low" },
    scan_status: "complete",
    analysis_errors: [],
    ...overrides,
  };
}

function validPayload(reports = [validReport()]) {
  return {
    schema_version: "1.0",
    scanner_version: "1.0.0",
    scan_started_at: "2026-01-01T00:00:00Z",
    scan_completed_at: "2026-01-01T00:01:00Z",
    message_count: reports.length,
    reports,
  };
}

test("accepts the scanner telemetry schema", () => {
  assert.deepEqual(validateScanPayload(validPayload()), []);
});

test("rejects malformed and inconsistent payloads", () => {
  assert.ok(validateScanPayload(null).length > 0);
  assert.ok(validateScanPayload({ reports: [] }).length > 0);
  assert.ok(validateScanPayload({ ...validPayload(), message_count: 2 }).length > 0);
  assert.ok(validateScanPayload(validPayload([validReport({ scan_status: "unknown" })])).length > 0);
  assert.ok(
    validateScanPayload(
      validPayload([
        validReport({
          url_analysis: {
            extracted_count: 1,
            sanitised_count: 1,
            sanitised_urls: ["https://example.com"],
            url_records: [{ original_url: 12, sanitised_url: "https://example.com" }],
          },
        }),
      ]),
    ).length > 0,
  );
});

test("bounds in-memory report history and returns defensive copies", () => {
  const store = createReportStore(2);
  store.add(validPayload());
  store.add({ ...validPayload(), scan_completed_at: "2026-01-02T00:00:00Z" });
  store.add({ ...validPayload(), scan_completed_at: "2026-01-03T00:00:00Z" });

  const reports = store.list();
  assert.equal(reports.length, 2);
  assert.equal(reports[0].scan_completed_at, "2026-01-03T00:00:00Z");
  reports[0].message_count = 99;
  assert.equal(store.list()[0].message_count, 1);
});
