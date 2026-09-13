"use strict";

const path = require("node:path");
const express = require("express");

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 3000;
const DEFAULT_HISTORY_LIMIT = 25;
const MAX_HISTORY_LIMIT = 100;
const BODY_SIZE_LIMIT = "5mb";
const ALLOWED_RISK_LEVELS = new Set(["low", "medium", "high"]);
const ALLOWED_SCAN_STATUSES = new Set(["complete", "partial"]);

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed)
    ? Math.min(Math.max(parsed, minimum), maximum)
    : fallback;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isString(value, maximumLength = 10_000) {
  return typeof value === "string" && value.length <= maximumLength;
}

function isNullableString(value, maximumLength = 10_000) {
  return value === null || isString(value, maximumLength);
}

function isNullableCount(value) {
  return value === null || (Number.isInteger(value) && value >= 0);
}

function validateUrlRecord(record, prefix) {
  if (!isObject(record)) return [`${prefix} must be an object`];
  const errors = [];
  if (!isString(record.original_url)) errors.push(`${prefix}.original_url must be a string`);
  if (!isString(record.sanitised_url)) errors.push(`${prefix}.sanitised_url must be a string`);
  return errors;
}

function validateMatchedIndicator(indicator, prefix) {
  if (!isObject(indicator)) return [`${prefix} must be an object`];
  const errors = [];
  if (!isString(indicator.indicator, 100)) errors.push(`${prefix}.indicator must be a string`);
  if (!isString(indicator.phrase, 500)) errors.push(`${prefix}.phrase must be a string`);
  if (!new Set(["subject", "body"]).has(indicator.location)) {
    errors.push(`${prefix}.location is invalid`);
  }
  if (!Number.isInteger(indicator.points) || indicator.points < 0 || indicator.points > 100) {
    errors.push(`${prefix}.points must be an integer from 0 to 100`);
  }
  return errors;
}

function validateVerdict(verdict, prefix) {
  if (!isObject(verdict)) return [`${prefix} must be an object`];
  const errors = [];
  for (const field of ["sanitised_url", "url_id", "lookup_status"]) {
    if (!isString(verdict[field])) errors.push(`${prefix}.${field} must be a string`);
  }
  if (verdict.http_status !== null && !Number.isInteger(verdict.http_status)) {
    errors.push(`${prefix}.http_status must be an integer or null`);
  }
  for (const field of ["malicious_count", "suspicious_count", "harmless_count", "undetected_count"]) {
    if (!isNullableCount(verdict[field])) {
      errors.push(`${prefix}.${field} must be a non-negative integer or null`);
    }
  }
  if (!isNullableString(verdict.last_analysis_date, 100)) {
    errors.push(`${prefix}.last_analysis_date must be a string or null`);
  }
  if (!isNullableString(verdict.error)) errors.push(`${prefix}.error must be a string or null`);
  return errors;
}

function validateLookupError(error, prefix) {
  if (!isObject(error)) return [`${prefix} must be an object`];
  const errors = [];
  if (!isString(error.sanitised_url)) errors.push(`${prefix}.sanitised_url must be a string`);
  if (!isString(error.status, 100)) errors.push(`${prefix}.status must be a string`);
  if (!isNullableString(error.error)) errors.push(`${prefix}.error must be a string or null`);
  return errors;
}

function validateEmailReport(report, index) {
  const errors = [];
  const prefix = `reports[${index}]`;
  if (!isObject(report)) return [`${prefix} must be an object`];

  for (const field of ["message_id", "thread_id", "subject", "sender", "reply_to"]) {
    if (!isString(report[field])) errors.push(`${prefix}.${field} must be a string`);
  }
  if (report.received_at !== null && !isString(report.received_at, 100)) {
    errors.push(`${prefix}.received_at must be a string or null`);
  }
  if (!ALLOWED_SCAN_STATUSES.has(report.scan_status)) {
    errors.push(`${prefix}.scan_status is invalid`);
  }
  if (
    !Array.isArray(report.spoofing_flags) ||
    !report.spoofing_flags.every((value) => isString(value))
  ) {
    errors.push(`${prefix}.spoofing_flags must be a string array`);
  }
  if (
    !Array.isArray(report.analysis_errors) ||
    !report.analysis_errors.every((value) => isString(value))
  ) {
    errors.push(`${prefix}.analysis_errors must be a string array`);
  }

  if (!isObject(report.authentication)) {
    errors.push(`${prefix}.authentication must be an object`);
  } else {
    for (const field of ["spf", "dkim", "dmarc"]) {
      if (!isString(report.authentication[field], 32)) {
        errors.push(`${prefix}.authentication.${field} must be a string`);
      }
    }
  }

  if (!isObject(report.url_analysis)) {
    errors.push(`${prefix}.url_analysis must be an object`);
  } else {
    for (const field of ["extracted_count", "sanitised_count"]) {
      if (!Number.isInteger(report.url_analysis[field]) || report.url_analysis[field] < 0) {
        errors.push(`${prefix}.url_analysis.${field} must be a non-negative integer`);
      }
    }
    if (
      !Array.isArray(report.url_analysis.sanitised_urls) ||
      !report.url_analysis.sanitised_urls.every((value) => isString(value))
    ) {
      errors.push(`${prefix}.url_analysis.sanitised_urls must be a string array`);
    }
    if (!Array.isArray(report.url_analysis.url_records)) {
      errors.push(`${prefix}.url_analysis.url_records must be an array`);
    } else {
      report.url_analysis.url_records.forEach((record, recordIndex) => {
        errors.push(...validateUrlRecord(record, `${prefix}.url_analysis.url_records[${recordIndex}]`));
      });
    }
    if (
      Array.isArray(report.url_analysis.sanitised_urls) &&
      Number.isInteger(report.url_analysis.sanitised_count) &&
      report.url_analysis.sanitised_count !== report.url_analysis.sanitised_urls.length
    ) {
      errors.push(`${prefix}.url_analysis.sanitised_count must equal sanitised_urls.length`);
    }
  }

  if (!isObject(report.social_engineering)) {
    errors.push(`${prefix}.social_engineering must be an object`);
  } else {
    const score = report.social_engineering.score;
    if (!Number.isInteger(score) || score < 0 || score > 100) {
      errors.push(`${prefix}.social_engineering.score must be an integer from 0 to 100`);
    }
    if (!ALLOWED_RISK_LEVELS.has(report.social_engineering.severity)) {
      errors.push(`${prefix}.social_engineering.severity is invalid`);
    }
    if (!Array.isArray(report.social_engineering.matched_indicators)) {
      errors.push(`${prefix}.social_engineering.matched_indicators must be an array`);
    } else {
      report.social_engineering.matched_indicators.forEach((indicator, indicatorIndex) => {
        errors.push(
          ...validateMatchedIndicator(
            indicator,
            `${prefix}.social_engineering.matched_indicators[${indicatorIndex}]`,
          ),
        );
      });
    }
    if (
      !Array.isArray(report.social_engineering.explanations) ||
      !report.social_engineering.explanations.every((value) => isString(value))
    ) {
      errors.push(`${prefix}.social_engineering.explanations must be a string array`);
    }
  }

  if (!isObject(report.virus_total)) {
    errors.push(`${prefix}.virus_total must be an object`);
  } else {
    if (!Array.isArray(report.virus_total.verdicts)) {
      errors.push(`${prefix}.virus_total.verdicts must be an array`);
    } else {
      report.virus_total.verdicts.forEach((verdict, verdictIndex) => {
        errors.push(...validateVerdict(verdict, `${prefix}.virus_total.verdicts[${verdictIndex}]`));
      });
    }
    if (!Array.isArray(report.virus_total.lookup_errors)) {
      errors.push(`${prefix}.virus_total.lookup_errors must be an array`);
    } else {
      report.virus_total.lookup_errors.forEach((lookupError, errorIndex) => {
        errors.push(
          ...validateLookupError(
            lookupError,
            `${prefix}.virus_total.lookup_errors[${errorIndex}]`,
          ),
        );
      });
    }
  }

  if (!isObject(report.overall_risk)) {
    errors.push(`${prefix}.overall_risk must be an object`);
  } else {
    if (
      !Number.isInteger(report.overall_risk.score) ||
      report.overall_risk.score < 0 ||
      report.overall_risk.score > 100
    ) {
      errors.push(`${prefix}.overall_risk.score must be an integer from 0 to 100`);
    }
    if (!ALLOWED_RISK_LEVELS.has(report.overall_risk.classification)) {
      errors.push(`${prefix}.overall_risk.classification is invalid`);
    }
  }

  return errors;
}

function validateScanPayload(payload) {
  const errors = [];
  if (!isObject(payload)) return ["Request body must be a JSON object"];

  for (const field of ["schema_version", "scanner_version", "scan_started_at", "scan_completed_at"]) {
    if (!isString(payload[field], 100) || payload[field].length === 0) {
      errors.push(`${field} must be a non-empty string`);
    }
  }
  if (!Array.isArray(payload.reports)) {
    errors.push("reports must be an array");
    return errors;
  }
  if (!Number.isInteger(payload.message_count) || payload.message_count !== payload.reports.length) {
    errors.push("message_count must equal reports.length");
  }
  if (payload.reports.length > 100) errors.push("reports cannot contain more than 100 messages");
  payload.reports.forEach((report, index) => errors.push(...validateEmailReport(report, index)));
  return errors.slice(0, 50);
}

function createReportStore(limit = DEFAULT_HISTORY_LIMIT) {
  const history = [];
  return {
    add(payload) {
      history.unshift(structuredClone(payload));
      if (history.length > limit) history.length = limit;
    },
    list() {
      return structuredClone(history);
    },
    count() {
      return history.length;
    },
  };
}

function createApp(options = {}) {
  const historyLimit = boundedInteger(
    options.historyLimit ?? process.env.REPORT_HISTORY_LIMIT,
    DEFAULT_HISTORY_LIMIT,
    1,
    MAX_HISTORY_LIMIT,
  );
  const store = options.store || createReportStore(historyLimit);
  const allowedOrigin = options.allowedOrigin ?? process.env.DASHBOARD_ALLOWED_ORIGIN ?? null;
  const app = express();

  app.disable("x-powered-by");
  app.use((request, response, next) => {
    const origin = request.get("origin");
    const sameOrigin = `${request.protocol}://${request.get("host")}`;
    if (origin && origin !== sameOrigin && origin !== allowedOrigin) {
      return response.status(403).json({ error: "Cross-origin request is not permitted" });
    }
    if (origin && origin === allowedOrigin) {
      response.set("Access-Control-Allow-Origin", origin);
      response.set("Vary", "Origin");
    }
    if (request.method === "OPTIONS") {
      response.set("Access-Control-Allow-Headers", "Content-Type");
      response.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      return response.sendStatus(204);
    }
    return next();
  });
  app.use(express.json({ limit: BODY_SIZE_LIMIT, strict: true }));

  app.get("/api/health", (request, response) => {
    response.json({ status: "ok", stored_report_count: store.count() });
  });

  app.get("/api/reports", (request, response) => {
    const reports = store.list();
    response.json({ count: reports.length, reports });
  });

  app.post("/api/reports", (request, response) => {
    const errors = validateScanPayload(request.body);
    if (errors.length) return response.status(422).json({ error: "Invalid scan payload", details: errors });

    store.add(request.body);
    console.info("Scan report accepted", {
      message_count: request.body.message_count,
      stored_report_count: store.count(),
    });
    return response.status(202).json({ status: "accepted", stored_report_count: store.count() });
  });

  app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));
  app.use((request, response) => response.status(404).json({ error: "Route not found" }));
  app.use((error, request, response, next) => {
    void request;
    void next;
    if (error instanceof SyntaxError && "body" in error) {
      return response.status(400).json({ error: "Malformed JSON request body" });
    }
    if (error.type === "entity.too.large") {
      return response.status(413).json({ error: "Request body is too large" });
    }
    console.error("Dashboard request failed", { error_type: error.name || "Error" });
    return response.status(500).json({ error: "Internal dashboard error" });
  });

  return app;
}

function startServer() {
  const host = process.env.DASHBOARD_HOST || DEFAULT_HOST;
  const port = boundedInteger(process.env.DASHBOARD_PORT, DEFAULT_PORT, 1, 65_535);
  const app = createApp();
  const server = app.listen(port, host, () => {
    console.info(`Email Threat Scanner dashboard listening on http://${host}:${port}`);
  });

  function shutdown(signal) {
    console.info(`Received ${signal}; closing dashboard`);
    server.close((error) => {
      if (error) {
        console.error("Dashboard shutdown failed", { error_type: error.name || "Error" });
        process.exitCode = 1;
      }
    });
  }
  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  return server;
}

if (require.main === module) startServer();

module.exports = { createApp, createReportStore, startServer, validateScanPayload };
