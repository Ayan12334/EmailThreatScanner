"""Stable JSON telemetry assembly for email threat scans."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable, Protocol

try:
    from .analyse import (
        analyse_headers,
        extract_body,
        extract_urls,
        sanitise_urls,
        score_social_engineering,
    )
    from .virustotal import virus_total_url_id
except ImportError:
    from analyse import (  # type: ignore[no-redef]
        analyse_headers,
        extract_body,
        extract_urls,
        sanitise_urls,
        score_social_engineering,
    )
    from virustotal import virus_total_url_id  # type: ignore[no-redef]


SCHEMA_VERSION = "1.0"
SCANNER_VERSION = "1.0.0"


class UrlLookupClient(Protocol):
    def lookup_urls(self, urls: Iterable[str]) -> list[dict[str, Any]]: ...


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _header_value(headers: list[dict[str, str]], name: str, default: str = "") -> str:
    sought_name = name.casefold()
    return next(
        (
            str(header.get("value", ""))
            for header in headers
            if isinstance(header, dict)
            and str(header.get("name", "")).casefold() == sought_name
        ),
        default,
    )


def _received_at(message: dict[str, Any], headers: list[dict[str, str]]) -> str | None:
    internal_date = message.get("internalDate")
    try:
        milliseconds = int(internal_date)
        return (
            datetime.fromtimestamp(milliseconds / 1000, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OverflowError, OSError):
        pass

    date_header = _header_value(headers, "Date")
    if not date_header:
        return None
    try:
        parsed = parsedate_to_datetime(date_header)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return None


def _unavailable_verdict(url: str, error: str) -> dict[str, Any]:
    return {
        "sanitised_url": url,
        "url_id": virus_total_url_id(url),
        "http_status": None,
        "lookup_status": "unavailable",
        "malicious_count": None,
        "suspicious_count": None,
        "harmless_count": None,
        "undetected_count": None,
        "last_analysis_date": None,
        "error": error,
    }


def _overall_risk(
    social_engineering: dict[str, Any],
    authentication: dict[str, str],
    spoofing_flags: list[str],
    verdicts: list[dict[str, Any]],
) -> dict[str, Any]:
    score = int(social_engineering["score"])
    for status in authentication.values():
        if status in {"fail", "softfail", "permerror"}:
            score += 20
        elif status != "pass":
            score += 5
    if any(flag.startswith("Reply-To mismatch") for flag in spoofing_flags):
        score += 20

    malicious_total = sum(
        verdict.get("malicious_count") or 0 for verdict in verdicts
    )
    suspicious_total = sum(
        verdict.get("suspicious_count") or 0 for verdict in verdicts
    )
    if malicious_total:
        score = max(score, 90)
    elif suspicious_total:
        score += 25

    bounded_score = min(score, 100)
    classification = "high" if bounded_score >= 50 else "medium" if bounded_score >= 25 else "low"
    return {"score": bounded_score, "classification": classification}


def build_email_report(
    message: dict[str, Any],
    *,
    virus_total_client: UrlLookupClient | None = None,
    virus_total_error: str | None = None,
    additional_errors: Iterable[str] = (),
) -> dict[str, Any]:
    """Convert one Gmail message payload into stable, content-minimised telemetry."""
    analysis_errors = [str(error) for error in additional_errors if error]
    if not isinstance(message, dict):
        analysis_errors.append("Gmail message must be an object")
    safe_message = message if isinstance(message, dict) else {}
    raw_payload = safe_message.get("payload", {})
    if not isinstance(raw_payload, dict):
        analysis_errors.append("Gmail message payload must be an object")
    payload = raw_payload if isinstance(raw_payload, dict) else {}
    raw_headers = payload.get("headers", [])
    if not isinstance(raw_headers, list):
        analysis_errors.append("Gmail message headers must be an array")
    headers = raw_headers if isinstance(raw_headers, list) else []

    subject = _header_value(headers, "Subject", "(No Subject)")
    body = extract_body(payload)
    extracted_urls = extract_urls(body)
    url_records = sanitise_urls(extracted_urls)
    sanitised_url_values = [record["sanitised_url"] for record in url_records]
    social_engineering = score_social_engineering(subject, body)
    header_analysis = analyse_headers(headers)
    authentication = {
        "spf": header_analysis["spf"],
        "dkim": header_analysis["dkim"],
        "dmarc": header_analysis["dmarc"],
    }

    verdicts: list[dict[str, Any]] = []
    if sanitised_url_values:
        if virus_total_client is None:
            unavailable_error = virus_total_error or "VirusTotal client is unavailable"
            verdicts = [
                _unavailable_verdict(url, unavailable_error) for url in sanitised_url_values
            ]
        else:
            try:
                verdicts = virus_total_client.lookup_urls(sanitised_url_values)
            except Exception:
                analysis_errors.append("VirusTotal lookup failed unexpectedly")
                verdicts = [
                    _unavailable_verdict(url, "VirusTotal lookup failed unexpectedly")
                    for url in sanitised_url_values
                ]

    lookup_errors = [
        {
            "sanitised_url": verdict["sanitised_url"],
            "status": verdict["lookup_status"],
            "error": verdict["error"],
        }
        for verdict in verdicts
        if verdict.get("lookup_status") != "complete"
    ]
    scan_status = "partial" if analysis_errors or lookup_errors else "complete"
    spoofing_flags = sorted(set(header_analysis["flags"]))

    return {
        "message_id": str(safe_message.get("id", "")),
        "thread_id": str(safe_message.get("threadId", "")),
        "received_at": _received_at(safe_message, headers),
        "subject": subject,
        "sender": header_analysis["from"],
        "reply_to": header_analysis["reply_to"],
        "authentication": authentication,
        "spoofing_flags": spoofing_flags,
        "url_analysis": {
            "extracted_count": len(extracted_urls),
            "sanitised_count": len(sanitised_url_values),
            "sanitised_urls": sanitised_url_values,
            "url_records": url_records,
        },
        "social_engineering": social_engineering,
        "virus_total": {"verdicts": verdicts, "lookup_errors": lookup_errors},
        "overall_risk": _overall_risk(
            social_engineering, authentication, spoofing_flags, verdicts
        ),
        "scan_status": scan_status,
        "analysis_errors": analysis_errors,
    }


def build_scan_payload(
    reports: Iterable[dict[str, Any]],
    *,
    started_at: str,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic multi-message scan envelope."""
    ordered_reports = sorted(
        reports,
        key=lambda report: (
            report.get("received_at") or "",
            report.get("message_id") or "",
        ),
        reverse=True,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "scan_started_at": started_at,
        "scan_completed_at": completed_at or utc_now(),
        "message_count": len(ordered_reports),
        "reports": ordered_reports,
    }


def serialise_scan_payload(payload: dict[str, Any], *, pretty: bool = False) -> str:
    """Serialise telemetry as valid UTF-8-compatible JSON without ASCII escaping."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2 if pretty else None,
        sort_keys=True,
    )
