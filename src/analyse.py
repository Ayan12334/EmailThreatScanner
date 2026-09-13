"""Deterministic MIME, header, URL, and text analysis helpers."""

from __future__ import annotations

import base64
import html
import ipaddress
import re
from dataclasses import dataclass
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit


URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

IGNORED_HOSTS = frozenset(
    {
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "static.cloudflareinsights.com",
        "unpkg.com",
        "w3.org",
        "www.w3.org",
    }
)
IGNORED_HOST_SUFFIXES = (".w3.org",)
INTERNAL_HOST_SUFFIXES = (".internal", ".intranet", ".local", ".localhost", ".test")
STATIC_ASSET_SUFFIXES = frozenset(
    {
        ".apng",
        ".avif",
        ".bmp",
        ".css",
        ".eot",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".map",
        ".otf",
        ".png",
        ".svg",
        ".tif",
        ".tiff",
        ".ttf",
        ".webp",
        ".woff",
        ".woff2",
    }
)
TRACKING_PATH_NAMES = frozenset(
    {
        "/1x1.gif",
        "/beacon.gif",
        "/favicon.ico",
        "/open.gif",
        "/pixel.gif",
        "/tracking.gif",
    }
)

MAX_SCORING_CHARACTERS = 200_000
SUBJECT_WEIGHT_MULTIPLIER = 1.5


@dataclass(frozen=True)
class ScoringRule:
    indicator: str
    weight: int
    phrases: tuple[str, ...]
    explanation: str


SOCIAL_ENGINEERING_RULES = (
    ScoringRule(
        "routine_deadline",
        6,
        ("by close of business", "deadline", "due today", "before end of day"),
        "Uses routine deadline language.",
    ),
    ScoringRule(
        "limited_time_pressure",
        15,
        ("24 hours only", "limited time", "expires today", "immediately"),
        "Creates time pressure that may discourage careful review.",
    ),
    ScoringRule(
        "urgent_action",
        18,
        ("act now", "urgent action required", "take action now", "respond urgently"),
        "Demands urgent action.",
    ),
    ScoringRule(
        "account_threat",
        30,
        (
            "account suspension",
            "account suspended",
            "account will be suspended",
            "account closure",
            "account will be closed",
            "restricted access",
        ),
        "Threatens account suspension, closure, or restricted access.",
    ),
    ScoringRule(
        "payment_pressure",
        24,
        (
            "payment failed",
            "payment failure",
            "payment declined",
            "overdue payment",
            "unpaid invoice",
        ),
        "Claims a payment problem requiring attention.",
    ),
    ScoringRule(
        "credential_expiry",
        25,
        ("password expires", "password expiry", "password has expired", "reset your password"),
        "Uses password-expiry or reset pressure.",
    ),
    ScoringRule(
        "security_alert",
        20,
        (
            "security alert",
            "suspicious activity",
            "unusual sign-in",
            "unauthorised access",
        ),
        "Uses security-alert language.",
    ),
    ScoringRule(
        "threat_of_loss",
        24,
        ("penalty", "funds will be lost", "lose access", "legal action", "service terminated"),
        "Threatens loss, penalties, or termination.",
    ),
    ScoringRule(
        "identity_verification",
        25,
        (
            "verify your identity",
            "verify your account",
            "confirm your credentials",
            "provide your password",
            "confirm your login",
        ),
        "Requests identity or credential verification.",
    ),
    ScoringRule(
        "secrecy_pressure",
        22,
        (
            "keep this confidential",
            "do not tell anyone",
            "do not discuss",
            "strictly confidential",
            "between you and me",
        ),
        "Applies secrecy or confidentiality pressure.",
    ),
)


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag.lower() in {"script", "style"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


def decode_payload_data(encoded_data: str) -> str:
    """Decode base64url data returned by the Gmail API."""
    if not encoded_data:
        return ""

    try:
        padding = "=" * (-len(encoded_data) % 4)
        decoded_bytes = base64.urlsafe_b64decode((encoded_data + padding).encode("ascii"))
        return decoded_bytes.decode("utf-8", errors="replace")
    except (TypeError, ValueError, UnicodeEncodeError):
        return ""


def extract_body(payload: dict[str, Any]) -> str:
    """Traverse a MIME tree and combine its plain-text and HTML body parts."""
    if not isinstance(payload, dict):
        return ""

    body = payload.get("body")
    if isinstance(body, dict) and isinstance(body.get("data"), str):
        return decode_payload_data(body["data"])

    body_text: list[str] = []
    parts = payload.get("parts", [])
    if not isinstance(parts, list):
        return ""

    for part in parts:
        if not isinstance(part, dict):
            continue
        mime_type = str(part.get("mimeType", "")).lower()
        part_body = part.get("body", {})
        if (
            mime_type in {"text/plain", "text/html"}
            and isinstance(part_body, dict)
            and isinstance(part_body.get("data"), str)
        ):
            body_text.append(decode_payload_data(part_body["data"]))
        elif isinstance(part.get("parts"), list):
            nested_text = extract_body(part)
            if nested_text:
                body_text.append(nested_text)

    return "\n".join(body_text)


def _trim_url_artifacts(value: str) -> str:
    cleaned = html.unescape(value).strip().lstrip("([{<\"'")
    cleaned = cleaned.rstrip(".,;:!?\"'>")

    for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
        while cleaned.endswith(closing) and cleaned.count(closing) > cleaned.count(opening):
            cleaned = cleaned[:-1]
    return cleaned


def extract_urls(text: str) -> list[str]:
    """Extract stable, unique HTTP(S) URL candidates from decoded message text."""
    if not text:
        return []
    candidates = (_trim_url_artifacts(match.group(0)) for match in URL_REGEX.finditer(text))
    return sorted({candidate for candidate in candidates if candidate})


def _is_internal_host(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(INTERNAL_HOST_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return not address.is_global


def _normalised_netloc(parsed: SplitResult, hostname: str) -> str | None:
    try:
        port = parsed.port
    except ValueError:
        return None

    display_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is None or (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    ):
        return display_host
    return f"{display_host}:{port}"


def sanitise_url(url: str, *, allow_internal: bool = False) -> str | None:
    """Normalise an external HTTP(S) URL without resolving or requesting it."""
    if not isinstance(url, str):
        return None

    candidate = _trim_url_artifacts(url)
    if not candidate or any(character.isspace() for character in candidate):
        return None

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        return None

    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None

    if not hostname or hostname in IGNORED_HOSTS or hostname.endswith(IGNORED_HOST_SUFFIXES):
        return None
    if not allow_internal and _is_internal_host(hostname):
        return None

    path_lower = parsed.path.lower()
    if any(path_lower.endswith(suffix) for suffix in STATIC_ASSET_SUFFIXES):
        return None
    if path_lower in TRACKING_PATH_NAMES:
        return None

    netloc = _normalised_netloc(parsed, hostname)
    if netloc is None:
        return None

    return urlunsplit((scheme, netloc, parsed.path or "", parsed.query, ""))


def sanitise_urls(
    urls: list[str], *, allow_internal: bool = False
) -> list[dict[str, str]]:
    """Return auditable, de-duplicated URL records sorted by sanitised URL."""
    records: dict[str, str] = {}
    for original_url in urls:
        sanitised_url = sanitise_url(original_url, allow_internal=allow_internal)
        if sanitised_url is not None:
            records.setdefault(sanitised_url, original_url)

    return [
        {"original_url": records[sanitised_url], "sanitised_url": sanitised_url}
        for sanitised_url in sorted(records)
    ]


def _normalise_visible_text(value: str) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(value[:MAX_SCORING_CHARACTERS])
        parser.close()
        visible_text = " ".join(parser.parts)
    except (ValueError, AssertionError):
        visible_text = value[:MAX_SCORING_CHARACTERS]
    return " ".join(html.unescape(visible_text).casefold().split())


def score_social_engineering(subject: str, body: str) -> dict[str, Any]:
    """Calculate a bounded, explainable pressure score from visible email text."""
    normalised_subject = _normalise_visible_text(subject or "")
    normalised_body = _normalise_visible_text(body or "")

    score = 0
    matches: list[dict[str, Any]] = []
    explanations: list[str] = []

    for rule in SOCIAL_ENGINEERING_RULES:
        subject_phrase = next(
            (phrase for phrase in rule.phrases if phrase in normalised_subject), None
        )
        body_phrase = next((phrase for phrase in rule.phrases if phrase in normalised_body), None)
        if subject_phrase is None and body_phrase is None:
            continue

        if subject_phrase is not None:
            location = "subject"
            phrase = subject_phrase
            points = round(rule.weight * SUBJECT_WEIGHT_MULTIPLIER)
        else:
            location = "body"
            phrase = body_phrase
            points = rule.weight

        score += points
        matches.append(
            {
                "indicator": rule.indicator,
                "phrase": phrase,
                "location": location,
                "points": points,
            }
        )
        explanations.append(rule.explanation)

    bounded_score = min(score, 100)
    if bounded_score >= 50:
        severity = "high"
    elif bounded_score >= 25:
        severity = "medium"
    else:
        severity = "low"

    if not explanations:
        explanations.append("No pressure or manipulation indicators were detected.")

    return {
        "score": bounded_score,
        "severity": severity,
        "matched_indicators": matches,
        "explanations": explanations,
    }


def analyse_headers(headers: list[dict[str, str]]) -> dict[str, Any]:
    """Inspect routing and authentication headers for spoofing flags."""
    header_map = {
        str(header.get("name", "")).lower(): str(header.get("value", ""))
        for header in headers
        if isinstance(header, dict)
    }

    from_header = header_map.get("from", "")
    reply_to = header_map.get("reply-to", "")
    auth_results = header_map.get("authentication-results", "")
    auth_results_lower = auth_results.lower()

    flags: list[str] = []
    from_address = parseaddr(from_header)[1].casefold()
    reply_to_address = parseaddr(reply_to)[1].casefold()
    if reply_to_address and reply_to_address != from_address:
        flags.append(
            f"Reply-To mismatch detected: From '{from_header}' vs Reply-To '{reply_to}'"
        )

    def authentication_status(mechanism: str) -> str:
        match = re.search(
            rf"(?:^|[\s;]){mechanism}=(pass|fail|softfail|neutral|none|temperror|permerror)",
            auth_results_lower,
        )
        return match.group(1) if match else "missing"

    spf_status = authentication_status("spf")
    dkim_status = authentication_status("dkim")
    dmarc_status = authentication_status("dmarc")

    for name, status in (("SPF", spf_status), ("DKIM", dkim_status), ("DMARC", dmarc_status)):
        if status != "pass":
            flags.append(f"{name} result is {status}")

    return {
        "from": from_header,
        "reply_to": reply_to,
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "spf_pass": spf_status == "pass",
        "dkim_pass": dkim_status == "pass",
        "dmarc_pass": dmarc_status == "pass",
        "flags": flags,
    }
