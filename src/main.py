"""Gmail ingestion, threat-analysis orchestration, and dashboard publishing."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

try:
    from .reporting import (
        build_email_report,
        build_scan_payload,
        serialise_scan_payload,
        utc_now,
    )
    from .virustotal import VirusTotalClient, VirusTotalConfigurationError
except ImportError:
    from reporting import (  # type: ignore[no-redef]
        build_email_report,
        build_scan_payload,
        serialise_scan_payload,
        utc_now,
    )
    from virustotal import VirusTotalClient, VirusTotalConfigurationError  # type: ignore[no-redef]


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOKEN_PATH = PROJECT_ROOT / "token.json"
CREDENTIALS_PATH = PROJECT_ROOT / "credentials.json"
DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3000/api/reports"
DEFAULT_MESSAGE_LIMIT = 5
DASHBOARD_TIMEOUT = (3.05, 10.0)


class ScannerError(RuntimeError):
    """Raised when the scanner cannot complete its core Gmail workflow."""


def _message_limit() -> int:
    try:
        configured = int(os.getenv("GMAIL_MAX_MESSAGES", DEFAULT_MESSAGE_LIMIT))
    except ValueError:
        configured = DEFAULT_MESSAGE_LIMIT
    return max(1, min(configured, 100))


def authenticate_gmail() -> Credentials:
    """Load, refresh, or obtain Gmail read-only OAuth credentials."""
    credentials: Credentials | None = None
    try:
        if TOKEN_PATH.exists():
            credentials = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

        if not credentials or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
            else:
                if not CREDENTIALS_PATH.exists():
                    raise ScannerError(
                        f"OAuth desktop credentials were not found at {CREDENTIALS_PATH}"
                    )
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(CREDENTIALS_PATH), SCOPES
                )
                credentials = flow.run_local_server(port=0)
            TOKEN_PATH.write_text(credentials.to_json(), encoding="utf-8")
    except (GoogleAuthError, OSError, ValueError) as exc:
        raise ScannerError("Gmail authorisation failed") from exc

    return credentials


def _create_virus_total_client() -> tuple[VirusTotalClient | None, str | None]:
    try:
        return VirusTotalClient(), None
    except VirusTotalConfigurationError as exc:
        return None, str(exc)


def scan_inbox() -> dict[str, Any]:
    """Scan configured Gmail inbox messages and return one telemetry envelope."""
    started_at = utc_now()
    credentials = authenticate_gmail()
    virus_total_client, virus_total_error = _create_virus_total_client()

    try:
        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                labelIds=["INBOX"],
                maxResults=_message_limit(),
            )
            .execute()
        )
    except (HttpError, OSError) as exc:
        raise ScannerError("Gmail message listing failed") from exc

    message_references = response.get("messages", [])
    if not isinstance(message_references, list):
        message_references = []

    reports: list[dict[str, Any]] = []
    for reference in message_references:
        message_id = str(reference.get("id", "")) if isinstance(reference, dict) else ""
        if not message_id:
            reports.append(
                build_email_report(
                    {},
                    virus_total_client=virus_total_client,
                    virus_total_error=virus_total_error,
                    additional_errors=["Gmail returned a malformed message reference"],
                )
            )
            continue

        try:
            message = (
                service.users()
                .messages()
                .get(userId="me", id=message_id, format="full")
                .execute()
            )
            reports.append(
                build_email_report(
                    message,
                    virus_total_client=virus_total_client,
                    virus_total_error=virus_total_error,
                )
            )
        except (HttpError, OSError):
            reports.append(
                build_email_report(
                    {"id": message_id},
                    virus_total_client=virus_total_client,
                    virus_total_error=virus_total_error,
                    additional_errors=["Gmail message retrieval failed"],
                )
            )

    return build_scan_payload(reports, started_at=started_at)


def publish_report(
    payload: dict[str, Any],
    *,
    report_url: str | None = None,
    post: Callable[..., requests.Response] = requests.post,
) -> None:
    """Send the final JSON payload to the Node.js dashboard once per scan."""
    destination = report_url or os.getenv("DASHBOARD_REPORT_URL", DEFAULT_DASHBOARD_URL)
    try:
        response = post(destination, json=payload, timeout=DASHBOARD_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        error_msg = exc.response.text if getattr(exc, 'response', None) is not None else str(exc)
        raise ScannerError(f"Dashboard report delivery failed: {error_msg}") from exc


def main() -> int:
    try:
        payload = scan_inbox()
        print(serialise_scan_payload(payload, pretty=True))
        publish_report(payload)
    except ScannerError as exc:
        print(f"Scanner error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
