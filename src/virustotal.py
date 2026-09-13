"""Quota-aware VirusTotal API v3 URL lookups."""

from __future__ import annotations

import base64
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

import requests
from dotenv import load_dotenv


VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"
MAX_URLS_PER_EXECUTION = 3
MINIMUM_THROTTLE_SECONDS = 16.0
DEFAULT_TIMEOUT = (5.0, 15.0)


class VirusTotalConfigurationError(RuntimeError):
    """Raised when VirusTotal cannot be configured safely."""


def virus_total_url_id(url: str) -> str:
    """Return the unpadded URL-safe identifier required by VirusTotal API v3."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _bounded_max_urls(value: str | int | None) -> int:
    try:
        configured = int(value) if value is not None else MAX_URLS_PER_EXECUTION
    except (TypeError, ValueError):
        configured = MAX_URLS_PER_EXECUTION
    return max(0, min(configured, MAX_URLS_PER_EXECUTION))


def _bounded_throttle(value: str | float | None) -> float:
    try:
        configured = float(value) if value is not None else MINIMUM_THROTTLE_SECONDS
    except (TypeError, ValueError):
        configured = MINIMUM_THROTTLE_SECONDS
    return max(configured, MINIMUM_THROTTLE_SECONDS)


def _iso_timestamp(value: Any) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


class VirusTotalClient:
    """Perform bounded URL lookups without retries or quota ambiguity."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        max_urls: int | None = None,
        throttle_seconds: float | None = None,
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        load_dotenv()
        configured_api_key = os.getenv("VT_API_KEY", "") if api_key is None else api_key
        self.api_key = configured_api_key.strip()
        if not self.api_key:
            raise VirusTotalConfigurationError("VT_API_KEY is not configured")

        configured_max = max_urls if max_urls is not None else os.getenv("VT_MAX_URLS")
        configured_throttle = (
            throttle_seconds
            if throttle_seconds is not None
            else os.getenv("VT_THROTTLE_SECONDS")
        )
        self.max_urls = _bounded_max_urls(configured_max)
        self.throttle_seconds = _bounded_throttle(configured_throttle)
        self.timeout = timeout
        self.session = session or requests.Session()
        self.clock = clock
        self.sleeper = sleeper
        self.request_count = 0
        self._last_request_started: float | None = None

    def _wait_for_quota_window(self) -> None:
        if self._last_request_started is None:
            return
        elapsed = self.clock() - self._last_request_started
        remaining = self.throttle_seconds - elapsed
        if remaining > 0:
            self.sleeper(remaining)

    @staticmethod
    def _empty_result(url: str, lookup_status: str, error: str | None) -> dict[str, Any]:
        return {
            "sanitised_url": url,
            "url_id": virus_total_url_id(url),
            "http_status": None,
            "lookup_status": lookup_status,
            "malicious_count": None,
            "suspicious_count": None,
            "harmless_count": None,
            "undetected_count": None,
            "last_analysis_date": None,
            "error": error,
        }

    def lookup_url(self, url: str) -> dict[str, Any]:
        """Look up one URL and return a stable verdict object."""
        if self.request_count >= self.max_urls:
            return self._empty_result(
                url, "skipped_limit", "VirusTotal execution URL limit reached"
            )

        result = self._empty_result(url, "pending", None)
        self._wait_for_quota_window()
        self._last_request_started = self.clock()
        self.request_count += 1

        try:
            response = self.session.get(
                f"{VIRUSTOTAL_URL_API}/{result['url_id']}",
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
                timeout=self.timeout,
            )
        except requests.Timeout:
            result.update(lookup_status="timeout", error="VirusTotal request timed out")
            return result
        except requests.RequestException:
            result.update(lookup_status="request_error", error="VirusTotal request failed")
            return result

        result["http_status"] = response.status_code
        if response.status_code == 429:
            result.update(lookup_status="rate_limited", error="VirusTotal rate limit reached")
            return result
        if response.status_code in {401, 403}:
            result.update(
                lookup_status="authentication_error",
                error="VirusTotal rejected the configured credentials",
            )
            return result
        if response.status_code == 404:
            result.update(
                lookup_status="not_found",
                error="URL has no available VirusTotal analysis",
            )
            return result
        if response.status_code != 200:
            result.update(
                lookup_status="http_error",
                error=f"VirusTotal returned HTTP {response.status_code}",
            )
            return result

        try:
            attributes = response.json()["data"]["attributes"]
            statistics = attributes["last_analysis_stats"]
            counts = {
                name: int(statistics.get(name, 0))
                for name in ("malicious", "suspicious", "harmless", "undetected")
            }
        except (KeyError, TypeError, ValueError, requests.JSONDecodeError):
            result.update(
                lookup_status="invalid_response",
                error="VirusTotal returned an unexpected response",
            )
            return result

        result.update(
            lookup_status="complete",
            malicious_count=counts["malicious"],
            suspicious_count=counts["suspicious"],
            harmless_count=counts["harmless"],
            undetected_count=counts["undetected"],
            last_analysis_date=_iso_timestamp(attributes.get("last_analysis_date")),
        )
        return result

    def lookup_urls(self, urls: Iterable[str]) -> list[dict[str, Any]]:
        """Look up stable unique URLs while retaining skipped-limit results."""
        return [self.lookup_url(url) for url in sorted(set(urls))]
