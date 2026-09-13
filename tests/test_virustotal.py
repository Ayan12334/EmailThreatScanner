import unittest

import requests

from src.virustotal import (
    VirusTotalClient,
    VirusTotalConfigurationError,
    virus_total_url_id,
)


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self.payload = payload or {}

    def json(self) -> dict:
        return self.payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse | Exception]) -> None:
        self.responses = responses
        self.calls: list[dict] = []

    def get(self, url: str, **kwargs):
        self.calls.append({"url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class AdjustableClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class VirusTotalClientTests(unittest.TestCase):
    def test_requires_an_api_key(self) -> None:
        with self.assertRaises(VirusTotalConfigurationError):
            VirusTotalClient(api_key="")

    def test_builds_the_api_v3_url_identifier(self) -> None:
        self.assertEqual(virus_total_url_id("https://example.com"), "aHR0cHM6Ly9leGFtcGxlLmNvbQ")

    def test_parses_a_successful_verdict(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {
                                    "malicious": 2,
                                    "suspicious": 1,
                                    "harmless": 70,
                                    "undetected": 5,
                                },
                                "last_analysis_date": 1_700_000_000,
                            }
                        }
                    },
                )
            ]
        )
        client = VirusTotalClient(api_key="secret", session=session)

        result = client.lookup_url("https://example.com")

        self.assertEqual(result["lookup_status"], "complete")
        self.assertEqual(result["malicious_count"], 2)
        self.assertEqual(result["suspicious_count"], 1)
        self.assertEqual(session.calls[0]["timeout"], (5.0, 15.0))
        self.assertNotIn("secret", str(result))

    def test_enforces_three_requests_and_sixteen_second_intervals(self) -> None:
        clock = AdjustableClock()
        session = FakeSession([FakeResponse(404), FakeResponse(404), FakeResponse(404)])
        client = VirusTotalClient(
            api_key="secret",
            max_urls=99,
            throttle_seconds=1,
            session=session,
            clock=clock,
            sleeper=clock.sleep,
        )

        results = client.lookup_urls(
            [f"https://example.com/{number}" for number in range(4)]
        )

        self.assertEqual(len(session.calls), 3)
        self.assertEqual(clock.sleeps, [16.0, 16.0])
        self.assertEqual(results[-1]["lookup_status"], "skipped_limit")

    def test_handles_rate_limits_and_timeouts_without_retrying(self) -> None:
        session = FakeSession([FakeResponse(429), requests.Timeout()])
        clock = AdjustableClock()
        client = VirusTotalClient(
            api_key="secret", session=session, clock=clock, sleeper=clock.sleep
        )

        rate_limited = client.lookup_url("https://example.com/a")
        timed_out = client.lookup_url("https://example.com/b")

        self.assertEqual(rate_limited["lookup_status"], "rate_limited")
        self.assertEqual(timed_out["lookup_status"], "timeout")
        self.assertEqual(len(session.calls), 2)


if __name__ == "__main__":
    unittest.main()
