import base64
import json
import unittest

from src.reporting import build_email_report, build_scan_payload, serialise_scan_payload


def encoded(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")


def gmail_message(
    message_id: str = "message-1",
    *,
    subject: str = "Status update",
    sender: str = "Analyst <analyst@example.com>",
    body: str = "Routine message",
    internal_date: str = "1700000000000",
) -> dict:
    return {
        "id": message_id,
        "threadId": "thread-1",
        "internalDate": internal_date,
        "payload": {
            "headers": [
                {"name": "Subject", "value": subject},
                {"name": "From", "value": sender},
                {
                    "name": "Authentication-Results",
                    "value": "spf=pass; dkim=pass; dmarc=pass",
                },
            ],
            "body": {"data": encoded(body)},
        },
    }


class FakeVirusTotalClient:
    def lookup_urls(self, urls):
        return [
            {
                "sanitised_url": url,
                "url_id": "identifier",
                "http_status": 200,
                "lookup_status": "complete",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 80,
                "undetected_count": 5,
                "last_analysis_date": "2026-01-01T00:00:00Z",
                "error": None,
            }
            for url in urls
        ]


class ReportingTests(unittest.TestCase):
    def test_handles_missing_headers_and_no_urls(self) -> None:
        report = build_email_report({"id": "minimal", "payload": {}})

        self.assertEqual(report["subject"], "(No Subject)")
        self.assertEqual(report["url_analysis"]["sanitised_urls"], [])
        self.assertEqual(report["virus_total"]["verdicts"], [])
        self.assertEqual(report["scan_status"], "complete")

    def test_marks_virus_total_unavailability_as_partial(self) -> None:
        report = build_email_report(
            gmail_message(body="Review https://example.com/login"),
            virus_total_error="VT_API_KEY is not configured",
        )

        self.assertEqual(report["scan_status"], "partial")
        self.assertEqual(
            report["virus_total"]["verdicts"][0]["lookup_status"], "unavailable"
        )
        self.assertIsNone(report["virus_total"]["verdicts"][0]["harmless_count"])

    def test_supports_unicode_subjects_and_senders(self) -> None:
        report = build_email_report(
            gmail_message(subject="Säkerhetsöversikt 🔐", sender="Zoë <zoe@example.com>")
        )
        payload = build_scan_payload([report], started_at="2026-01-01T00:00:00Z")

        serialised = serialise_scan_payload(payload)

        self.assertIn("Säkerhetsöversikt 🔐", serialised)
        self.assertIn("Zoë", serialised)
        self.assertEqual(json.loads(serialised)["message_count"], 1)

    def test_orders_multiple_messages_deterministically(self) -> None:
        earlier = build_email_report(gmail_message("a", internal_date="1600000000000"))
        later = build_email_report(gmail_message("b", internal_date="1700000000000"))

        payload = build_scan_payload(
            [earlier, later],
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:01:00Z",
        )

        self.assertEqual(payload["message_count"], 2)
        self.assertEqual([item["message_id"] for item in payload["reports"]], ["b", "a"])

    def test_accepts_partial_and_malformed_gmail_payloads(self) -> None:
        report = build_email_report(
            {"id": "broken", "payload": "invalid"},
        )

        self.assertEqual(report["message_id"], "broken")
        self.assertEqual(report["scan_status"], "partial")
        self.assertEqual(report["analysis_errors"], ["Gmail message payload must be an object"])

    def test_includes_completed_virus_total_verdicts(self) -> None:
        report = build_email_report(
            gmail_message(body="Visit https://example.com/login"),
            virus_total_client=FakeVirusTotalClient(),
        )

        self.assertEqual(report["scan_status"], "complete")
        self.assertEqual(report["virus_total"]["verdicts"][0]["harmless_count"], 80)


if __name__ == "__main__":
    unittest.main()
