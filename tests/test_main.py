import unittest

from src.main import DASHBOARD_TIMEOUT, publish_report


class FakeResponse:
    def __init__(self) -> None:
        self.raise_calls = 0

    def raise_for_status(self) -> None:
        self.raise_calls += 1


class DashboardPublishingTests(unittest.TestCase):
    def test_posts_the_complete_payload_once(self) -> None:
        calls = []
        response = FakeResponse()

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            return response

        payload = {"schema_version": "1.0", "message_count": 0, "reports": []}
        publish_report(
            payload,
            report_url="http://127.0.0.1:3000/api/reports",
            post=fake_post,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["json"], payload)
        self.assertEqual(calls[0][1]["timeout"], DASHBOARD_TIMEOUT)
        self.assertEqual(response.raise_calls, 1)


if __name__ == "__main__":
    unittest.main()
