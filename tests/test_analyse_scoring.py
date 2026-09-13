import unittest

from src.analyse import score_social_engineering


class SocialEngineeringScoringTests(unittest.TestCase):
    def test_benign_business_deadline_stays_low(self) -> None:
        result = score_social_engineering(
            "Quarterly planning", "The document deadline is Friday. Thank you."
        )

        self.assertEqual(result["score"], 6)
        self.assertEqual(result["severity"], "low")

    def test_strong_account_suspension_language_is_high(self) -> None:
        result = score_social_engineering(
            "Urgent action required: account suspension",
            "Verify your identity immediately to retain access.",
        )

        self.assertEqual(result["severity"], "high")
        self.assertGreaterEqual(result["score"], 50)

    def test_multiple_categories_are_reported(self) -> None:
        result = score_social_engineering(
            "Payment failed",
            "Security alert. Confirm your credentials and keep this confidential.",
        )

        indicators = {item["indicator"] for item in result["matched_indicators"]}
        self.assertEqual(
            indicators,
            {"payment_pressure", "security_alert", "identity_verification", "secrecy_pressure"},
        )
        self.assertEqual(result["score"], 100)

    def test_repeated_phrase_is_counted_once(self) -> None:
        once = score_social_engineering("", "Act now")
        repeated = score_social_engineering("", "Act now, act now, ACT NOW")

        self.assertEqual(repeated["score"], once["score"])
        self.assertEqual(len(repeated["matched_indicators"]), 1)

    def test_ignores_scripts_and_markup(self) -> None:
        result = score_social_engineering(
            "Routine update",
            "<html><script>act now; account suspended</script><p>Meeting at noon.</p></html>",
        )

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["matched_indicators"], [])

    def test_empty_and_very_long_bodies_are_bounded(self) -> None:
        empty = score_social_engineering("", "")
        long_body = score_social_engineering("", "ordinary text " * 100_000 + "act now")

        self.assertEqual(empty["score"], 0)
        self.assertEqual(empty["severity"], "low")
        self.assertGreaterEqual(long_body["score"], 0)
        self.assertLessEqual(long_body["score"], 100)


if __name__ == "__main__":
    unittest.main()
