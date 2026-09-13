import unittest

from src.analyse import extract_urls, sanitise_url, sanitise_urls


class UrlSanitisationTests(unittest.TestCase):
    def test_removes_surrounding_punctuation_and_fragments(self) -> None:
        extracted = extract_urls("Visit (HTTPS://Example.COM/path?q=1#details), now.")

        self.assertEqual(extracted, ["HTTPS://Example.COM/path?q=1#details"])
        self.assertEqual(sanitise_url(extracted[0]), "https://example.com/path?q=1")

    def test_deduplicates_after_normalisation(self) -> None:
        records = sanitise_urls(
            ["https://EXAMPLE.com:443/login#one", "https://example.com/login#two"]
        )

        self.assertEqual(
            records,
            [
                {
                    "original_url": "https://EXAMPLE.com:443/login#one",
                    "sanitised_url": "https://example.com/login",
                }
            ],
        )

    def test_filters_namespaces_cdn_assets_and_tracking_pixels(self) -> None:
        urls = [
            "https://www.w3.org/2000/svg",
            "https://cdn.jsdelivr.net/library/app.min.js",
            "https://example.com/pixel.gif?message=1",
            "https://example.com/account",
        ]

        self.assertEqual(
            sanitise_urls(urls),
            [
                {
                    "original_url": "https://example.com/account",
                    "sanitised_url": "https://example.com/account",
                }
            ],
        )

    def test_rejects_malformed_non_http_and_internal_urls(self) -> None:
        values = [
            "mailto:analyst@example.com",
            "javascript:alert(1)",
            "https:///missing-host",
            "https://localhost/admin",
            "http://127.0.0.1:8080/test",
            "http://10.0.0.4/internal",
        ]

        self.assertTrue(all(sanitise_url(value) is None for value in values))

    def test_can_explicitly_allow_internal_addresses(self) -> None:
        self.assertEqual(
            sanitise_url("http://127.0.0.1:8080/test", allow_internal=True),
            "http://127.0.0.1:8080/test",
        )

    def test_preserves_queries_and_normalises_internationalised_hosts(self) -> None:
        self.assertEqual(
            sanitise_url("https://BÜCHER.example/prüfen?next=%2Fkonto"),
            "https://xn--bcher-kva.example/prüfen?next=%2Fkonto",
        )


if __name__ == "__main__":
    unittest.main()
