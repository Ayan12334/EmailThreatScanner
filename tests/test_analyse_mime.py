import base64
import unittest

from src.analyse import extract_body


def encoded(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


class MimeExtractionTests(unittest.TestCase):
    def test_extracts_a_plain_text_single_part_body(self) -> None:
        self.assertEqual(extract_body({"body": {"data": encoded("Plain body")}}), "Plain body")

    def test_extracts_an_html_body(self) -> None:
        payload = {
            "parts": [{"mimeType": "text/html", "body": {"data": encoded("<p>Hello</p>")}}]
        }

        self.assertEqual(extract_body(payload), "<p>Hello</p>")

    def test_traverses_nested_multipart_alternative(self) -> None:
        payload = {
            "parts": [
                {
                    "mimeType": "multipart/alternative",
                    "parts": [
                        {"mimeType": "text/plain", "body": {"data": encoded("Plain")}},
                        {"mimeType": "text/html", "body": {"data": encoded("<p>HTML</p>")}},
                    ],
                }
            ]
        }

        self.assertEqual(extract_body(payload), "Plain\n<p>HTML</p>")

    def test_handles_missing_and_malformed_bodies(self) -> None:
        self.assertEqual(extract_body({}), "")
        self.assertEqual(extract_body({"parts": "invalid"}), "")
        self.assertEqual(extract_body({"body": {"data": "%%%"}}), "")


if __name__ == "__main__":
    unittest.main()
