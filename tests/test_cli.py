import unittest
from headerguard.cli import review

class ReviewTests(unittest.TestCase):
    def test_missing_headers_are_reported(self):
        result = review({"headers": {}})
        self.assertEqual(result["result"], "review")
        self.assertEqual(len(result["findings"]), 5)

    def test_valid_baseline_is_clean(self):
        result = review({"target": "sample", "headers": {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }})
        self.assertEqual(result["result"], "baseline-present")
        self.assertEqual(result["findings"], [])

    def test_headers_must_be_object(self):
        with self.assertRaises(ValueError):
            review({"headers": []})

if __name__ == "__main__":
    unittest.main()
