import json
import unittest
from unittest.mock import patch, MagicMock
from vortex_ai import review, summarize, coverage


class LocalReviewTests(unittest.TestCase):
    def test_only_counts_leave_process(self):
        report = {"results": [{"target": "PRIVATE", "findings": [
            {"severity": "low", "evidence": "SECRET"}]}]}
        with patch("vortex_ai.urllib.request.build_opener") as build:
            response = build.return_value.open.return_value.__enter__.return_value
            response.read.return_value = json.dumps({"message": {"content": '{"summary":"Review findings."}'}}).encode()
            result = review(report)
            request = build.return_value.open.call_args.args[0]
            self.assertNotIn(b"PRIVATE", request.data)
            self.assertNotIn(b"SECRET", request.data)
            self.assertEqual(result["counts"]["low"], 1)
            self.assertTrue(result["advisory_only"])

    def test_coverage_reports_failed_assessments_and_demo(self):
        report = {"demo": True, "results": [{"outcome": "completed"}, {"outcome": "error"}]}
        result = coverage(report)
        self.assertEqual(result["targets"], 2)
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["errors"], 1)
        self.assertTrue(result["demo"])
        self.assertIn("unknown", result["limitations"])

    def test_unknown_severity_rejected(self):
        with self.assertRaises(ValueError):
            summarize({"results": [{"findings": [{"severity": "unknown"}]}]})

    def test_invalid_model_rejected(self):
        with self.assertRaises(ValueError):
            review({"results": []}, "remote")


if __name__ == "__main__":
    unittest.main()
