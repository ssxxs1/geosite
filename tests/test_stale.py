from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from script.check_stale_rules import (
    StaleReportItem,
    extract_timestamp_from_text,
    generate_stale_markdown_report,
    inspect_source_updated_date,
)


class TestCheckStaleRules(unittest.TestCase):
    def test_extract_timestamp_from_text(self):
        text1 = "# NAME: Direct\n# UPDATED: 2025-08-12 02:08:14\nHOST,example.com"
        dt1 = extract_timestamp_from_text(text1)
        self.assertIsNotNone(dt1)
        self.assertEqual(dt1.year, 2025)
        self.assertEqual(dt1.month, 8)
        self.assertEqual(dt1.day, 12)

        text2 = "# Updated: 2025/12/07\nHOST-SUFFIX,apple.com"
        dt2 = extract_timestamp_from_text(text2)
        self.assertIsNotNone(dt2)
        self.assertEqual(dt2.year, 2025)
        self.assertEqual(dt2.month, 12)
        self.assertEqual(dt2.day, 7)

        text3 = "payload:\n  - google.com\n  - youtube.com"
        self.assertIsNone(extract_timestamp_from_text(text3))

    def test_generate_stale_markdown_report_zero(self):
        report = generate_stale_markdown_report([], threshold_days=180)
        self.assertIn("所有上游规则源均处于活跃状态", report)

    def test_generate_stale_markdown_report_with_items(self):
        items = [
            StaleReportItem(
                base_name="Direct",
                source_url="https://raw.githubusercontent.com/.../Direct.list",
                last_updated="2025-08-11",
                days_stale=463,
                source_kind="远程上游",
            ),
            StaleReportItem(
                base_name="Google",
                source_url="https://raw.githubusercontent.com/.../Google.list",
                last_updated="2026-05-11",
                days_stale=190,
                source_kind="远程上游",
            ),
        ]
        report = generate_stale_markdown_report(items, threshold_days=180)
        self.assertIn("Direct", report)
        self.assertIn("463 天", report)
        self.assertIn("Google", report)
        self.assertIn("190 天", report)

    def test_inspect_raw_github_refs_heads_url(self):
        session = mock.MagicMock()
        raw_resp = mock.MagicMock(status_code=200, text="DOMAIN-SUFFIX,steampowered.com\n")
        api_resp = mock.MagicMock(status_code=200)
        api_resp.json.return_value = [{"commit": {"committer": {"date": "2026-10-01T00:00:00Z"}}}]
        session.get.side_effect = [raw_resp, api_resp]

        url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Game/Game.list"
        with tempfile.TemporaryDirectory() as tmp:
            dt, note = inspect_source_updated_date(url, Path(tmp), session)

        self.assertEqual(dt, datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc))
        self.assertIn("master", note)
        api_call_kwargs = session.get.call_args_list[1].kwargs
        self.assertEqual(api_call_kwargs["params"]["sha"], "master")
        self.assertEqual(api_call_kwargs["params"]["path"], "rule/Clash/Game/Game.list")


if __name__ == "__main__":
    unittest.main()
