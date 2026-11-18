from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# 确保在任意工作目录下运行测试均可正确解析项目根目录模块
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from script.diff_radar import (
    apply_candidates_to_local,
    extract_registrable_root,
    generate_markdown_report,
    is_clean_rfc_domain,
    is_subsumed,
    load_candidates_json,
    parse_local_list,
    run_radar_scan,
    save_candidates_json,
    NewCandidate,
)
from script.magicrule_resolver import is_safe_magicrule_url


class TestDiffRadar(unittest.TestCase):
    def test_is_clean_rfc_domain_security(self):
        self.assertTrue(is_clean_rfc_domain("claude.ai"))
        self.assertTrue(is_clean_rfc_domain("downloads.claude.com"))
        self.assertTrue(is_clean_rfc_domain("x.ai"))
        self.assertTrue(is_clean_rfc_domain("api.openai.co.uk"))

        # CRLF / 分隔符注入拦截
        self.assertFalse(is_clean_rfc_domain("claude.com\nHOST,evil.com"))
        self.assertFalse(is_clean_rfc_domain("claude.com\r\n"))
        self.assertFalse(is_clean_rfc_domain("claude.com\t"))
        self.assertFalse(is_clean_rfc_domain("claude.com,evil.com"))
        self.assertFalse(is_clean_rfc_domain("claude.com;evil.com"))
        self.assertFalse(is_clean_rfc_domain("claude.com evil.com"))

        # 纯 IP 拦截
        self.assertFalse(is_clean_rfc_domain("1.1.1.1"))
        self.assertFalse(is_clean_rfc_domain("192.168.1.1"))
        self.assertFalse(is_clean_rfc_domain("::1"))

        # 通配符与非法格式拦截
        self.assertFalse(is_clean_rfc_domain("*.claude.ai"))
        self.assertFalse(is_clean_rfc_domain("claude.*.ai"))
        self.assertFalse(is_clean_rfc_domain("claude"))
        self.assertFalse(is_clean_rfc_domain(""))
        self.assertFalse(is_clean_rfc_domain("a" * 260 + ".com"))

    def test_is_subsumed_logic(self):
        suffix_set = {"claude.com", "claude.ai", "anthropic.com"}
        exact_set = {"servd-anthropic-website.b-cdn.net"}
        wildcard_set = {"*.apple.com", "*cdn*"}

        self.assertTrue(is_subsumed("servd-anthropic-website.b-cdn.net", suffix_set, exact_set))
        self.assertTrue(is_subsumed("claude.com", suffix_set, exact_set))
        self.assertTrue(is_subsumed("claude.ai", suffix_set, exact_set))
        self.assertTrue(is_subsumed("downloads.claude.com", suffix_set, exact_set))
        self.assertTrue(is_subsumed("a-cdn.claude.ai", suffix_set, exact_set))
        self.assertTrue(is_subsumed("preview.claude.ai", suffix_set, exact_set))
        self.assertTrue(is_subsumed("staging.preview.downloads.claude.com", suffix_set, exact_set))
        self.assertTrue(is_subsumed("api.anthropic.com", suffix_set, exact_set))
        self.assertTrue(is_subsumed("music.apple.com", suffix_set, exact_set, wildcard_set))
        self.assertTrue(is_subsumed("mycdnhost.net", suffix_set, exact_set, wildcard_set))

        self.assertFalse(is_subsumed("claude.space", suffix_set, exact_set, wildcard_set))
        self.assertFalse(is_subsumed("api.claude.new", suffix_set, exact_set, wildcard_set))
        self.assertFalse(is_subsumed("anthropic.cloud", suffix_set, exact_set, wildcard_set))
        self.assertFalse(is_subsumed("myclaude.com", suffix_set, exact_set, wildcard_set))
        self.assertFalse(is_subsumed("notanthropic.com", suffix_set, exact_set, wildcard_set))

    def test_extract_registrable_root(self):
        self.assertEqual(extract_registrable_root("downloads.claude.com"), "claude.com")
        self.assertEqual(extract_registrable_root("a.b.c.claude.ai"), "claude.ai")
        self.assertEqual(extract_registrable_root("claude.com"), "claude.com")
        self.assertEqual(extract_registrable_root("api.service.com.cn"), "service.com.cn")
        self.assertEqual(extract_registrable_root("sub.domain.co.uk"), "domain.co.uk")
        self.assertEqual(extract_registrable_root("ai.gateway.co.jp"), "gateway.co.jp")
        self.assertEqual(extract_registrable_root("Claude.AI."), "claude.ai")

    def test_apply_skips_auto_generated_ai_list_and_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Private").mkdir()
            ai_file = root / "Private" / "AI.list"
            ai_file.write_text("# UPDATED: 2026-11-18 00:00:00\nHOST-SUFFIX,openai.com\n", encoding="utf-8")
            claude_file = root / "Private" / "Claude.list"
            claude_file.write_text("# UPDATED: 2026-11-18 00:00:00\nHOST-SUFFIX,claude.ai\n", encoding="utf-8")

            results = {
                "AI": [NewCandidate("x.ai", "AI", "Community", "xai.yaml", "HOST-SUFFIX,x.ai", True)],
                "Claude": [NewCandidate("claude.space", "Claude", "CT-Logs", "claude.ai", "HOST-SUFFIX,claude.space", True)],
            }
            json_path = root / "candidates.json"
            save_candidates_json(results, json_path)
            loaded = load_candidates_json(json_path)
            added = apply_candidates_to_local(loaded, project_root=root)

            self.assertEqual(added, 1)
            self.assertNotIn("x.ai", ai_file.read_text(encoding="utf-8"))
            claude_text = claude_file.read_text(encoding="utf-8")
            self.assertIn("HOST-SUFFIX,claude.space", claude_text)
            self.assertNotIn("2026-11-18 00:00:00", claude_text)

    def test_radar_category_gating_for_ai_blacklist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Private").mkdir()
            (root / "Private" / "AppleProxy.list").write_text("HOST-SUFFIX,apple.com\n", encoding="utf-8")
            (root / "Private" / "AI.list").write_text("HOST-SUFFIX,openai.com\n", encoding="utf-8")
            targets = {
                "AppleProxy": {
                    "local": "Private/AppleProxy.list",
                    "community_sources": ["https://example.com/apple.yaml"],
                    "ct_roots": [],
                    "category": "apple",
                },
                "AI": {
                    "local": "Private/AI.list",
                    "community_sources": ["https://example.com/ai.yaml"],
                    "ct_roots": [],
                    "category": "ai",
                },
            }

            def fake_fetch(url, _session):
                if "apple" in url:
                    return {"mzstatic.com"}
                return {"sentry.io", "newai.ai"}

            with mock.patch("script.diff_radar.fetch_community_domains", side_effect=fake_fetch):
                res = run_radar_scan(targets=targets, project_root=root, verbose=False)

            self.assertEqual([c.domain for c in res["AppleProxy"]], ["mzstatic.com"])
            self.assertEqual([c.domain for c in res["AI"]], ["newai.ai"])

    def test_parse_local_list(self):
        project_root = Path(__file__).resolve().parent.parent
        claude_path = project_root / "Private" / "Claude.list"
        self.assertTrue(claude_path.exists())

        rule_set = parse_local_list(claude_path, "Claude")
        self.assertIn("claude.com", rule_set.suffix_domains)
        self.assertIn("claude.ai", rule_set.suffix_domains)
        self.assertIn("anthropic.com", rule_set.suffix_domains)
        self.assertIn("servd-anthropic-website.b-cdn.net", rule_set.exact_domains)

    def test_generate_markdown_report_zero_new(self):
        report = generate_markdown_report({})
        self.assertIn("本次巡检未发现任何未收录的新业务域名", report)

    def test_generate_markdown_report_with_candidates(self):
        candidates = {
            "Claude": [
                NewCandidate(
                    domain="claude.space",
                    target_name="Claude",
                    source_type="CT-Logs",
                    source_name="claude.space",
                    suggested_rule="HOST-SUFFIX,claude.space",
                    is_root_promotion=True,
                )
            ]
        }
        report = generate_markdown_report(candidates)
        self.assertIn("Claude", report)
        self.assertIn("claude.space", report)
        self.assertIn("HOST-SUFFIX,claude.space", report)


    def test_magicrule_ssrf_protection(self):
        self.assertTrue(is_safe_magicrule_url("https://magicrule.pages.dev/data/index/QuantumultX.json"))
        self.assertTrue(is_safe_magicrule_url("https://magicrule.pages.dev/data/rules/QuantumultX/manifest.json"))
        self.assertTrue(is_safe_magicrule_url("https://magicrule.pages.dev/data/_shared/artifacts/GitHub_rules_123.list"))
        self.assertTrue(is_safe_magicrule_url("https://rule-26r.pages.dev/data/rules/Bybit/manifest.json"))
        self.assertTrue(is_safe_magicrule_url("https://rule-26r.pages.dev/data/_shared/artifacts/Bybit_rules_abc.list"))

        self.assertFalse(is_safe_magicrule_url("http://magicrule.pages.dev/data/index/QuantumultX.json"))
        self.assertFalse(is_safe_magicrule_url("https://evil.com/manifest.json"))
        self.assertFalse(is_safe_magicrule_url("http://169.254.169.254/latest/meta-data/"))
        self.assertFalse(is_safe_magicrule_url("http://127.0.0.1:8080/evil.json"))
        self.assertFalse(is_safe_magicrule_url("file:///etc/passwd"))
        self.assertFalse(is_safe_magicrule_url("https://magicrule.pages.dev.evil.com/manifest.json"))
        self.assertFalse(is_safe_magicrule_url("https://evil.pages.dev/manifest.json"))
        self.assertFalse(is_safe_magicrule_url("https://attacker.pages.dev/manifest.json"))
        self.assertFalse(is_safe_magicrule_url(""))
        self.assertFalse(is_safe_magicrule_url(None))


if __name__ == "__main__":
    unittest.main()
