from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from script.rule_filter import (
    is_ai_ruleset,
    is_blocked_ai_rule,
    is_time_or_ntp,
    is_valid_domain_or_suffix,
)
from main import (
    build_quantumult_x_list,
    cleanup_orphaned_outputs,
    convert_source,
    parse_rule_entry,
    resolve_base_name,
)


class TestRuleFilter(unittest.TestCase):
    def test_single_label_suffixes_and_domains(self):
        # Whitelisted single-labels must pass
        self.assertTrue(is_valid_domain_or_suffix("domain-suffix", "cn"))
        self.assertTrue(is_valid_domain_or_suffix("domain-suffix", "aws"))
        self.assertTrue(is_valid_domain_or_suffix("domain", "localhost"))
        self.assertTrue(is_valid_domain_or_suffix("host-suffix", "cn"))
        self.assertTrue(is_valid_domain_or_suffix("host", "localhost"))

        # Invalid single-label suffixes and domains must be rejected
        self.assertFalse(is_valid_domain_or_suffix("domain-suffix", "ms"))
        self.assertFalse(is_valid_domain_or_suffix("domain-suffix", "azure"))
        self.assertFalse(is_valid_domain_or_suffix("domain-suffix", "bing"))
        self.assertFalse(is_valid_domain_or_suffix("domain-suffix", "office"))
        self.assertFalse(is_valid_domain_or_suffix("host-suffix", "windows"))

        # Single-label exact domains without dots must also be rejected
        self.assertFalse(is_valid_domain_or_suffix("domain", "azure"))
        self.assertFalse(is_valid_domain_or_suffix("domain", "ms"))
        self.assertFalse(is_valid_domain_or_suffix("host", "bing"))

        # Normal multi-label domains must always pass
        self.assertTrue(is_valid_domain_or_suffix("domain-suffix", "google.com"))
        self.assertTrue(is_valid_domain_or_suffix("domain", "chatgpt.com"))
        self.assertTrue(is_valid_domain_or_suffix("domain-suffix", "sub.domain.co.uk"))

    def test_blocked_vps_asns_for_ai(self):
        # DigitalOcean (14061) and Vultr (20473) must be blocked in AI rulesets
        self.assertEqual(is_blocked_ai_rule("ip-asn", "14061"), "blocked-vps-asn")
        self.assertEqual(is_blocked_ai_rule("ip-asn", "20473"), "blocked-vps-asn")
        self.assertEqual(is_blocked_ai_rule("ip-asn", "AS14061"), "blocked-vps-asn")
        self.assertEqual(is_blocked_ai_rule("ip-asn", "AS20473"), "blocked-vps-asn")

        # Legitimate non-blocked ASNs should pass (e.g. Google ASN 15169, OpenAI ASN 399358)
        self.assertIsNone(is_blocked_ai_rule("ip-asn", "15169"))
        self.assertIsNone(is_blocked_ai_rule("ip-asn", "399358"))

    def test_blocked_telemetry_and_analytics_for_ai(self):
        # Tracking, analytics and telemetry should be blocked in AI rulesets
        self.assertEqual(is_blocked_ai_rule("domain", "static.cloudflareinsights.com"), "exact-domain")
        self.assertEqual(is_blocked_ai_rule("domain", "www.google-analytics.com"), "exact-domain")
        self.assertEqual(is_blocked_ai_rule("domain-suffix", "doubleclick.net"), "blocked-suffix")
        self.assertEqual(is_blocked_ai_rule("domain-suffix", "sentry.io"), "blocked-suffix")
        self.assertEqual(is_blocked_ai_rule("domain-suffix", "datadoghq.com"), "blocked-suffix")

        # Legitimate AI domains and critical infrastructure (auth/payment/Claude logging) must pass
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "openai.com"))
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "anthropic.com"))
        self.assertIsNone(is_blocked_ai_rule("domain", "chatgpt.com"))
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "claude.ai"))
        # auth0 / stripe 必须走代理，不能被阻断为直连
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "stripe.com"))
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "auth0.com"))
        # Claude Datadog 日志端点与埋点必须放行走代理
        self.assertIsNone(is_blocked_ai_rule("domain", "http-intake.logs.us5.datadoghq.com"))
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "browser-intake-datadoghq.com"))

    def test_time_and_ntp_no_false_positives(self):
        # Genuine NTP / time servers must be matched
        self.assertTrue(is_time_or_ntp("time.google.com"))
        self.assertTrue(is_time_or_ntp("time1.apple.com"))
        self.assertTrue(is_time_or_ntp("time-a.nist.gov"))
        self.assertTrue(is_time_or_ntp("ntp1.aliyun.com"))
        self.assertTrue(is_time_or_ntp("pool.ntp.org"))
        self.assertEqual(is_blocked_ai_rule("domain", "time.google.com"), "time-or-ntp")

        # Commercial media, magazines, and AI services containing "time" MUST NOT be blocked
        self.assertFalse(is_time_or_ntp("time.com"))
        self.assertFalse(is_time_or_ntp("time.is"))
        self.assertFalse(is_time_or_ntp("nytimes.com"))
        self.assertFalse(is_time_or_ntp("timetravel.ai"))
        self.assertFalse(is_time_or_ntp("api.anytime.ai"))
        self.assertFalse(is_time_or_ntp("timeout.com"))
        self.assertFalse(is_time_or_ntp("realtime.example.com"))
        self.assertFalse(is_time_or_ntp("runtime.io"))

        self.assertIsNone(is_blocked_ai_rule("domain", "time.com"))
        self.assertIsNone(is_blocked_ai_rule("domain", "nytimes.com"))
        self.assertIsNone(is_blocked_ai_rule("domain", "timetravel.ai"))
        self.assertIsNone(is_blocked_ai_rule("domain", "api.anytime.ai"))

    def test_parse_rule_entry(self):
        # Valid rules
        self.assertEqual(parse_rule_entry("DOMAIN-SUFFIX,cn"), ("domain-suffix", "cn", ()))
        self.assertEqual(parse_rule_entry("DOMAIN-SUFFIX,aws"), ("domain-suffix", "aws", ()))
        self.assertEqual(parse_rule_entry("DOMAIN,example.com"), ("domain", "example.com", ()))
        self.assertEqual(parse_rule_entry("IP-ASN,14061"), ("ip-asn", "14061", ()))

        # Invalid single-label suffixes are skipped (returns None)
        self.assertIsNone(parse_rule_entry("DOMAIN-SUFFIX,ms"))
        self.assertIsNone(parse_rule_entry("DOMAIN-SUFFIX,azure"))
        self.assertIsNone(parse_rule_entry("DOMAIN-SUFFIX,bing"))

        # Bare single-label words are also skipped (prevents DOMAIN,azure bypass)
        self.assertIsNone(parse_rule_entry("DOMAIN,azure"))
        self.assertIsNone(parse_rule_entry("azure"))
        self.assertIsNone(parse_rule_entry("ms"))

        # YAML & v2fly geosite syntax compatibility
        self.assertEqual(parse_rule_entry("+.chatgpt.com"), ("domain-suffix", "chatgpt.com", ()))
        self.assertEqual(parse_rule_entry(".openai.com"), ("domain-suffix", "openai.com", ()))
        self.assertEqual(parse_rule_entry("full:api.openai.com"), ("domain", "api.openai.com", ()))
        self.assertEqual(parse_rule_entry("domain:oaistatic.com"), ("domain-suffix", "oaistatic.com", ()))
        self.assertEqual(parse_rule_entry("keyword:openai"), ("domain-keyword", "openai", ()))
        self.assertEqual(parse_rule_entry("regexp:^.*\\.openai\\.com$"), ("domain-regex", "^.*\\.openai\\.com$", ()))
        self.assertEqual(parse_rule_entry("AS13335"), ("ip-asn", "13335", ()))
        self.assertEqual(parse_rule_entry("bilibili.com:@cn"), ("domain", "bilibili.com", ()))
        self.assertEqual(parse_rule_entry("example.com # official"), ("domain", "example.com", ()))
        self.assertIsNone(parse_rule_entry(True))
        self.assertIsNone(parse_rule_entry(12345))

    def test_is_ai_ruleset(self):
        # Canonical AI rulesets
        self.assertTrue(is_ai_ruleset("OpenAI"))
        self.assertTrue(is_ai_ruleset("Copilot"))
        self.assertTrue(is_ai_ruleset("Claude"))
        self.assertTrue(is_ai_ruleset("Gemini"))
        self.assertTrue(is_ai_ruleset("AppleIntelligence"))
        self.assertTrue(is_ai_ruleset("AI"))

        # Expanded next-gen AI rulesets
        self.assertTrue(is_ai_ruleset("ChatGPT"))
        self.assertTrue(is_ai_ruleset("Perplexity"))
        self.assertTrue(is_ai_ruleset("Grok"))
        self.assertTrue(is_ai_ruleset("Sora"))
        self.assertTrue(is_ai_ruleset("Anthropic"))
        self.assertTrue(is_ai_ruleset("AI_Suite"))
        self.assertTrue(is_ai_ruleset("My_AI"))

        # Non-AI rulesets
        self.assertFalse(is_ai_ruleset("China"))
        self.assertFalse(is_ai_ruleset("Global"))
        self.assertFalse(is_ai_ruleset("Direct"))
        self.assertFalse(is_ai_ruleset("Microsoft"))
        self.assertFalse(is_ai_ruleset("Tailscale"))
        self.assertFalse(is_ai_ruleset("Email"))

    def test_cross_client_dialects_blocked_in_ai(self):
        # QX (host-regex / host-keyword), Clash/Mihomo (domain-regex / domain-keyword), Sing-box (domain_regex / domain_keyword)
        for kind in ("host-regex", "domain-regex", "domain_regex"):
            self.assertEqual(is_blocked_ai_rule(kind, r"^.*\.datadoghq\.com$"), "blocked-telemetry-keyword")
            self.assertEqual(is_blocked_ai_rule(kind, r"^ntp[0-9]*\."), "time-or-ntp")

        for kind in ("host-keyword", "domain-keyword", "domain_keyword"):
            self.assertEqual(is_blocked_ai_rule(kind, "appsflyer"), "blocked-telemetry-keyword")
            self.assertEqual(is_blocked_ai_rule(kind, "google-analytics"), "blocked-telemetry-keyword")
            self.assertEqual(is_blocked_ai_rule(kind, "bytedapm"), "blocked-telemetry-keyword")
            self.assertEqual(is_blocked_ai_rule(kind, "sentry"), "blocked-telemetry-keyword")
            # Legitimate AI keywords and critical auth/payment infra must not be blocked
            self.assertIsNone(is_blocked_ai_rule(kind, "openai"))
            self.assertIsNone(is_blocked_ai_rule(kind, "claude"))
            self.assertIsNone(is_blocked_ai_rule(kind, "stripe"))
            self.assertIsNone(is_blocked_ai_rule(kind, "auth0"))

        # Sing-box domain_suffix single-label check
        self.assertFalse(is_valid_domain_or_suffix("domain_suffix", "azure"))
        self.assertTrue(is_valid_domain_or_suffix("domain_suffix", "cn"))

    def test_generate_ai_options_merge_and_subdomain_folding(self):
        from collections import Counter
        from script.generate_ai import Rule, add_rule, fold_covered_rules

        aggregate = {}
        stats = Counter()
        # Same-level, same-key merge preserves options
        add_rule(aggregate, Rule("host-suffix", "openai.com", options=("custom-opt",), sources={"s1"}), stats)
        add_rule(aggregate, Rule("host-suffix", "openai.com", options=(), sources={"s2"}), stats)
        # Subdomain rules with specific options must NOT pollute parent host-suffix
        add_rule(aggregate, Rule("host", "api.openai.com", options=("force-remote-dns",), sources={"s1"}), stats)
        add_rule(aggregate, Rule("host-suffix", "chat.openai.com", options=("no-resolve",), sources={"s3"}), stats)
        # Same key merge preserves options
        add_rule(aggregate, Rule("ip-cidr", "1.1.1.0/24", options=(), sources={"s1"}), stats)
        add_rule(aggregate, Rule("ip-cidr", "1.1.1.0/24", options=("no-resolve",), sources={"s2"}), stats)

        fold_covered_rules(aggregate, stats)
        self.assertIn(("host-suffix", "openai.com"), aggregate)
        self.assertNotIn(("host", "api.openai.com"), aggregate)
        self.assertNotIn(("host-suffix", "chat.openai.com"), aggregate)
        # Parent rule preserves its own options, cleanly isolated from child subdomains
        self.assertEqual(aggregate[("host-suffix", "openai.com")].options, ("custom-opt",))
        self.assertEqual(aggregate[("ip-cidr", "1.1.1.0/24")].options, ("no-resolve",))

    def test_resolve_base_name(self):
        # Fragment anchor overrides
        self.assertEqual(resolve_base_name("https://example.com/openai.yaml#OpenAI"), "OpenAI")
        self.assertEqual(resolve_base_name("https://example.com/httpdns.yaml#BlockHttpDNS"), "BlockHttpDNS")

        # Canonical mappings fallback
        self.assertEqual(resolve_base_name("https://example.com/openai.yaml"), "OpenAI")
        self.assertEqual(resolve_base_name("https://example.com/facebook.yaml"), "Facebook")
        self.assertEqual(resolve_base_name("https://example.com/binance.yaml"), "Binance")
        self.assertEqual(resolve_base_name("https://example.com/playstation.yaml"), "PlayStation")
        self.assertEqual(resolve_base_name("https://example.com/ea.yaml"), "EA")
        self.assertEqual(resolve_base_name("https://example.com/cloudflare.yaml"), "Cloudflare")
        self.assertEqual(resolve_base_name("https://example.com/whatsapp.yaml"), "Whatsapp")
        self.assertEqual(resolve_base_name("https://example.com/httpdns.yaml"), "BlockHttpDNS")

        # Local paths & magicrule://
        self.assertEqual(resolve_base_name("Private/Gemini.list"), "Gemini")
        self.assertEqual(resolve_base_name("Private/Copilot.list"), "Copilot")
        self.assertEqual(resolve_base_name("Private/SystemOTA.list"), "SystemOTA")
        self.assertEqual(resolve_base_name("Private/ChinaMedia.list"), "ChinaMedia")
        self.assertEqual(resolve_base_name("magicrule://Direct#Direct"), "Direct")
        self.assertEqual(resolve_base_name("magicrule://Direct"), "Direct")

    def test_build_quantumult_x_list_preserves_no_resolve_wildcards_and_timestamp(self):
        rules = [
            ("domain", "example.com", ("DIRECT",)),
            ("domain-suffix", "cici.com", ("extended-matching",)),
            ("domain-wildcard", "chatgpt*.azurefd.net", ()),
            ("domain-regex", r"^api-\d+\.example\.com$", ()),
            ("ip-cidr", "199.47.142.0/23", ("no-resolve",)),
            ("ip-cidr", "1.1.1.0/24", ()),
            ("ip-cidr6", "2604:f20::/32", ("no-resolve",)),
            ("ip-asn", "401518", ()),
            ("ip-asn", "399358", ("no-resolve",)),
        ]
        rendered = build_quantumult_x_list(rules, base_name="TestSet", updated_at="2026-11-18 10:00:00 UTC")
        self.assertIn("HOST,example.com\n", rendered)
        self.assertNotIn("DIRECT", rendered)
        self.assertIn("HOST-SUFFIX,cici.com,extended-matching\n", rendered)
        self.assertIn("HOST-WILDCARD,chatgpt*.azurefd.net\n", rendered)
        self.assertIn(r"HOST-REGEX,^api-\d+\.example\.com$" + "\n", rendered)
        self.assertIn("IP-CIDR,199.47.142.0/23,no-resolve\n", rendered)
        self.assertIn("IP-CIDR,1.1.1.0/24,no-resolve\n", rendered)
        self.assertIn("IP6-CIDR,2604:f20::/32,no-resolve\n", rendered)
        self.assertIn("IP-ASN,401518\n", rendered)
        self.assertIn("IP-ASN,399358,no-resolve\n", rendered)

        with tempfile.TemporaryDirectory() as tmp:
            qx_path = Path(tmp) / "TestSet.list"
            qx_path.write_text(rendered, encoding="utf-8")
            rerendered = build_quantumult_x_list(rules, base_name="TestSet", existing_path=qx_path)
            self.assertEqual(rerendered, rendered)

    def test_private_source_does_not_pull_magicrule_and_orphan_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            src = tmp_dir / "Claude.list"
            src.write_text("HOST-SUFFIX,claude.ai\nHOST,claude.com\n", encoding="utf-8")
            out_dir = tmp_dir / "rules"
            out_dir.mkdir()
            (out_dir / "AdvertisingLite.json").write_text("{}", encoding="utf-8")
            (out_dir / "Claude.mrs").write_text("old", encoding="utf-8")

            with mock.patch("main.get_magicrule_resolver") as mock_resolver:
                convert_source(str(src), out_dir, mock.MagicMock(), compile_srs=False, compile_mrs=False)
                mock_resolver.assert_not_called()

            removed = cleanup_orphaned_outputs(out_dir, {"Claude"})
            self.assertEqual(removed, ["AdvertisingLite.json"])
            self.assertFalse((out_dir / "AdvertisingLite.json").exists())
            self.assertTrue((out_dir / "Claude.json").exists())


if __name__ == "__main__":
    unittest.main()
