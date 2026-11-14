from __future__ import annotations

import unittest
from pathlib import Path

from script.rule_filter import (
    ALLOWED_SINGLE_LABELS,
    ALLOWED_SINGLE_LABEL_SUFFIXES,
    BLOCKED_VPS_ASNS,
    is_ai_ruleset,
    is_blocked_ai_rule,
    is_time_or_ntp,
    is_valid_domain_or_suffix,
)
from main import parse_rule_entry


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
        self.assertEqual(is_blocked_ai_rule("domain-suffix", "stripe.com"), "blocked-suffix")
        self.assertEqual(is_blocked_ai_rule("domain-suffix", "auth0.com"), "blocked-suffix")

        # Legitimate AI domains must pass
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "openai.com"))
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "anthropic.com"))
        self.assertIsNone(is_blocked_ai_rule("domain", "chatgpt.com"))
        self.assertIsNone(is_blocked_ai_rule("domain-suffix", "claude.ai"))

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
        self.assertTrue(is_ai_ruleset("DeepSeek"))
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
            self.assertEqual(is_blocked_ai_rule(kind, "stripe"), "blocked-telemetry-keyword")
            self.assertEqual(is_blocked_ai_rule(kind, "auth0"), "blocked-telemetry-keyword")
            # Legitimate AI keywords must not be blocked
            self.assertIsNone(is_blocked_ai_rule(kind, "openai"))
            self.assertIsNone(is_blocked_ai_rule(kind, "claude"))

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


if __name__ == "__main__":
    unittest.main()
