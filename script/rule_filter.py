"""
Common rule filtering and validation for geosite.
Provides:
1. is_valid_domain_or_suffix: Rejects single-label domain/suffix entries (e.g. 'ms', 'azure') unless whitelisted ('cn', 'aws', 'localhost').
2. is_blocked_ai_rule: Common filter for AI rulesets (blocks broad VPS datacenters ASN 14061/20473, analytics, telemetry, search, captcha).
3. is_ai_ruleset: Helper to detect AI-related ruleset names with fuzzy / prefix / suffix support.
"""
from __future__ import annotations

import re

# 1. 允许的单标签白名单 (例如 .cn 顶级域名、.aws 品牌顶级域名、localhost 本地回环)
ALLOWED_SINGLE_LABELS: set[str] = {"cn", "aws", "localhost"}
ALLOWED_SINGLE_LABEL_SUFFIXES: set[str] = ALLOWED_SINGLE_LABELS  # 兼容向后引用

# 2. AI 规则集黑名单：精确域名
BLOCKED_EXACT_DOMAINS: set[str] = {
    # 通用分析与遥测 (Analytics & Telemetry) - 避免将全网统计上报归入 AI 策略组
    "www.google-analytics.com",
    "static.cloudflareinsights.com",
    "digicert.com",
    "identrust.com",
    # 开发者通用接口 - 防止 git 命令被 AI 策略接管
    "api.github.com",
    # 谷歌通用静态资源与地图 - 避免全网静态资源与地图走 AI
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "maps.googleapis.com",
    "maps.gstatic.com",
    "streetviewpixels-pa.googleapis.com",
    "i.ytimg.com",
    "yt3.ggpht.com",
    "ipv4.google.com",
    "h3.google.com",
    "developerprofiles.google.com",
    "www.gstatic.com",
    "ssl.gstatic.com",
    "apis.google.com",
    # 网络授时与时间同步
    "clock.isc.org",
    "ats1.e-timing.ne.jp",
    # 通用搜索引擎主页与网络探针
    "www.bing.com",
    "challenges.cloudflare.com",
    "cp2.cloudflare.com",
    "cp4.cloudflare.com",
}

# 3. AI 规则集黑名单：域名后缀
BLOCKED_DOMAIN_SUFFIXES: set[str] = {
    # 移动广告归因、埋点与 APM 监控 (Ads, Tracking & Telemetry)
    "appsflyer.com",
    "appsflyersdk.com",
    "browser-intake-datadoghq.com",
    "cdn.usefathom.com",
    "datadoghq.com",
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "intercom.io",
    "intercomcdn.com",
    "sentry.io",
    "segment.io",
    "segment.com",
    "segmentify.com",
    "stripe.com",
    "stripecdn.com",
    "stripe.network",
    "statsig.com",
    "statsigapi.net",
    "launchdarkly.com",
    "observeit.net",
    "honeycomb.io",
    "ct.sendgrid.net",
    "algolia.net",
    "auth0.com",
    # 字节跳动与 TikTok 支付与监控
    "pipopay.com",
    "bytedapm.com",
    "byteintlapi.com",
    "byteoversea.com",
    "itobsnssdk.com",
    "ttwstatic.com",
    # 常见非 AI 网页排版与通用 Web 工具平台
    "canva.com",
    "canva.dev",
    "canva.site",
    "asana.com",
    "atlassian.com",
    "linear.app",
    # 苹果生态非 AI 媒体与系统 OTA 服务
    "mzstatic.com",
    "updates.cdn-apple.com",
    "updates-http.cdn-apple.com",
    "gdmf.apple.com",
    "appldnld.apple.com",
    "swcdn.apple.com",
    "gg.apple.com",
    "appsto.re",
    "apps.apple.com",
}

# 宽泛 VPS 机房 ASN 黑名单 (禁止进任何 AI 策略)
BLOCKED_VPS_ASNS: set[str] = {
    "14061",  # DigitalOcean
    "20473",  # Vultr / The Constant Company
}

# 明确的遥测/广告/非 AI 追踪关键词黑名单 (用于 KEYWORD 类规则防污染，避免误杀短词)
BLOCKED_TELEMETRY_KEYWORDS: tuple[str, ...] = (
    "datadog",
    "appsflyer",
    "google-analytics",
    "googletagmanager",
    "doubleclick",
    "statsig",
    "launchdarkly",
    "bytedapm",
    "byteoversea",
    "itobsnssdk",
    "pipopay",
    "observeit",
    "intercomcdn",
    "segmentify",
    "usefathom",
    "sendgrid",
)

# 明确的公共 NTP / 授时服务权威域名后缀
NTP_OFFICIAL_SUFFIXES: tuple[str, ...] = (
    ".nist.gov",
    ".colorado.edu",
    ".qcomgeo2.com",
    ".miz.nao.ac.jp",
    ".ntp-servers.net",
    ".ring.gr.jp",
    ".time.nl",
    ".e-timing.ne.jp",
)

AI_KEYWORDS: tuple[str, ...] = (
    "openai",
    "copilot",
    "claude",
    "gemini",
    "appleintelligence",
    "chatgpt",
    "perplexity",
    "grok",
    "sora",
    "deepseek",
    "anthropic",
)


def is_time_or_ntp(domain: str) -> bool:
    """
    Check if domain is a time/NTP server.
    Prevents false positives on commercial domains/media/AI services (e.g. time.com, nytimes.com, anytime.ai, timetravel.ai).
    """
    domain_clean = domain.strip().lower().rstrip(".")
    if domain_clean.endswith(NTP_OFFICIAL_SUFFIXES):
        return True
    labels = domain_clean.split(".")
    if len(labels) >= 2:
        # 如果非顶级后缀部分包含 'ntp'，判定为 NTP 服务器 (如 ntp1.aliyun.com, pool.ntp.org, ntp.org)
        if any("ntp" in lbl for lbl in labels[:-1]):
            return True
        # 针对三级及以上的主机名前缀匹配时间服务标识 (如 time.google.com, time1.apple.com, time-a.nist.gov)
        if len(labels) > 2:
            host_label = labels[0]
            if re.fullmatch(r"(?:^time[0-9]*$|^time-[0-9a-z\-]+$|^timeserver[0-9a-z\-]*$)", host_label):
                return True
    return False


def is_valid_domain_or_suffix(kind: str, value: str) -> bool:
    """
    Validate domain and domain-suffix rules across QX, Clash/Mihomo, Surge, and Sing-box spellings.
    If a domain or domain-suffix rule has no dot (single label like 'ms', 'azure'),
    it is rejected unless explicitly whitelisted in ALLOWED_SINGLE_LABELS.
    """
    kind_lower = kind.lower().strip()
    if kind_lower in {"domain-suffix", "host-suffix", "domain_suffix", "domain", "host"}:
        val = value.strip().lstrip(".").rstrip(".").lower()
        if "." not in val:
            return val in ALLOWED_SINGLE_LABELS
    return True


# 兼容原函数名
is_valid_single_label_suffix = is_valid_domain_or_suffix


def is_blocked_ai_rule(kind: str, value: str) -> str | None:
    """
    Check if a rule is blocked from AI rulesets.
    Supports rule type spellings across:
    - QX: host, host-suffix, host-keyword, host-wildcard, host-regex, ip-asn, user-agent
    - Clash/Mihomo/Surge: domain, domain-suffix, domain-keyword, domain-wildcard, domain-regex, ip-asn, user-agent
    - Sing-box: domain, domain_suffix, domain_keyword, domain_regex
    Returns reason string if blocked, None if allowed.
    """
    kind_lower = kind.lower().strip()
    val = value.strip().rstrip(".").lower()

    # 1. Block unwanted non-AI Apple media user agents
    if kind_lower in {"user-agent"}:
        if any(val.startswith(p) for p in ("applenews", "appletv", "com.apple.news", "com.apple.tv")):
            return "blocked-apple-media-ua"
        return None

    # 2. Block broad VPS datacenter ASNs (DigitalOcean, Vultr)
    if kind_lower in {"ip-asn", "asn"}:
        asn_clean = val.removeprefix("as")
        if asn_clean in BLOCKED_VPS_ASNS:
            return "blocked-vps-asn"
        return None

    # 3. Block telemetry wildcards, regexes & keywords across all client dialects
    if kind_lower in {
        "host-keyword", "domain-keyword", "domain_keyword",
        "host-wildcard", "domain-wildcard",
        "host-regex", "domain-regex", "domain_regex",
    }:
        if any(kw in val for kw in BLOCKED_TELEMETRY_KEYWORDS) or val == "sift":
            return "blocked-telemetry-keyword"
        if "ntp" in val or val.startswith(("time*", "time-", "timeserver")):
            return "time-or-ntp"
        if kind_lower in {"host-keyword", "domain-keyword", "domain_keyword"}:
            if val in BLOCKED_EXACT_DOMAINS or any(val == s or val.endswith("." + s) for s in BLOCKED_DOMAIN_SUFFIXES):
                return "blocked-suffix"
            return None

    # 4. Check domain & domain-suffix & wildcards (and regexes that contain exact blocked domains/suffixes)
    if kind_lower not in {
        "host", "host-suffix", "domain", "domain-suffix", "domain_suffix",
        "host-wildcard", "domain-wildcard",
    }:
        return None

    if val in BLOCKED_EXACT_DOMAINS:
        return "exact-domain"

    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if val == suffix or val.endswith("." + suffix):
            return "blocked-suffix"

    if is_time_or_ntp(val):
        return "time-or-ntp"

    return None


def is_ai_ruleset(name: str) -> bool:
    """Determine if a ruleset name is AI-related with fuzzy / prefix / suffix support."""
    n = name.lower().replace("-", "_").replace(".", "_")
    if n == "ai" or n.startswith("ai_") or n.endswith("_ai") or "_ai_" in n:
        return True
    return any(k in n for k in AI_KEYWORDS)
