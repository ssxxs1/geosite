from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


OUTPUT_PATH = Path("Private/AI.list")
MINIMUM_RULES = 100
MAX_SHRINK_RATIO = 0.35


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    format: str = "plain"
    provider: str | None = None
    required: bool = False
    authoritative: bool = False


@dataclass
class Rule:
    kind: str
    value: str
    options: tuple[str, ...] = ()
    sources: set[str] = field(default_factory=set)
    providers: set[str] = field(default_factory=set)
    authoritative: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return self.kind, self.value


SOURCES = [
    Source(
        "bm7-openai",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.list",
        provider="openai",
        required=True,
        authoritative=True,
    ),
    Source(
        "bm7-gemini",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Gemini/Gemini.list",
        provider="gemini",
        required=True,
        authoritative=True,
    ),
    Source(
        "bm7-claude",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.list",
        provider="claude",
        required=True,
        authoritative=True,
    ),
    Source(
        "bm7-copilot",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Copilot/Copilot.list",
        provider="copilot",
        required=True,
        authoritative=True,
    ),
    Source(
        "RocM301",
        "https://raw.githubusercontent.com/RocM301/Apple-Rule/refs/heads/main/Apple-AI.list",
    ),
    Source(
        "ddgksf2013-apple-intelligence",
        "https://raw.githubusercontent.com/ddgksf2013/Filter/refs/heads/master/AppleIntelligence.list",
    ),
    Source(
        "shangrenxi",
        "https://raw.githubusercontent.com/shangrenxi/Rules/refs/heads/master/rules/AI.list",
    ),
    Source(
        "dler-ai-suite",
        "https://raw.githubusercontent.com/dler-io/Rules/main/Surge/Surge%203/Provider/AI%20Suite.list",
    ),
    Source(
        "sukkaw-ai",
        "https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/ai.conf",
    ),
    Source(
        "rulego-ai",
        "https://raw.githubusercontent.com/ConnersHua/RuleGo/master/Surge/Ruleset/Extra/AI.list",
    ),
    # Kelee8's former raw GitHub URL returns 404 and kelee.one blocks CI-style clients.
    # Keep it disabled until a stable, directly downloadable URL is available.
    Source(
        "accademia-gemini",
        "https://raw.githubusercontent.com/Accademia/Additional_Rule_For_Clash/main/Gemini/Gemini_No_Resolve.yaml",
        format="yaml-payload",
    ),
]

SUPPLEMENTAL_AI_DOMAINS = [
    # Top AI Chat, Search & LLM APIs
    "phind.com",
    "cohere.com",
    "fireworks.ai",
    "replicate.com",
    "replicate.delivery",
    "gamma.app",
    # Coding & Fullstack Agentic Builders
    "bolt.new",
    "lovable.dev",
    # Generative Video & Audio
    "lumalabs.ai",
    "pika.art",
    "heygen.com",
    "udio.com",
    "klingai.com",
    "hailuoai.com",
    "haiper.ai",
    "runway.com",
    # Generative Image & Models
    "ideogram.ai",
    "krea.ai",
    "blackforestlabs.ai",
    "civitai.com",
]

PROVIDER_ANCHORS = {
    "openai": {"openai.com", "chatgpt.com"},
    "gemini": {"gemini.google.com"},
    "claude": {"anthropic.com", "claude.ai"},
    "copilot": {"copilot.microsoft.com"},
}

TYPE_ALIASES = {
    "domain": "host",
    "host": "host",
    "domain-suffix": "host-suffix",
    "host-suffix": "host-suffix",
    "domain-keyword": "host-keyword",
    "host-keyword": "host-keyword",
    "domain-wildcard": "host-wildcard",
    "host-wildcard": "host-wildcard",
    "url-regex": "url-regex",
    "domain-regex": "host-regex",
    "host-regex": "host-regex",
    "ip-cidr": "ip-cidr",
    "ip-cidr6": "ip6-cidr",
    "ip6-cidr": "ip6-cidr",
    "ip-asn": "ip-asn",
    "geoip": "geoip",
    "user-agent": "user-agent",
}

DOMAIN_KINDS = {
    "host",
    "host-suffix",
    "host-keyword",
    "host-wildcard",
    "host-regex",
}

TYPE_ORDER = {
    "host": 0,
    "host-suffix": 1,
    "host-keyword": 2,
    "host-wildcard": 3,
    "host-regex": 4,
    "url-regex": 5,
    "ip-cidr": 6,
    "ip6-cidr": 7,
    "ip-asn": 8,
    "geoip": 9,
    "user-agent": 10,
}

HEADER_TYPE_NAMES = {
    "host": "HOST",
    "host-suffix": "HOST-SUFFIX",
    "host-keyword": "HOST-KEYWORD",
    "host-wildcard": "HOST-WILDCARD",
    "host-regex": "HOST-REGEX",
    "url-regex": "URL-REGEX",
    "ip-cidr": "IP-CIDR",
    "ip6-cidr": "IP6-CIDR",
    "ip-asn": "IP-ASN",
    "geoip": "GEOIP",
    "user-agent": "USER-AGENT",
}

UPDATED_PATTERN = re.compile(r"^# UPDATED: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$")

BLOCKED_EXACT_DOMAINS = {
    # 1. 通用分析与遥测 (Analytics & Telemetry) - 避免将全网统计上报归入 AI 策略组
    "www.google-analytics.com",  # Google 网站流量统计服务
    "static.cloudflareinsights.com",  # Cloudflare Web Analytics 性能探针脚本
    "digicert.com",  # DigiCert CA 根证书吊销状态/OCSP 验证
    "identrust.com",  # IdenTrust CA 根证书验证服务
    # 2. 开发者通用接口 (General Dev CLI) - 防止 git 命令被 AI 策略接管
    "api.github.com",  # GitHub 基础 REST API (保留 copilot 子域名)
    # 3. 谷歌通用静态资源与地图 (Google Static CDN & Maps) - 避免全网静态资源与地图走 AI
    "fonts.googleapis.com",  # Google Web 字体 CSS
    "fonts.gstatic.com",  # Google Web 字体静态分发
    "maps.googleapis.com",  # Google 地图 API
    "maps.gstatic.com",  # Google 地图静态瓦片与资源
    "streetviewpixels-pa.googleapis.com",  # 谷歌街景全景瓦片
    "i.ytimg.com",  # YouTube 视频缩略图与静态封面
    "yt3.ggpht.com",  # YouTube 频道头像与通用静态图
    "ipv4.google.com",  # Google IPv4 连通性测试端点
    "h3.google.com",  # Google HTTP/3 实验测试端点
    "developerprofiles.google.com",  # 谷歌开发者个人资料展示
    "www.gstatic.com",  # Google 全球通用静态资源宿主 (Chrome/Android 基础资产)
    "ssl.gstatic.com",  # Google 全球 SSL 静态资源分发
    "apis.google.com",  # Google 基础通用 API 入口 (网页授权/JS API)
    # 4. 网络授时与时间同步 (NTP / Time Sync) - 保持本地时间基准
    "clock.isc.org",  # ISC 公共 NTP 授时服务
    "ats1.e-timing.ne.jp",  # 日本精准时间戳与授时服务
    # 5. 通用搜索引擎主页与网络探针 (Search & Captive Portal)
    "www.bing.com",  # 必应主站搜索引擎页面 (Copilot 专用为 sydney.bing.com)
    "challenges.cloudflare.com",  # Cloudflare Turnstile 全球人机验证验证码
    "cp2.cloudflare.com",  # Cloudflare 网络准入/强制门户检测 (Captive Portal)
    "cp4.cloudflare.com",  # Cloudflare 网络准入/强制门户检测 (Captive Portal)
}

BLOCKED_DOMAIN_SUFFIXES = {
    # 1. 移动广告归因、埋点与 APM 监控 (Ads, Tracking & Telemetry)
    "appsflyer.com",  # AppsFlyer 移动广告归因与转化率分析
    "appsflyersdk.com",  # AppsFlyer 移动端 SDK 数据上报
    "browser-intake-datadoghq.com",  # DataDog 前端 RUM 性能监控采集
    "cdn.usefathom.com",  # Fathom Analytics 无 Cookie 隐私统计 CDN
    "datadoghq.com",  # DataDog APM 性能与应用日志监控
    "doubleclick.net",  # Google 广告展示与重定向网络
    "google-analytics.com",  # Google Analytics 网站用户行为分析
    "googletagmanager.com",  # Google Tag Manager 动态标签管理器
    "intercom.io",  # Intercom 在线客服系统与用户行为追踪
    "intercomcdn.com",  # Intercom 静态资产与组件 CDN
    "sentry.io",  # Sentry 全端异常崩溃与错误日志采集
    "segment.io",  # Segment 用户行为全渠道数据管道
    "segment.com",  # Segment 客户数据平台 (CDP)
    "segmentify.com",  # Segmentify 电商推荐与转化追踪
    "stripe.com",  # Stripe 国际在线支付核心结算网关
    "stripecdn.com",  # Stripe 结账收银台静态资源
    "stripe.network",  # Stripe 欺诈检测与支付风险控制网络
    "statsig.com",  # Statsig 功能灰度发布与 A/B 测试 (非 AI 核心推理)
    "statsigapi.net",  # Statsig API 遥测数据上报端点
    "launchdarkly.com",  # LaunchDarkly 功能开关与动态配置控制
    "observeit.net",  # ObserveIT 用户操作审计与会话记录
    "honeycomb.io",  # Honeycomb 现代可观测性分布式链路追踪
    "ct.sendgrid.net",  # SendGrid 营销邮件点击追踪与链接重定向
    "algolia.net",  # Algolia 站内全文检索 SaaS (非大模型文本生成)
    "auth0.com",  # Auth0 通用身份认证、单点登录 SSO 与 OAuth (通用基础设施)

    # 2. 字节跳动与 TikTok 支付与监控 (ByteDance Tracking & Payments)
    "pipopay.com",  # Pipo 跨境电商支付结算网关
    "bytedapm.com",  # 字节跳动海外 APM 应用性能与稳定性监控
    "byteintlapi.com",  # 字节跳动海外多业务基础通用 API
    "byteoversea.com",  # 字节跳动海外通用业务接口与配置服务
    "itobsnssdk.com",  # 字节跳动移动端日志与安全追踪服务
    "ttwstatic.com",  # TikTok 基础静态资源与前端加速 CDN

    # 3. 常见非 AI 网页排版与通用 Web 工具平台 (General Web Apps & Hostings)
    "canva.com",  # Canva 可画在线图形设计平台
    "canva.dev",  # Canva 开放平台开发者门户
    "canva.site",  # Canva 静态网站与展示页托管
    "asana.com",  # Asana 团队任务与项目协同管理
    "asana.biz",  # Asana 企业级协作管理入口
    "buffer.com",  # Buffer 社交媒体定时内容发布与管理
    "bufferapp.com",  # Buffer 移动与网页端主站
    "zapier.com",  # Zapier 多应用自动化工作流串联工具
    "wp.com",  # Automattic / WordPress.com 博客与 CMS 平台
    "playwright.azureedge.net",  # Playwright 自动化测试浏览器驱动下载镜像
    "open-vsx.org",  # Eclipse Open VSX 开源代码编辑器插件市场
    "zed.dev",  # Zed 高性能代码编辑器主站与扩展同步
    "vercel.com",  # Vercel Serverless 云托管平台控制台
    "vercel.sh",  # Vercel 自动化部署静态预览与子域
    "wondershare.com",  # 万兴科技多媒体工具与创意软件官网
    "zeetings.com",  # Zeetings 远程互动演示文稿服务
    "slidesgo.com",  # Slidesgo 免费幻灯片与演示模板库
    "smartmockups.com",  # Smartmockups 线上产品样机生成器
    "enhancv.com",  # Enhancv 简历设计与职业履历制作平台
    "kickresume.com",  # Kickresume 简历与求职信制作工具
    "microsoftonline.com",  # 微软 Entra ID / Office 365 组织通用登录与凭据中心
    "bingapis.com",  # 必应通用认知服务与搜索爬虫数据接口

    # 4. 苹果非 AI 媒体、应用商店与系统 OTA 固件更新 (Apple Media, AppStore & System Updates)
    "itunes.apple.com",  # iTunes Store / App Store 元数据与购买接口
    "apple.news",  # Apple News 原创资讯服务短链接
    "tv.apple.com",  # Apple TV+ 视频流媒体点播平台
    "applemusic.com",  # Apple Music 音乐流媒体服务
    "developer.apple.com",  # 苹果开发者官网门户与官方技术文档
    "devimages-cdn.apple.com",  # 苹果开发者 SDK 文档图片与素材 CDN
    "devstreaming-cdn.apple.com",  # WWDC 开发者大会技术视频与流媒体分发 CDN
    "docs-assets.developer.apple.com",  # 苹果开发者官方 API 参考手册静态资源库
    "testflight.apple.com",  # TestFlight 移动端 App 灰度内测分发平台
    "apple.comscoreresearch.com",  # Comscore 针对 Apple 媒体服务的市场收视率调研
    "blobstore.apple.com",  # Apple 内部大型二进制对象存储网关
    "cdn.apple-cloudkit.com",  # CloudKit 通用云端数据库与存储静态加速
    "cvws.icloud-content.com",  # iCloud 照片图库与大吞吐量同步内容服务器
    "appsto.re",  # App Store 应用分享与下载官方短链接
    "apps.apple.com",  # App Store 网页版全球应用详情与展示页
    # "mzstatic.com",  # App Store 核心分发 CDN (全量应用包与游戏资源下载，天量带宽)
    "updates.cdn-apple.com",  # Apple iOS/iPadOS/macOS 系统 OTA 完整固件升级包下载 CDN (天量带宽)
    "updates-http.cdn-apple.com",  # Apple 系统 OTA 固件 HTTP 明文回退分发节点
    "gdmf.apple.com",  # Apple 全球下载管理服务 (Global Download Management Facility 固件版本校验)
    "appldnld.apple.com",  # 早期 iOS 及特定系统组件固件下载源
    "swcdn.apple.com",  # macOS 软件更新核心分发 CDN (Software Update CDN)
    "gg.apple.com",  # Apple 设备激活与固件签名握手通信端点
}


class GenerationError(RuntimeError):
    pass


def build_session(verify_tls: bool = True) -> requests.Session:
    session = requests.Session()
    session.verify = verify_tls
    retries = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers["User-Agent"] = "geosite-ai-rule-generator/2.0"
    return session


def normalize_kind(raw_kind: str) -> str | None:
    return TYPE_ALIASES.get(raw_kind.strip().lower())


def normalize_value(kind: str, raw_value: str) -> str:
    value = raw_value.strip().strip("'\"")
    if not value:
        raise ValueError("empty value")

    if kind in {"host", "host-suffix"}:
        while value.startswith("+."):
            value = value[2:]
        value = value.lstrip(".").rstrip(".").lower()
        if not value or "/" in value or "://" in value or any(ch.isspace() for ch in value):
            raise ValueError("invalid domain")
        return value

    if kind in {"host-keyword"}:
        return value.lower()

    if kind in {"host-wildcard", "host-regex", "url-regex", "user-agent"}:
        return value

    if kind in {"ip-cidr", "ip6-cidr"}:
        network = ipaddress.ip_network(value, strict=False)
        if kind == "ip-cidr" and network.version != 4:
            kind_name = "IPv4"
            raise ValueError(f"expected {kind_name} network")
        if kind == "ip6-cidr" and network.version != 6:
            kind_name = "IPv6"
            raise ValueError(f"expected {kind_name} network")
        return str(network)

    if kind == "ip-asn":
        normalized = value.upper()
        if normalized.startswith("AS"):
            normalized = normalized[2:]
        if not normalized.isdigit() or int(normalized) <= 0:
            raise ValueError("invalid ASN")
        return normalized

    if kind == "geoip":
        normalized = value.upper()
        if not re.fullmatch(r"[A-Z]{2}", normalized):
            raise ValueError("invalid GEOIP country code")
        return normalized

    raise ValueError(f"unsupported rule kind: {kind}")


def parse_rule_text(text: str, source: Source) -> tuple[Rule | None, str | None]:
    line = text.strip().lstrip("﻿")
    if not line or line.startswith(("#", ";", "//")) or line == "payload:":
        return None, None

    if line.startswith("-"):
        line = line[1:].strip()
    line = line.strip("'\"")
    if not line:
        return None, None

    raw_type, separator, remainder = line.partition(",")
    if not separator:
        fields = [line]
    else:
        normalized_type = normalize_kind(raw_type)
        if normalized_type in {"host-regex", "url-regex", "user-agent"}:
            fields = [raw_type.strip(), remainder.strip().strip("'\"")]
        else:
            fields = [raw_type.strip()] + [
                field.strip().strip("'\"") for field in remainder.split(",")
            ]
    if len(fields) == 1:
        value = fields[0]
        try:
            network = ipaddress.ip_network(value, strict=False)
            raw_kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        except ValueError:
            raw_kind = "DOMAIN-SUFFIX" if value.startswith(("+.", ".")) else "DOMAIN"
        fields = [raw_kind, value]

    if len(fields) < 2:
        return None, "malformed"

    kind = normalize_kind(fields[0])
    if kind is None:
        return None, f"unsupported:{fields[0].strip().upper()}"

    try:
        value = normalize_value(kind, fields[1])
    except ValueError:
        return None, "invalid"

    options = tuple(option for option in fields[2:] if option)
    providers = {source.provider} if source.provider else set()
    return Rule(
        kind=kind,
        value=value,
        options=options,
        sources={source.name},
        providers=providers,
        authoritative=source.authoritative,
    ), None


def parse_source_text(text: str, source: Source) -> tuple[list[Rule], Counter]:
    stats = Counter(lines=len(text.splitlines()))
    if source.format == "yaml-payload":
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise GenerationError(f"{source.name}: invalid YAML: {exc}") from exc
        if not isinstance(document, dict) or not isinstance(document.get("payload"), list):
            raise GenerationError(f"{source.name}: YAML must contain a list-valued payload")
        entries: Iterable[object] = document["payload"]
    else:
        entries = text.splitlines()

    rules = []
    for entry in entries:
        if not isinstance(entry, str):
            stats["malformed"] += 1
            continue
        rule, reason = parse_rule_text(entry, source)
        if rule:
            rules.append(rule)
            stats[f"type:{rule.kind}"] += 1
            stats["parsed"] += 1
        elif reason:
            stats[reason] += 1
    return rules, stats


def is_time_or_ntp(domain: str) -> bool:
    if domain.endswith((
        ".nist.gov",
        ".colorado.edu",
        ".qcomgeo2.com",
        ".miz.nao.ac.jp",
        ".ntp-servers.net",
        ".ring.gr.jp",
        ".time.nl",
        ".e-timing.ne.jp",
    )):
        return True
    labels = domain.split(".")
    for label in labels:
        if re.fullmatch(r"(?:.*ntp.*|.*time[0-9a-z\-]*|timeserver.*)", label):
            if label not in {"realtime", "runtime", "airtime", "primetime", "uptime"}:
                return True
    return False


def domain_is_blocked(rule: Rule) -> str | None:
    # Block unwanted non-AI Apple media user agents (Apple News, Apple TV)
    if rule.kind == "user-agent":
        val = rule.value.lower()
        if any(val.startswith(p) for p in ("applenews", "appletv", "com.apple.news", "com.apple.tv")):
            return "blocked-apple-media-ua"
        return None

    # Block broad VPS datacenter ASNs (DigitalOcean 14061, Vultr 20473)
    if rule.kind == "ip-asn":
        if rule.value in {"14061", "20473"}:
            return "blocked-vps-asn"
        return None

    # Block telemetry wildcards & keywords
    if rule.kind in {"host-keyword", "host-wildcard"}:
        val = rule.value.lower()
        if "datadog" in val or val == "sift":
            return "blocked-telemetry-keyword"
        return None

    if rule.kind not in {"host", "host-suffix"}:
        return None

    domain = rule.value.lower().rstrip(".")
    if domain in BLOCKED_EXACT_DOMAINS:
        return "exact-domain"
    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            return "blocked-suffix"
    if is_time_or_ntp(domain):
        return "time-or-ntp"
    return None


def add_rule(aggregate: dict[tuple[str, str], Rule], rule: Rule, stats: Counter) -> None:
    if rule.kind in {"host", "host-suffix"}:
        exact_key = ("host", rule.value)
        suffix_key = ("host-suffix", rule.value)
        if rule.kind == "host-suffix" and exact_key in aggregate:
            existing = aggregate.pop(exact_key)
            rule.sources.update(existing.sources)
            rule.providers.update(existing.providers)
            rule.authoritative = rule.authoritative or existing.authoritative
            stats["covered-exact"] += 1
        elif rule.kind == "host" and suffix_key in aggregate:
            existing = aggregate[suffix_key]
            existing.sources.update(rule.sources)
            existing.providers.update(rule.providers)
            existing.authoritative = existing.authoritative or rule.authoritative
            stats["covered-exact"] += 1
            return

    existing = aggregate.get(rule.key)
    if existing:
        existing.sources.update(rule.sources)
        existing.providers.update(rule.providers)
        existing.authoritative = existing.authoritative or rule.authoritative
        stats["duplicates"] += 1
        return
    aggregate[rule.key] = rule
    stats["unique"] += 1


def render_qx_body(rules: Iterable[Rule]) -> str:
    ordered = sorted(rules, key=lambda rule: (TYPE_ORDER.get(rule.kind, 99), rule.value))
    lines = []
    for rule in ordered:
        kind_upper = HEADER_TYPE_NAMES.get(rule.kind, rule.kind.upper())
        line = f"{kind_upper},{rule.value}"
        if rule.options:
            line += "," + ",".join(rule.options)
        lines.append(line + "\n")
    return "".join(lines)


def render_qx(rules: Iterable[Rule], updated_at: str) -> str:
    rules = list(rules)
    type_counts = Counter(rule.kind for rule in rules)
    lines = [
        "# NAME: AI\n",
        "# AUTHOR: ssxxs1\n",
        "# REPO: https://github.com/ssxxs1/geosite\n",
        f"# UPDATED: {updated_at}\n",
    ]
    for kind in sorted(type_counts, key=lambda item: TYPE_ORDER.get(item, 99)):
        lines.append(f"# {HEADER_TYPE_NAMES[kind]}: {type_counts[kind]}\n")
    lines.extend((f"# TOTAL: {len(rules)}\n", "\n", render_qx_body(rules)))
    return "".join(lines)


def extract_rule_body(content: str) -> str:
    return "".join(
        line.strip() + "\n"
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def extract_updated_at(content: str) -> str | None:
    for line in content.splitlines():
        match = UPDATED_PATTERN.fullmatch(line.strip())
        if match:
            return match.group(1)
    return None


def resolve_updated_at(path: Path, candidate_body: str, now: datetime | None = None) -> str:
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        existing_updated_at = extract_updated_at(existing)
        if existing_updated_at and extract_rule_body(existing) == candidate_body:
            return existing_updated_at

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def read_existing_rule_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def validate_candidate(rules: list[Rule], previous_count: int, allow_large_shrink: bool) -> None:
    if len(rules) < MINIMUM_RULES:
        raise GenerationError(f"candidate has only {len(rules)} rules; minimum is {MINIMUM_RULES}")

    domains_by_provider = defaultdict(set)
    for rule in rules:
        if rule.kind not in {"host", "host-suffix"}:
            continue
        for provider in rule.providers:
            domains_by_provider[provider].add(rule.value)

    for provider, anchors in PROVIDER_ANCHORS.items():
        provider_domains = domains_by_provider.get(provider, set())
        if not provider_domains:
            raise GenerationError(f"required provider has no retained rules: {provider}")
        missing = anchors - provider_domains
        if missing:
            raise GenerationError(f"{provider} is missing anchors: {', '.join(sorted(missing))}")

    if previous_count and len(rules) < previous_count * (1 - MAX_SHRINK_RATIO) and not allow_large_shrink:
        raise GenerationError(
            f"candidate shrank from {previous_count} to {len(rules)} rules; "
            "use --allow-large-shrink for an intentional cleanup"
        )


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def generate(
    session: requests.Session,
    output_path: Path = OUTPUT_PATH,
    allow_large_shrink: bool = False,
    now: datetime | None = None,
) -> list[Rule]:
    aggregate: dict[tuple[str, str], Rule] = {}
    aggregate_stats = Counter()
    required_success = set()

    for source in SOURCES:
        try:
            response = session.get(source.url, timeout=(10, 30))
            response.raise_for_status()
            rules, stats = parse_source_text(response.text, source)
            if not rules:
                raise GenerationError("zero valid rules parsed")
            if source.required:
                required_success.add(source.name)
        except Exception as exc:
            print(f"[source] {source.name}: FAILED ({exc})")
            if source.required:
                raise GenerationError(f"required source failed: {source.name}") from exc
            continue

        filtered = Counter()
        for rule in rules:
            reason = domain_is_blocked(rule)
            if reason:
                filtered[reason] += 1
                continue
            add_rule(aggregate, rule, aggregate_stats)

        type_summary = ", ".join(
            f"{key.removeprefix('type:')}={value}"
            for key, value in sorted(stats.items())
            if key.startswith("type:")
        )
        unsupported = sum(value for key, value in stats.items() if key.startswith("unsupported:"))
        print(
            f"[source] {source.name}: parsed={stats['parsed']} malformed={stats['malformed']} "
            f"invalid={stats['invalid']} unsupported={unsupported} filtered={sum(filtered.values())} "
            f"types=[{type_summary}]"
        )

    expected_required = {source.name for source in SOURCES if source.required}
    if required_success != expected_required:
        missing = expected_required - required_success
        raise GenerationError(f"missing required sources: {', '.join(sorted(missing))}")

    supplemental_source = Source("supplemental", "local://supplemental")
    for domain in SUPPLEMENTAL_AI_DOMAINS:
        rule, reason = parse_rule_text(f"DOMAIN-SUFFIX,{domain}", supplemental_source)
        if not rule or reason:
            raise GenerationError(f"invalid supplemental rule: {domain}")
        add_rule(aggregate, rule, aggregate_stats)

    rules = list(aggregate.values())
    validate_candidate(rules, read_existing_rule_count(output_path), allow_large_shrink)
    body = render_qx_body(rules)
    content = render_qx(rules, resolve_updated_at(output_path, body, now))

    reparsed, reparse_stats = parse_source_text(content, Source("candidate", "local://candidate"))
    if len(reparsed) != len(rules) or reparse_stats["invalid"] or reparse_stats["malformed"]:
        raise GenerationError("rendered candidate failed round-trip validation")

    existing_content = output_path.read_text(encoding="utf-8") if output_path.exists() else None
    if existing_content != content:
        atomic_write(output_path, content)
    type_counts = Counter(rule.kind for rule in rules)
    print(f"[result] wrote {output_path} with {len(rules)} rules: {dict(sorted(type_counts.items()))}")
    print(f"[result] aggregation: {dict(sorted(aggregate_stats.items()))}")
    return rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the aggregated Quantumult X AI rule list")
    parser.add_argument(
        "--allow-large-shrink",
        action="store_true",
        help="allow an intentional output reduction larger than the safety threshold",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification for local environments with a broken CA store",
    )
    args = parser.parse_args(argv)

    try:
        generate(
            build_session(verify_tls=not args.insecure),
            allow_large_shrink=args.allow_large_shrink,
        )
    except GenerationError as exc:
        print(f"AI list generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
