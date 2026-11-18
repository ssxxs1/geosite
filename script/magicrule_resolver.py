#!/usr/bin/env python3
"""
magicrule_resolver.py - blackmatrix7 MagicRule (Cloudflare Pages) 动态哈希源解析器

特性:
1. 按需精准查询：仅加载一次轻量客户端索引 (~100KB)，仅对目标规则按需发起 manifest 解析，绝不拉取全量 1000+ 规则；
2. 动态哈希自动捕获：秒级提取 https://magicrule.pages.dev/data/_shared/artifacts/{Rule}_rules_{hash}.list 最新直链；
3. 优雅双轨降级：当 Cloudflare Pages 波动或未收录时，自动回退到 GitHub Raw 仓库 (blackmatrix7/ios_rule_script)。
"""
from __future__ import annotations

import sys
from typing import Any
from urllib.parse import urlparse

import requests

INDEX_URL = "https://magicrule.pages.dev/data/index/QuantumultX.json"
# 显式白名单，防止误引入非官方 pages.dev 镜像
ALLOWED_MAGICRULE_HOSTS: frozenset[str] = frozenset({
    "magicrule.pages.dev",
    "rule-26r.pages.dev",
})
GITHUB_RAW_TEMPLATE = (
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/{name}/{name}.list"
)


def is_safe_magicrule_url(url: str) -> bool:
    """红队防御：严格校验 URL 协议与受信域名，杜绝 SSRF 与协议走私"""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        netloc = parsed.netloc.lower()
        return parsed.scheme == "https" and netloc in ALLOWED_MAGICRULE_HOSTS
    except Exception:
        return False


class MagicRuleResolver:
    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; GeositeSync/2.0; +https://github.com/ssxxs1/geosite)"
        })
        self._index: dict[str, dict[str, Any]] | None = None
        self._artifact_cache: dict[str, str] = {}

    def load_index(self) -> dict[str, dict[str, Any]]:
        if self._index is not None:
            return self._index
        try:
            resp = self.session.get(INDEX_URL, timeout=(6, 15))
            if resp.status_code == 200:
                data = resp.json()
                self._index = {
                    item["name"].lower(): item
                    for item in data.get("rules", [])
                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                }
            else:
                self._index = {}
        except Exception as exc:
            print(f"[MagicRule·提示] 加载索引失败 ({exc})，将直接使用 GitHub Raw 兜底", file=sys.stderr)
            self._index = {}
        return self._index

    def get_artifact_url(self, rule_name: str) -> str | None:
        name_key = rule_name.strip().lower()
        if name_key in self._artifact_cache:
            return self._artifact_cache[name_key]

        index = self.load_index()
        item = index.get(name_key)
        if not item or not item.get("manifest"):
            return None

        manifest_url = item["manifest"]
        if not is_safe_magicrule_url(manifest_url):
            print(f"[MagicRule·防御] 拦截非白名单 manifest URL: {manifest_url}", file=sys.stderr)
            return None

        try:
            resp = self.session.get(manifest_url, timeout=(6, 12))
            if resp.status_code == 200:
                data = resp.json()
                for art in data.get("artifacts", []):
                    if art.get("ext") == "list" and art.get("url"):
                        resolved_url = art["url"]
                        if not is_safe_magicrule_url(resolved_url):
                            print(f"[MagicRule·防御] 拦截非白名单 artifact 直链: {resolved_url}", file=sys.stderr)
                            continue
                        self._artifact_cache[name_key] = resolved_url
                        return resolved_url
        except Exception as exc:
            print(f"[MagicRule·告警] 拉取 {rule_name} manifest 失败: {exc}", file=sys.stderr)

        return None

    def get_fallback_raw_url(self, rule_name: str) -> str:
        clean_name = rule_name.strip()
        return GITHUB_RAW_TEMPLATE.format(name=clean_name)

    def fetch_supplementary_rules(self, rule_name: str) -> str | None:
        """
        双轨拉取目标规则内容：
        1. 优先尝试 MagicRule 动态哈希直链
        2. 失败则回退 GitHub Raw 直链
        """
        artifact_url = self.get_artifact_url(rule_name)
        if artifact_url:
            try:
                resp = self.session.get(artifact_url, timeout=(8, 25))
                if resp.status_code == 200 and resp.text:
                    return resp.text
            except Exception as exc:
                print(f"[MagicRule·降级] 动态哈希直链拉取失败 ({artifact_url}): {exc}，回退 Raw", file=sys.stderr)

        raw_url = self.get_fallback_raw_url(rule_name)
        try:
            resp = self.session.get(raw_url, timeout=(8, 25))
            if resp.status_code == 200 and resp.text:
                return resp.text
        except Exception as exc:
            print(f"[MagicRule·告警] GitHub Raw 兜底亦失败 ({raw_url}): {exc}", file=sys.stderr)

        return None
