"""
diff_radar.py - 规则雷达巡检与证书透明度探针 (Rule Radar & CT Logs Sentinel)

核心功能:
1. 双核探针：
   - 社区源差分：定时对比 MetaCubeX / 社区活跃规则集与本地 Private/*.list 的差分。
   - 证书透明度 (CT Logs)：针对顶级 AI 资产 (Anthropic/OpenAI/xAI等) 查询最新签发证书。
2. 两道漏斗过滤：
   - 第一道：子域覆盖吸收 (Subsumption Check) - 凡已被现有 DOMAIN-SUFFIX 覆盖的子域直接在第一步排除，0 噪音。
   - 第二道：安全校验 (rule_filter) - 自动剔除遥测埋点、数据分析、NTP 授时及非法单标签。
3. 智能泛化提示：
   - 识别全新主域并智能推荐以 HOST-SUFFIX 形式纳管。
4. 输出支持：
   - 终端高亮展示、Markdown 报告输出（供 PR 与 Step Summary）、可选一键合并 (--apply)。
"""
from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import yaml

try:
    from script.rule_filter import (
        is_blocked_ai_rule,
        is_valid_domain_or_suffix,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from script.rule_filter import (
        is_blocked_ai_rule,
        is_valid_domain_or_suffix,
    )


RFC_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def is_clean_rfc_domain(domain: str) -> bool:
    """校验 RFC 域名格式，拦截控制字符（CRLF 注入）及纯 IP 地址。"""
    if not domain or len(domain) > 253:
        return False
    if any(c in domain for c in ("\r", "\n", "\t", "\0", "\b", "\f")):
        return False
    d = domain.strip().lower().rstrip(".")
    if not RFC_DOMAIN_REGEX.fullmatch(d):
        return False
    try:
        ipaddress.ip_address(d)
        return False
    except ValueError:
        pass
    return True


RADAR_TARGETS: dict[str, dict[str, Any]] = {
    "OpenAI": {
        "local": "Private/OpenAI.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml",
        ],
        "ct_roots": ["openai.com", "chatgpt.com", "sora.com", "oaistatic.com", "oaiusercontent.com"],
        "category": "ai",
    },
    "Claude": {
        "local": "Private/Claude.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/anthropic.yaml",
        ],
        "ct_roots": ["claude.ai", "anthropic.com"],
        "category": "ai",
    },
    "Gemini": {
        "local": "Private/Gemini.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-gemini.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-deepmind.yaml",
        ],
        "ct_roots": ["gemini.google.com", "deepmind.google"],
        "category": "ai",
    },
    "Copilot": {
        "local": "Private/Copilot.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github-copilot.yaml",
        ],
        "ct_roots": ["copilot.microsoft.com", "githubcopilot.com"],
        "category": "ai",
    },
    "AppleProxy": {
        "local": "Private/AppleProxy.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple-relay.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple-pki.yaml",
        ],
        "ct_roots": [],
        "category": "apple",
    },
    "ChinaMedia": {
        "local": "Private/ChinaMedia.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/bilibili.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/iqiyi.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tencentvideo.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youku.yaml",
        ],
        "ct_roots": [],
        "category": "media",
    },
    "GameDownload": {
        "local": "Private/GameDownload.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/epicgames.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ea.yaml",
        ],
        "ct_roots": [],
        "category": "game",
    },
    "IPTVMainland": {
        "local": "Private/IPTVMainland.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cctv.yaml",
        ],
        "ct_roots": [],
        "category": "media",
    },
    "AI": {
        "local": "Private/AI.list",
        "community_sources": [
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/deepseek.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/xai.yaml",
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/perplexity.yaml",
        ],
        "ct_roots": ["x.ai", "grok.com", "deepseek.com", "perplexity.ai", "mistral.ai", "cursor.com"],
        "category": "ai",
        "auto_apply": False,
    },
}


@dataclass
class LocalRuleSet:
    target_name: str
    file_path: Path
    exact_domains: set[str] = field(default_factory=set)
    suffix_domains: set[str] = field(default_factory=set)
    wildcards: set[str] = field(default_factory=set)
    raw_lines: list[str] = field(default_factory=list)


@dataclass
class NewCandidate:
    domain: str
    target_name: str
    source_type: str  # "Community" 或 "CT-Logs"
    source_name: str
    suggested_rule: str
    is_root_promotion: bool = False


def parse_local_list(path: Path, target_name: str) -> LocalRuleSet:
    """读取本地 Private/*.list 并解析出已有后缀与精确主机名集合"""
    rule_set = LocalRuleSet(target_name=target_name, file_path=path)
    if not path.exists():
        return rule_set

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        rule_set.raw_lines = f.readlines()

    for line in rule_set.raw_lines:
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2:
            kind = parts[0].upper()
            val = parts[1].strip().lower().rstrip(".")
            if kind in {"HOST-SUFFIX", "DOMAIN-SUFFIX"}:
                rule_set.suffix_domains.add(val.removeprefix("+.").lstrip("."))
            elif kind in {"HOST", "DOMAIN"}:
                rule_set.exact_domains.add(val)
            elif kind in {"HOST-WILDCARD", "DOMAIN-WILDCARD"}:
                rule_set.wildcards.add(val)
        elif len(parts) == 1:
            val = parts[0].strip().lower().rstrip(".")
            if val.startswith(("+.", ".")):
                rule_set.suffix_domains.add(val.removeprefix("+.").lstrip("."))
            else:
                rule_set.exact_domains.add(val)

    return rule_set


def is_subsumed(
    domain: str,
    suffix_set: set[str],
    exact_set: set[str],
    wildcard_set: set[str] | None = None,
) -> bool:
    """
    第一道漏斗：子域覆盖吸收检测。
    如果候选域名已在精确表、以现有任何后缀结尾，或匹配现有通配符，直接判定为 True（静默丢弃）。
    例: 'downloads.claude.com' 会被已存在的 'claude.com' 吸收，返回 True。
    """
    d = domain.lower().strip().rstrip(".")
    if d in exact_set or d in suffix_set:
        return True

    labels = d.split(".")
    for i in range(1, len(labels)):
        sub_suffix = ".".join(labels[i:])
        if sub_suffix in suffix_set:
            return True

    if wildcard_set:
        for wc in wildcard_set:
            wc_pattern = wc.lower().strip()
            if fnmatch.fnmatchcase(d, wc_pattern):
                return True

    return False


COMMON_SECOND_LEVEL_TLDS: set[str] = {
    "com", "net", "org", "gov", "edu", "co", "ac", "mil", "biz", "info"
}


def extract_registrable_root(domain: str) -> str:
    """提取二段式主域（处理常见 .com / .ai / .org / .net / .com.cn 等）"""
    clean = domain.lower().strip().rstrip(".")
    labels = clean.split(".")
    if len(labels) <= 2:
        return clean
    if len(labels) >= 3 and labels[-2] in COMMON_SECOND_LEVEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def fetch_community_domains(url: str, session: requests.Session) -> set[str]:
    """从 MetaCubeX YAML / List 中拉取并提取候选域名"""
    domains = set()
    try:
        resp = session.get(url, timeout=12)
        if resp.status_code != 200:
            return domains

        text = resp.text
        if text.strip().startswith(("payload:", "-")):
            try:
                data = yaml.safe_load(text)
                if isinstance(data, dict) and "payload" in data:
                    entries = data["payload"]
                elif isinstance(data, list):
                    entries = data
                else:
                    entries = text.splitlines()
            except Exception:
                entries = text.splitlines()
        else:
            entries = text.splitlines()

        for entry in entries:
            if not isinstance(entry, str):
                continue
            line = entry.strip().lstrip("-").strip().strip("'\"")
            if not line or line.startswith(("#", ";", "//")):
                continue
            parts = [p.strip() for p in line.split(",")]
            val = parts[1] if len(parts) >= 2 else parts[0]
            val = val.removeprefix("+.").lstrip(".").rstrip(".").lower()
            if is_clean_rfc_domain(val):
                domains.add(val)
    except Exception as exc:
        print(f"[雷达·告警] 拉取社区源失败 ({url}): {exc}", file=sys.stderr)

    return domains


def fetch_ct_logs_domains(root_domain: str, session: requests.Session) -> set[str]:
    """
    查询公开 SSL 证书透明度日志 (优先 CertSpotter，备用 crt.sh)，
    仅保留属于 root_domain 本身或其子域名，剔除 multi-SAN 共享证书中的无关第三方域名。
    """
    domains = set()
    clean_root = root_domain.lower().strip().rstrip(".")
    if not is_clean_rfc_domain(clean_root):
        return domains

    certspotter_url = (
        f"https://api.certspotter.com/v1/issuances?domain={clean_root}&include_subdomains=true&expand=dns_names"
    )
    try:
        resp = session.get(certspotter_url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            for item in data:
                for dns_name in item.get("dns_names", []):
                    raw_name = dns_name.lower().strip()
                    d = re.sub(r"^(?:\*\.)+", "", raw_name).rstrip(".")
                    if (d == clean_root or d.endswith("." + clean_root)) and is_clean_rfc_domain(d):
                        domains.add(d)
            if domains:
                return domains
        elif resp.status_code == 429:
            print(f"[雷达·限流] CertSpotter API 触发 429 速率限制，自动转入备用探针...", file=sys.stderr)
    except Exception as exc:
        print(f"[雷达·提示] CertSpotter 查询 {clean_root} 异常 ({exc})，转入备用探针", file=sys.stderr)

    crtsh_url = f"https://crt.sh/?q=%.{clean_root}&output=json"
    try:
        resp = session.get(crtsh_url, timeout=10)
        if resp.status_code == 200 and resp.text.startswith(("[", "{")):
            data = resp.json()
            for item in data:
                name_val = item.get("name_value", "")
                for sub in name_val.splitlines():
                    raw_name = sub.lower().strip()
                    d = re.sub(r"^(?:\*\.)+", "", raw_name).rstrip(".")
                    if (d == clean_root or d.endswith("." + clean_root)) and is_clean_rfc_domain(d):
                        domains.add(d)
    except Exception as exc:
        print(f"[雷达·提示] crt.sh 查询 {clean_root} 异常 ({exc})", file=sys.stderr)

    return domains


def run_radar_scan(
    targets: dict[str, dict[str, Any]] = RADAR_TARGETS,
    project_root: Path = Path("."),
    verbose: bool = True,
) -> dict[str, list[NewCandidate]]:
    """
    运行全量雷达扫描：
    1. 解析本地
    2. 探测社区源 + CT Logs
    3. 运行两道漏斗（覆盖吸收 + 安全清洗）
    4. 产出有效新增候选清单
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; GeositeRadar/2.0; +https://github.com/ssxxs1/geosite)"
    })

    results: dict[str, list[NewCandidate]] = defaultdict(list)

    for target_name, config in targets.items():
        local_rel = config["local"]
        local_path = project_root / local_rel
        rule_set = parse_local_list(local_path, target_name)

        if verbose:
            print(f"\n[📡 巡检中] {target_name} ({local_rel}) - 已收录: 精确={len(rule_set.exact_domains)}, 后缀={len(rule_set.suffix_domains)}")

        candidates: dict[str, tuple[str, str]] = {}

        for comm_url in config.get("community_sources", []):
            src_name = Path(urlparse(comm_url).path).name
            found_domains = fetch_community_domains(comm_url, session)
            for d in found_domains:
                if d not in candidates:
                    candidates[d] = ("Community", src_name)

        # 0.3s 间隔防止 CT API 突发限流
        for ct_root in config.get("ct_roots", []):
            time.sleep(0.3)
            ct_domains = fetch_ct_logs_domains(ct_root, session)
            for d in ct_domains:
                if d not in candidates:
                    candidates[d] = ("CT-Logs", ct_root)

        filtered_new: list[NewCandidate] = []
        covered_count = 0
        blocked_count = 0

        for domain, (src_type, src_name) in candidates.items():
            if is_subsumed(domain, rule_set.suffix_domains, rule_set.exact_domains, rule_set.wildcards):
                covered_count += 1
                continue

            if not is_valid_domain_or_suffix("domain", domain):
                blocked_count += 1
                continue

            if config.get("category") == "ai":
                block_reason = is_blocked_ai_rule("domain", domain)
                if block_reason:
                    blocked_count += 1
                    continue

            root_domain = extract_registrable_root(domain)
            is_root = (domain == root_domain)
            suggested = f"HOST-SUFFIX,{domain}" if is_root else f"HOST,{domain}"

            candidate = NewCandidate(
                domain=domain,
                target_name=target_name,
                source_type=src_type,
                source_name=src_name,
                suggested_rule=suggested,
                is_root_promotion=is_root,
            )
            filtered_new.append(candidate)

        if filtered_new:
            results[target_name] = filtered_new
            if verbose:
                print(f"  🚨 发现 {len(filtered_new)} 个新有效域名候选! (过滤已覆盖子域: {covered_count}, 拦截遥测垃圾: {blocked_count})")
                for c in filtered_new[:5]:
                    print(f"     + [{c.source_type}] {c.domain} -> 建议: {c.suggested_rule}")
                if len(filtered_new) > 5:
                    print(f"     ... 还有 {len(filtered_new) - 5} 个候选")
        else:
            if verbose:
                print(f"  ✅ 库状态最新，无新资产需要同步。(已覆盖子域: {covered_count}, 垃圾拦截: {blocked_count})")

    session.close()
    return results


def generate_markdown_report(results: dict[str, list[NewCandidate]]) -> str:
    """生成排版精美、可直接用于 GitHub Issue / PR 的 Markdown 战报"""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_new = sum(len(items) for items in results.values())

    lines = [
        "## 📡 规则雷达自动化巡检报告 (Rule Radar Report)",
        f"- **巡检时间**: `{now_str}`",
        f"- **监控规则集数量**: `{len(RADAR_TARGETS)}`",
        f"- **发现新域名候选总计**: `{total_new}`",
        "",
    ]

    if total_new == 0:
        lines.append("> ✅ **本次巡检未发现任何未收录的新业务域名。所有规则集均处于最新纯净状态！**\n")
        return "\n".join(lines)

    lines.append("> 💡 **提示**：所有候选域名均已**自动通过子域吸收过滤**（已收录后缀的子域已被静默排除）并**通过了 `rule_filter` 遥测黑名单安全审查**。\n")

    for target_name, candidates in sorted(results.items()):
        target_cfg = RADAR_TARGETS.get(target_name, {})
        local_file = target_cfg.get("local", f"Private/{target_name}.list")
        lines.append(f"### 🎯 {target_name} (`{local_file}`)")
        if not target_cfg.get("auto_apply", True):
            lines.append("> ℹ️ *注：该规则集由 `script/generate_ai.py` 自动生成，自动 PR 不会直接修改此文件，请人工确认后补充至 `SUPPLEMENTAL_AI_DOMAINS`。*\n")
        lines.append(f"共发现 **{len(candidates)}** 个未收录的新域名候选：\n")
        lines.append("| 序号 | 候选域名 (New Domain) | 发现来源 (Source) | 建议收录规则 (Suggested Rule) |")
        lines.append("| :---: | :--- | :--- | :--- |")
        for idx, c in enumerate(candidates, 1):
            src_desc = f"{c.source_type} ({c.source_name})"
            rule_badge = f"`{c.suggested_rule}`"
            if c.is_root_promotion:
                rule_badge += " *(主域)*"
            lines.append(f"| {idx} | `{c.domain}` | {src_desc} | {rule_badge} |")
        lines.append("")

    lines.append("---")
    lines.append("*本报告由 GitHub Actions 自动化规则雷达巡检系统生成。请人工复核后决定是否合并。*")
    return "\n".join(lines)


def apply_candidates_to_local(results: dict[str, list[NewCandidate]], project_root: Path = Path(".")) -> int:
    """将发现的候选域名一键追加写入对应的 Private/*.list 文件末尾（跳过由脚本自动生成的只读目标）"""
    applied_count = 0
    now_utc = datetime.now(timezone.utc)
    now_ts = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    now_day = now_utc.strftime("%Y-%m-%d")

    for target_name, candidates in results.items():
        if not candidates:
            continue
        target_cfg = RADAR_TARGETS.get(target_name, {})
        if not target_cfg.get("auto_apply", True):
            continue
        local_rel = target_cfg["local"]
        file_path = project_root / local_rel
        if not file_path.exists():
            continue

        existing_text = file_path.read_text(encoding="utf-8")
        updated_text, _ = re.subn(
            r"^(#\s*UPDATED:\s*).*$",
            rf"\g<1>{now_ts}",
            existing_text,
            count=1,
            flags=re.MULTILINE,
        )
        if not updated_text.endswith("\n"):
            updated_text += "\n"
        addition_lines = [f"\n# --- 规则雷达自动发现 ({now_day}) ---\n"]
        for c in candidates:
            addition_lines.append(f"{c.suggested_rule}\n")
            applied_count += 1
        file_path.write_text(updated_text + "".join(addition_lines), encoding="utf-8")

    return applied_count


def save_candidates_json(results: dict[str, list[NewCandidate]], output_path: Path) -> None:
    payload = {
        target_name: [
            {
                "domain": c.domain,
                "target_name": c.target_name,
                "source_type": c.source_type,
                "source_name": c.source_name,
                "suggested_rule": c.suggested_rule,
                "is_root_promotion": c.is_root_promotion,
            }
            for c in items
        ]
        for target_name, items in results.items()
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_candidates_json(input_path: Path) -> dict[str, list[NewCandidate]]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    results: dict[str, list[NewCandidate]] = {}
    for target_name, items in payload.items():
        results[target_name] = [
            NewCandidate(
                domain=item["domain"],
                target_name=item["target_name"],
                source_type=item["source_type"],
                source_name=item["source_name"],
                suggested_rule=item["suggested_rule"],
                is_root_promotion=bool(item.get("is_root_promotion", False)),
            )
            for item in items
        ]
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="规则雷达巡检与证书透明度探针")
    parser.add_argument("--output", "-o", help="输出 Markdown 报告文件路径 (如 radar_report.md)")
    parser.add_argument("--save-json", help="将发现的新域名候选保存为 JSON 文件，供后续 --apply-json 复用")
    parser.add_argument("--apply", action="store_true", help="一键将发现的新规则追加写入本地 Private/*.list 文件")
    parser.add_argument("--apply-json", help="直接读取 --save-json 生成的结果写入本地 Private/*.list，避免重复网络探测")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式，仅输出关键信息")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent

    if args.apply_json:
        results = load_candidates_json(Path(args.apply_json))
        added = apply_candidates_to_local(results, project_root=project_root)
        if not args.quiet:
            print(f"✨ 已从 {args.apply_json} 成功将 {added} 条新规则追加写入本地 Private 列表！")
        return

    results = run_radar_scan(targets=RADAR_TARGETS, project_root=project_root, verbose=not args.quiet)
    total_new = sum(len(items) for items in results.values())

    report_md = generate_markdown_report(results)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report_md, encoding="utf-8")
        if not args.quiet:
            print(f"\n📄 巡检战报已写入: {out_path.resolve()}")

    if args.save_json:
        save_candidates_json(results, Path(args.save_json))

    if args.apply and total_new > 0:
        added = apply_candidates_to_local(results, project_root=project_root)
        print(f"✨ 已成功将 {added} 条新规则追加写入本地 Private 列表！")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"has_new_domains={'true' if total_new > 0 else 'false'}\n")
            f.write(f"new_domain_count={total_new}\n")


if __name__ == "__main__":
    main()
