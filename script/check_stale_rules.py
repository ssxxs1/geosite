#!/usr/bin/env python3
"""
check_stale_rules.py - 规则集活跃度与陈旧源巡检器 (Stale Rule Sentinel)

核心功能:
1. 扫描 links.txt 中的所有上游规则链接；
2. 提取规则的最后更新时间戳 (文件内嵌 UPDATED、GitHub Commits API 或 Git 历史)；
3. 识别超过指定天数 (默认 180 天) 未更新的“僵尸/陈旧规则源”；
4. 生成排版精美的 Markdown 报告，供 CI 邮件提醒和 Step Summary 聚合展示。

已知限制：
  MetaCubeX `meta` 分支由机器人每日自动 commit（内容是否变化均会产生提交），
  导致 GitHub Commits API 返回的"最后更新时间"永远是近期，陈旧检测对该分支实际无效。
  MetaCubeX 源的检测结果仅供参考，不代表规则内容有实质性变化。
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dateutil import parser as date_parser

try:
    from main import load_links, resolve_base_name
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from main import load_links, resolve_base_name


@dataclass
class StaleReportItem:
    base_name: str
    source_url: str
    last_updated: str
    days_stale: int
    source_kind: str  # "Local Private" 或 "Remote Upstream"


def extract_timestamp_from_text(text: str) -> datetime | None:
    """从文本前 4096 字符中提取内嵌的更新时间戳"""
    sample = text[:4096]
    match = re.search(
        r"#\s*(?:UPDATED|Updated|updated|LAST_MODIFIED|Date):\s*([0-9]{4}[-/][0-9]{2}[-/][0-9]{2}[^\r\n]*)",
        sample,
    )
    if not match:
        return None
    raw_date_str = match.group(1).strip()
    try:
        dt = date_parser.parse(raw_date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None


def fetch_github_file_last_commit(
    owner: str,
    repo: str,
    file_path: str,
    session: requests.Session,
    branch: str = "",
) -> datetime | None:
    """通过 GitHub Commits API 查询单个文件的最新提交时间"""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    headers = {}
    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"

    params = {"path": file_path, "page": 1, "per_page": 1}
    if branch:
        params["sha"] = branch

    try:
        resp = session.get(
            api_url,
            params=params,
            headers=headers,
            timeout=(5, 10),
        )
        if resp.status_code == 200:
            commits = resp.json()
            if isinstance(commits, list) and commits:
                commit_date_str = (
                    commits[0]
                    .get("commit", {})
                    .get("committer", {})
                    .get("date")
                )
                if commit_date_str:
                    return date_parser.parse(commit_date_str).astimezone(timezone.utc)
    except Exception:
        pass
    return None


def inspect_source_updated_date(
    source_url: str,
    project_root: Path,
    session: requests.Session,
) -> tuple[datetime | None, str]:
    """
    检查单个规则源的最后更新时间：
    返回 (datetime | None, 来源描述)
    """
    clean_url = source_url.split("#")[0].strip()

    if clean_url.startswith("magicrule://"):
        rule_name = clean_url[len("magicrule://") :].strip("/").strip()
        try:
            from script.magicrule_resolver import MagicRuleResolver

            resolver = MagicRuleResolver(session)
            index = resolver.load_index()
            item = index.get(rule_name.lower())
            if item and item.get("rule_updated_at"):
                return date_parser.parse(item["rule_updated_at"]).astimezone(timezone.utc), "MagicRule 索引更新时间"
        except Exception as exc:
            return None, f"MagicRule 查询失败 ({exc})"

    if clean_url.startswith("Private/"):
        local_path = project_root / clean_url
        if local_path.exists():
            text = local_path.read_text(encoding="utf-8", errors="ignore")
            dt = extract_timestamp_from_text(text)
            if dt:
                return dt, "文件内嵌时间戳"
            # 优先使用 Git 提交时间，避免 CI checkout 导致 mtime 失真
            try:
                proc = subprocess.run(
                    ["git", "log", "-1", "--format=%cI", "--", clean_url],
                    cwd=project_root,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return date_parser.parse(proc.stdout.strip()).astimezone(timezone.utc), "Git 提交历史"
            except Exception:
                pass
            mtime = local_path.stat().st_mtime
            return datetime.fromtimestamp(mtime, tz=timezone.utc), "本地文件修改时间"
        return None, "本地文件不存在"

    parsed = urlparse(clean_url)
    try:
        resp = session.get(clean_url, timeout=(6, 15))
        if resp.status_code == 200:
            text = resp.text
            dt = extract_timestamp_from_text(text)
            if dt:
                return dt, "上游文件内嵌时间戳"

            if parsed.netloc.lower() == "raw.githubusercontent.com":
                parts = parsed.path.strip("/").split("/")
                owner = repo = branch = file_path = ""
                if len(parts) >= 6 and parts[2] == "refs" and parts[3] in {"heads", "tags"}:
                    owner, repo, branch = parts[0], parts[1], parts[4]
                    file_path = "/".join(parts[5:])
                elif len(parts) >= 4:
                    owner, repo, branch = parts[0], parts[1], parts[2]
                    file_path = "/".join(parts[3:])
                if owner and repo and file_path:
                    gh_dt = fetch_github_file_last_commit(owner, repo, file_path, session, branch=branch)
                    if gh_dt:
                        return gh_dt, f"GitHub 提交历史 ({branch})"
    except Exception as exc:
        return None, f"请求失败 ({exc})"

    return None, "未探测到有效时间戳"


def check_all_stale_rules(
    links_path: Path,
    project_root: Path,
    threshold_days: int = 180,
    session: requests.Session | None = None,
) -> tuple[list[StaleReportItem], list[tuple[str, str, str]]]:
    """
    全量体检 links.txt：
    返回: (超过阈值的陈旧规则列表, 所有规则体检明细)
    """
    links = load_links(links_path)
    sess = session or requests.Session()
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; GeositeStaleChecker/1.0; +https://github.com/ssxxs1/geosite)"
    })

    now = datetime.now(timezone.utc)
    stale_items: list[StaleReportItem] = []
    all_details: list[tuple[str, str, str]] = []

    for raw_link in links:
        base_name = resolve_base_name(raw_link)
        dt, note = inspect_source_updated_date(raw_link, project_root, sess)

        if dt is not None:
            days_ago = (now - dt).days
            date_str = dt.strftime("%Y-%m-%d")
            all_details.append((base_name, date_str, f"{days_ago} 天前 ({note})"))

            if days_ago > threshold_days:
                source_kind = "本地维护" if raw_link.startswith("Private/") else "远程上游"
                stale_items.append(
                    StaleReportItem(
                        base_name=base_name,
                        source_url=raw_link,
                        last_updated=date_str,
                        days_stale=days_ago,
                        source_kind=source_kind,
                    )
                )
        else:
            all_details.append((base_name, "未知", note))

    stale_items.sort(key=lambda x: x.days_stale, reverse=True)
    return stale_items, all_details


def generate_stale_markdown_report(
    stale_items: list[StaleReportItem],
    threshold_days: int = 180,
) -> str:
    """生成格式化的 Markdown 告警战报"""
    lines = [
        f"### ⚠️ 规则集活跃度巡检告警 (Stale Rules Alert)",
        f"- **停更判定阈值**: `超过 {threshold_days} 天未更新`",
        f"- **发现超期未更新规则集**: `{len(stale_items)} 个`",
        "",
    ]

    if not stale_items:
        lines.append(f"> ✅ **所有上游规则源均处于活跃状态（最近 {threshold_days} 天内均有更新），健康度良好！**\n")
        return "\n".join(lines)

    lines.append(
        f"> 💡 **提示**：以下规则集已**连续超 {threshold_days} 天未更新**。建议关注其是否已停更，可考虑转入 `Private/*.list` 自主维护或寻找新的活跃替代源。\n"
    )
    lines.append("| 序号 | 规则名称 | 类型 | 上次更新日期 | 停更天数 | 原始引用链接 |")
    lines.append("| :---: | :--- | :---: | :---: | :---: | :--- |")

    for idx, item in enumerate(stale_items, 1):
        clean_url = item.source_url.split("#")[0]
        url_display = f"`{clean_url}`" if len(clean_url) < 60 else f"[{item.base_name}]({clean_url})"
        lines.append(
            f"| {idx} | **{item.base_name}** | {item.source_kind} | `{item.last_updated}` | 🔴 **{item.days_stale} 天** | {url_display} |"
        )

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="规则集活跃度与陈旧源巡检器")
    parser.add_argument("--links", default="links.txt", help="links.txt 文件路径")
    parser.add_argument("--threshold", type=int, default=180, help="停更告警天数阈值 (默认 180)")
    parser.add_argument("--output", "-o", help="输出 Markdown 报告文件路径 (如 stale_report.md)")
    parser.add_argument("--append-to", help="将告警战报追加到已有的 Markdown 文件末尾 (如 radar_report.md)")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    links_path = project_root / args.links

    print(f"[🔍 活跃度体检] 正在扫描 {links_path.name} 中的规则集 (阈值: {args.threshold} 天)...")
    stale_items, _ = check_all_stale_rules(
        links_path=links_path,
        project_root=project_root,
        threshold_days=args.threshold,
    )

    print(f"\n体检完毕: 共发现 {len(stale_items)} 个规则集超过 {args.threshold} 天未更新：")
    for item in stale_items:
        print(f"  ⚠️ [{item.base_name}] 上次更新: {item.last_updated} ({item.days_stale} 天前) - {item.source_url}")

    report_md = generate_stale_markdown_report(stale_items, threshold_days=args.threshold)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report_md, encoding="utf-8")
        print(f"\n📄 活跃度战报已写入: {out_path.resolve()}")

    if args.append_to:
        target_path = Path(args.append_to)
        if target_path.exists():
            existing = target_path.read_text(encoding="utf-8")
            target_path.write_text(existing + "\n\n" + report_md, encoding="utf-8")
            print(f"📌 已成功将活跃度告警追加至: {target_path.resolve()}")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"has_stale_rules={'true' if len(stale_items) > 0 else 'false'}\n")
            f.write(f"stale_rules_count={len(stale_items)}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
