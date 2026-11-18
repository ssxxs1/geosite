from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests
import yaml

from script.convert_to_mrs import convert_yaml_to_mrs, fetch_release_file
from script.magicrule_resolver import MagicRuleResolver
from script.rule_filter import (
    is_blocked_ai_rule,
    is_valid_domain_or_suffix,
    is_ai_ruleset,
)

_MAGICRULE_RESOLVER: MagicRuleResolver | None = None


def get_magicrule_resolver(session: requests.Session) -> MagicRuleResolver:
    global _MAGICRULE_RESOLVER
    if _MAGICRULE_RESOLVER is None:
        _MAGICRULE_RESOLVER = MagicRuleResolver(session=session)
    return _MAGICRULE_RESOLVER


SING_BOX_MAP = {
    "domain-suffix": "domain_suffix",
    "domain": "domain",
    "domain-keyword": "domain_keyword",
    "domain-wildcard": "domain_regex",
    "domain-regex": "domain_regex",
    "ip-cidr": "ip_cidr",
    "ip-cidr6": "ip_cidr",
    "src-ip-cidr": "source_ip_cidr",
    "geoip": "geoip",
    "dst-port": "port",
    "src-port": "source_port",
    "process-name": "process_name",
    "process-path": "process_path",
}

MIHOMO_MAP = {
    "domain-suffix": "DOMAIN-SUFFIX",
    "domain": "DOMAIN",
    "domain-keyword": "DOMAIN-KEYWORD",
    "domain-wildcard": "DOMAIN-WILDCARD",
    "domain-regex": "DOMAIN-REGEX",
    "ip-cidr": "IP-CIDR",
    "ip-cidr6": "IP-CIDR6",
    "ip-asn": "IP-ASN",
    "src-ip-cidr": "SRC-IP-CIDR",
    "geoip": "GEOIP",
    "dst-port": "DST-PORT",
    "src-port": "SRC-PORT",
    "process-name": "PROCESS-NAME",
    "process-path": "PROCESS-PATH",
}

TYPE_ALIASES = {
    "domain": "domain",
    "host": "domain",
    "domain-suffix": "domain-suffix",
    "host-suffix": "domain-suffix",
    "domain-keyword": "domain-keyword",
    "host-keyword": "domain-keyword",
    "domain-wildcard": "domain-wildcard",
    "host-wildcard": "domain-wildcard",
    "domain-regex": "domain-regex",
    "host-regex": "domain-regex",
    "url-regex": "url-regex",
    "ip-cidr": "ip-cidr",
    "ip-cidr6": "ip-cidr6",
    "ip6-cidr": "ip-cidr6",
    "ip-asn": "ip-asn",
    "src-ip-cidr": "src-ip-cidr",
    "geoip": "geoip",
    "user-agent": "user-agent",
    "dst-port": "dst-port",
    "src-port": "src-port",
    "process-name": "process-name",
    "process-path": "process-path",
}

TARGET_EXCEPTIONS = {
    "sing-box": {"url-regex", "ip-asn", "user-agent"},
    "mihomo": {"url-regex", "user-agent"},
}

# Backwards-compatible public name used by older callers.
MAP_DICT = SING_BOX_MAP

CANONICAL_RULESET_NAMES = {
    "openai": "OpenAI",
    "facebook": "Facebook",
    "binance": "Binance",
    "playstation": "PlayStation",
    "ea": "EA",
    "cloudflare": "Cloudflare",
    "whatsapp": "Whatsapp",
    "httpdns": "BlockHttpDNS",
}


def resolve_base_name(source: str) -> str:
    parsed = urlparse(source)
    if parsed.fragment:
        return parsed.fragment.strip()
    if parsed.scheme == "magicrule":
        return parsed.netloc or parsed.path.strip("/")
    raw_stem = Path(parsed.path).stem.replace(".", "_").replace("-", "_")
    return CANONICAL_RULESET_NAMES.get(raw_stem.lower(), raw_stem)


class ConversionError(RuntimeError):
    pass


def normalize_type(raw_type: str) -> str | None:
    return TYPE_ALIASES.get(raw_type.strip().lower())


def infer_bare_rule(value: str) -> tuple[str, str]:
    candidate = value.strip().strip("'\"")
    # 剥离行内注释 (#, ;, //)
    for comment_char in ("#", ";", "//"):
        if comment_char in candidate:
            candidate = candidate.split(comment_char)[0].strip()

    # 剥离 v2fly / geosite 的 @ 属性标签 (如 :@cn 或 @ads)
    if "@" in candidate:
        candidate = candidate.split("@")[0].rstrip(":")

    # 识别 v2fly / MetaCubeX geosite 显式前缀
    if candidate.startswith("full:"):
        return "domain", candidate[5:].strip()
    if candidate.startswith("domain:"):
        return "domain-suffix", candidate[7:].strip()
    if candidate.startswith("keyword:"):
        return "domain-keyword", candidate[8:].strip()
    if candidate.startswith("regexp:"):
        return "domain-regex", candidate[7:].strip()

    # 识别 ASN (如 AS13335)
    upper_val = candidate.upper()
    if upper_val.startswith("AS") and upper_val[2:].isdigit():
        return "ip-asn", upper_val[2:]

    # 识别 IP CIDR / IP 单地址
    try:
        network = ipaddress.ip_network(candidate, strict=False)
        return ("ip-cidr" if network.version == 4 else "ip-cidr6"), str(network)
    except ValueError:
        pass

    # 识别 +. 或 . 开头的域名后缀
    if candidate.startswith(("+.", ".")):
        return "domain-suffix", candidate.removeprefix("+.").lstrip(".")
    return "domain", candidate


def normalize_value(kind: str, value: str) -> str:
    normalized = value.strip().strip("'\"")
    if not normalized:
        raise ConversionError("empty rule value")
    if kind in {"domain", "domain-suffix"}:
        normalized = normalized.removeprefix("+.").lstrip(".").rstrip(".").lower()
    elif kind in {"domain-keyword"}:
        normalized = normalized.lower()
    elif kind in {"ip-cidr", "ip-cidr6", "src-ip-cidr"}:
        network = ipaddress.ip_network(normalized, strict=False)
        if kind == "ip-cidr" and network.version != 4:
            raise ConversionError(f"expected IPv4 CIDR, got {normalized}")
        if kind == "ip-cidr6" and network.version != 6:
            raise ConversionError(f"expected IPv6 CIDR, got {normalized}")
        normalized = str(network)
    elif kind == "ip-asn":
        normalized = normalized.upper().removeprefix("AS")
        if not normalized.isdigit():
            raise ConversionError(f"invalid ASN: {value}")
    elif kind == "geoip":
        normalized = normalized.upper()
    return normalized


def parse_rule_entry(entry: object) -> tuple[str, str, tuple[str, ...]] | None:
    if entry is None:
        return None
    line = str(entry).strip().lstrip("﻿")
    if not line or line.startswith(("#", ";", "//")) or line == "payload:":
        return None
    if line.startswith("-"):
        line = line[1:].strip()
    line = line.strip("'\"")
    if not line:
        return None

    raw_type, separator, remainder = line.partition(",")
    if not separator:
        fields = [line]
    else:
        normalized_type = normalize_type(raw_type)
        if normalized_type in {"domain-regex", "url-regex", "user-agent"}:
            fields = [raw_type.strip(), remainder.strip().strip("'\"")]
        else:
            fields = [raw_type.strip()] + [
                part.strip().strip("'\"") for part in remainder.split(",")
            ]
    if len(fields) == 1:
        kind, value = infer_bare_rule(fields[0])
        val = normalize_value(kind, value)
        if not is_valid_domain_or_suffix(kind, val):
            print(f"[跳过] 单标签无效域名规则: {val}", file=sys.stderr)
            return None
        return kind, val, ()

    kind = normalize_type(fields[0])
    if kind is None:
        raise ConversionError(f"unsupported input type: {fields[0]}")
    val = normalize_value(kind, fields[1])
    if not is_valid_domain_or_suffix(kind, val):
        print(f"[跳过] 单标签无效域名规则: {val}", file=sys.stderr)
        return None
    return kind, val, tuple(part for part in fields[2:] if part)


def fetch_text(source: str, session: requests.Session) -> str:
    clean_source = source.split("#")[0]
    if clean_source.startswith("magicrule://"):
        rule_name = clean_source[len("magicrule://") :].strip("/").strip()
        resolver = get_magicrule_resolver(session)
        text = resolver.fetch_supplementary_rules(rule_name)
        if text:
            return text
        raise ConversionError(f"failed to fetch magicrule for {rule_name}")

    path = Path(clean_source)
    if not path.is_absolute() and not path.exists():
        candidate = Path(__file__).resolve().parent / path
        if candidate.exists():
            path = candidate
    if path.exists():
        return path.read_text(encoding="utf-8")
    response = session.get(clean_source, timeout=(10, 60))
    response.raise_for_status()
    return response.text


def parse_source(source: str, session: requests.Session) -> list[tuple[str, str, tuple[str, ...]]]:
    text = fetch_text(source, session)
    clean_source = source.split("#")[0]
    path = urlparse(clean_source).path.lower()
    entries: Iterable[object]

    if path.endswith((".yaml", ".yml")):
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError:
            document = None
        if isinstance(document, dict):
            if isinstance(document.get("payload"), list):
                entries = document["payload"]
            elif isinstance(document.get("rules"), list):
                entries = document["rules"]
            else:
                entries = text.splitlines()
        elif isinstance(document, list):
            entries = document
        else:
            entries = text.splitlines()
    else:
        entries = text.splitlines()

    rules = []
    for entry in entries:
        if entry is None:
            continue
        if not isinstance(entry, str):
            if isinstance(entry, (int, float, bool)):
                entry = str(entry)
            else:
                continue
        parsed = parse_rule_entry(entry)
        if parsed:
            rules.append(parsed)
    if not rules:
        raise ConversionError(f"no valid rules found in {source}")
    return rules


def deduplicate_rules(
    rules: Iterable[tuple[str, str, tuple[str, ...]]],
) -> list[tuple[str, str, tuple[str, ...]]]:
    unique = {}
    for kind, value, options in rules:
        unique[(kind, value)] = (kind, value, options)
    return sorted(unique.values(), key=lambda item: (item[0], item[1]))


def wildcard_to_regex(value: str) -> str:
    parts = []
    index = 0
    while index < len(value):
        if value[index : index + 2] == "*.":
            parts.append(r"(?:[^.]+\.)*")
            index += 2
        elif value[index] == "*":
            parts.append(".*")
            index += 1
        elif value[index] == "?":
            parts.append(".")
            index += 1
        else:
            parts.append(re.escape(value[index]))
            index += 1
    return "^" + "".join(parts) + "$"


def convert_for_target(
    rules: Iterable[tuple[str, str, tuple[str, ...]]],
    target: str,
) -> tuple[list[tuple[str, str]], Counter]:
    mapping = SING_BOX_MAP if target == "sing-box" else MIHOMO_MAP
    exceptions = TARGET_EXCEPTIONS[target]
    converted = []
    stats = Counter()

    for kind, value, _options in rules:
        mapped = mapping.get(kind)
        if mapped:
            if target == "sing-box" and kind == "domain-wildcard":
                value = wildcard_to_regex(value)
            converted.append((mapped, value))
            stats["emitted"] += 1
        elif kind in exceptions:
            stats[f"skipped:{kind}"] += 1
        else:
            raise ConversionError(f"{target} has no declared policy for rule type {kind}")
    return converted, stats


def sort_dict(obj):
    if isinstance(obj, dict):
        return {key: sort_dict(obj[key]) for key in sorted(obj)}
    if isinstance(obj, list) and all(isinstance(item, dict) for item in obj):
        return sorted((sort_dict(item) for item in obj), key=lambda item: sorted(item)[0])
    if isinstance(obj, list):
        return sorted(sort_dict(item) for item in obj)
    return obj


def write_temp_text(destination: Path, content: str) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent, text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(name, 0o644)
    return Path(name)


def publish_outputs(staged: list[tuple[Path, Path]]) -> None:
    # 过滤掉内容未发生任何改变的文件，保留原始 mtime 并避免触发任何文件系统/Git 变动事件
    effective_staged: list[tuple[Path, Path]] = []
    for temporary, destination in staged:
        if destination.exists():
            try:
                if destination.read_bytes() == temporary.read_bytes():
                    temporary.unlink(missing_ok=True)
                    continue
            except Exception:
                pass
        effective_staged.append((temporary, destination))

    if not effective_staged:
        return

    backups: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for _temporary, destination in effective_staged:
            if destination.exists():
                backup = destination.with_name(f".{destination.name}.{os.getpid()}.bak")
                os.replace(destination, backup)
                backups.append((backup, destination))
        for temporary, destination in effective_staged:
            os.replace(temporary, destination)
            published.append(destination)
    except Exception:
        for destination in published:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
        for backup, destination in reversed(backups):
            if backup.exists():
                os.replace(backup, destination)
        raise
    finally:
        for backup, _destination in backups:
            try:
                backup.unlink()
            except FileNotFoundError:
                pass


def build_sing_box_json(converted: Iterable[tuple[str, str]]) -> str:
    grouped: dict[str, set[str]] = {}
    for kind, value in converted:
        grouped.setdefault(kind, set()).add(value)
    result = {
        "version": 2,
        "rules": [{kind: sorted(values)} for kind, values in sorted(grouped.items())],
    }
    return json.dumps(sort_dict(result), ensure_ascii=False, indent=2)


def build_mihomo_yaml(
    converted: Iterable[tuple[str, str]],
    base_name: str = "",
    updated_at: str = "",
    existing_path: Path | None = None,
) -> str:
    entries = []
    for kind, value in converted:
        entry = f"{kind},{value}"
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            entry += ",no-resolve"
        entries.append(entry)
    unique_entries = sorted(set(entries))
    yaml_content = yaml.safe_dump(
        {"payload": unique_entries},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )

    # 若未显式传入 updated_at，且已有文件内容 payload 与新生成的内容完全一致，沿用旧时间戳
    if not updated_at and existing_path and existing_path.exists():
        try:
            content = existing_path.read_text(encoding="utf-8")
            match = re.search(r"^# UPDATED: (.*)$", content, re.MULTILINE)
            if match:
                old_data = yaml.safe_load(content)
                if isinstance(old_data, dict) and old_data.get("payload") == unique_entries:
                    updated_at = match.group(1).strip()
        except Exception:
            pass

    if not updated_at:
        updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    header = ""
    if base_name:
        type_counts = Counter(entry.split(",")[0] for entry in unique_entries)
        header_lines = [
            f"# NAME: {base_name}",
            "# AUTHOR: ssxxs1",
            "# REPO: https://github.com/ssxxs1/geosite",
            f"# UPDATED: {updated_at}",
        ]
        for kind, count in sorted(type_counts.items()):
            header_lines.append(f"# {kind}: {count}")
        header_lines.append(f"# TOTAL: {len(unique_entries)}")
        header = "\n".join(header_lines) + "\n\n"
    return header + yaml_content


def build_quantumult_x_list(
    rules: Iterable[tuple[str, str, tuple[str, ...]]],
    base_name: str = "",
    updated_at: str = "",
    existing_path: Path | None = None,
) -> str:
    """
    生成 Quantumult X 原生 .list 分流规则文件
    支持 HOST, HOST-SUFFIX, HOST-KEYWORD, HOST-WILDCARD, HOST-REGEX, IP-CIDR, IP6-CIDR, IP-ASN, USER-AGENT
    """
    qx_type_map = {
        "domain": "HOST",
        "host": "HOST",
        "domain-suffix": "HOST-SUFFIX",
        "host-suffix": "HOST-SUFFIX",
        "domain-keyword": "HOST-KEYWORD",
        "host-keyword": "HOST-KEYWORD",
        "domain-wildcard": "HOST-WILDCARD",
        "host-wildcard": "HOST-WILDCARD",
        "domain-regex": "HOST-REGEX",
        "host-regex": "HOST-REGEX",
        "ip-cidr": "IP-CIDR",
        "ip-cidr6": "IP6-CIDR",
        "ip-asn": "IP-ASN",
        "asn": "IP-ASN",
        "user-agent": "USER-AGENT",
    }
    entries = []
    for kind, val, options in rules:
        k = kind.lower().strip()
        qx_kind = qx_type_map.get(k)
        if not qx_kind:
            continue

        line = f"{qx_kind},{val}"
        lower_opts = {opt.lower() for opt in options}
        if qx_kind in {"IP-CIDR", "IP6-CIDR"}:
            line += ",no-resolve"
        elif qx_kind == "IP-ASN" and "no-resolve" in lower_opts:
            line += ",no-resolve"
        elif qx_kind in {"HOST", "HOST-SUFFIX"}:
            for flag in ("extended-matching", "force-remote-dns"):
                if flag in lower_opts:
                    line += f",{flag}"
        entries.append(line)

    unique_entries = sorted(set(entries))

    # 若未显式传入 updated_at，且已有文件规则体与新生成的内容完全一致，沿用旧时间戳保证幂等
    if not updated_at and existing_path and existing_path.exists():
        try:
            content = existing_path.read_text(encoding="utf-8")
            match = re.search(r"^# UPDATED: (.*)$", content, re.MULTILINE)
            if match:
                old_entries = [
                    ln.strip()
                    for ln in content.splitlines()
                    if ln.strip() and not ln.lstrip().startswith("#")
                ]
                if old_entries == unique_entries:
                    updated_at = match.group(1).strip()
        except Exception:
            pass

    if not updated_at:
        updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    header = ""
    if base_name:
        type_counts = Counter(entry.split(",")[0] for entry in unique_entries)
        header_lines = [
            f"# NAME: {base_name}",
            "# AUTHOR: ssxxs1/geosite",
            "# REPO: https://github.com/ssxxs1/geosite",
            f"# UPDATED: {updated_at}",
        ]
        for kind, count in sorted(type_counts.items()):
            header_lines.append(f"# {kind}: {count}")
        header_lines.append(f"# TOTAL: {len(unique_entries)}")
        header = "\n".join(header_lines) + "\n\n"

    return header + "\n".join(unique_entries) + "\n"


def fallback_recover_source(
    base_name: str,
    output_directory: Path,
    session: requests.Session,
    repo: str = "ssxxs1/geosite",
    mihomo_command: str = "mihomo",
    compile_mrs: bool = True,
) -> bool:
    """
    CI / GitHub Actions 冗余兜底恢复策略：
    当上游源拉取失败或解析异常时，直接从上一次打包发布的 GitHub Release 中拉取备份：
    1. 优先从 GitHub Latest Release 下载 _clash.yaml、.json、.srs
    2. 若成功拉回 _clash.yaml，基于此 YAML 尝试转换/校验 .mrs
    3. 若无法转换，则直接从 Release 把上一次打包好的 .mrs 复制下载过来
    """
    clash_path = output_directory / f"{base_name}_clash.yaml"
    json_path = output_directory / f"{base_name}.json"
    srs_path = output_directory / f"{base_name}.srs"
    qx_path = output_directory / f"{base_name}.list"

    print(f"[Release兜底] 源规则不可用，正在从 GitHub Release ({repo}) 拉取 {base_name} 上次发布的规则备份...")

    recovered = False
    for fname, fpath in [
        (f"{base_name}_clash.yaml", clash_path),
        (f"{base_name}.json", json_path),
        (f"{base_name}.srs", srs_path),
        (f"{base_name}.list", qx_path),
    ]:
        if fetch_release_file(fname, fpath, session=session, repo=repo):
            recovered = True

    # 针对 MRS：若有了 YAML 则尝试重新编译出 MRS；若失败则直接从 Release 拉取 .mrs
    mrs_ready = False
    if compile_mrs and clash_path.exists() and clash_path.stat().st_size > 0:
        try:
            mrs_stat = convert_yaml_to_mrs(
                clash_path,
                output_directory,
                mihomo_cmd=mihomo_command,
                verify=True,
                session=session,
                repo=repo,
            )
            print(f"[Release兜底] 基于 Release YAML 成功生成 MRS: {', '.join(mrs_stat['files'])}")
            mrs_ready = True
            recovered = True
        except Exception as exc:
            print(f"[Release兜底] MRS 转换失败 ({exc})，直接从 Release 拉取上次发布的 .mrs 文件...", file=sys.stderr)

    if not mrs_ready:
        for target_mrs in [f"{base_name}.mrs", f"{base_name}_domain.mrs", f"{base_name}_ip.mrs"]:
            dest = output_directory / target_mrs
            if fetch_release_file(target_mrs, dest, session=session, repo=repo):
                recovered = True

    return recovered


def convert_source(
    source: str,
    output_directory: Path,
    session: requests.Session,
    sing_box_command: str = "sing-box",
    compile_srs: bool = True,
    mihomo_command: str = "mihomo",
    compile_mrs: bool = True,
    repo: str = "ssxxs1/geosite",
) -> Path:
    raw_rules = parse_source(source, session)
    base_name = resolve_base_name(source)

    # 仅针对 MetaCubeX 官方纯域名源合并同名 GeoIP 伴侣（超阈值跳过以防误代理）与 MagicRule 互补规则
    MAX_GEOIP_CIDR = 2000
    clean_src = source.split("#")[0]
    clean_src_lower = clean_src.lower()
    if "meta-rules-dat/meta/geo/geosite/" in clean_src_lower:
        geoip_src = clean_src.replace("/geo/geosite/", "/geo/geoip/").replace("/geo/GEOSITE/", "/geo/geoip/")
        try:
            geoip_rules = parse_source(geoip_src, session)
            if geoip_rules:
                geoip_ips = sum(1 for r in geoip_rules if r[0] in {"ip-cidr", "ip-cidr6"})
                if geoip_ips > MAX_GEOIP_CIDR:
                    print(
                        f"[GeoIP伴侣·跳过] {base_name}: geoip 过大 ({geoip_ips} 条 > 阈值 {MAX_GEOIP_CIDR})，"
                        f"跳过自动融合（建议手动决策或依赖 DNS 缓存）"
                    )
                else:
                    before_count = len(raw_rules)
                    raw_rules = list(dict.fromkeys(raw_rules + geoip_rules))
                    print(f"[GeoIP伴侣] {base_name}: 自动融合 MetaCubeX 官方 GeoIP 规则 (总条目: {before_count} -> {len(raw_rules)}, 补充 IP: {geoip_ips})")
        except Exception:
            pass

    if "metacubex" in clean_src_lower:
        resolver = get_magicrule_resolver(session)
        supp_text = resolver.fetch_supplementary_rules(base_name)
        if supp_text:
            supp_rules = []
            for line in supp_text.splitlines():
                entry = line.strip()
                if not entry or entry.startswith(("#", ";", "//")):
                    continue
                try:
                    parsed = parse_rule_entry(entry)
                    if parsed:
                        supp_rules.append(parsed)
                except ConversionError:
                    continue
            if supp_rules:
                before_count = len(raw_rules)
                raw_rules = list(dict.fromkeys(raw_rules + supp_rules))
                supp_ips = sum(1 for r in supp_rules if r[0] in {"ip-cidr", "ip-cidr6"})
                print(f"[多源融合] {base_name}: 成功吸收 MagicRule 补充规则 (总条目: {before_count} -> {len(raw_rules)}, 补充 IP: {supp_ips})")

    if is_ai_ruleset(base_name):
        cleaned_rules = []
        for r in raw_rules:
            reason = is_blocked_ai_rule(r[0], r[1])
            if reason:
                print(f"[清洗] {base_name}: 拦截 AI 污染规则 ({reason}) -> {r[0]},{r[1]}")
            else:
                cleaned_rules.append(r)
        rules = deduplicate_rules(cleaned_rules)
    else:
        rules = deduplicate_rules(raw_rules)

    sing_box_rules, sing_box_stats = convert_for_target(rules, "sing-box")
    mihomo_rules, mihomo_stats = convert_for_target(rules, "mihomo")

    json_path = output_directory / f"{base_name}.json"
    srs_path = output_directory / f"{base_name}.srs"
    clash_path = output_directory / f"{base_name}_clash.yaml"
    qx_path = output_directory / f"{base_name}.list"

    json_temp = write_temp_text(json_path, build_sing_box_json(sing_box_rules))
    clash_temp = write_temp_text(clash_path, build_mihomo_yaml(mihomo_rules, base_name, existing_path=clash_path))
    qx_temp = write_temp_text(qx_path, build_quantumult_x_list(rules, base_name, existing_path=qx_path))
    srs_temp = srs_path.with_name(f".{srs_path.name}.{os.getpid()}.tmp")

    srs_compiled = False
    if compile_srs:
        try:
            subprocess.run(
                [sing_box_command, "rule-set", "compile", "--output", str(srs_temp), str(json_temp)],
                check=True,
                capture_output=True,
                text=True,
            )
            if srs_temp.exists() and srs_temp.stat().st_size > 0:
                srs_compiled = True
            else:
                print(f"[警告] sing-box 未生成有效 .srs，保留现有版本", file=sys.stderr)
        except Exception as exc:
            print(f"[警告] sing-box 编译 .srs 失败 ({exc})，不阻断 Clash 与 MRS 生成", file=sys.stderr)

    staged = [(json_temp, json_path), (clash_temp, clash_path), (qx_temp, qx_path)]
    if srs_compiled:
        staged.append((srs_temp, srs_path))
    elif not srs_path.exists():
        # 如果 sing-box 编译失败且本地无旧版 .srs，尝试从 Release 兜底拉取旧版 .srs
        fetch_release_file(srs_path.name, srs_path, session=session, repo=repo)

    try:
        publish_outputs(staged)
    except Exception:
        for temporary in (json_temp, clash_temp, qx_temp, srs_temp):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise

    accounted_sing_box = sing_box_stats["emitted"] + sum(
        value for key, value in sing_box_stats.items() if key.startswith("skipped:")
    )
    accounted_mihomo = mihomo_stats["emitted"] + sum(
        value for key, value in mihomo_stats.items() if key.startswith("skipped:")
    )
    if accounted_sing_box != len(rules) or accounted_mihomo != len(rules):
        raise ConversionError(f"unaccounted rules while converting {source}")

    print(f"[生成] sing-box JSON : {json_path}")
    if srs_compiled:
        print(f"[生成] sing-box SRS  : {srs_path}")
    elif srs_path.exists() and srs_path.stat().st_size > 0:
        print(f"[保底] sing-box SRS  : {srs_path}（保留历史/Release版本）")
    else:
        print(f"[跳过] sing-box SRS  : {srs_path}（--skip-srs 或编译失败）")

    print(f"[生成] Clash YAML    : {clash_path}")
    print(f"[生成] QuantumultX   : {qx_path}")

    if compile_mrs:
        try:
            mrs_stat = convert_yaml_to_mrs(
                clash_path,
                output_directory,
                mihomo_cmd=mihomo_command,
                verify=True,
                session=session,
                repo=repo,
            )
            print(f"[生成] Mihomo MRS    : {', '.join(mrs_stat['files'])}")
        except Exception as exc:
            print(f"[跳过] Mihomo MRS    : {exc}（未能编译 .mrs）", file=sys.stderr)
    else:
        print(f"[跳过] Mihomo MRS    : （--skip-mrs）")

    print(
        f"[统计] {base_name}: input={len(rules)} "
        f"sing-box={dict(sorted(sing_box_stats.items()))} "
        f"mihomo={dict(sorted(mihomo_stats.items()))}"
    )
    return json_path


def cleanup_orphaned_outputs(output_dir: Path, active_names: set[str]) -> list[str]:
    """清理已从 links.txt 下线但仍残留在输出目录中的孤立规则文件"""
    known_suffixes = ("_clash.yaml", "_domain.mrs", "_ip.mrs", ".json", ".srs", ".mrs", ".list")
    removed: list[str] = []
    if not output_dir.exists():
        return removed
    for path in sorted(output_dir.iterdir()):
        if not path.is_file():
            continue
        name = path.name
        for suffix in known_suffixes:
            if name.endswith(suffix):
                stem = name[: -len(suffix)]
                if stem not in active_names:
                    path.unlink(missing_ok=True)
                    removed.append(name)
                break
    return removed


def load_links(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert geosite sources for sing-box and Mihomo")
    parser.add_argument("--links", default="links.txt")
    parser.add_argument("--output", default="rules")
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--mihomo", default="mihomo")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", "ssxxs1/geosite"),
        help="GitHub repository for release fallback",
    )
    parser.add_argument(
        "--skip-srs",
        action="store_true",
        help="skip SRS compilation (intended for local development only)",
    )
    parser.add_argument(
        "--skip-mrs",
        action="store_true",
        help="skip MRS compilation",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification for local environments with a broken CA store",
    )
    args = parser.parse_args(argv)

    session = requests.Session()
    session.verify = not args.insecure
    session.headers["User-Agent"] = "geosite-rule-converter/2.0"

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    sources = load_links(Path(args.links))
    success_sources = []
    recovered_sources = []
    failed_sources = []

    for source in sources:
        base_name = resolve_base_name(source)
        try:
            convert_source(
                source,
                output_dir,
                session,
                args.sing_box,
                compile_srs=not args.skip_srs,
                mihomo_command=args.mihomo,
                compile_mrs=not args.skip_mrs,
                repo=args.repo,
            )
            success_sources.append(base_name)
        except Exception as exc:
            print(f"[错误] 源规则处理失败 [{base_name}] ({source}): {exc}", file=sys.stderr)
            recovered = fallback_recover_source(
                base_name,
                output_dir,
                session,
                repo=args.repo,
                mihomo_command=args.mihomo,
                compile_mrs=not args.skip_mrs,
            )
            if recovered:
                recovered_sources.append(base_name)
            else:
                failed_sources.append(base_name)

    print("\n" + "=" * 70)
    print("规则处理总览 (Processing Summary):")
    print(f"  成功拉取并更新   : {len(success_sources)}")
    print(f"  拉取失败但保底成功: {len(recovered_sources)} ({', '.join(recovered_sources) if recovered_sources else '无'})")
    if failed_sources:
        print(f"  完全失败且无保底 : {len(failed_sources)} ({', '.join(failed_sources)})", file=sys.stderr)
        return 1

    active_names = {resolve_base_name(source) for source in sources}
    removed_orphans = cleanup_orphaned_outputs(output_dir, active_names)
    if removed_orphans:
        print(f"  清理已下线孤立产物: {len(removed_orphans)} 个 ({', '.join(removed_orphans)})")

    print("所有规则集均已就绪（含正常更新与冗余保底）！")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
