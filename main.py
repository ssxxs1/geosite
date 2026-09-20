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
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests
import yaml

from script.convert_to_mrs import convert_yaml_to_mrs, fetch_release_file


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


class ConversionError(RuntimeError):
    pass


def normalize_type(raw_type: str) -> str | None:
    return TYPE_ALIASES.get(raw_type.strip().lower())


def infer_bare_rule(value: str) -> tuple[str, str]:
    candidate = value.strip().strip("'\"")
    try:
        network = ipaddress.ip_network(candidate, strict=False)
        return ("ip-cidr" if network.version == 4 else "ip-cidr6"), str(network)
    except ValueError:
        pass

    if candidate.startswith(("+.", ".")):
        return "domain-suffix", candidate.removeprefix("+.").lstrip(".")
    return "domain", candidate


def normalize_value(kind: str, value: str) -> str:
    normalized = value.strip().strip("'\"")
    if not normalized:
        raise ConversionError("empty rule value")
    if kind in {"domain", "domain-suffix"}:
        normalized = normalized.removeprefix("+.").lstrip(".").rstrip(".").lower()
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


def parse_rule_entry(entry: str) -> tuple[str, str, tuple[str, ...]] | None:
    line = entry.strip().lstrip("﻿")
    if not line or line.startswith(("#", ";", "//")) or line == "payload:":
        return None
    if line.startswith("-"):
        line = line[1:].strip()
    line = line.strip("'\"")

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
        return kind, normalize_value(kind, value), ()

    kind = normalize_type(fields[0])
    if kind is None:
        raise ConversionError(f"unsupported input type: {fields[0]}")
    return kind, normalize_value(kind, fields[1]), tuple(part for part in fields[2:] if part)


def fetch_text(source: str, session: requests.Session) -> str:
    path = Path(source)
    if path.exists():
        return path.read_text(encoding="utf-8")
    response = session.get(source, timeout=(10, 60))
    response.raise_for_status()
    return response.text


def parse_source(source: str, session: requests.Session) -> list[tuple[str, str, tuple[str, ...]]]:
    text = fetch_text(source, session)
    path = urlparse(source).path.lower()
    entries: Iterable[object]

    if path.endswith((".yaml", ".yml")):
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError:
            document = None
        if isinstance(document, dict) and isinstance(document.get("payload"), list):
            entries = document["payload"]
        else:
            entries = text.splitlines()
    else:
        entries = text.splitlines()

    rules = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ConversionError(f"non-string rule in {source}: {entry!r}")
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
    return Path(name)


def publish_outputs(staged: list[tuple[Path, Path]]) -> None:
    backups: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for _temporary, destination in staged:
            if destination.exists():
                backup = destination.with_name(f".{destination.name}.{os.getpid()}.bak")
                os.replace(destination, backup)
                backups.append((backup, destination))
        for temporary, destination in staged:
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


from datetime import datetime, timezone

def build_mihomo_yaml(converted: Iterable[tuple[str, str]], base_name: str = "", updated_at: str = "") -> str:
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

    print(f"[Release兜底] 源规则不可用，正在从 GitHub Release ({repo}) 拉取 {base_name} 上次发布的规则备份...")

    recovered = False
    for fname, fpath in [
        (f"{base_name}_clash.yaml", clash_path),
        (f"{base_name}.json", json_path),
        (f"{base_name}.srs", srs_path),
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
    rules = deduplicate_rules(parse_source(source, session))
    sing_box_rules, sing_box_stats = convert_for_target(rules, "sing-box")
    mihomo_rules, mihomo_stats = convert_for_target(rules, "mihomo")

    base_name = Path(urlparse(source).path).stem.replace(".", "_").replace("-", "_")
    json_path = output_directory / f"{base_name}.json"
    srs_path = output_directory / f"{base_name}.srs"
    clash_path = output_directory / f"{base_name}_clash.yaml"

    updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    json_temp = write_temp_text(json_path, build_sing_box_json(sing_box_rules))
    clash_temp = write_temp_text(clash_path, build_mihomo_yaml(mihomo_rules, base_name, updated_at))
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

    staged = [(json_temp, json_path), (clash_temp, clash_path)]
    if srs_compiled:
        staged.append((srs_temp, srs_path))
    elif not srs_path.exists():
        # 如果 sing-box 编译失败且本地无旧版 .srs，尝试从 Release 兜底拉取旧版 .srs
        fetch_release_file(srs_path.name, srs_path, session=session, repo=repo)

    try:
        publish_outputs(staged)
    except Exception:
        for temporary in (json_temp, clash_temp, srs_temp):
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


def load_links(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert geosite sources for sing-box and Mihomo")
    parser.add_argument("--links", default="links.txt")
    parser.add_argument("--output", default="rule")
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
        base_name = Path(urlparse(source).path).stem.replace(".", "_").replace("-", "_")
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

    print("所有规则集均已就绪（含正常更新与冗余保底）！")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
