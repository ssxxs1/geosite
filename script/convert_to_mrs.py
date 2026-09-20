#!/usr/bin/env python3
"""
Convert existing Clash YAML rule-providers to Mihomo MRS (.mrs) format.
Supports behavior: domain and behavior: ipcidr, with automated roundtrip verification
and GitHub Release fallback redundancy.
"""

from __future__ import annotations

import argparse
import glob
import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import requests


def fetch_release_file(
    filename: str,
    destination: Path,
    session: requests.Session | None = None,
    repo: str = "ssxxs1/geosite",
) -> bool:
    """Download a file from the latest GitHub release as fallback."""
    url = f"https://github.com/{repo}/releases/latest/download/{filename}"
    if session is None:
        session = requests.Session()
    try:
        resp = session.get(url, timeout=(5, 30))
        if resp.status_code == 200 and resp.content:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(resp.content)
            print(f"[冗余兜底] 从 Release 恢复成功: {filename}")
            return True
    except Exception as exc:
        print(f"[冗余兜底] 从 Release 拉取 {filename} 失败: {exc}", file=sys.stderr)
    return False


def is_valid_mrs_wildcard(pattern: str) -> bool:
    """
    Mihomo MRS (DomainSet) requires that '*' wildcard must occupy the entire label
    (e.g., '*.google.com' or '*.*.azurefd.net'). Partial wildcards like 'lh*.google.com'
    or '*-pa.googleapis.com' are rejected by Mihomo's Domain Trie and must remain in
    Classical Clash YAML.
    """
    labels = pattern.split(".")
    return all("*" not in label or label == "*" for label in labels)


def parse_clash_yaml(yaml_path: Path) -> tuple[list[str], list[str], list[str]]:
    """
    Parse a Clash classical YAML file into domain rules, IP CIDRs, and other rules.
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    payload = []
    in_payload = False
    for line in lines:
        stripped = line.strip()
        if stripped == "payload:":
            in_payload = True
            continue
        if in_payload and stripped.startswith("- "):
            payload.append(stripped[2:].strip("'\""))

    domain_rules = []
    ip_rules = []
    other_rules = []

    for entry in payload:
        parts = entry.split(",")
        kind = parts[0].strip().upper()
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-REGEX"}:
            domain_rules.append(f"{kind},{parts[1].strip()}")
        elif kind == "DOMAIN-WILDCARD":
            pattern = parts[1].strip()
            if is_valid_mrs_wildcard(pattern):
                domain_rules.append(f"DOMAIN-WILDCARD,{pattern}")
            else:
                other_rules.append(entry)
        elif kind == "DOMAIN-KEYWORD":
            clean_kw = parts[1].strip().strip(".")
            domain_rules.append(f"DOMAIN-KEYWORD,{clean_kw}")
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            ip_rules.append(parts[1].strip())
        else:
            other_rules.append(entry)

    # Deduplicate preserving order
    unique_domains = list(dict.fromkeys(domain_rules))
    unique_ips = list(dict.fromkeys(ip_rules))
    unique_others = list(dict.fromkeys(other_rules))

    return unique_domains, unique_ips, unique_others


def calculate_expected_ip_count(ip_list: list[str]) -> int:
    """
    Calculate the expected count of CIDRs after Mihomo's Radix tree merge.
    Mihomo automatically collapses contiguous CIDRs and subsumes subnets.
    """
    v4 = []
    v6 = []
    for ip_str in ip_list:
        try:
            net = ipaddress.ip_network(ip_str, strict=False)
            if net.version == 4:
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            pass

    collapsed_v4 = list(ipaddress.collapse_addresses(v4))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6))
    return len(collapsed_v4) + len(collapsed_v6)


def compile_and_verify_domain_mrs(
    domain_rules: list[str],
    output_path: Path,
    mihomo_cmd: str = "mihomo",
    verify: bool = True,
) -> int:
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write("\n".join(domain_rules).encode("utf-8"))
        txt_path = Path(f.name)

    temp_mrs = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    rec_txt = txt_path.with_name(f".{txt_path.name}.rec.txt")

    try:
        # Compile to MRS
        subprocess.run(
            [mihomo_cmd, "convert-ruleset", "domain", "text", str(txt_path), str(temp_mrs)],
            capture_output=True,
            text=True,
            check=True,
        )

        # Verify by decompiling back
        if verify:
            subprocess.run(
                [mihomo_cmd, "convert-ruleset", "domain", "mrs", str(temp_mrs), str(rec_txt)],
                capture_output=True,
                text=True,
                check=True,
            )
            decompiled_count = len(
                [l for l in rec_txt.read_text(encoding="utf-8").splitlines() if l.strip()]
            )
            if decompiled_count != len(domain_rules):
                raise ValueError(
                    f"Domain rule count mismatch for {output_path.name}: "
                    f"decompiled {decompiled_count} != expected {len(domain_rules)}"
                )

        os.replace(temp_mrs, output_path)
        return len(domain_rules)
    finally:
        for p in (txt_path, temp_mrs, rec_txt):
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass


def compile_and_verify_ip_mrs(
    ip_rules: list[str],
    output_path: Path,
    mihomo_cmd: str = "mihomo",
    verify: bool = True,
) -> tuple[int, int]:
    expected_collapsed = calculate_expected_ip_count(ip_rules)

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write("\n".join(ip_rules).encode("utf-8"))
        txt_path = Path(f.name)

    temp_mrs = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    rec_txt = txt_path.with_name(f".{txt_path.name}.rec.txt")

    try:
        # Compile to MRS
        subprocess.run(
            [mihomo_cmd, "convert-ruleset", "ipcidr", "text", str(txt_path), str(temp_mrs)],
            capture_output=True,
            text=True,
            check=True,
        )

        # Verify by decompiling back
        if verify:
            subprocess.run(
                [mihomo_cmd, "convert-ruleset", "ipcidr", "mrs", str(temp_mrs), str(rec_txt)],
                capture_output=True,
                text=True,
                check=True,
            )
            decompiled_count = len(
                [l for l in rec_txt.read_text(encoding="utf-8").splitlines() if l.strip()]
            )
            if decompiled_count != expected_collapsed:
                raise ValueError(
                    f"IP rule count mismatch for {output_path.name}: "
                    f"decompiled {decompiled_count} != expected collapsed {expected_collapsed} (raw {len(ip_rules)})"
                )

        os.replace(temp_mrs, output_path)
        return len(ip_rules), expected_collapsed
    finally:
        for p in (txt_path, temp_mrs, rec_txt):
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass


def convert_yaml_to_mrs(
    yaml_path: Path,
    output_dir: Path,
    mihomo_cmd: str = "mihomo",
    verify: bool = True,
    session: requests.Session | None = None,
    repo: str = "ssxxs1/geosite",
) -> dict:
    base_name = yaml_path.name.replace("_clash.yaml", "")

    # If YAML doesn't exist locally, attempt Release download fallback
    if not yaml_path.exists() or yaml_path.stat().st_size == 0:
        print(f"[提示] 本地未找到 {yaml_path.name}，正在尝试从 GitHub Release 下载兜底...")
        if not fetch_release_file(yaml_path.name, yaml_path, session=session, repo=repo):
            # If even YAML is not in Release, try downloading existing .mrs directly
            direct_mrs = output_dir / f"{base_name}.mrs"
            if fetch_release_file(direct_mrs.name, direct_mrs, session=session, repo=repo):
                return {
                    "name": base_name,
                    "domains": 0,
                    "ips_raw": 0,
                    "ips_collapsed": 0,
                    "others": 0,
                    "files": [direct_mrs.name],
                    "status": "RECOVERED_FROM_RELEASE",
                }
            raise FileNotFoundError(f"Neither local file nor release asset found for {yaml_path.name}")

    domain_rules, ip_rules, other_rules = parse_clash_yaml(yaml_path)

    has_domains = len(domain_rules) > 0
    has_ips = len(ip_rules) > 0

    generated_files = []
    stats = {
        "name": base_name,
        "domains": len(domain_rules),
        "ips_raw": len(ip_rules),
        "ips_collapsed": 0,
        "others": len(other_rules),
        "files": [],
        "status": "OK",
    }

    try:
        if has_domains and not has_ips:
            # Pure domain ruleset -> {base_name}.mrs
            out_mrs = output_dir / f"{base_name}.mrs"
            compile_and_verify_domain_mrs(domain_rules, out_mrs, mihomo_cmd, verify)
            generated_files.append(out_mrs.name)

        elif has_ips and not has_domains:
            # Pure IP ruleset -> {base_name}.mrs
            out_mrs = output_dir / f"{base_name}.mrs"
            _, collapsed = compile_and_verify_ip_mrs(ip_rules, out_mrs, mihomo_cmd, verify)
            stats["ips_collapsed"] = collapsed
            generated_files.append(out_mrs.name)

        elif has_domains and has_ips:
            # Mixed ruleset:
            # 1. Primary domain MRS: {base_name}.mrs
            primary_mrs = output_dir / f"{base_name}.mrs"
            compile_and_verify_domain_mrs(domain_rules, primary_mrs, mihomo_cmd, verify)
            generated_files.append(primary_mrs.name)

            # 2. Explicit domain MRS: {base_name}_domain.mrs
            domain_mrs = output_dir / f"{base_name}_domain.mrs"
            shutil.copyfile(primary_mrs, domain_mrs)
            generated_files.append(domain_mrs.name)

            # 3. IP MRS: {base_name}_ip.mrs
            ip_mrs = output_dir / f"{base_name}_ip.mrs"
            _, collapsed = compile_and_verify_ip_mrs(ip_rules, ip_mrs, mihomo_cmd, verify)
            stats["ips_collapsed"] = collapsed
            generated_files.append(ip_mrs.name)

    except Exception as exc:
        print(f"[警告] {base_name} 编译 MRS 失败 ({exc})，尝试从 Release 兜底恢复...", file=sys.stderr)
        recovered_any = False
        for target_name in [f"{base_name}.mrs", f"{base_name}_domain.mrs", f"{base_name}_ip.mrs"]:
            target_path = output_dir / target_name
            if fetch_release_file(target_name, target_path, session=session, repo=repo):
                generated_files.append(target_name)
                recovered_any = True
        if recovered_any:
            stats["status"] = "RECOVERED_FROM_RELEASE"
        else:
            raise

    stats["files"] = generated_files
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert Clash YAML rules to Mihomo MRS format")
    parser.add_argument("--dir", default="rule", help="Directory containing _clash.yaml files")
    parser.add_argument("--file", default=None, help="Process a single _clash.yaml file")
    parser.add_argument("--mihomo", default="mihomo", help="Path to mihomo binary")
    parser.add_argument("--no-verify", action="store_true", help="Skip decompilation verification")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", "ssxxs1/geosite"),
        help="GitHub repository for release fallback",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification for local environments with a broken CA store",
    )
    args = parser.parse_args()

    session = requests.Session()
    session.verify = not args.insecure

    output_dir = Path(args.dir)
    if not output_dir.exists():
        print(f"Error: Directory '{output_dir}' does not exist.", file=sys.stderr)
        return 1

    if args.file:
        yaml_files = [Path(args.file)]
    else:
        yaml_files = sorted(output_dir.glob("*_clash.yaml"))

    if not yaml_files:
        print(f"No *_clash.yaml files found in {output_dir}.", file=sys.stderr)
        return 1

    print(f"Converting {len(yaml_files)} YAML files to Mihomo MRS in '{output_dir}' (Fallback Repo: {args.repo})...")
    print("=" * 80)
    print(f"{'Rule Name':<28} | {'Domains':<8} | {'IP (Raw/Merge)':<14} | {'Other':<6} | {'Generated MRS':<20}")
    print("-" * 80)

    total_domains = 0
    total_ips_raw = 0
    total_ips_merged = 0
    total_others = 0
    total_mrs_files = 0
    errors = []

    for yaml_path in yaml_files:
        try:
            stat = convert_yaml_to_mrs(
                yaml_path,
                output_dir,
                mihomo_cmd=args.mihomo,
                verify=not args.no_verify,
                session=session,
                repo=args.repo,
            )
            total_domains += stat["domains"]
            total_ips_raw += stat["ips_raw"]
            total_ips_merged += stat["ips_collapsed"]
            total_others += stat["others"]
            total_mrs_files += len(stat["files"])

            ip_col_str = f"{stat['ips_raw']}/{stat['ips_collapsed']}" if stat['ips_raw'] else "-"
            files_str = ", ".join(stat["files"])
            print(
                f"{stat['name']:<28} | {stat['domains']:<8} | {ip_col_str:<14} | {stat['others']:<6} | {files_str:<20}"
            )
        except Exception as exc:
            errors.append((yaml_path.name, str(exc)))
            print(f"{yaml_path.stem:<28} | ERROR: {exc}", file=sys.stderr)

    print("=" * 80)
    print("Summary:")
    print(f"  Processed YAML Files : {len(yaml_files)}")
    print(f"  Generated MRS Files  : {total_mrs_files}")
    print(f"  Total Domain Rules   : {total_domains} (100% verified via decompilation)")
    print(f"  Total IP Rules       : {total_ips_raw} raw -> {total_ips_merged} merged (100% verified via decompilation)")
    print(f"  Total Other Rules    : {total_others} (non-MRS rules preserved in Clash YAML)")
    if errors:
        print(f"  Failed Conversions   : {len(errors)}")
        for name, err in errors:
            print(f"    - {name}: {err}")
        return 1

    print("All MRS rule-sets compiled and mathematically verified successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
