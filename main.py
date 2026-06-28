#!/usr/bin/env python3
"""Convert common proxy rule lists to sing-box rule-set files."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


ROOT = Path(__file__).resolve().parent
DEFAULT_LINKS_FILE = ROOT / "links.txt"
DEFAULT_OUTPUT_DIR = ROOT / "rule"
USER_AGENT = "sing-box-geosite/1.0"
DOMAIN_RULE_TYPES = frozenset({"domain", "domain_suffix", "domain_keyword", "domain_regex"})
IP_RULE_TYPES = frozenset({"ip_cidr", "source_ip_cidr"})

RULE_TYPE_MAP = {
    "DOMAIN-SUFFIX": "domain_suffix",
    "HOST-SUFFIX": "domain_suffix",
    "DOMAIN": "domain",
    "HOST": "domain",
    "DOMAIN-KEYWORD": "domain_keyword",
    "HOST-KEYWORD": "domain_keyword",
    "PROCESS-NAME": "process_name",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "IP6-CIDR": "ip_cidr",
    "SRC-IP-CIDR": "source_ip_cidr",
    "GEOIP": "geoip",
    "DST-PORT": "port",
    "SRC-PORT": "source_port",
    "URL-REGEX": "domain_regex",
    "DOMAIN-REGEX": "domain_regex",
}


def create_session() -> requests.Session:
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


def download(url: str, timeout: float = 30) -> str:
    with create_session() as session:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _payload_items(text: str) -> Iterable[str]:
    """Return rules from Clash YAML or a plain Surge/QuantumultX list."""
    first_content_line = next(
        (line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")),
        "",
    )
    if not first_content_line.startswith("payload:"):
        return text.splitlines()

    try:
        parsed: Any = yaml.safe_load(text)
    except yaml.YAMLError:
        parsed = None

    if isinstance(parsed, dict) and isinstance(parsed.get("payload"), list):
        return (str(item) for item in parsed["payload"])
    return text.splitlines()


def parse_rule(item: str) -> tuple[str, str] | None:
    line = item.strip().strip("'\"")
    if not line or line.startswith(("#", ";", "//")):
        return None

    # Inline comments in these lists are metadata, not part of a domain.
    line = line.split(" #", 1)[0].strip()
    if not line or line.upper().startswith(("AND,", "OR,", "NOT,")):
        return None

    if "," in line:
        raw_type, value = line.split(",", 1)
        raw_type = raw_type.strip().upper()
        value = value.split(",", 1)[0].strip()
    else:
        value = line
        if _is_network(value):
            raw_type = "IP-CIDR"
        elif value.startswith(("+.", ".", "+")):
            raw_type = "DOMAIN-SUFFIX"
            value = value.lstrip("+.")
        else:
            raw_type = "DOMAIN"

    if raw_type == "HOST-WILDCARD":
        # sing-box has regex matching rather than a separate wildcard field.
        value = "^" + re.escape(value).replace(r"\*", ".*").replace(r"\?", ".") + "$"
        mapped_type = "domain_regex"
    else:
        mapped_type = RULE_TYPE_MAP.get(raw_type)
    if not mapped_type or not value:
        return None
    return mapped_type, value


def convert_text(text: str) -> dict[str, Any]:
    grouped: dict[str, set[str]] = {}
    for item in _payload_items(text):
        parsed = parse_rule(item)
        if parsed is None:
            continue
        rule_type, value = parsed
        grouped.setdefault(rule_type, set()).add(value)

    rules = [
        {rule_type: sorted(values)}
        for rule_type, values in sorted(grouped.items(), key=lambda pair: pair[0])
    ]
    return {"version": 2, "rules": rules}


def split_rule_set(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return domain/IP variants when a rule set contains both categories."""
    domain_rules = [rule for rule in data["rules"] if set(rule) <= DOMAIN_RULE_TYPES]
    ip_rules = [rule for rule in data["rules"] if set(rule) <= IP_RULE_TYPES]
    if not domain_rules or not ip_rules:
        return {}
    return {
        "domain": {"version": data["version"], "rules": domain_rules},
        "ip": {"version": data["version"], "rules": ip_rules},
    }


def output_name(url: str) -> str:
    name = Path(urlparse(url).path).name
    if not name:
        raise ValueError(f"URL 中没有可用的文件名: {url}")
    return Path(name).stem


def write_document(
    stem: str,
    data: dict[str, Any],
    output_dir: Path,
    sing_box: str,
    compile_srs: bool,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{stem}.json"
    json_tmp = output_dir / f".{stem}.json.tmp"
    srs_path = output_dir / f"{stem}.srs"
    srs_tmp = output_dir / f".{stem}.srs.tmp"

    json_tmp.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    try:
        if compile_srs:
            subprocess.run(
                [sing_box, "rule-set", "compile", "--output", str(srs_tmp), str(json_tmp)],
                check=True,
            )
            srs_tmp.replace(srs_path)
        json_tmp.replace(json_path)
    finally:
        json_tmp.unlink(missing_ok=True)
        srs_tmp.unlink(missing_ok=True)
    return json_path


def write_rule_set(
    url: str,
    text: str,
    output_dir: Path,
    sing_box: str,
    compile_srs: bool,
) -> list[Path]:
    stem = output_name(url)
    data = convert_text(text)
    documents = {stem: data}
    documents.update(
        {f"{stem}_{kind}": subset for kind, subset in split_rule_set(data).items()}
    )
    return [
        write_document(name, document, output_dir, sing_box, compile_srs)
        for name, document in documents.items()
    ]


def read_links(path: Path) -> list[str]:
    links = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    duplicates = sorted(link for link, count in Counter(links).items() if count > 1)
    if duplicates:
        raise ValueError(f"links 文件包含重复 URL: {', '.join(duplicates)}")
    stems = [output_name(link) for link in links]
    collisions = sorted(stem for stem, count in Counter(stems).items() if count > 1)
    if collisions:
        raise ValueError(f"多个 URL 会覆盖同名输出: {', '.join(collisions)}")
    return links


def run(args: argparse.Namespace) -> int:
    links = read_links(args.links)
    failures: list[tuple[str, Exception]] = []
    downloaded: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {executor.submit(download, link, args.timeout): link for link in links}
        for future in as_completed(futures):
            link = futures[future]
            try:
                downloaded[link] = future.result()
            except Exception as exc:  # Report all failed sources together.
                failures.append((link, exc))

    if failures:
        for link, exc in failures:
            print(f"下载失败: {link}: {exc}", file=sys.stderr)
        return 1

    for link in links:
        paths = write_rule_set(
            link, downloaded[link], args.output, args.sing_box, not args.no_compile
        )
        for path in paths:
            print(f"已生成 {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--links", type=Path, default=DEFAULT_LINKS_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--no-compile", action="store_true", help="只生成 JSON")
    parser.add_argument("--jobs", type=int, default=6, help="并行下载数")
    parser.add_argument("--timeout", type=float, default=30, help="单次请求超时（秒）")
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
