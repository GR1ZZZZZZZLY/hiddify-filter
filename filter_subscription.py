#!/usr/bin/env python3
"""Build three verified subscriptions without RU nodes for HAPP/Hiddify."""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request, urlopen


SOURCE_URL = os.environ.get(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
OUTPUT_FILE = Path(os.environ.get("OUTPUT_FILE", "subscription.txt"))
REALITY_OUTPUT_FILE = Path(
    os.environ.get("REALITY_OUTPUT_FILE", "reality_tcp.txt")
)
REALITY_ALL_OUTPUT_FILE = Path(
    os.environ.get("REALITY_ALL_OUTPUT_FILE", "reality_all.txt")
)
MIN_CONFIGS = int(os.environ.get("MIN_CONFIGS", "5"))
MIN_REALITY_CONFIGS = int(os.environ.get("MIN_REALITY_CONFIGS", "1"))
MIN_REALITY_ALL_CONFIGS = int(
    os.environ.get("MIN_REALITY_ALL_CONFIGS", "1")
)

URI_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
RUSSIA_RE = re.compile(
    r"(?:🇷🇺|(?<!\w)(?:RU|RUS|Russia|Russian|Россия|Российская\s+Федерация|"
    r"РФ|Москва|Moscow|Санкт[-\s]?Петербург|Saint\s+Petersburg)(?!\w))",
    re.IGNORECASE,
)


def decode_base64_text(value: str) -> str:
    """Decode standard or URL-safe base64 without requiring padding."""
    value = unquote(value).strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")
    except (UnicodeDecodeError, ValueError, TypeError):
        return ""


def node_names(line: str) -> list[str]:
    """Extract the visible node name from common subscription URI formats."""
    names: list[str] = []

    if "#" in line:
        fragment = unquote(line.split("#", 1)[1]).strip()
        if fragment:
            names.append(fragment)

    scheme = line.split("://", 1)[0].lower()

    if scheme == "vmess":
        payload = line.split("://", 1)[1].split("#", 1)[0]
        decoded = decode_base64_text(payload)
        if decoded:
            try:
                value = json.loads(decoded).get("ps", "")
            except (json.JSONDecodeError, AttributeError):
                value = ""
            if isinstance(value, str) and value.strip():
                names.append(value.strip())

    if scheme == "ssr":
        payload = line.split("://", 1)[1].split("#", 1)[0]
        decoded = decode_base64_text(payload)
        if "/?" in decoded:
            query = parse_qs(decoded.split("/?", 1)[1])
            for encoded_name in query.get("remarks", []):
                value = decode_base64_text(encoded_name).strip()
                if value:
                    names.append(value)

    return names


def is_russian_node(line: str) -> bool:
    return any(RUSSIA_RE.search(name) for name in node_names(line))


def first_query_value(query: dict[str, list[str]], name: str) -> str:
    """Return the first case-insensitive query value in lowercase."""
    for key, values in query.items():
        if key.lower() == name and values:
            return values[0].strip().lower()
    return ""


def is_reality_tcp_vision(line: str) -> bool:
    """Keep only VLESS over TCP/RAW with REALITY and XTLS Vision."""
    try:
        parsed = urlsplit(line)
    except ValueError:
        return False

    if parsed.scheme.lower() != "vless":
        return False

    query = parse_qs(parsed.query, keep_blank_values=True)
    transport = first_query_value(query, "type")
    if not transport:
        transport = first_query_value(query, "network")

    security = first_query_value(query, "security")
    flow = first_query_value(query, "flow")

    # Xray renamed the old transport label "tcp" to "raw". Subscription
    # links in the wild use both names for the same transport family.
    return (
        transport in {"", "tcp", "raw"}
        and security == "reality"
        and flow.startswith("xtls-rprx-vision")
    )


def is_reality_supported(line: str) -> bool:
    """Keep VLESS REALITY links using a transport supported by Xray."""
    try:
        parsed = urlsplit(line)
    except ValueError:
        return False

    if parsed.scheme.lower() != "vless":
        return False

    query = parse_qs(parsed.query, keep_blank_values=True)
    transport = first_query_value(query, "type")
    if not transport:
        transport = first_query_value(query, "network")

    security = first_query_value(query, "security")
    return security == "reality" and transport in {
        "",
        "tcp",
        "raw",
        "xhttp",
        "splithttp",
        "grpc",
    }


def fetch_source() -> str:
    request = Request(
        SOURCE_URL,
        headers={"User-Agent": "hiddify-country-filter/1.0"},
    )
    with urlopen(request, timeout=45) as response:
        return response.read().decode("utf-8-sig")


def build_subscriptions(
    source: str,
) -> tuple[list[str], list[str], list[str], int, int]:
    kept: list[str] = []
    reality_tcp: list[str] = []
    reality_all: list[str] = []
    seen: set[str] = set()
    removed_ru = 0
    duplicates = 0

    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or not URI_RE.match(line):
            continue
        if is_russian_node(line):
            removed_ru += 1
            continue
        if line in seen:
            duplicates += 1
            continue
        seen.add(line)
        kept.append(line)
        if is_reality_tcp_vision(line):
            reality_tcp.append(line)
        if is_reality_supported(line):
            reality_all.append(line)

    return kept, reality_tcp, reality_all, removed_ru, duplicates


def write_subscription(path: Path, lines: list[str], title: str) -> None:
    """Atomically replace one generated subscription."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    headers = [
        f"#profile-title: {title}",
        "#profile-update-interval: 1",
        "#ping-type: proxy",
        "#check-url-via-proxy: https://cp.cloudflare.com/generate_204",
    ]
    temporary.write_text(
        "\n".join(headers + lines) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    source = fetch_source()
    source_count = sum(
        1 for line in source.splitlines() if URI_RE.match(line.strip())
    )
    kept, reality_tcp, reality_all, removed_ru, duplicates = build_subscriptions(
        source
    )

    if len(kept) < MIN_CONFIGS:
        raise RuntimeError(
            f"Refusing to replace the last good file: only {len(kept)} configs remain"
        )
    if len(reality_tcp) < MIN_REALITY_CONFIGS:
        raise RuntimeError(
            "Refusing to replace the last good Reality file: "
            f"only {len(reality_tcp)} matching configs remain"
        )
    if len(reality_all) < MIN_REALITY_ALL_CONFIGS:
        raise RuntimeError(
            "Refusing to replace the last good expanded Reality file: "
            f"only {len(reality_all)} matching configs remain"
        )

    output_paths = {
        OUTPUT_FILE.resolve(),
        REALITY_OUTPUT_FILE.resolve(),
        REALITY_ALL_OUTPUT_FILE.resolve(),
    }
    if len(output_paths) != 3:
        raise RuntimeError("All output files must have different paths")

    write_subscription(OUTPUT_FILE, kept, "VERIFIED без RU")
    write_subscription(
        REALITY_OUTPUT_FILE,
        reality_tcp,
        "REALITY TCP Vision без RU",
    )
    write_subscription(
        REALITY_ALL_OUTPUT_FILE,
        reality_all,
        "REALITY расширенный без RU",
    )
    print(
        f"source={source_count} kept={len(kept)} "
        f"reality_tcp={len(reality_tcp)} "
        f"reality_all={len(reality_all)} "
        f"removed_ru={removed_ru} duplicates={duplicates}"
    )


if __name__ == "__main__":
    main()
