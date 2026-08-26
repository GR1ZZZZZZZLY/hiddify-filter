#!/usr/bin/env python3
"""Build a Hiddify subscription without Russian-labelled nodes."""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote
from urllib.request import Request, urlopen


SOURCE_URL = os.environ.get(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
)
OUTPUT_FILE = Path(os.environ.get("OUTPUT_FILE", "subscription.txt"))
MIN_CONFIGS = int(os.environ.get("MIN_CONFIGS", "5"))

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


def fetch_source() -> str:
    request = Request(
        SOURCE_URL,
        headers={"User-Agent": "hiddify-country-filter/1.0"},
    )
    with urlopen(request, timeout=45) as response:
        return response.read().decode("utf-8-sig")


def build_subscription(source: str) -> tuple[list[str], int, int]:
    kept: list[str] = []
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

    return kept, removed_ru, duplicates


def main() -> None:
    source = fetch_source()
    source_count = sum(
        1 for line in source.splitlines() if URI_RE.match(line.strip())
    )
    kept, removed_ru, duplicates = build_subscription(source)

    if len(kept) < MIN_CONFIGS:
        raise RuntimeError(
            f"Refusing to replace the last good file: only {len(kept)} configs remain"
        )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print(
        f"source={source_count} kept={len(kept)} "
        f"removed_ru={removed_ru} duplicates={duplicates}"
    )


if __name__ == "__main__":
    main()
