#!/usr/bin/env python3
"""Build safer public subscriptions without RU-labelled nodes for HAPP/Hiddify."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit
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
REPORT_FILE = Path(os.environ.get("REPORT_FILE", "security_report.json"))
MIN_CONFIGS = int(os.environ.get("MIN_CONFIGS", "5"))
MIN_REALITY_CONFIGS = int(os.environ.get("MIN_REALITY_CONFIGS", "1"))
MIN_REALITY_ALL_CONFIGS = int(
    os.environ.get("MIN_REALITY_ALL_CONFIGS", "1")
)

URI_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
BAD_PERCENT_RE = re.compile(r"%(?![0-9a-fA-F]{2})")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
SAFE_TOKEN_RE = re.compile(r"^[a-z0-9._-]{1,64}$", re.I)
RUSSIA_RE = re.compile(
    r"(?:🇷🇺|(?<!\w)(?:RU|RUS|Russia|Russian|Россия|Российская\s+Федерация|"
    r"РФ|Москва|Moscow|Санкт[-\s]?Петербург|Saint\s+Petersburg)(?!\w))",
    re.IGNORECASE,
)

UNSAFE_QUERY_KEYS = {
    "allowinsecure",
    "insecure",
    "skipcertverify",
    "skipverify",
    "tlsallowinsecure",
}
FALSE_VALUES = {"0", "false", "no", "off"}
STRICT_TRANSPORTS = {"tcp", "raw"}
EXPANDED_TRANSPORTS = {"tcp", "raw", "xhttp", "splithttp", "grpc"}
VISION_FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}
RESERVED_DNS_SUFFIXES = (
    ".example",
    ".home",
    ".internal",
    ".invalid",
    ".lan",
    ".local",
    ".localhost",
    ".test",
)


def decode_base64_text(value: str) -> str:
    """Decode standard or URL-safe base64 without requiring padding."""
    value = unquote(value).strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")
    except (UnicodeDecodeError, ValueError, TypeError, binascii.Error):
        return ""


def decode_base64_bytes(value: str) -> bytes | None:
    """Strictly decode URL-safe base64, accepting omitted padding."""
    value = unquote(value).strip()
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        return None
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None


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


def normalized_query(raw_query: str) -> dict[str, list[str]]:
    """Parse a query with bounded field count and case-insensitive names."""
    result: defaultdict[str, list[str]] = defaultdict(list)
    for key, value in parse_qsl(
        raw_query,
        keep_blank_values=True,
        max_num_fields=100,
    ):
        result[key.strip().lower()].append(value.strip())
    return dict(result)


def values_for(query: dict[str, list[str]], *aliases: str) -> list[str]:
    values: list[str] = []
    for alias in aliases:
        values.extend(query.get(alias.lower(), []))
    return values


def unique_value(
    query: dict[str, list[str]],
    aliases: tuple[str, ...],
) -> tuple[str, bool]:
    """Return a value and whether aliases contain conflicting values."""
    all_values = values_for(query, *aliases)
    unique = {value.casefold() for value in all_values}
    if len(unique) > 1:
        return "", True
    values = [value for value in all_values if value != ""]
    return (values[0] if values else ""), False


def has_unsafe_option(query: dict[str, list[str]]) -> bool:
    for key, values in query.items():
        normalized_key = re.sub(r"[-_]", "", key.casefold())
        if normalized_key not in UNSAFE_QUERY_KEYS:
            continue
        if not values or any(value.casefold() not in FALSE_VALUES for value in values):
            return True
    return False


def valid_dns_name(value: str) -> bool:
    value = value.rstrip(".").casefold()
    if not value or len(value) > 253:
        return False
    if value == "localhost" or value.endswith(RESERVED_DNS_SUFFIXES):
        return False
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if "." not in ascii_value:
        return False
    return all(DNS_LABEL_RE.fullmatch(label) for label in ascii_value.split("."))


def valid_public_host(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return valid_dns_name(value)


def valid_server_name(value: str) -> bool:
    """REALITY permits a DNS SNI or a public IP placeholder."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return valid_dns_name(value)


def is_reality_candidate(line: str) -> bool:
    try:
        parsed = urlsplit(line)
        query = normalized_query(parsed.query)
    except (ValueError, UnicodeError):
        return False
    security, conflict = unique_value(query, ("security",))
    return (
        not conflict
        and parsed.scheme.casefold() == "vless"
        and security.casefold() == "reality"
    )


def reality_rejection_reason(
    line: str,
    *,
    allowed_transports: set[str],
    require_vision: bool,
) -> str | None:
    """Return a safe aggregate reason code, never the credential-bearing URI."""
    if len(line) > 8192:
        return "line_too_long"
    if CONTROL_RE.search(line) or BAD_PERCENT_RE.search(line):
        return "malformed_text"

    try:
        parsed = urlsplit(line)
        query = normalized_query(parsed.query)
        port = parsed.port
        host = parsed.hostname
    except (ValueError, UnicodeError):
        return "invalid_uri"

    if parsed.scheme.casefold() != "vless":
        return "not_vless"
    if parsed.password is not None:
        return "invalid_userinfo"

    user_id = unquote(parsed.username or "")
    try:
        parsed_uuid = uuid.UUID(user_id)
    except (ValueError, AttributeError):
        return "invalid_uuid"
    if parsed_uuid.int == 0:
        return "invalid_uuid"

    if not host or not valid_public_host(host):
        return "non_public_endpoint"
    if port is None or not 1 <= port <= 65535:
        return "invalid_port"

    fragment = unquote(parsed.fragment)
    if len(fragment) > 300 or CONTROL_RE.search(fragment):
        return "invalid_display_name"
    if has_unsafe_option(query):
        return "unsafe_option"

    security, conflict = unique_value(query, ("security",))
    if conflict:
        return "conflicting_security"
    if security.casefold() != "reality":
        return "not_reality"

    encryption, conflict = unique_value(query, ("encryption",))
    if conflict:
        return "conflicting_encryption"
    if encryption.casefold() != "none":
        return "invalid_encryption"

    transport, conflict = unique_value(query, ("type", "network"))
    if conflict:
        return "conflicting_transport"
    transport = transport.casefold()
    if transport not in allowed_transports:
        return "unsupported_transport"

    flow, conflict = unique_value(query, ("flow",))
    if conflict:
        return "conflicting_flow"
    flow = flow.casefold()
    if flow and flow not in VISION_FLOWS:
        return "invalid_flow"
    if require_vision and flow not in VISION_FLOWS:
        return "vision_required"

    public_key, conflict = unique_value(
        query,
        ("pbk", "publickey", "password"),
    )
    if conflict:
        return "conflicting_reality_key"
    decoded_key = decode_base64_bytes(public_key)
    if decoded_key is None:
        return "missing_or_invalid_reality_key"
    if len(decoded_key) != 32:
        return "invalid_reality_key_length"

    server_name, conflict = unique_value(query, ("sni", "servername"))
    if conflict:
        return "conflicting_server_name"
    if not server_name or not valid_server_name(server_name):
        return "missing_or_invalid_server_name"

    fingerprint, conflict = unique_value(query, ("fp", "fingerprint"))
    if conflict:
        return "conflicting_fingerprint"
    if (
        not fingerprint
        or fingerprint.casefold() == "unsafe"
        or not SAFE_TOKEN_RE.fullmatch(fingerprint)
    ):
        return "missing_or_invalid_fingerprint"

    short_id, conflict = unique_value(query, ("sid", "shortid"))
    if conflict:
        return "conflicting_short_id"
    if short_id and (
        len(short_id) > 16
        or len(short_id) % 2 != 0
        or not re.fullmatch(r"[0-9a-fA-F]+", short_id)
    ):
        return "invalid_short_id"

    return None


def build_subscriptions(
    source: str,
) -> tuple[list[str], list[str], list[str], dict[str, object]]:
    kept: list[str] = []
    reality_tcp: list[str] = []
    reality_all: list[str] = []
    seen: set[str] = set()
    removed_ru = 0
    duplicates = 0
    reality_candidates = 0
    rejected_reality: Counter[str] = Counter()
    excluded_from_strict: Counter[str] = Counter()

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

        if not is_reality_candidate(line):
            continue
        reality_candidates += 1

        expanded_reason = reality_rejection_reason(
            line,
            allowed_transports=EXPANDED_TRANSPORTS,
            require_vision=False,
        )
        if expanded_reason is not None:
            rejected_reality[expanded_reason] += 1
            continue
        reality_all.append(line)

        strict_reason = reality_rejection_reason(
            line,
            allowed_transports=STRICT_TRANSPORTS,
            require_vision=True,
        )
        if strict_reason is None:
            reality_tcp.append(line)
        else:
            excluded_from_strict[strict_reason] += 1

    report: dict[str, object] = {
        "source": SOURCE_URL,
        "source_configs": sum(
            1 for line in source.splitlines() if URI_RE.match(line.strip())
        ),
        "outputs": {
            "all_protocols_without_ru": len(kept),
            "safe_reality_expanded": len(reality_all),
            "safe_reality_tcp_vision": len(reality_tcp),
        },
        "filtering": {
            "duplicates": duplicates,
            "reality_candidates": reality_candidates,
            "reality_rejected": dict(sorted(rejected_reality.items())),
            "safe_reality_excluded_from_tcp_vision": dict(
                sorted(excluded_from_strict.items())
            ),
            "ru_label": removed_ru,
        },
        "limitations": [
            "Availability tests and URI validation do not establish operator trust.",
            "Country filtering relies on the source label and is not a GeoIP guarantee.",
            "The all-protocols reserve file is not covered by strict REALITY validation.",
        ],
    }
    return kept, reality_tcp, reality_all, report


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


def write_report(path: Path, report: dict[str, object]) -> None:
    """Write a stable report without timestamps or credential-bearing links."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    source = fetch_source()
    kept, reality_tcp, reality_all, report = build_subscriptions(source)

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
        REPORT_FILE.resolve(),
    }
    if len(output_paths) != 4:
        raise RuntimeError("All output files must have different paths")

    write_subscription(OUTPUT_FILE, kept, "VERIFIED резерв без RU")
    write_subscription(
        REALITY_OUTPUT_FILE,
        reality_tcp,
        "REALITY TCP SAFE без RU",
    )
    write_subscription(
        REALITY_ALL_OUTPUT_FILE,
        reality_all,
        "REALITY SAFE расширенный без RU",
    )
    write_report(REPORT_FILE, report)

    outputs = report["outputs"]
    filtering = report["filtering"]
    print(
        f"source={report['source_configs']} kept={outputs['all_protocols_without_ru']} "
        f"reality_tcp_safe={outputs['safe_reality_tcp_vision']} "
        f"reality_all_safe={outputs['safe_reality_expanded']} "
        f"removed_ru={filtering['ru_label']} duplicates={filtering['duplicates']}"
    )


def fetch_source() -> str:
    request = Request(
        SOURCE_URL,
        headers={"User-Agent": "happ-reality-safety-filter/4.0"},
    )
    with urlopen(request, timeout=45) as response:
        return response.read().decode("utf-8-sig")


if __name__ == "__main__":
    main()
