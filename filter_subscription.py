#!/usr/bin/env python3
"""Build ranked, safer public subscriptions for HAPP/Hiddify.

Only nodes from the upstream ``verified`` feed can be published.  The upstream
``fast``, ``secure`` and ``top100`` feeds are ranking signals, not additional
sources of credentials.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit
from urllib.request import Request, urlopen


SOURCE_URL = os.environ.get(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
FAST_SOURCE_URL = os.environ.get(
    "FAST_SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
)
SECURE_SOURCE_URL = os.environ.get(
    "SECURE_SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt",
)
TOP_SOURCE_URL = os.environ.get(
    "TOP_SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
)
OUTPUT_FILE = Path(os.environ.get("OUTPUT_FILE", "subscription.txt"))
REALITY_OUTPUT_FILE = Path(
    os.environ.get("REALITY_OUTPUT_FILE", "reality_tcp.txt")
)
REALITY_ALL_OUTPUT_FILE = Path(
    os.environ.get("REALITY_ALL_OUTPUT_FILE", "reality_all.txt")
)
BEST_OUTPUT_FILE = Path(os.environ.get("BEST_OUTPUT_FILE", "reality_best.txt"))
STABLE_OUTPUT_FILE = Path(
    os.environ.get("STABLE_OUTPUT_FILE", "reality_stable.txt")
)
REPORT_FILE = Path(os.environ.get("REPORT_FILE", "security_report.json"))
HISTORY_FILE = Path(os.environ.get("HISTORY_FILE", "node_history.json"))
CHECKSUMS_FILE = Path(os.environ.get("CHECKSUMS_FILE", "checksums.sha256"))
MIN_CONFIGS = int(os.environ.get("MIN_CONFIGS", "5"))
MIN_REALITY_CONFIGS = int(os.environ.get("MIN_REALITY_CONFIGS", "1"))
MIN_REALITY_ALL_CONFIGS = int(
    os.environ.get("MIN_REALITY_ALL_CONFIGS", "1")
)
MIN_BEST_CONFIGS = int(os.environ.get("MIN_BEST_CONFIGS", "1"))
MIN_STABLE_CONFIGS = int(os.environ.get("MIN_STABLE_CONFIGS", "1"))
BEST_LIMIT = int(os.environ.get("BEST_LIMIT", "50"))
STABLE_LIMIT = int(os.environ.get("STABLE_LIMIT", "100"))

HISTORY_VERSION = 1
TRUST_STREAK = 2
MAX_SEEN_STREAK = 8
MAX_MISS_STREAK = 8
MAX_SEEN_TOTAL = 255
MAX_REVIVALS = 255

RANK_WEIGHTS = {
    "top100": 1600,
    "top100_position_max": 300,
    "secure": 600,
    "fast": 500,
    "trusted": 200,
    "seen_streak": 15,
}

URI_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
BAD_PERCENT_RE = re.compile(r"%(?![0-9a-fA-F]{2})")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
SAFE_TOKEN_RE = re.compile(r"^[a-z0-9._-]{1,64}$", re.I)
COUNTRY_LABEL_RE = re.compile(
    r"^\s*(?:[\U0001F1E6-\U0001F1FF]{2}\s*)?"
    r"([A-Za-z]{2})(?:\s*[\U0001F1E6-\U0001F1FF]{2})?\s*\|"
)
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


def iter_uri_lines(source: str):
    """Yield stripped subscription URIs, ignoring comments and blank lines."""
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if line and URI_RE.match(line):
            yield line


def source_config_count(source: str) -> int:
    return sum(1 for _ in iter_uri_lines(source))


def node_identity(line: str) -> str | None:
    """Return a credential-safe identity hash, excluding the display name.

    Query order and key case are normalized so the same connection can be
    matched across upstream quality feeds even when its visible label differs.
    The canonical connection string itself is never persisted.
    """
    try:
        parsed = urlsplit(line)
        query = sorted(
            (key.casefold(), value)
            for key, value in parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=100,
            )
        )
        host = (parsed.hostname or "").casefold()
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    if not parsed.scheme or not host or port is None:
        return None
    canonical = json.dumps(
        [
            parsed.scheme.casefold(),
            unquote(parsed.username or "").casefold(),
            host,
            port,
            parsed.path,
            query,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def source_identities(source: str) -> set[str]:
    identities: set[str] = set()
    for line in iter_uri_lines(source):
        identity = node_identity(line)
        if identity is not None:
            identities.add(identity)
    return identities


def source_identity_positions(source: str) -> dict[str, int]:
    positions: dict[str, int] = {}
    for position, line in enumerate(iter_uri_lines(source)):
        identity = node_identity(line)
        if identity is not None and identity not in positions:
            positions[identity] = position
    return positions


def country_code(line: str) -> str:
    """Read a two-letter source label; this is not an independent GeoIP check."""
    for name in node_names(line):
        match = COUNTRY_LABEL_RE.search(name)
        if match:
            return match.group(1).upper()
    return "ZZ"


def endpoint_and_network(line: str) -> tuple[str, str]:
    """Return in-memory diversity buckets. They are never written to reports."""
    parsed = urlsplit(line)
    host = (parsed.hostname or "").casefold()
    port = parsed.port or 0
    endpoint = f"{host}:{port}"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return endpoint, f"dns:{host}"
    prefix = 24 if address.version == 4 else 48
    network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    return endpoint, f"ip:{network}"


def _bounded_integer(value: object, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return min(max(value, 0), maximum)


def load_history(path: Path) -> dict[str, dict[str, object]]:
    """Load and sanitize the opaque history file.

    Unknown fields are discarded. A malformed existing file aborts the build
    instead of silently destroying accumulated history.
    """
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read history file: {error}") from error
    if not isinstance(document, dict) or document.get("version") != HISTORY_VERSION:
        raise RuntimeError("Unsupported or malformed history file")
    raw_nodes = document.get("nodes")
    if not isinstance(raw_nodes, dict):
        raise RuntimeError("Malformed history nodes")

    nodes: dict[str, dict[str, object]] = {}
    for identity, raw_entry in raw_nodes.items():
        if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise RuntimeError("History contains a non-hash node identifier")
        if not isinstance(raw_entry, dict):
            raise RuntimeError("History contains a malformed node record")
        nodes[identity] = {
            "seen_streak": _bounded_integer(
                raw_entry.get("seen_streak"), MAX_SEEN_STREAK
            ),
            "miss_streak": _bounded_integer(
                raw_entry.get("miss_streak"), MAX_MISS_STREAK
            ),
            "seen_total": _bounded_integer(
                raw_entry.get("seen_total"), MAX_SEEN_TOTAL
            ),
            "trusted": raw_entry.get("trusted") is True,
            "revivals": _bounded_integer(
                raw_entry.get("revivals"), MAX_REVIVALS
            ),
        }
    return nodes


def update_history(
    current_identities: set[str],
    previous: dict[str, dict[str, object]],
) -> tuple[dict[str, dict[str, object]], dict[str, int]]:
    """Advance consecutive-presence and quarantine counters by one run."""
    updated: dict[str, dict[str, object]] = {}
    revived = 0
    expired = 0

    for identity in sorted(current_identities):
        old = previous.get(identity)
        if old is None:
            entry = {
                "seen_streak": 1,
                "miss_streak": 0,
                "seen_total": 1,
                "trusted": False,
                "revivals": 0,
            }
        else:
            old_misses = int(old["miss_streak"])
            new_streak = (
                min(int(old["seen_streak"]) + 1, MAX_SEEN_STREAK)
                if old_misses == 0
                else 1
            )
            was_revived = old_misses > 0 and old["trusted"] is True
            if was_revived:
                revived += 1
            entry = {
                "seen_streak": new_streak,
                "miss_streak": 0,
                "seen_total": min(int(old["seen_total"]) + 1, MAX_SEEN_TOTAL),
                "trusted": old["trusted"] is True or new_streak >= TRUST_STREAK,
                "revivals": min(
                    int(old["revivals"]) + int(was_revived), MAX_REVIVALS
                ),
            }
        updated[identity] = entry

    for identity in sorted(set(previous) - current_identities):
        old = previous[identity]
        misses = int(old["miss_streak"]) + 1
        if misses > MAX_MISS_STREAK:
            expired += 1
            continue
        updated[identity] = {
            "seen_streak": 0,
            "miss_streak": misses,
            "seen_total": int(old["seen_total"]),
            "trusted": old["trusted"] is True,
            "revivals": int(old["revivals"]),
        }

    current_entries = [updated[identity] for identity in current_identities]
    stats = {
        "current_fresh": sum(entry["trusted"] is not True for entry in current_entries),
        "current_trusted": sum(entry["trusted"] is True for entry in current_entries),
        "expired": expired,
        "quarantined": sum(
            identity not in current_identities
            and entry["trusted"] is True
            and int(entry["miss_streak"]) > 0
            for identity, entry in updated.items()
        ),
        "records": len(updated),
        "revived": revived,
    }
    return updated, stats


@dataclass(frozen=True)
class RankedNode:
    line: str
    identity: str
    score: int
    country: str
    endpoint: str
    network: str


def rank_nodes(
    lines: list[str],
    *,
    fast_source: str,
    secure_source: str,
    top_source: str,
    history: dict[str, dict[str, object]],
) -> tuple[list[RankedNode], dict[str, object]]:
    """Rank verified strict nodes using upstream tiers plus local history."""
    fast = source_identities(fast_source)
    secure = source_identities(secure_source)
    top_positions = source_identity_positions(top_source)
    matched = Counter()
    ranked: list[RankedNode] = []
    ranked_identities: set[str] = set()

    for line in lines:
        identity = node_identity(line)
        if identity is None:
            continue
        if identity in ranked_identities:
            matched["duplicate_identity_collapsed"] += 1
            continue
        ranked_identities.add(identity)
        entry = history[identity]
        score = 0
        if identity in top_positions:
            matched["top100"] += 1
            score += RANK_WEIGHTS["top100"]
            score += max(
                0,
                RANK_WEIGHTS["top100_position_max"] - top_positions[identity] * 3,
            )
        if identity in secure:
            matched["secure"] += 1
            score += RANK_WEIGHTS["secure"]
        if identity in fast:
            matched["fast"] += 1
            score += RANK_WEIGHTS["fast"]
        if entry["trusted"] is True:
            matched["history_trusted"] += 1
            score += RANK_WEIGHTS["trusted"]
        score += int(entry["seen_streak"]) * RANK_WEIGHTS["seen_streak"]
        endpoint, network = endpoint_and_network(line)
        ranked.append(
            RankedNode(
                line=line,
                identity=identity,
                score=score,
                country=country_code(line),
                endpoint=endpoint,
                network=network,
            )
        )

    ranked.sort(key=lambda node: (-node.score, node.country, node.identity))
    report = {
        "matched_strict_candidates": dict(sorted(matched.items())),
        "weights": dict(RANK_WEIGHTS),
    }
    return ranked, report


def select_diverse(
    ranked: list[RankedNode],
    *,
    limit: int,
    max_per_country: int,
    max_per_endpoint: int,
    max_per_network: int,
) -> tuple[list[str], dict[str, int]]:
    """Select a deterministic subset while limiting correlated endpoints."""
    selected: list[str] = []
    countries: Counter[str] = Counter()
    endpoints: Counter[str] = Counter()
    networks: Counter[str] = Counter()
    skipped = Counter()

    for node in ranked:
        if len(selected) >= limit:
            break
        if countries[node.country] >= max_per_country:
            skipped["country_cap"] += 1
            continue
        if endpoints[node.endpoint] >= max_per_endpoint:
            skipped["endpoint_cap"] += 1
            continue
        if networks[node.network] >= max_per_network:
            skipped["network_cap"] += 1
            continue
        selected.append(node.line)
        countries[node.country] += 1
        endpoints[node.endpoint] += 1
        networks[node.network] += 1

    stats = {
        "countries": len(countries),
        "largest_country_group": max(countries.values(), default=0),
        "selected": len(selected),
        "skipped_country_cap": skipped["country_cap"],
        "skipped_endpoint_cap": skipped["endpoint_cap"],
        "skipped_network_cap": skipped["network_cap"],
    }
    return selected, stats


def build_quality_profiles(
    strict_lines: list[str],
    *,
    fast_source: str,
    secure_source: str,
    top_source: str,
    previous_history: dict[str, dict[str, object]],
) -> tuple[
    list[str],
    list[str],
    dict[str, object],
    dict[str, object],
]:
    current_ids = {
        identity
        for line in strict_lines
        if (identity := node_identity(line)) is not None
    }
    history_nodes, history_stats = update_history(current_ids, previous_history)
    ranked, ranking_report = rank_nodes(
        strict_lines,
        fast_source=fast_source,
        secure_source=secure_source,
        top_source=top_source,
        history=history_nodes,
    )

    best, best_diversity = select_diverse(
        ranked,
        limit=BEST_LIMIT,
        max_per_country=12,
        max_per_endpoint=2,
        max_per_network=3,
    )
    trusted_ranked = [
        node for node in ranked if history_nodes[node.identity]["trusted"] is True
    ]
    bootstrap = not trusted_ranked
    stable_pool = ranked if bootstrap else trusted_ranked
    stable, stable_diversity = select_diverse(
        stable_pool,
        limit=STABLE_LIMIT,
        max_per_country=30,
        max_per_endpoint=3,
        max_per_network=5,
    )
    history_stats["bootstrap_fill"] = len(stable) if bootstrap else 0
    history_stats["stable_candidates"] = len(stable_pool)

    quality_report = {
        "ranking": ranking_report,
        "diversity": {
            "best": {
                "limits": {
                    "nodes": BEST_LIMIT,
                    "per_country": 12,
                    "per_endpoint": 2,
                    "per_ip_network": 3,
                },
                **best_diversity,
            },
            "stable": {
                "limits": {
                    "nodes": STABLE_LIMIT,
                    "per_country": 30,
                    "per_endpoint": 3,
                    "per_ip_network": 5,
                },
                **stable_diversity,
            },
        },
        "history": history_stats,
    }
    history_document: dict[str, object] = {
        "version": HISTORY_VERSION,
        "nodes": history_nodes,
    }
    return best, stable, history_document, quality_report


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
        "source_configs": source_config_count(source),
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


def write_checksums(path: Path, generated_files: list[Path]) -> None:
    """Publish hashes so downloaded subscription files can be compared."""
    lines = []
    for generated in sorted(generated_files, key=lambda item: item.name):
        digest = hashlib.sha256(generated.read_bytes()).hexdigest()
        lines.append(f"{digest}  {generated.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    sources = {
        "verified": fetch_source(SOURCE_URL),
        "fast": fetch_source(FAST_SOURCE_URL),
        "secure": fetch_source(SECURE_SOURCE_URL),
        "top100": fetch_source(TOP_SOURCE_URL),
    }
    kept, reality_tcp, reality_all, report = build_subscriptions(
        sources["verified"]
    )
    previous_history = load_history(HISTORY_FILE)
    reality_best, reality_stable, history, quality = build_quality_profiles(
        reality_tcp,
        fast_source=sources["fast"],
        secure_source=sources["secure"],
        top_source=sources["top100"],
        previous_history=previous_history,
    )

    report["version"] = 5
    report["sources"] = {
        "verified": {
            "url": SOURCE_URL,
            "configs": source_config_count(sources["verified"]),
            "publishes_nodes": True,
        },
        "fast": {
            "url": FAST_SOURCE_URL,
            "configs": source_config_count(sources["fast"]),
            "publishes_nodes": False,
        },
        "secure": {
            "url": SECURE_SOURCE_URL,
            "configs": source_config_count(sources["secure"]),
            "publishes_nodes": False,
        },
        "top100": {
            "url": TOP_SOURCE_URL,
            "configs": source_config_count(sources["top100"]),
            "publishes_nodes": False,
        },
    }
    outputs = report["outputs"]
    outputs["ranked_best"] = len(reality_best)
    outputs["history_stable"] = len(reality_stable)
    report["ranking"] = quality["ranking"]
    report["diversity"] = quality["diversity"]
    report["history"] = quality["history"]
    report["limitations"].extend(
        [
            "Quality tiers are upstream observations, not guarantees of future availability.",
            "History contains only identity hashes and counters; it cannot retain a disappeared URI.",
        ]
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
    if len(reality_best) < MIN_BEST_CONFIGS:
        raise RuntimeError(
            "Refusing to replace the last good best profile: "
            f"only {len(reality_best)} configs remain"
        )
    if len(reality_stable) < MIN_STABLE_CONFIGS:
        raise RuntimeError(
            "Refusing to replace the last good stable profile: "
            f"only {len(reality_stable)} configs remain"
        )

    output_paths = {
        OUTPUT_FILE.resolve(),
        REALITY_OUTPUT_FILE.resolve(),
        REALITY_ALL_OUTPUT_FILE.resolve(),
        BEST_OUTPUT_FILE.resolve(),
        STABLE_OUTPUT_FILE.resolve(),
        REPORT_FILE.resolve(),
        HISTORY_FILE.resolve(),
        CHECKSUMS_FILE.resolve(),
    }
    if len(output_paths) != 8:
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
    write_subscription(
        BEST_OUTPUT_FILE,
        reality_best,
        "REALITY BEST без RU",
    )
    write_subscription(
        STABLE_OUTPUT_FILE,
        reality_stable,
        "REALITY STABLE без RU",
    )
    write_report(REPORT_FILE, report)
    write_report(HISTORY_FILE, history)
    write_checksums(
        CHECKSUMS_FILE,
        [
            OUTPUT_FILE,
            REALITY_OUTPUT_FILE,
            REALITY_ALL_OUTPUT_FILE,
            BEST_OUTPUT_FILE,
            STABLE_OUTPUT_FILE,
        ],
    )

    filtering = report["filtering"]
    print(
        f"source={report['source_configs']} kept={outputs['all_protocols_without_ru']} "
        f"reality_tcp_safe={outputs['safe_reality_tcp_vision']} "
        f"reality_all_safe={outputs['safe_reality_expanded']} "
        f"best={outputs['ranked_best']} stable={outputs['history_stable']} "
        f"removed_ru={filtering['ru_label']} duplicates={filtering['duplicates']}"
    )


def fetch_source(url: str = SOURCE_URL) -> str:
    request = Request(
        url,
        headers={"User-Agent": "happ-reality-safety-filter/5.0"},
    )
    with urlopen(request, timeout=45) as response:
        return response.read().decode("utf-8-sig")


if __name__ == "__main__":
    main()
