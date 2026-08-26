#!/usr/bin/env python3
"""Offline tests for the subscription safety filter."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

import filter_subscription as target


UUID = "e08ff179-2c35-4a95-a8f8-6b2f7bd315ef"
PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def reality_link(
    *,
    host: str = "1.1.1.1",
    name: str = "US test",
    transport: str = "tcp",
    flow: str | None = "xtls-rprx-vision",
    overrides: dict[str, str | None] | None = None,
) -> str:
    query: dict[str, str] = {
        "security": "reality",
        "encryption": "none",
        "type": transport,
        "pbk": PUBLIC_KEY,
        "sni": "www.cloudflare.com",
        "fp": "chrome",
        "sid": "12ab",
    }
    if flow is not None:
        query["flow"] = flow
    for key, value in (overrides or {}).items():
        if value is None:
            query.pop(key, None)
        else:
            query[key] = value
    return f"vless://{UUID}@{host}:443?{urlencode(query)}#{name}"


class RealitySafetyTests(unittest.TestCase):
    def reason(self, line: str, *, strict: bool = True) -> str | None:
        return target.reality_rejection_reason(
            line,
            allowed_transports=(
                target.STRICT_TRANSPORTS if strict else target.EXPANDED_TRANSPORTS
            ),
            require_vision=strict,
        )

    def test_accepts_well_formed_tcp_vision(self) -> None:
        self.assertIsNone(self.reason(reality_link()))

    def test_accepts_grpc_only_in_expanded_profile(self) -> None:
        line = reality_link(transport="grpc", flow=None)
        self.assertEqual(self.reason(line), "unsupported_transport")
        self.assertIsNone(self.reason(line, strict=False))

    def test_accepts_empty_short_id(self) -> None:
        self.assertIsNone(self.reason(reality_link(overrides={"sid": ""})))

    def test_rejects_unsafe_certificate_option(self) -> None:
        line = reality_link(overrides={"allowInsecure": "1"})
        self.assertEqual(self.reason(line), "unsafe_option")

    def test_explicit_false_unsafe_option_is_not_rejected(self) -> None:
        line = reality_link(overrides={"allowInsecure": "false"})
        self.assertIsNone(self.reason(line))

    def test_rejects_private_endpoint(self) -> None:
        self.assertEqual(
            self.reason(reality_link(host="192.168.1.10")),
            "non_public_endpoint",
        )

    def test_rejects_missing_fingerprint(self) -> None:
        line = reality_link(overrides={"fp": None})
        self.assertEqual(self.reason(line), "missing_or_invalid_fingerprint")

    def test_rejects_bad_public_key(self) -> None:
        line = reality_link(overrides={"pbk": "not-a-32-byte-key"})
        self.assertEqual(self.reason(line), "missing_or_invalid_reality_key")

    def test_rejects_odd_short_id(self) -> None:
        line = reality_link(overrides={"sid": "abc"})
        self.assertEqual(self.reason(line), "invalid_short_id")

    def test_rejects_conflicting_security(self) -> None:
        base = reality_link()
        before_fragment, fragment = base.split("#", 1)
        line = f"{before_fragment}&security=tls#{fragment}"
        self.assertEqual(self.reason(line), "conflicting_security")

    def test_build_removes_ru_and_deduplicates(self) -> None:
        good = reality_link(name="US good")
        ru = reality_link(name="RU Russia")
        unsafe = reality_link(
            name="US unsafe",
            overrides={"allowInsecure": "true"},
        )
        grpc = reality_link(name="DE grpc", transport="grpc", flow=None)
        source = "\n".join([good, good, ru, unsafe, grpc])

        kept, strict, expanded, report = target.build_subscriptions(source)

        self.assertEqual(len(kept), 3)
        self.assertEqual(strict, [good])
        self.assertEqual(expanded, [good, grpc])
        self.assertEqual(report["filtering"]["duplicates"], 1)
        self.assertEqual(report["filtering"]["ru_label"], 1)
        self.assertEqual(
            report["filtering"]["reality_rejected"],
            {"unsafe_option": 1},
        )


class QualityProfileTests(unittest.TestCase):
    def test_identity_ignores_label_and_query_order(self) -> None:
        first = reality_link(name="US first")
        before_fragment = first.split("#", 1)[0]
        prefix, query = before_fragment.split("?", 1)
        second = f"{prefix}?{'&'.join(reversed(query.split('&')))}#DE second"
        self.assertEqual(target.node_identity(first), target.node_identity(second))

    def test_country_label_accepts_flag_before_or_after_code(self) -> None:
        self.assertEqual(
            target.country_code(reality_link(name="US 🇺🇸 | tagged")), "US"
        )
        self.assertEqual(
            target.country_code(reality_link(name="🇩🇪 DE | tagged")), "DE"
        )

    def test_quality_profiles_collapse_same_connection_with_new_label(self) -> None:
        first = reality_link(name="US 🇺🇸 | first")
        second = reality_link(name="DE 🇩🇪 | second")
        best, stable, _, report = target.build_quality_profiles(
            [first, second],
            fast_source="",
            secure_source="",
            top_source="",
            previous_history={},
        )
        self.assertEqual(best, [first])
        self.assertEqual(stable, [first])
        self.assertEqual(
            report["ranking"]["matched_strict_candidates"][
                "duplicate_identity_collapsed"
            ],
            1,
        )

    def test_tier_only_node_is_not_published(self) -> None:
        verified = reality_link(host="1.1.1.1", name="US verified")
        tier_only = reality_link(host="8.8.8.8", name="DE tier only")
        best, stable, _, _ = target.build_quality_profiles(
            [verified],
            fast_source=tier_only,
            secure_source=tier_only,
            top_source=tier_only,
            previous_history={},
        )
        self.assertEqual(best, [verified])
        self.assertEqual(stable, [verified])
        self.assertNotIn(tier_only, best + stable)

    def test_top100_candidate_ranks_first(self) -> None:
        ordinary = reality_link(host="1.1.1.1", name="US ordinary")
        top = reality_link(host="8.8.8.8", name="DE top")
        best, _, _, _ = target.build_quality_profiles(
            [ordinary, top],
            fast_source="",
            secure_source="",
            top_source=top,
            previous_history={},
        )
        self.assertEqual(best[0], top)

    def test_first_run_bootstraps_then_second_run_trusts(self) -> None:
        nodes = [
            reality_link(host="1.1.1.1", name="US one"),
            reality_link(host="8.8.8.8", name="DE two"),
        ]
        _, first_stable, first_history, first_report = (
            target.build_quality_profiles(
                nodes,
                fast_source="",
                secure_source="",
                top_source="",
                previous_history={},
            )
        )
        self.assertEqual(len(first_stable), 2)
        self.assertEqual(first_report["history"]["bootstrap_fill"], 2)
        self.assertEqual(first_report["history"]["current_trusted"], 0)

        _, second_stable, second_history, second_report = (
            target.build_quality_profiles(
                nodes,
                fast_source="",
                secure_source="",
                top_source="",
                previous_history=first_history["nodes"],
            )
        )
        self.assertEqual(len(second_stable), 2)
        self.assertEqual(second_report["history"]["bootstrap_fill"], 0)
        self.assertEqual(second_report["history"]["current_trusted"], 2)
        self.assertTrue(
            all(entry["trusted"] for entry in second_history["nodes"].values())
        )

    def test_trusted_node_is_quarantined_and_revived(self) -> None:
        identity = "a" * 64
        trusted = {
            identity: {
                "seen_streak": 4,
                "miss_streak": 0,
                "seen_total": 4,
                "trusted": True,
                "revivals": 0,
            }
        }
        absent, absent_stats = target.update_history(set(), trusted)
        self.assertEqual(absent_stats["quarantined"], 1)
        returned, returned_stats = target.update_history({identity}, absent)
        self.assertTrue(returned[identity]["trusted"])
        self.assertEqual(returned[identity]["miss_streak"], 0)
        self.assertEqual(returned_stats["revived"], 1)

    def test_history_record_expires_after_quarantine(self) -> None:
        identity = "b" * 64
        history = {
            identity: {
                "seen_streak": 4,
                "miss_streak": 0,
                "seen_total": 4,
                "trusted": True,
                "revivals": 0,
            }
        }
        stats = {}
        for _ in range(target.MAX_MISS_STREAK + 1):
            history, stats = target.update_history(set(), history)
        self.assertNotIn(identity, history)
        self.assertEqual(stats["expired"], 1)

    def test_network_diversity_cap_is_enforced(self) -> None:
        ranked = []
        for number in range(1, 8):
            line = reality_link(
                host=f"8.8.8.{number}",
                name=f"US node {number}",
            )
            ranked.append(
                target.RankedNode(
                    line=line,
                    identity=target.node_identity(line) or "",
                    score=100 - number,
                    country="US",
                    endpoint=f"8.8.8.{number}:443",
                    network="ip:8.8.8.0/24",
                )
            )
        selected, stats = target.select_diverse(
            ranked,
            limit=10,
            max_per_country=10,
            max_per_endpoint=2,
            max_per_network=3,
        )
        self.assertEqual(len(selected), 3)
        self.assertEqual(stats["skipped_network_cap"], 4)

    def test_history_contains_hashes_not_credentials(self) -> None:
        line = reality_link(host="1.1.1.1", name="US private marker")
        _, _, history, report = target.build_quality_profiles(
            [line],
            fast_source=line,
            secure_source=line,
            top_source=line,
            previous_history={},
        )
        serialized = json.dumps({"history": history, "report": report})
        self.assertNotIn(UUID, serialized)
        self.assertNotIn("1.1.1.1", serialized)
        self.assertNotIn("private marker", serialized)
        self.assertRegex(next(iter(history["nodes"])), r"^[0-9a-f]{64}$")

    def test_malformed_history_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node_history.json"
            path.write_text('{"version": 1, "nodes": {"secret": {}}}')
            with self.assertRaisesRegex(RuntimeError, "non-hash"):
                target.load_history(path)

    def test_main_generates_and_updates_all_v5_files(self) -> None:
        source = "\n".join(
            [
                reality_link(host="1.1.1.1", name="US one"),
                reality_link(host="8.8.8.8", name="DE two"),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "OUTPUT_FILE": root / "subscription.txt",
                "REALITY_OUTPUT_FILE": root / "reality_tcp.txt",
                "REALITY_ALL_OUTPUT_FILE": root / "reality_all.txt",
                "BEST_OUTPUT_FILE": root / "reality_best.txt",
                "STABLE_OUTPUT_FILE": root / "reality_stable.txt",
                "REPORT_FILE": root / "security_report.json",
                "HISTORY_FILE": root / "node_history.json",
                "CHECKSUMS_FILE": root / "checksums.sha256",
                "MIN_CONFIGS": 1,
                "MIN_REALITY_CONFIGS": 1,
                "MIN_REALITY_ALL_CONFIGS": 1,
                "MIN_BEST_CONFIGS": 1,
                "MIN_STABLE_CONFIGS": 1,
            }
            with mock.patch.multiple(target, **paths), mock.patch.object(
                target, "fetch_source", return_value=source
            ):
                target.main()
                target.main()

            for value in paths.values():
                if isinstance(value, Path):
                    self.assertTrue(value.exists(), value)
            report = json.loads(paths["REPORT_FILE"].read_text(encoding="utf-8"))
            history = json.loads(paths["HISTORY_FILE"].read_text(encoding="utf-8"))
            self.assertEqual(report["version"], 5)
            self.assertEqual(report["history"]["current_trusted"], 2)
            self.assertEqual(report["outputs"]["ranked_best"], 2)
            self.assertEqual(report["outputs"]["history_stable"], 2)
            self.assertEqual(len(history["nodes"]), 2)
            self.assertEqual(
                len(paths["CHECKSUMS_FILE"].read_text().splitlines()), 5
            )


if __name__ == "__main__":
    unittest.main()
