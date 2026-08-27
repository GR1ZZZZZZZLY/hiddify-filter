#!/usr/bin/env python3
"""Offline tests for the subscription safety filter."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
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
    user_id: str = UUID,
    public_key: str = PUBLIC_KEY,
    server_name: str = "www.cloudflare.com",
    overrides: dict[str, str | None] | None = None,
) -> str:
    query: dict[str, str] = {
        "security": "reality",
        "encryption": "none",
        "type": transport,
        "pbk": public_key,
        "sni": server_name,
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
    return f"vless://{user_id}@{host}:443?{urlencode(query)}#{name}"


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


class LocalResultsTests(unittest.TestCase):
    SECRET = bytes(range(32))
    ENCODED_SECRET = base64.b64encode(SECRET).decode("ascii")

    def write_report(
        self,
        path: Path,
        line: str,
        generated_at: datetime,
        *,
        successes: int = 2,
        attempts: int = 3,
        current_ok: bool = True,
        latency: int = 420,
    ) -> None:
        tag = target.local_uri_tag(line, self.SECRET)
        document = {
            "version": 1,
            "identifier_scheme": target.LOCAL_IDENTIFIER_SCHEME,
            "generated_at_utc": generated_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "history_window": 3,
            "total_tested": 201,
            "current_successes": 9,
            "invalid_candidates": 0,
            "expected_http_status": 204,
            "failure_reasons": {"curl_exit_28": 192},
            "nodes": {
                tag: {
                    "current_ok": current_ok,
                    "successes": successes,
                    "attempts": attempts,
                    "median_latency_ms": latency,
                }
            },
        }
        path.write_text(json.dumps(document), encoding="utf-8")

    def test_hmac_matches_windows_tester_vector_and_ignores_label(self) -> None:
        uri = (
            "vless://e08ff179-2c35-4a95-a8f8-6b2f7bd315ef@1.1.1.1:443?"
            "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&"
            "pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&"
            "sni=www.cloudflare.com&fp=chrome&sid=12ab"
        )
        expected = (
            "3ffbea00ccc8950f26f4e803ec9783c036fb142470da3298f23180a446636b8e"
        )
        self.assertEqual(target.local_uri_tag(uri, self.SECRET), expected)
        self.assertEqual(
            target.local_uri_tag(uri + "#US first", self.SECRET),
            target.local_uri_tag(uri + "#DE renamed", self.SECRET),
        )

    def test_fresh_report_matches_current_line_and_qualifies(self) -> None:
        line = reality_link(name="US original")
        now = datetime(2026, 8, 27, 9, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local_results.json"
            self.write_report(path, line, now - timedelta(minutes=4))
            secret, by_tag, report = target.load_local_results(
                path,
                self.ENCODED_SECRET,
                now=now,
            )
        matched = target.match_local_evidence(
            [line.split("#", 1)[0] + "#DE renamed"],
            secret,
            by_tag,
        )
        self.assertEqual(report["status"], "active")
        self.assertTrue(report["fresh"])
        self.assertEqual(report["qualified_report_nodes"], 1)
        self.assertEqual(len(matched), 1)
        self.assertTrue(target.is_local_qualified(next(iter(matched.values()))))
        self.assertNotIn(
            target.local_uri_tag(line, self.SECRET),
            json.dumps(report),
        )
        self.assertNotIn(self.ENCODED_SECRET, json.dumps(report))

    def test_stale_report_is_ignored(self) -> None:
        line = reality_link()
        now = datetime(2026, 8, 27, 13, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local_results.json"
            self.write_report(path, line, now - timedelta(hours=4))
            secret, nodes, report = target.load_local_results(
                path,
                self.ENCODED_SECRET,
                now=now,
            )
        self.assertIsNone(secret)
        self.assertEqual(nodes, {})
        self.assertEqual(report["status"], "stale")
        self.assertFalse(report["fresh"])

    def test_missing_or_invalid_secret_does_not_stop_remote_profiles(self) -> None:
        line = reality_link()
        now = datetime(2026, 8, 27, 9, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local_results.json"
            self.write_report(path, line, now)
            _, _, missing = target.load_local_results(path, "", now=now)
            _, _, invalid = target.load_local_results(path, "not-base64", now=now)
        self.assertEqual(missing["status"], "secret_missing")
        self.assertEqual(invalid["status"], "invalid")
        self.assertEqual(invalid["reason"], "invalid_secret_encoding")

    def test_local_profile_uses_two_of_three_and_orders_reliable_nodes(self) -> None:
        perfect = reality_link(host="1.1.1.1", name="US perfect")
        qualified = reality_link(host="8.8.8.8", name="DE qualified")
        unstable = reality_link(host="9.9.9.9", name="NL unstable")
        evidence = {
            target.node_identity(perfect) or "": target.LocalEvidence(
                True, 3, 3, 600
            ),
            target.node_identity(qualified) or "": target.LocalEvidence(
                False, 2, 3, 300
            ),
            target.node_identity(unstable) or "": target.LocalEvidence(
                True, 1, 3, 100
            ),
        }
        selected, stats = target.build_local_profile(
            [unstable, qualified, perfect],
            evidence,
        )
        self.assertEqual(selected, [perfect, qualified])
        self.assertEqual(stats["selected"], 2)
        self.assertEqual(stats["perfect_3_of_3_selected"], 1)
        self.assertEqual(stats["qualified_2_of_3_selected"], 1)

    def test_local_evidence_has_highest_best_priority(self) -> None:
        local = reality_link(host="1.1.1.1", name="US local")
        remote_top = reality_link(host="8.8.8.8", name="DE top")
        local_id = target.node_identity(local) or ""
        best, _, _, _, report = target.build_quality_profiles(
            [remote_top, local],
            fast_source=remote_top,
            secure_source=remote_top,
            top_source=remote_top,
            previous_history={},
            local_evidence={
                local_id: target.LocalEvidence(True, 3, 3, 400)
            },
        )
        self.assertEqual(best[0], local)
        self.assertEqual(
            report["ranking"]["matched_strict_candidates"]["local_verified"],
            1,
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
        self.assertEqual(
            target.country_code(
                reality_link(name="v2go | 🇫🇷 FR | VLESS | 1")
            ),
            "FR",
        )

    def test_v2go_ru_label_is_removed(self) -> None:
        ru = reality_link(name="v2go | 🇷🇺 RU | VLESS | 1")
        kept, strict, expanded, report = target.build_subscriptions(ru)
        self.assertEqual((kept, strict, expanded), ([], [], []))
        self.assertEqual(report["filtering"]["ru_label"], 1)

    def test_merge_prefers_primary_and_tracks_both_sources(self) -> None:
        primary = reality_link(name="US 🇺🇸 | primary")
        secondary = reality_link(name="v2go | 🇺🇸 US | VLESS | 1")
        merged, memberships, report = target.merge_candidate_sources(
            primary,
            secondary,
        )
        identity = target.node_identity(primary) or ""
        self.assertEqual(list(target.iter_uri_lines(merged)), [primary])
        self.assertEqual(
            memberships[identity],
            frozenset({"radikal_verified", "v2go_live"}),
        )
        self.assertEqual(report["cross_source_identities"], 1)
        self.assertEqual(report["duplicates_collapsed"], 1)

    def test_quality_profiles_collapse_same_connection_with_new_label(self) -> None:
        first = reality_link(name="US 🇺🇸 | first")
        second = reality_link(name="DE 🇩🇪 | second")
        best, stable, durable, _, report = target.build_quality_profiles(
            [first, second],
            fast_source="",
            secure_source="",
            top_source="",
            previous_history={},
        )
        self.assertEqual(best, [first])
        self.assertEqual(stable, [first])
        self.assertEqual(durable, [])
        self.assertEqual(
            report["ranking"]["matched_strict_candidates"][
                "duplicate_identity_collapsed"
            ],
            1,
        )

    def test_tier_only_node_is_not_published(self) -> None:
        verified = reality_link(host="1.1.1.1", name="US verified")
        tier_only = reality_link(host="8.8.8.8", name="DE tier only")
        best, stable, durable, _, _ = target.build_quality_profiles(
            [verified],
            fast_source=tier_only,
            secure_source=tier_only,
            top_source=tier_only,
            previous_history={},
        )
        self.assertEqual(best, [verified])
        self.assertEqual(stable, [verified])
        self.assertEqual(durable, [])
        self.assertNotIn(tier_only, best + stable + durable)

    def test_top100_candidate_ranks_first(self) -> None:
        ordinary = reality_link(host="1.1.1.1", name="US ordinary")
        top = reality_link(host="8.8.8.8", name="DE top")
        best, _, _, _, _ = target.build_quality_profiles(
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
        _, first_stable, first_durable, first_history, first_report = (
            target.build_quality_profiles(
                nodes,
                fast_source="",
                secure_source="",
                top_source="",
                previous_history={},
            )
        )
        self.assertEqual(len(first_stable), 2)
        self.assertEqual(first_durable, [])
        self.assertEqual(first_report["history"]["bootstrap_fill"], 2)
        self.assertEqual(first_report["history"]["current_trusted"], 0)

        _, second_stable, second_durable, second_history, second_report = (
            target.build_quality_profiles(
                nodes,
                fast_source="",
                secure_source="",
                top_source="",
                previous_history=first_history["nodes"],
            )
        )
        self.assertEqual(len(second_stable), 2)
        self.assertEqual(second_durable, [])
        self.assertEqual(second_report["history"]["bootstrap_fill"], 2)
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
                "presence_bits": target._presence_hex(0b1111),
                "observed_runs": 4,
                "cross_source_hits": 0,
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
                "presence_bits": target._presence_hex(0b1111),
                "observed_runs": 4,
                "cross_source_hits": 0,
            }
        }
        stats = {}
        for _ in range(target.MAX_MISS_STREAK + 1):
            history, stats = target.update_history(set(), history)
        self.assertNotIn(identity, history)
        self.assertEqual(stats["expired"], 1)

    def test_v5_history_is_migrated_without_fake_24h_evidence(self) -> None:
        identity = "c" * 64
        document = {
            "version": 1,
            "nodes": {
                identity: {
                    "seen_streak": 8,
                    "miss_streak": 0,
                    "seen_total": 20,
                    "trusted": True,
                    "revivals": 1,
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node_history.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            migrated = target.load_history(path)[identity]
        self.assertEqual(target.presence_count(migrated), 8)
        self.assertEqual(migrated["observed_runs"], 8)
        self.assertEqual(migrated["cross_source_hits"], 0)
        self.assertTrue(target.is_stable_entry(migrated))
        self.assertFalse(target.is_durable_entry(migrated))

    def test_stable_requires_six_of_last_eight_runs(self) -> None:
        identity = "d" * 64
        history: dict[str, dict[str, object]] = {}
        for present in (True, True, False, True, True, False, True, True):
            history, _ = target.update_history(
                {identity} if present else set(),
                history,
            )
        entry = history[identity]
        self.assertEqual(target.presence_count(entry, 8), 6)
        self.assertTrue(target.is_stable_entry(entry))

        history, _ = target.update_history(set(), history)
        self.assertEqual(target.presence_count(history[identity], 8), 5)
        self.assertFalse(target.is_stable_entry(history[identity]))

    def test_durable_requires_72_of_96_and_cross_source_confirmation(self) -> None:
        qualifying = {
            "presence_bits": target._presence_hex((1 << 72) - 1),
            "observed_runs": 96,
            "cross_source_hits": 2,
        }
        self.assertTrue(target.is_durable_entry(qualifying))
        self.assertFalse(
            target.is_durable_entry({**qualifying, "cross_source_hits": 1})
        )
        self.assertFalse(
            target.is_durable_entry(
                {
                    **qualifying,
                    "presence_bits": target._presence_hex((1 << 71) - 1),
                }
            )
        )

    def test_cross_source_candidate_gets_ranking_bonus(self) -> None:
        single = reality_link(host="1.1.1.1", name="US single")
        cross = reality_link(host="8.8.8.8", name="DE cross")
        identities = {
            target.node_identity(single) or "",
            target.node_identity(cross) or "",
        }
        history, _ = target.update_history(identities, {})
        memberships = {
            target.node_identity(single) or "": frozenset({"radikal_verified"}),
            target.node_identity(cross) or "": frozenset(
                {"radikal_verified", "v2go_live"}
            ),
        }
        ranked, report = target.rank_nodes(
            [single, cross],
            fast_source="",
            secure_source="",
            top_source="",
            history=history,
            source_memberships=memberships,
        )
        self.assertEqual(ranked[0].line, cross)
        self.assertEqual(
            report["matched_strict_candidates"]["cross_source"], 1
        )

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
                    user_cluster=f"user-{number}",
                    reality_key_cluster=f"key-{number}",
                    operator_cluster=f"operator-{number}",
                    source_count=1,
                )
            )
        selected, stats = target.select_diverse(
            ranked,
            limit=10,
            max_per_country=10,
            max_per_endpoint=2,
            max_per_network=3,
            max_per_user_id=10,
            max_per_reality_key=10,
            max_per_operator_cluster=10,
        )
        self.assertEqual(len(selected), 3)
        self.assertEqual(stats["skipped_network_cap"], 4)

    def test_operator_cluster_cap_is_enforced(self) -> None:
        ranked = []
        for number in range(5):
            line = reality_link(host=f"8.8.{number}.1", name=f"US {number}")
            ranked.append(
                target.RankedNode(
                    line=line,
                    identity=target.node_identity(line) or "",
                    score=100 - number,
                    country="US",
                    endpoint=f"8.8.{number}.1:443",
                    network=f"ip:8.8.{number}.0/24",
                    user_cluster=f"user-{number}",
                    reality_key_cluster=f"key-{number}",
                    operator_cluster="same-operator",
                    source_count=1,
                )
            )
        selected, stats = target.select_diverse(
            ranked,
            limit=10,
            max_per_country=10,
            max_per_endpoint=10,
            max_per_network=10,
            max_per_user_id=10,
            max_per_reality_key=10,
            max_per_operator_cluster=2,
        )
        self.assertEqual(len(selected), 2)
        self.assertEqual(stats["skipped_operator_cluster_cap"], 3)

    def test_history_contains_hashes_not_credentials(self) -> None:
        line = reality_link(host="1.1.1.1", name="US private marker")
        _, _, _, history, report = target.build_quality_profiles(
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

    def test_main_generates_and_updates_all_v61_files(self) -> None:
        first = reality_link(host="1.1.1.1", name="US one")
        second = reality_link(host="8.8.8.8", name="DE two")
        source = "\n".join([first, second])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local_results = root / "local_results.json"
            LocalResultsTests().write_report(
                local_results,
                first,
                datetime.now(timezone.utc),
                successes=3,
                attempts=3,
                current_ok=True,
                latency=300,
            )
            paths = {
                "OUTPUT_FILE": root / "subscription.txt",
                "REALITY_OUTPUT_FILE": root / "reality_tcp.txt",
                "REALITY_ALL_OUTPUT_FILE": root / "reality_all.txt",
                "BEST_OUTPUT_FILE": root / "reality_best.txt",
                "STABLE_OUTPUT_FILE": root / "reality_stable.txt",
                "DURABLE_OUTPUT_FILE": root / "reality_durable.txt",
                "LOCAL_OUTPUT_FILE": root / "reality_local.txt",
                "REPORT_FILE": root / "security_report.json",
                "HISTORY_FILE": root / "node_history.json",
                "CHECKSUMS_FILE": root / "checksums.sha256",
                "LOCAL_RESULTS_FILE": local_results,
                "LOCAL_TEST_HMAC_KEY": LocalResultsTests.ENCODED_SECRET,
                "MIN_CONFIGS": 1,
                "MIN_REALITY_CONFIGS": 1,
                "MIN_REALITY_ALL_CONFIGS": 1,
                "MIN_BEST_CONFIGS": 1,
                "MIN_STABLE_CONFIGS": 1,
                "MIN_DURABLE_CONFIGS": 0,
                "MIN_LOCAL_CONFIGS": 0,
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
            self.assertEqual(report["version"], "6.1")
            self.assertEqual(report["history"]["current_trusted"], 2)
            self.assertEqual(report["outputs"]["ranked_best"], 2)
            self.assertEqual(report["outputs"]["history_stable"], 2)
            self.assertEqual(report["outputs"]["history_durable_24h"], 0)
            self.assertEqual(report["outputs"]["local_verified"], 1)
            self.assertEqual(report["local"]["status"], "active")
            self.assertEqual(report["local"]["selected"], 1)
            self.assertEqual(len(history["nodes"]), 2)
            self.assertEqual(
                len(paths["CHECKSUMS_FILE"].read_text().splitlines()), 7
            )


if __name__ == "__main__":
    unittest.main()
