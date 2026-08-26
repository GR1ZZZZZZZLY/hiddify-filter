#!/usr/bin/env python3
"""Offline tests for the subscription safety filter."""

from __future__ import annotations

import base64
import unittest
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


if __name__ == "__main__":
    unittest.main()
