#!/usr/bin/env python3
"""Offline tests for transition-only Telegram notifications."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import telegram_notify as target


TEST_TELEGRAM_TOKEN = "123456789:" + ("A" * 35)
TEST_GITHUB_TOKEN = "ghs_" + ("x" * 36)
ROOT = Path(__file__).resolve().parent


class FakeResponse:
    def __init__(self, payload: bytes = b'{"ok":true}') -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.payload


def status(
    *,
    health: str = "healthy",
    local_time: str = "2026-08-27T14:20:00Z",
    local_status: str = "active",
    durable: int = 12,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "health": {"status": health, "reasons": []},
        "profiles": {
            "best": {"count": 50},
            "stable": {"count": 100},
            "durable": {"count": durable},
            "local": {"count": 7},
        },
        "local": {
            "status": local_status,
            "generated_at_utc": local_time,
            "selected": 7,
            "current_ok_selected": 6,
        },
    }


class NotificationTests(unittest.TestCase):
    def test_unchanged_status_does_not_notify(self) -> None:
        current = status()
        previous = json.loads(json.dumps(current))
        self.assertIsNone(target.build_success_message(current, previous))

    def test_force_sends_manual_check_for_unchanged_status(self) -> None:
        current = status()
        previous = json.loads(json.dumps(current))
        message = target.build_success_message(current, previous, force=True)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertIn("Ручная проверка", message)

    def test_new_local_result_creates_bounded_message(self) -> None:
        previous = status(local_time="2026-08-27T10:00:00Z")
        current = status(local_time="2026-08-27T14:20:00Z")
        message = target.build_success_message(
            current,
            previous,
            run_url=(
                "https://github.com/GR1ZZZZZZZLY/hiddify-filter/"
                "actions/runs/33065326101"
            ),
        )
        self.assertIsNotNone(message)
        assert message is not None
        self.assertIn("LOCAL обновлён", message)
        self.assertIn("BEST 50", message)
        self.assertLessEqual(len(message), target.MAX_MESSAGE_LENGTH)

    def test_health_recovery_and_durable_milestone_are_reported(self) -> None:
        previous = status(health="degraded", durable=0)
        current = status(health="healthy", durable=9)
        message = target.build_success_message(current, previous)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertIn("восстановилась", message)
        self.assertIn("DURABLE сформирован: 9", message)

    def test_failure_message_promises_last_good_files(self) -> None:
        message = target.build_failure_message()
        self.assertIn("ошибкой", message)
        self.assertIn("оставлены без изменений", message)

    def test_repeated_workflow_failure_is_detected_without_token_leak(self) -> None:
        token = TEST_GITHUB_TOKEN
        payload = json.dumps(
            {
                "workflow_runs": [
                    {"id": 200, "conclusion": None},
                    {"id": 199, "conclusion": "failure"},
                ]
            }
        ).encode("utf-8")
        captured = {}

        def opener(request, timeout):
            captured["request"] = request
            return FakeResponse(payload)

        repeated = target.previous_workflow_run_failed(
            repository="GR1ZZZZZZZLY/hiddify-filter",
            workflow="update.yml",
            current_run_id="200",
            token=token,
            opener=opener,
        )
        self.assertTrue(repeated)
        self.assertNotIn(token, captured["request"].full_url)

    def test_previous_success_allows_failure_notification(self) -> None:
        payload = json.dumps(
            {"workflow_runs": [{"id": 199, "conclusion": "success"}]}
        ).encode("utf-8")

        def opener(request, timeout):
            return FakeResponse(payload)

        self.assertFalse(
            target.previous_workflow_run_failed(
                repository="GR1ZZZZZZZLY/hiddify-filter",
                workflow="update.yml",
                current_run_id="200",
                token=TEST_GITHUB_TOKEN,
                opener=opener,
            )
        )

    def test_missing_secrets_skip_network(self) -> None:
        calls = []

        def opener(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("network must not be called")

        self.assertFalse(
            target.send_telegram(
                "test",
                token="",
                chat_id="",
                opener=opener,
            )
        )
        self.assertEqual(calls, [])

    def test_valid_notification_uses_json_post(self) -> None:
        captured = {}

        def opener(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse()

        sent = target.send_telegram(
            "Безопасное сообщение",
            token=TEST_TELEGRAM_TOKEN,
            chat_id="123456789",
            opener=opener,
        )
        self.assertTrue(sent)
        request = captured["request"]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["chat_id"], "123456789")
        self.assertEqual(payload["text"], "Безопасное сообщение")
        self.assertEqual(captured["timeout"], 15)

    def test_transport_failure_does_not_expose_token(self) -> None:
        token = TEST_TELEGRAM_TOKEN

        def opener(request, timeout):
            raise RuntimeError(request.full_url)

        try:
            target.send_telegram(
                "test",
                token=token,
                chat_id="123456789",
                opener=opener,
            )
        except RuntimeError as error:
            self.assertNotIn(token, str(error))
            self.assertIsNone(error.__cause__)
        else:
            self.fail("Transport failure was not reported")

    def test_invalid_chat_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "numeric"):
            target.send_telegram(
                "test",
                token=TEST_TELEGRAM_TOKEN,
                chat_id="@public-channel",
            )


class ReleaseContractTests(unittest.TestCase):
    def test_required_bridge_files_exist(self) -> None:
        for relative in (
            "filter_subscription.py",
            "test_filter_subscription.py",
            "telegram_notify.py",
            "test_telegram_notify.py",
            "README_RU.md",
            ".github/workflows/update.yml",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_workflow_keeps_notification_secrets_out_of_filter_step(self) -> None:
        text = (ROOT / ".github/workflows/update.yml").read_text(encoding="utf-8")
        build = text.split("- name: Build safer subscriptions", 1)[1].split(
            "- name: Commit changed subscription", 1
        )[0]
        self.assertNotIn("TELEGRAM_BOT_TOKEN", build)
        self.assertNotIn("TELEGRAM_CHAT_ID", build)
        self.assertIn("BOT_STATUS_FILE: bot_status.json", build)
        self.assertIn("continue-on-error: true", text)
        self.assertIn("actions: read", text)
        self.assertIn("contents: write", text)

    def test_no_literal_credentials_are_bundled(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8", errors="strict")
            for path in ROOT.rglob("*")
            if path.is_file() and path.suffix.lower() in {".py", ".yml", ".md"}
            and "__pycache__" not in path.parts
        )
        self.assertIsNone(
            re.search(r"[0-9]{6,12}:[A-Za-z0-9_-]{30,80}", text)
        )
        self.assertIsNone(
            re.search(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}", text)
        )

    def test_public_status_builder_never_reads_secret_values(self) -> None:
        source = (ROOT / "filter_subscription.py").read_text(encoding="utf-8")
        block = source.split("def build_bot_status", 1)[1].split(
            "def write_checksums", 1
        )[0]
        for forbidden in (
            "LOCAL_TEST_HMAC_KEY",
            "TELEGRAM_BOT_TOKEN",
            "GITHUB_TOKEN",
            "local_uri_tag",
        ):
            self.assertNotIn(forbidden, block)


if __name__ == "__main__":
    unittest.main()
