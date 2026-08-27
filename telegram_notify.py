#!/usr/bin/env python3
"""Send bounded, transition-only Telegram notifications for filter v6.2."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


MAX_STATUS_BYTES = 256 * 1024
MAX_MESSAGE_LENGTH = 3500
TOKEN_RE = re.compile(r"^[0-9]{6,12}:[A-Za-z0-9_-]{30,80}$")
CHAT_ID_RE = re.compile(r"^-?[0-9]{1,20}$")
HEALTH_STATES = {"healthy", "degraded", "failed"}
FAILED_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "stale",
    "startup_failure",
    "timed_out",
}


def load_status(path: Path, *, required: bool) -> dict[str, object] | None:
    if not path.exists():
        if required:
            raise RuntimeError(f"Status file is missing: {path.name}")
        return None
    if path.stat().st_size > MAX_STATUS_BYTES:
        raise RuntimeError("Status file is too large")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Status file is not valid JSON") from error
    if not isinstance(document, dict):
        raise RuntimeError("Status document must be an object")
    if required and document.get("schema_version") != 1:
        raise RuntimeError("Unsupported bot status schema")
    return document


def nested(document: dict[str, object] | None, *keys: str) -> object | None:
    value: object = document
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def bounded_count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return min(max(value, 0), 100000)


def safe_run_url(value: str) -> str:
    if not value:
        return ""
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+", parsed.path)
    ):
        return ""
    return value


def profile_line(status: dict[str, object]) -> str:
    names = ("best", "stable", "durable", "local")
    values = [
        f"{name.upper()} {bounded_count(nested(status, 'profiles', name, 'count'))}"
        for name in names
    ]
    return " · ".join(values)


def build_success_message(
    current: dict[str, object],
    previous: dict[str, object] | None,
    *,
    run_url: str = "",
    force: bool = False,
) -> str | None:
    current_health = str(nested(current, "health", "status") or "failed")
    if current_health not in HEALTH_STATES:
        raise RuntimeError("Current status contains an invalid health state")
    previous_health = (
        str(nested(previous, "health", "status")) if previous else ""
    )
    events: list[str] = []

    if previous is None or previous.get("schema_version") != 1:
        events.append("Мониторинг v6.2 подключён.")
    elif current_health != previous_health:
        if current_health == "healthy":
            events.append("Система восстановилась: статус HEALTHY.")
        elif current_health == "degraded":
            events.append("Система работает с ограничениями: статус DEGRADED.")
        else:
            events.append("Обнаружен критический статус FAILED.")

    current_local_time = nested(current, "local", "generated_at_utc")
    previous_local_time = nested(previous, "local", "generated_at_utc")
    current_local_status = str(nested(current, "local", "status") or "unknown")
    previous_local_status = str(nested(previous, "local", "status") or "")
    if (
        isinstance(current_local_time, str)
        and current_local_time
        and current_local_time != previous_local_time
        and current_local_status == "active"
    ):
        selected = bounded_count(nested(current, "local", "selected"))
        current_ok = bounded_count(
            nested(current, "local", "current_ok_selected")
        )
        events.append(
            f"LOCAL обновлён: опубликовано {selected}, работают сейчас {current_ok}."
        )
    elif previous is not None and current_local_status != previous_local_status:
        if current_local_status == "active":
            events.append("LOCAL снова активен.")
        elif current_local_status == "stale":
            events.append("LOCAL устарел; требуется новый запуск тестера.")
        else:
            events.append(f"LOCAL недоступен: {current_local_status}.")

    current_durable = bounded_count(
        nested(current, "profiles", "durable", "count")
    )
    previous_durable = bounded_count(
        nested(previous, "profiles", "durable", "count")
    )
    if current_durable > 0 and previous_durable == 0:
        events.append(f"DURABLE сформирован: {current_durable} узлов.")

    if force and not events:
        events.append("Ручная проверка Telegram-уведомлений выполнена.")

    if not events:
        return None

    icon = {"healthy": "✅", "degraded": "⚠️", "failed": "❌"}[current_health]
    lines = [
        f"{icon} HAPP Filter v6.2",
        *events,
        profile_line(current),
    ]
    reasons = nested(current, "health", "reasons")
    if current_health != "healthy" and isinstance(reasons, list):
        safe_reasons = [
            item for item in reasons if isinstance(item, str) and re.fullmatch(r"[a-z0-9_]{1,80}", item)
        ]
        if safe_reasons:
            lines.append("Причины: " + ", ".join(safe_reasons[:8]))
    validated_url = safe_run_url(run_url)
    if validated_url:
        lines.append("Workflow: " + validated_url)
    return "\n".join(lines)[:MAX_MESSAGE_LENGTH]


def build_failure_message(*, run_url: str = "") -> str:
    lines = [
        "❌ HAPP Filter: workflow завершился ошибкой.",
        "Последние успешные подписки оставлены без изменений.",
    ]
    validated_url = safe_run_url(run_url)
    if validated_url:
        lines.append("Workflow: " + validated_url)
    return "\n".join(lines)


def previous_workflow_run_failed(
    *,
    repository: str,
    workflow: str,
    current_run_id: str,
    token: str,
    opener=urlopen,
) -> bool:
    """Best-effort protection against repeated scheduled failure messages."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return False
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.ya?ml", workflow):
        return False
    if not re.fullmatch(r"[0-9]+", current_run_id):
        return False
    token = token.strip()
    if len(token) < 20 or len(token) > 200 or re.search(r"\s", token):
        return False

    endpoint = (
        f"https://api.github.com/repos/{repository}/actions/workflows/"
        f"{quote(workflow, safe='')}/runs?per_page=10"
    )
    request = Request(
        endpoint,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "happ-filter-telegram-notifier/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with opener(request, timeout=15) as response:
            raw = response.read(1048577)
        if len(raw) > 1048576:
            return False
        document = json.loads(raw.decode("utf-8"))
    except Exception:
        # Failure lookup is advisory. Prefer one extra alert to suppressing the
        # first real incident, and never expose an exception that may carry a
        # credential-bearing request object.
        return False
    runs = document.get("workflow_runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        return False
    current_id = int(current_run_id)
    for run in runs:
        if not isinstance(run, dict) or run.get("id") == current_id:
            continue
        conclusion = run.get("conclusion")
        if isinstance(conclusion, str) and conclusion:
            return conclusion in FAILED_CONCLUSIONS
    return False


def send_telegram(
    message: str,
    *,
    token: str,
    chat_id: str,
    opener=urlopen,
) -> bool:
    token = token.strip()
    chat_id = chat_id.strip()
    if not token and not chat_id:
        return False
    if not TOKEN_RE.fullmatch(token):
        raise RuntimeError("TELEGRAM_BOT_TOKEN has an invalid format")
    if not CHAT_ID_RE.fullmatch(chat_id):
        raise RuntimeError("TELEGRAM_CHAT_ID must be a numeric chat identifier")
    if not message or len(message) > MAX_MESSAGE_LENGTH:
        raise RuntimeError("Telegram message has an invalid length")

    payload = json.dumps(
        {
            "chat_id": chat_id,
            "text": message,
            "disable_web_page_preview": True,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    request = Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "happ-filter-telegram-notifier/1",
        },
        method="POST",
    )
    try:
        with opener(request, timeout=15) as response:
            raw = response.read(65537)
    except Exception:
        # Never chain the transport exception: some clients include the full
        # request URL, which contains the bot token.
        raise RuntimeError("Telegram API request failed") from None
    if len(raw) > 65536:
        raise RuntimeError("Telegram API returned an oversized response")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Telegram API returned malformed JSON") from error
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError("Telegram API rejected the notification")
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("success", "failure"), required=True)
    parser.add_argument("--status", type=Path, default=Path("bot_status.json"))
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--run-url", default="")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.mode == "success":
        current = load_status(args.status, required=True)
        assert current is not None
        previous = (
            load_status(args.previous, required=False) if args.previous else None
        )
        message = build_success_message(
            current,
            previous,
            run_url=args.run_url,
            force=args.force,
        )
        if message is None:
            print("Telegram notification skipped: no significant state change")
            return
    else:
        if previous_workflow_run_failed(
            repository=os.environ.get("GITHUB_REPOSITORY", ""),
            workflow=os.environ.get("GITHUB_WORKFLOW_FILE", "update.yml"),
            current_run_id=os.environ.get("GITHUB_RUN_ID", ""),
            token=os.environ.get("GITHUB_READ_TOKEN", ""),
        ):
            print("Telegram notification skipped: previous workflow also failed")
            return
        message = build_failure_message(run_url=args.run_url)

    sent = send_telegram(
        message,
        token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
        chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
    )
    if sent:
        print("Telegram notification sent")
    else:
        print("Telegram notification skipped: secrets are not configured")


if __name__ == "__main__":
    main()
