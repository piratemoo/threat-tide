from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


FEED_PATH = Path("vulns.json")
STATE_PATH = Path("discord-post-state.json")
SITE_URL = "https://www.piratemoo.com/vulns/"
WEBHOOK_RE = re.compile(r"^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([^/?#]+)")


CHANNELS = {
    "vulns": {
        "secrets": ("DISCORD_VULNS_WEBHOOK", "DISCORD_WEBHOOK_VULNS"),
        "message_ids": ("DISCORD_VULNS_MESSAGE_ID", "DISCORD_WEBHOOK_VULNS_MESSAGE_ID"),
    },
}


def local_tz() -> dt.tzinfo:
    try:
        return ZoneInfo("America/Chicago")
    except ZoneInfoNotFoundError:
        return dt.timezone(dt.timedelta(hours=-5), "CDT")


def load_json(path: Path, fallback):
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def env_first(names: tuple[str, ...]) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def normalize_webhook(url: str) -> str:
    match = WEBHOOK_RE.match(url.strip())
    if not match:
        raise ValueError("Invalid Discord webhook URL")
    return f"https://discord.com/api/webhooks/{match.group(1)}/{match.group(2)}"


def request_json(method: str, url: str, payload: dict) -> dict:
    body = None if method == "GET" else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "pirate-moo-threat-tide-discord/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            text = response.read().decode("utf-8", errors="replace").strip()
            return json.loads(text) if text else {}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Discord {method} failed with HTTP {exc.code}: {error_body[:300]}") from exc


def local_time(value: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = dt.datetime.now(dt.timezone.utc)
    zone = local_tz()
    return parsed.astimezone(zone).strftime("%-I:%M %p %Z") if os.name != "nt" else parsed.astimezone(zone).strftime("%#I:%M %p %Z")


def truncate(value: str, limit: int) -> str:
    value = " ".join(str(value or "").split())
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "..."


def link(label: str, url: str) -> str:
    if not url:
        return label
    return f"[{label}]({url})"


def top_vulns(feed: dict, limit: int = 5) -> list[dict]:
    vulns = list(feed.get("vulns") or [])
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    return sorted(
        vulns,
        key=lambda item: (
            int(item.get("dayOffset", 99) or 99),
            severity_order.get(str(item.get("severity", "")).lower(), 9),
            -int(item.get("confidence", 0) or 0),
        ),
    )[:limit]


def top_research(feed: dict, limit: int = 5) -> list[dict]:
    research = [
        item
        for item in (feed.get("research") or [])
        if int(item.get("dayOffset", 99) or 99) <= 1
    ]
    if len(research) < limit:
        research = list(feed.get("research") or [])
    return sorted(research, key=lambda item: int(item.get("dayOffset", 99) or 99))[:limit]


def vuln_lines(feed: dict) -> str:
    lines = []
    for item in top_vulns(feed):
        cve = item.get("cve", "NO-CVE")
        sev = str(item.get("severity", "tracked")).upper()
        title = truncate(item.get("title", "Untitled vulnerability"), 95)
        url = item.get("pocUrl") or first_link(item, "GitHub") or SITE_URL
        lines.append(f"**{sev}** {link(cve, url)} - {title}")
    return "\n".join(lines) or "Nothing to see here today."


def research_lines(feed: dict) -> str:
    lines = []
    for item in top_research(feed):
        title = truncate(item.get("title", "Untitled research"), 105)
        source = item.get("source", "research")
        url = item.get("url") or item.get("sourceUrl") or SITE_URL
        lines.append(f"{link(title, url)} - {source}")
    return "\n".join(lines) or "Nothing to see here today."


def first_link(item: dict, label: str) -> str:
    for entry in item.get("links") or []:
        if len(entry) >= 2 and str(entry[0]).lower() == label.lower():
            return entry[1]
    return ""


def build_payload(channel: str, feed: dict) -> dict:
    updated = local_time(feed.get("updatedAt", ""))
    today_count = sum(1 for item in feed.get("vulns") or [] if int(item.get("dayOffset", 99) or 99) == 0)
    base = {
        "username": "pirate.moo",
        "avatar_url": "https://raw.githubusercontent.com/piratemoo/threat-tide/main/images/yespls.png",
        "allowed_mentions": {"parse": []},
    }
    description = f"Last Check: **{updated}**\nverified public pocs - **{today_count} posted today**\n\n{vuln_lines(feed)}"
    embed = {
        "title": "Threat Tide",
        "url": SITE_URL,
        "description": truncate(description, 3900),
        "color": 0xB026FF,
        "footer": {"text": "working public poc feed"},
    }
    return base | {"content": "", "embeds": [embed]}


def upsert_message(channel: str, webhook: str, message_id: str, payload: dict) -> str:
    webhook = normalize_webhook(webhook)
    if message_id:
        patch_url = f"{webhook}/messages/{urllib.parse.quote(message_id)}"
        request_json("PATCH", patch_url, payload)
        readback = request_json("GET", patch_url, {})
        if str(readback.get("id", "")) != str(message_id):
            raise RuntimeError(f"Discord readback mismatch for {channel}")
        return message_id

    created = request_json("POST", f"{webhook}?wait=true", payload)
    created_id = str(created.get("id", ""))
    if not created_id:
        raise RuntimeError(f"Discord did not return a message id for {channel}")
    return created_id


def main() -> int:
    feed = load_json(FEED_PATH, {})
    state = load_json(STATE_PATH, {"messages": {}})
    state.setdefault("messages", {})

    missing = [
        f"{channel}: set one of {', '.join(config['secrets'])}"
        for channel, config in CHANNELS.items()
        if not env_first(config["secrets"])
    ]
    if missing:
        print("Missing required Discord webhook secrets:")
        for item in missing:
            print(f"- {item}")
        return 1

    updated_channels = []

    for channel, config in CHANNELS.items():
        webhook = env_first(config["secrets"])
        message_id = env_first(config["message_ids"]) or state["messages"].get(channel, {}).get("messageId", "")
        payload = build_payload(channel, feed)
        new_id = upsert_message(channel, webhook, str(message_id), payload)
        state["messages"][channel] = {
            "messageId": new_id,
            "updatedAt": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        updated_channels.append(channel)

    if updated_channels:
        save_json(STATE_PATH, state)
    elif not STATE_PATH.exists():
        save_json(STATE_PATH, state)

    print("updated discord channels:", ", ".join(updated_channels))
    return 0


if __name__ == "__main__":
    sys.exit(main())
