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


class DiscordRequestError(RuntimeError):
    def __init__(self, method: str, status: int, body: str):
        self.status = status
        try:
            self.discord_code = json.loads(body).get("code")
        except (ValueError, AttributeError):
            self.discord_code = None
        super().__init__(f"Discord {method} failed with HTTP {status}: {body[:300]}")


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
        raise DiscordRequestError(method, exc.code, error_body) from exc


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


def truncate_message(value: str, limit: int) -> str:
    value = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
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


def first_link(item: dict, label: str) -> str:
    for entry in item.get("links") or []:
        if len(entry) >= 2 and str(entry[0]).lower() == label.lower():
            return entry[1]
    return ""


def display_date(item: dict, feed: dict) -> str:
    raw = item.get("firstSeenAt") or feed.get("updatedAt") or ""
    try:
        parsed = dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        parsed = dt.datetime.now(dt.timezone.utc)
    return parsed.strftime("%B %-d, %Y") if os.name != "nt" else parsed.strftime("%B %#d, %Y")


def tag_line(item: dict) -> str:
    tags = item.get("tags") or []
    return " ".join(truncate(tag, 22) for tag in tags[:5])


def link_line(item: dict) -> str:
    labels = {"github": "GitHub", "technical paper": "Technical Paper", "vendor advisory": "Advisory", "advisory": "Advisory"}
    parts = []
    seen = set()
    for entry in item.get("links") or []:
        if len(entry) < 2:
            continue
        label = labels.get(str(entry[0]).lower(), str(entry[0]))
        if label.lower() in seen:
            continue
        seen.add(label.lower())
        parts.append(link(label, entry[1]))
    if not parts and item.get("pocUrl"):
        parts.append(link("GitHub", item["pocUrl"]))
    return " | ".join(parts)


def similar_line(item: dict) -> str:
    category = str(item.get("category", "")).lower()
    ecosystem = str(item.get("ecosystem", "")).lower()
    if "sql" in category or "sqli" in " ".join(item.get("tags") or []).lower():
        return "\n".join([
            "CVE-2023-34362 MOVEit SQL injection",
            "CVE-2023-3519 Citrix ADC unauthenticated RCE",
            "CVE-2022-22965 Spring4Shell web RCE",
        ])
    if ecosystem == "linux":
        return "\n".join([
            "CVE-2022-0847 File overwrite to root (Dirty Pipe)",
            "CVE-2023-0386 OverlayFS privilege escalation",
            "CVE-2021-3156 Heap overflow to root (sudo Baron Samedit)",
        ])
    if ecosystem == "windows":
        return "\n".join([
            "CVE-2021-34527 PrintNightmare remote code execution",
            "CVE-2022-26923 AD CS domain escalation",
            "CVE-2023-23397 Outlook credential leak",
        ])
    return "\n".join([
        "CVE-2024-4577 PHP-CGI argument injection",
        "CVE-2023-22518 Confluence improper authorization",
        "CVE-2024-36401 GeoServer unauthenticated RCE",
    ])


def vuln_post(feed: dict) -> str:
    item = top_vulns(feed, 1)[0] if top_vulns(feed, 1) else None
    if not item:
        return f"**Nothing to see here today.**\n\n{SITE_URL}"
    cve = item.get("cve", "NO-CVE")
    title = truncate(item.get("title", "Untitled vulnerability"), 120)
    author = item.get("researcher", "unknown")
    language = item.get("language", "Unknown") or "Unknown"
    what = truncate(item.get("summary") or item.get("technicalSummary") or item.get("whatBroke") or title, 420)
    links = link_line(item)
    similar = similar_line(item)
    tags = tag_line(item)
    return "\n".join([
        f"｡ﾟﾟ･｡･ﾟﾟ｡ 🐮 {title} 🐮 ｡ﾟﾟ･｡･ﾟﾟ｡",
        "",
        f"{display_date(item, feed)} {cve}",
        tags,
        f"Author: {author} | Language: {language}",
        links,
        "",
        title,
        "",
        f"__What happened:__ {what}",
        "",
        "Similar:",
        similar,
        "⋆⋅☆⋅⋆⋅☆⋅⋆⋅☆⋅⋆⋅☆⋅⋆",
        "⠀",
    ])


def build_payload(channel: str, feed: dict) -> dict:
    return {
        "username": "VULNS",
        "avatar_url": "https://raw.githubusercontent.com/piratemoo/threat-tide/main/images/yespls.png",
        "allowed_mentions": {"parse": []},
        "content": truncate_message(vuln_post(feed), 1900),
        "embeds": [],
        "flags": 4,
    }


def upsert_message(channel: str, webhook: str, message_id: str, payload: dict) -> str:
    webhook = normalize_webhook(webhook)
    if message_id:
        patch_url = f"{webhook}/messages/{urllib.parse.quote(message_id)}"
        try:
            request_json("PATCH", patch_url, payload)
        except DiscordRequestError as error:
            # Only a deleted message can be repaired by creating another one.
            # A missing webhook or permission failure needs configuration repair.
            if error.status != 404 or error.discord_code != 10008:
                raise
        else:
            readback = request_json("GET", patch_url, {})
            if str(readback.get("id", "")) != str(message_id):
                raise RuntimeError(f"Discord readback mismatch for {channel}")
            return message_id

    created = request_json("POST", f"{webhook}?wait=true", payload)
    created_id = str(created.get("id", ""))
    if not created_id:
        raise RuntimeError(f"Discord did not return a message id for {channel}")
    return created_id


def select_message_id(config: dict, saved: dict, webhook_id: str) -> str:
    # The secret is a first-run seed. Once a replacement has been saved, it
    # must win over a stale secret on subsequent scheduled runs.
    if saved.get("webhookId", webhook_id) == webhook_id and saved.get("messageId"):
        return str(saved["messageId"])
    return env_first(config["message_ids"])


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
        print("::error title=Discord vulnerability feed::Missing required Discord webhook secrets")
        for item in missing:
            print(f"- {item}")
        return 1

    updated_channels = []

    for channel, config in CHANNELS.items():
        webhook = normalize_webhook(env_first(config["secrets"]))
        webhook_id = WEBHOOK_RE.match(webhook).group(1)
        message_id = select_message_id(config, state["messages"].get(channel, {}), webhook_id)
        payload = build_payload(channel, feed)
        new_id = upsert_message(channel, webhook, str(message_id), payload)
        state["messages"][channel] = {
            "messageId": new_id,
            "webhookId": webhook_id,
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
    try:
        sys.exit(main())
    except (DiscordRequestError, urllib.error.URLError, ValueError, RuntimeError) as error:
        # Surface the actual cause in GitHub's annotations, rather than only
        # the generic "Process completed with exit code 1" annotation.
        detail = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Discord vulnerability feed::{detail}", file=sys.stderr)
        sys.exit(1)
