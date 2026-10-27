import importlib.util
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "update_discord_posts.py"
SPEC = importlib.util.spec_from_file_location("discord_posts", SCRIPT)
posts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(posts)
WEBHOOK = "https://discord.com/api/webhooks/123456789/test-only-placeholder"


class DiscordRecoveryTests(unittest.TestCase):
    def test_deleted_message_is_replaced_once(self):
        deleted = posts.DiscordRequestError("PATCH", 404, '{"code":10008,"message":"Unknown Message"}')
        with patch.object(posts, "request_json", side_effect=[deleted, {"id": "new"}]) as request:
            result = posts.upsert_message("vulns", WEBHOOK, "deleted", {"content": "test"})
        self.assertEqual(result, "new")
        self.assertEqual([call.args[0] for call in request.call_args_list], ["PATCH", "POST"])

    def test_invalid_webhook_is_not_treated_as_deleted_message(self):
        invalid = posts.DiscordRequestError("PATCH", 404, '{"code":10015,"message":"Unknown Webhook"}')
        with patch.object(posts, "request_json", side_effect=invalid) as request:
            with self.assertRaises(posts.DiscordRequestError):
                posts.upsert_message("vulns", WEBHOOK, "old", {})
        self.assertEqual(request.call_count, 1)

    def test_permission_failure_does_not_create_a_post(self):
        forbidden = posts.DiscordRequestError("PATCH", 403, '{"code":50013,"message":"Missing Permissions"}')
        with patch.object(posts, "request_json", side_effect=forbidden) as request:
            with self.assertRaises(posts.DiscordRequestError):
                posts.upsert_message("vulns", WEBHOOK, "old", {})
        self.assertEqual(request.call_count, 1)

    def test_failed_readback_does_not_create_a_duplicate(self):
        missing = posts.DiscordRequestError("GET", 404, '{"code":10008,"message":"Unknown Message"}')
        with patch.object(posts, "request_json", side_effect=[{}, missing]) as request:
            with self.assertRaises(posts.DiscordRequestError):
                posts.upsert_message("vulns", WEBHOOK, "existing", {})
        self.assertEqual([call.args[0] for call in request.call_args_list], ["PATCH", "GET"])

    def test_saved_replacement_wins_over_stale_message_secret(self):
        with patch.dict(os.environ, {"DISCORD_VULNS_MESSAGE_ID": "old"}, clear=True):
            self.assertEqual(posts.select_message_id(posts.CHANNELS["vulns"], {"messageId": "replacement"}, "123456789"), "replacement")

    def test_changed_webhook_does_not_reuse_another_webhooks_state(self):
        config = posts.CHANNELS["vulns"]
        with patch.dict(os.environ, {"DISCORD_VULNS_MESSAGE_ID": "seed"}, clear=True):
            message_id = posts.select_message_id(config, {"messageId": "wrong", "webhookId": "other"}, "current")
        self.assertEqual(message_id, "seed")

    def test_formatter_preserves_vulns_identity_and_line_breaks(self):
        feed = {"vulns": [{"cve": "CVE-TEST", "title": "Example", "summary": "Details", "severity": "critical", "dayOffset": 1}]}
        payload = posts.build_payload("vulns", feed)
        self.assertEqual(payload["username"], "vulns")
        self.assertIn("\n\n", payload["content"])
        self.assertIn("<:critcow:1538457179802312744>", payload["content"])
        self.assertNotIn("avatar_url", payload)
        self.assertEqual(payload["embeds"], [])

    def test_week_window_excludes_stale_and_future_entries_and_dedupes_cves(self):
        now = dt.datetime.now(dt.timezone.utc)
        def entry(cve, days):
            return {"cve": cve, "firstSeenAt": (now - dt.timedelta(days=days)).isoformat()}
        feed = {"vulns": [entry("CVE-2026-1", 1), entry("CVE-2026-2", 6), entry("CVE-2026-1", 1),
                           entry("CVE-2026-3", 8), entry("CVE-2026-4", -1)]}
        self.assertEqual([v["cve"] for v in posts.recent_vulns(feed, now, 7)], ["CVE-2026-2", "CVE-2026-1"])

    def test_today_is_prioritized_over_yesterday(self):
        feed = {"vulns": [{"cve": "today", "dayOffset": 0}, {"cve": "yesterday", "dayOffset": 1}]}
        self.assertEqual(posts.top_vulns(feed, 1)[0]["cve"], "today")

    def test_each_vulnerability_posts_once_and_survives_a_failed_readback(self):
        with tempfile.TemporaryDirectory(prefix="vulns-ledger-") as temporary:
            feed_path = Path(temporary) / "feed.json"
            state_path = Path(temporary) / "state.json"
            recent = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
            feed_path.write_text(json.dumps({"vulns": [{"cve": "CVE-2026-1", "title": "One", "firstSeenAt": recent, "severity": "high"},
                                                        {"cve": "CVE-2026-2", "title": "Two", "firstSeenAt": recent, "severity": "critical"}]}), encoding="utf-8")
            created = {}
            fail_readback = [True]
            def create(channel, webhook, message_id, payload):
                self.assertEqual(message_id, "")
                message_id = str(len(created) + 1)
                created[message_id] = payload
                return message_id
            def request(method, url, payload):
                self.assertEqual(method, "GET")
                if url == WEBHOOK:
                    return {"avatar": "original-avatar"}
                if fail_readback[0]:
                    fail_readback[0] = False
                    raise RuntimeError("temporary readback failure")
                message_id = url.rsplit("/", 1)[1]
                return {"id": message_id, "content": created[message_id]["content"],
                        "author": {"username": "vulns", "avatar": "original-avatar"}}
            with patch.dict(os.environ, {"DISCORD_VULNS_WEBHOOK": WEBHOOK}, clear=True), \
                    patch.object(posts, "FEED_PATH", feed_path), patch.object(posts, "STATE_PATH", state_path), \
                    patch.object(posts, "upsert_message", side_effect=create), patch.object(posts, "request_json", side_effect=request), \
                    patch.object(posts.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, "temporary readback failure"):
                    posts.main([])
                self.assertEqual(len(created), 1)
                self.assertEqual(posts.main([]), 0)
                self.assertEqual(posts.main([]), 0)
                self.assertEqual(len(created), 2)
            ledger = json.loads(state_path.read_text())["postedVulns"]
            self.assertEqual(set(ledger), {"CVE-2026-1", "CVE-2026-2"})
            self.assertTrue(all(item["verified"] and item["identityVerified"] for item in ledger.values()))

    def test_all_severity_icons_match_the_original_server_emoji(self):
        for severity, icon in posts.SEVERITY_ICONS.items():
            payload = posts.build_payload("vulns", {"vulns": [{"cve": "CVE-2026-1", "title": "Example", "severity": severity}]})
            self.assertEqual(payload["content"].count(icon), 2)

    def test_legacy_post_is_updated_without_reposting_or_deleting_it(self):
        with tempfile.TemporaryDirectory(prefix="vulns-legacy-") as temporary:
            feed_path = Path(temporary) / "feed.json"
            state_path = Path(temporary) / "state.json"
            recent = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
            item = {"cve": "CVE-2026-1", "title": "Existing", "firstSeenAt": recent, "severity": "critical"}
            feed_path.write_text(json.dumps({"vulns": [item]}), encoding="utf-8")
            state_path.write_text(json.dumps({"messages": {"vulns": {"messageId": "existing"}}}), encoding="utf-8")
            content = ["Old style CVE-2026-1"]
            methods = []
            def request(method, url, payload):
                methods.append(method)
                if url == WEBHOOK:
                    return {"avatar": "original-avatar"}
                if method == "PATCH":
                    content[0] = payload["content"]
                return {"id": "existing", "content": content[0], "author": {"username": "old-name", "avatar": "old-avatar"}}
            with patch.dict(os.environ, {"DISCORD_VULNS_WEBHOOK": WEBHOOK}, clear=True), \
                    patch.object(posts, "FEED_PATH", feed_path), patch.object(posts, "STATE_PATH", state_path), \
                    patch.object(posts, "upsert_message") as create, patch.object(posts, "request_json", side_effect=request):
                self.assertEqual(posts.main([]), 0)
                self.assertEqual(posts.main([]), 0)
                create.assert_not_called()
            self.assertIn("PATCH", methods)
            self.assertNotIn("DELETE", methods)
            record = json.loads(state_path.read_text())["postedVulns"]["CVE-2026-1"]
            self.assertEqual(record["messageId"], "existing")
            self.assertTrue(record["verified"])
            self.assertFalse(record["identityVerified"])


if __name__ == "__main__":
    unittest.main()
