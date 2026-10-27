import importlib.util
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
        with tempfile.TemporaryDirectory(prefix="vulns-recovery-") as temporary:
            feed_path = Path(temporary) / "feed.json"
            state_path = Path(temporary) / "state.json"
            feed_path.write_text("{}", encoding="utf-8")
            state_path.write_text(json.dumps({"messages": {"vulns": {"messageId": "old"}}}), encoding="utf-8")
            env = {"DISCORD_VULNS_WEBHOOK": WEBHOOK, "DISCORD_VULNS_MESSAGE_ID": "old"}
            with patch.dict(os.environ, env, clear=True), patch.object(posts, "FEED_PATH", feed_path), \
                    patch.object(posts, "STATE_PATH", state_path), \
                    patch.object(posts, "upsert_message", return_value="replacement") as upsert:
                self.assertEqual(posts.main(), 0)
                self.assertEqual(upsert.call_args.args[2], "old")
                self.assertEqual(posts.main(), 0)
                self.assertEqual(upsert.call_args.args[2], "replacement")
            saved = json.loads(state_path.read_text())["messages"]["vulns"]
            self.assertEqual(saved["messageId"], "replacement")
            self.assertEqual(saved["webhookId"], "123456789")

    def test_changed_webhook_does_not_reuse_another_webhooks_state(self):
        config = posts.CHANNELS["vulns"]
        with patch.dict(os.environ, {"DISCORD_VULNS_MESSAGE_ID": "seed"}, clear=True):
            message_id = posts.select_message_id(config, {"messageId": "wrong", "webhookId": "other"}, "current")
        self.assertEqual(message_id, "seed")

    def test_formatter_preserves_vulns_identity_and_line_breaks(self):
        feed = {"vulns": [{"cve": "CVE-TEST", "title": "Example", "summary": "Details", "dayOffset": 1}]}
        payload = posts.build_payload("vulns", feed)
        self.assertEqual(payload["username"], "VULNS")
        self.assertIn("\n\n", payload["content"])
        self.assertIn("🐮", payload["content"])
        self.assertEqual(payload["embeds"], [])


if __name__ == "__main__":
    unittest.main()
