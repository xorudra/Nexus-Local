#!/usr/bin/env python3
"""Tests for the external /v1 API surface (owner order 2026-10-09):
Nexus supplies DSRclone's AI service through an OpenAI-compatible,
service-key-gated endpoint riding the integrated relay lanes.

Run:  python3 -m unittest discover -s tests -v
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))

os.environ.pop("NEXUS_RESTORE_KEY", None)  # never touch the real restore key

import server  # noqa: E402

FIXTURE_KEY = "fixture-v1-key-not-a-real-secret"


def _ok_payload(text="hello from the lane"):
    return {"id": "chatcmpl-fixture", "object": "chat.completion",
            "model": "fixture-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4}}


class V1RouteTests(unittest.TestCase):
    def test_auto_uses_full_lane_order(self):
        self.assertEqual(server._v1_route("nexus-auto"), list(server._V1_LANES))
        self.assertEqual(server._v1_route(""), list(server._V1_LANES))
        self.assertEqual(server._v1_route(None), list(server._V1_LANES))

    def test_lane_prefixed_model(self):
        self.assertEqual(server._v1_route("relay_groq/openai/gpt-oss-20b"),
                         [("relay_groq", "openai/gpt-oss-20b")])

    def test_known_default_model_maps_to_its_lane(self):
        self.assertEqual(server._v1_route("gemini-3.5-flash-lite"),
                         [("relay_gemini", "gemini-3.5-flash-lite")])

    def test_unknown_bare_model_tries_smart_lanes(self):
        attempts = server._v1_route("some-new-model")
        self.assertEqual(len(attempts), 3)
        self.assertTrue(all(m == "some-new-model" for _l, m in attempts))


class V1AuthTests(unittest.TestCase):
    def _handler(self, auth_header=None):
        h = server.Handler.__new__(server.Handler)
        h.headers = {}
        if auth_header is not None:
            h.headers["Authorization"] = auth_header
        return h

    def test_no_env_key_means_disabled(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NEXUS_V1_API_KEY", None)
            self.assertFalse(self._handler(f"Bearer {FIXTURE_KEY}")._v1_authorized())

    def test_correct_bearer_accepted_wrong_rejected(self):
        with mock.patch.dict(os.environ, {"NEXUS_V1_API_KEY": FIXTURE_KEY}):
            self.assertTrue(self._handler(f"Bearer {FIXTURE_KEY}")._v1_authorized())
            self.assertFalse(self._handler("Bearer wrong-key")._v1_authorized())
            self.assertFalse(self._handler("")._v1_authorized())
            self.assertFalse(self._handler(None)._v1_authorized())


class V1ChatTests(unittest.TestCase):
    def setUp(self):
        self._orig_keys = server.Handler.keys
        self._orig_down = dict(server._PROVIDER_HEALTH)

    def tearDown(self):
        server.Handler.keys = self._orig_keys
        server._PROVIDER_HEALTH.clear()
        server._PROVIDER_HEALTH.update(self._orig_down)

    def test_keyless_lane_answers_while_vault_locked(self):
        server.Handler.keys = None  # locked: keyed lanes are skipped

        def fake_call(lane, path, payload=None, timeout=90):
            self.assertEqual(lane, "relay_pollinations")
            return _ok_payload()

        with mock.patch.object(server, "_v1_relay_call", fake_call):
            code, out, lane = server._v1_chat(
                [{"role": "user", "content": "hi"}], "nexus-auto")
        self.assertEqual(code, 200)
        self.assertEqual(lane, "relay_pollinations")
        self.assertEqual(out["choices"][0]["message"]["content"],
                         "hello from the lane")

    def test_failover_skips_failing_lanes(self):
        server.Handler.keys = {}  # unlocked: keyed lanes are attempted

        def fake_call(lane, path, payload=None, timeout=90):
            if lane in ("relay_gemini", "relay_openrouter"):
                raise HTTPError("http://x", 429, "slow down", None, None)
            if lane == "relay_groq":
                return _ok_payload("from groq")
            raise AssertionError(f"unexpected lane {lane}")

        with mock.patch.object(server, "_v1_relay_call", fake_call):
            code, out, lane = server._v1_chat(
                [{"role": "user", "content": "hi"}], "nexus-auto")
        self.assertEqual(code, 200)
        self.assertEqual(lane, "relay_groq")

    def test_all_lanes_down_gives_502(self):
        server.Handler.keys = {}

        def fake_call(lane, path, payload=None, timeout=90):
            raise HTTPError("http://x", 503, "down", None, None)

        with mock.patch.object(server, "_v1_relay_call", fake_call):
            code, out, lane = server._v1_chat(
                [{"role": "user", "content": "hi"}], "nexus-auto")
        self.assertEqual(code, 502)
        self.assertIn("error", out)


class V1CapTests(unittest.TestCase):
    """The instance-wide daily cap must bind /v1 too (reel-risk fix):
    dashboard rows count per user, /v1 rows count under their
    'v1:<lane>' provider names; plain provider rows must not be
    double-counted."""

    COUNTS = {"ts": 0.0, "users": {"friendone": 2, "chatgpt": 1},
              "providers": {"v1:relay_groq": 3, "groq": 50}}

    def test_today_total_requests(self):
        with mock.patch.object(server, "_today_counts",
                               lambda fresh=False: dict(self.COUNTS)):
            self.assertEqual(server._today_total_requests(), 6)

    def test_instance_cap_reached(self):
        with mock.patch.object(server, "_today_counts",
                               lambda fresh=False: dict(self.COUNTS)):
            with mock.patch.dict(server._SETTINGS, {"global_cap": 0}):
                self.assertFalse(server._instance_cap_reached())
            with mock.patch.dict(server._SETTINGS, {"global_cap": 7}):
                self.assertFalse(server._instance_cap_reached())
            with mock.patch.dict(server._SETTINGS, {"global_cap": 6}):
                self.assertTrue(server._instance_cap_reached())
            with mock.patch.dict(server._SETTINGS, {"global_cap": 3}):
                self.assertTrue(server._instance_cap_reached())


class V1FreeLLanesTests(unittest.TestCase):
    """FreeLLMAPI providers as supply lanes (owner order 2026-10-09)."""

    def setUp(self):
        self._orig_keys = server.Handler.keys
        self._orig_down = dict(server._PROVIDER_HEALTH)

    def tearDown(self):
        server.Handler.keys = self._orig_keys
        server._PROVIDER_HEALTH.clear()
        server._PROVIDER_HEALTH.update(self._orig_down)

    def test_freellmapi_lanes_in_auto_order(self):
        lanes = [lane for lane, _m in server._V1_LANES]
        for name in ("google", "openrouter", "groq", "nvidia"):
            self.assertIn(name, lanes)
        # Relay key set first, FreeLLMAPI set next, keyless lane last.
        self.assertLess(lanes.index("relay_nvidia"), lanes.index("google"))
        self.assertLess(lanes.index("nvidia"), lanes.index("relay_pollinations"))
        self.assertEqual(lanes[-1], "relay_pollinations")

    def test_lane_prefixed_freellmapi_model(self):
        self.assertEqual(server._v1_route("groq/openai/gpt-oss-20b"),
                         [("groq", "openai/gpt-oss-20b")])

    def test_chat_can_answer_via_freellmapi_lane(self):
        server.Handler.keys = {"groq": "fixture"}

        def fake_call(lane, path, payload=None, timeout=90):
            self.assertEqual(lane, "groq")
            return _ok_payload("from freellmapi groq")

        with mock.patch.object(server, "_v1_relay_call", fake_call):
            code, out, lane = server._v1_chat(
                [{"role": "user", "content": "hi"}], "groq/openai/gpt-oss-20b")
        self.assertEqual((code, lane), (200, "groq"))
        self.assertEqual(out["choices"][0]["message"]["content"],
                         "from freellmapi groq")


class V1GenerateKeyTests(unittest.TestCase):
    """Admin-created service keys (owner orders 2026-10-09 + the
    multi-key features 2026-10-16): named keys in one restore-key
    encrypted list, disable/enable/delete semantics, last-used
    stamps, and in-place migration of the original single-key
    file shape."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="nexus-v1key-"))
        self._orig = (server.RESTORE_KEY, server.V1KEY_PATH,
                      list(server._V1KEYS["keys"]))
        server.RESTORE_KEY = "test-restore-key"
        server.V1KEY_PATH = self._tmp / "v1key.enc"
        server._V1KEYS["keys"] = []

    def tearDown(self):
        (server.RESTORE_KEY, server.V1KEY_PATH,
         server._V1KEYS["keys"]) = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _handler(self, auth_header=None):
        h = server.Handler.__new__(server.Handler)
        h.headers = {}
        if auth_header is not None:
            h.headers["Authorization"] = auth_header
        return h

    def test_create_persists_and_wins_over_env(self):
        entry = server._create_v1key("DSRclone")
        self.assertTrue(entry["key"].startswith("nxk-"))
        self.assertTrue(server.V1KEY_PATH.exists())
        with mock.patch.dict(os.environ, {"NEXUS_V1_API_KEY": FIXTURE_KEY}):
            self.assertEqual(server._v1_api_key(), entry["key"])
            self.assertEqual(server._v1_key_source(), "generated")
            self.assertTrue(self._handler(f"Bearer {entry['key']}")._v1_authorized())
            # Stored keys win outright: the env key no longer authenticates.
            self.assertFalse(self._handler(f"Bearer {FIXTURE_KEY}")._v1_authorized())
        # A fresh boot reloads the list from disk.
        server._V1KEYS["keys"] = []
        server._load_v1key()
        self.assertEqual([k["key"] for k in server._V1KEYS["keys"]], [entry["key"]])
        self.assertEqual(server._V1KEYS["keys"][0]["name"], "DSRclone")

    def test_create_needs_restore_key(self):
        server.RESTORE_KEY = ""
        self.assertIsNone(server._create_v1key("x"))
        self.assertEqual(server._v1_key_source(), "none")

    def test_migration_from_single_key_shape(self):
        server.encrypt_keys({"key": FIXTURE_KEY, "created": 4242},
                            "test-restore-key", server.V1KEY_PATH)
        server._load_v1key()
        self.assertEqual(len(server._V1KEYS["keys"]), 1)
        k = server._V1KEYS["keys"][0]
        self.assertEqual(k["key"], FIXTURE_KEY)
        self.assertEqual(k["created"], 4242)
        self.assertTrue(self._handler(f"Bearer {FIXTURE_KEY}")._v1_authorized())
        # The file on disk has been rewritten in the list shape.
        d = server.decrypt_keys(server.V1KEY_PATH, "test-restore-key")
        self.assertIn("keys", d)

    def test_disable_enable_delete_and_last_used(self):
        a = server._create_v1key("A")
        b = server._create_v1key("B")
        self.assertIsNone(a["last_used"])
        self.assertTrue(self._handler(f"Bearer {a['key']}")._v1_authorized())
        self.assertIsNotNone(a["last_used"])
        a["disabled"] = True
        self.assertFalse(self._handler(f"Bearer {a['key']}")._v1_authorized())
        self.assertTrue(self._handler(f"Bearer {b['key']}")._v1_authorized())
        a["disabled"] = False
        self.assertTrue(self._handler(f"Bearer {a['key']}")._v1_authorized())
        server._V1KEYS["keys"].remove(b)
        self.assertFalse(self._handler(f"Bearer {b['key']}")._v1_authorized())


if __name__ == "__main__":
    unittest.main()
