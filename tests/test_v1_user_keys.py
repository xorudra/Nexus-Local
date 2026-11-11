"""Per-user Nexus API keys (owner order 2026-11-07).

Friends generate their own /v1 service keys (max 3 active, shared pool,
per-key daily request/token limits the owner sets); the owner sees them
on the user card and can revoke or re-limit them. Unittest style only.
"""
import datetime
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import server

_ok_payload = {
    "id": "chatcmpl-test", "object": "chat.completion", "created": 1700000000,
    "model": "openai/gpt-oss-20b",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7},
}


class _V1KeyMixin:
    """tmp v1key store + RESTORE_KEY, as in test_v1_api.V1ApiTests."""

    def _reset(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig = (server.RESTORE_KEY, server.V1KEY_PATH,
                      list(server._V1KEYS["keys"]), server.USAGE_PATH)
        server.V1KEY_PATH = Path(self._tmpdir.name) / "v1key.enc"
        server.USAGE_PATH = Path(self._tmpdir.name) / "usage.jsonl"
        server.RESTORE_KEY = "test-restore-key"
        server._V1KEYS = {"keys": []}
        server._V1KEYS_TOUCH = {"at": 0.0}
        server._INFLIGHT = []
        server._USAGE = []
        server._CHATS = {}
        self._load_legacy([])
        self.addCleanup(self._tmpdir.cleanup)
        self.addCleanup(lambda: setattr(server, "_V1KEYS_TOUCH", {"at": 0.0}))
        self.addCleanup(lambda: setattr(server, "_INFLIGHT", []))
        self.addCleanup(self._restore_globals)

    def _restore_globals(self):
        (server.RESTORE_KEY, server.V1KEY_PATH,
         server._V1KEYS["keys"], server.USAGE_PATH) = self._orig

    def _load_legacy(self, keys):
        with server._KEYS_LOCK:
            server._V1KEYS = {"keys": keys}
            server._save_v1keys()

    def _mk_key(self, owner="friendone", req_limit=0, tok_limit=0, name="k"):
        entry = server._create_v1key(
            name, owner=owner, req_limit=req_limit, tok_limit=tok_limit)
        return entry, entry["key"]

    def _post(self, path, body, session=None):
        h = server.Handler.__new__(server.Handler)
        raw = json.dumps(body).encode()
        h.path = path
        h.headers = {"Content-Length": str(len(raw))}
        h.rfile = io.BytesIO(raw)
        h.wfile = io.BytesIO()
        h._head_only = False
        h._status = None
        h._out = []
        h._set_json_headers = lambda status=200: setattr(h, "_status", status)
        h._send_body = lambda data: h._out.append(data)
        h._ip_gate = lambda: True
        with mock.patch.object(server.Handler, "_session_info",
                               return_value=session):
            h.do_POST()
        data = b"".join(h._out) or h.wfile.getvalue()
        return h._status, json.loads(data or b"{}")

    def _get(self, path, session=None):
        """GET through do_GET with a stubbed session (mirrors _post)."""
        h = server.Handler.__new__(server.Handler)
        h.path = path
        h.headers = {}
        h.rfile = io.BytesIO(b"")
        h.wfile = io.BytesIO()
        h._head_only = False
        h._status = None
        h._out = []
        h.send_response = lambda code, message=None: setattr(h, "_status", code)
        h.send_header = lambda *a, **k: None
        h.end_headers = lambda: None
        h._set_json_headers = lambda status=200: setattr(h, "_status", status)
        h._send_body = lambda data: h._out.append(data)
        h._ip_gate = lambda: True
        with mock.patch.object(server.Handler, "_session_info",
                               return_value=session):
            h.do_GET()
        body = b"".join(h._out)
        try:
            return h._status, json.loads(body or b"{}")
        except Exception:
            return h._status, body

    def _v1(self, key, body=None):
        h = server.Handler.__new__(server.Handler)
        raw = json.dumps(body or {
            "model": "openai/gpt-oss-20b",
            "messages": [{"role": "user", "content": "hi"}]}).encode()
        h.headers = {"Authorization": "Bearer " + key,
                     "Content-Length": str(len(raw))}
        h.rfile = io.BytesIO(raw)
        h.wfile = io.BytesIO()
        h._head_only = False
        h._status = None
        h._set_json_headers = lambda status=200: setattr(h, "_status", status)
        return h


class BackfillTests(_V1KeyMixin, unittest.TestCase):
    def setUp(self):
        self._reset()

    def test_legacy_list_entry_backfills_to_admin_unlimited(self):
        self._load_legacy([{"id": "k1", "name": "old", "key": "nxk-old",
                            "created": 1700000000, "last_used": 0,
                            "disabled": False}])
        with server._KEYS_LOCK:
            server._load_v1key_locked({"keys": server._V1KEYS["keys"]})
            e = server._V1KEYS["keys"][0]
        self.assertEqual(e["owner"], "admin")
        self.assertEqual(e["req_limit"], 0)
        self.assertEqual(e["tok_limit"], 0)
        self.assertEqual(e["req_used"], 0)
        self.assertEqual(e["tok_used"], 0)
        self.assertEqual(e["used_day"], datetime.date.today().isoformat())

    def test_single_key_shape_backfills_to_admin_unlimited(self):
        self._load_legacy([{"id": "k1", "name": "old", "key": "nxk-old",
                            "created": 1700000000, "last_used": 0,
                            "disabled": False}])
        with server._KEYS_LOCK:
            server._load_v1key_locked({"key": server._V1KEYS["keys"][0]})
        self.assertEqual(len(server._V1KEYS["keys"]), 1)
        self.assertEqual(server._V1KEYS["keys"][0]["owner"], "admin")
        self.assertEqual(server._V1KEYS["keys"][0]["req_limit"], 0)

    def test_create_v1key_defaults_and_owner_limits(self):
        e, full = self._mk_key()
        self.assertEqual(e["owner"], "friendone")
        self.assertEqual(e["req_limit"], 0)
        self.assertEqual(e["tok_limit"], 0)
        e2 = server._create_v1key("capped", owner="friendtwo",
                                  req_limit=200, tok_limit=100000)
        self.assertEqual(e2["owner"], "friendtwo")
        self.assertEqual(e2["req_limit"], 200)
        self.assertEqual(e2["tok_limit"], 100000)
        self.assertTrue(full.startswith("nxk-"))


class MyKeysTests(_V1KeyMixin, unittest.TestCase):
    def setUp(self):
        self._reset()

    def test_friend_generate_lists_key_once_then_never_full(self):
        st, r = self._post("/api/mykeys", {"action": "v1generate",
                                           "name": "my key"},
                           session={"label": "friendone"})
        self.assertEqual(st, 200, r)
        self.assertTrue(r["ok"])
        self.assertTrue(r["key"].startswith("nxk-"))
        self.assertEqual(r["req_limit"], 200)
        self.assertEqual(r["tok_limit"], 100000)
        st, r = self._post("/api/mykeys", {"action": "v1keys"},
                           session={"label": "friendone"})
        self.assertEqual(st, 200, r)
        self.assertEqual(len(r["keys"]), 1)
        k = r["keys"][0]
        self.assertNotIn("key_full", k)
        self.assertNotIn("key", k)
        self.assertEqual(k["last4"], r["keys"][0]["last4"])
        self.assertEqual(k["req_used"], 0)
        self.assertEqual(k["tok_limit"], 100000)

    def test_friend_generate_cap_of_three_active(self):
        for i in range(3):
            st, r = self._post("/api/mykeys", {"action": "v1generate"},
                               session={"label": "friendone"})
            self.assertEqual(st, 200, r)
        st, r = self._post("/api/mykeys", {"action": "v1generate"},
                           session={"label": "friendone"})
        self.assertEqual(st, 400, r)
        # Disabling one frees a slot.
        st, r = self._post("/api/mykeys", {"action": "v1keys"},
                           session={"label": "friendone"})
        kid = r["keys"][0]["id"]
        st, r = self._post("/api/mykeys", {"action": "v1disable", "id": kid},
                           session={"label": "friendone"})
        self.assertEqual(st, 200, r)
        st, r = self._post("/api/mykeys", {"action": "v1generate"},
                           session={"label": "friendone"})
        self.assertEqual(st, 200, r)

    def test_friend_cannot_list_or_disable_others_keys(self):
        self._mk_key(owner="friendone")
        self._mk_key(owner="friendtwo")
        st, r = self._post("/api/mykeys", {"action": "v1keys"},
                           session={"label": "friendtwo"})
        self.assertEqual(st, 200, r)
        self.assertEqual(len(r["keys"]), 1)
        self.assertEqual(r["keys"][0]["name"], "k")
        other = [k for k in server._V1KEYS["keys"]
                 if k["owner"] == "friendone"][0]
        st, r = self._post("/api/mykeys", {"action": "v1disable",
                                           "id": other["id"]},
                           session={"label": "friendtwo"})
        self.assertEqual(st, 404, r)
        self.assertFalse(other["disabled"])
        st, r = self._post("/api/mykeys", {"action": "v1delete",
                                           "id": other["id"]},
                           session={"label": "friendtwo"})
        self.assertEqual(st, 404, r)
        self.assertEqual(len(server._V1KEYS["keys"]), 2)

    def test_admin_and_viewer_get_403_on_mykeys_v1(self):
        st, r = self._post("/api/mykeys", {"action": "v1keys"},
                           session={"admin": True, "label": "Rudra"})
        self.assertEqual(st, 403, r)
        st, r = self._post("/api/mykeys", {"action": "v1keys"},
                           session={"viewer": True, "label": "viewer:x"})
        self.assertEqual(st, 403, r)

    def test_label_reserved(self):
        # Signup lowercases the label first, so the helper is
        # case-sensitive by design ("RUDRA" never reaches it).
        self.assertTrue(server._label_reserved("admin"))
        self.assertTrue(server._label_reserved("rudra"))
        self.assertTrue(server._label_reserved("_x"))
        self.assertFalse(server._label_reserved("friendone"))

    def test_list_action_carries_v1keys_for_admin(self):
        e, _ = self._mk_key(owner="friendone", req_limit=200,
                            tok_limit=100000)
        with mock.patch.object(server, "_load_access",
                               return_value={"friendone": "hash"}):
            st, r = self._post("/api/access", {"action": "list"},
                               session={"admin": True})
        self.assertEqual(st, 200, r)
        acc = [a for a in r["access"] if a["label"] == "friendone"]
        self.assertEqual(len(acc), 1)
        self.assertEqual(len(acc[0]["v1keys"]), 1)
        self.assertEqual(acc[0]["v1keys"][0]["id"], e["id"])
        self.assertNotIn("key_full", acc[0]["v1keys"][0])


class LimitEnforcementTests(_V1KeyMixin, unittest.TestCase):
    def setUp(self):
        self._reset()

    def _call_v1(self, full, chat=(200, _ok_payload, "groq")):
        h = self._v1(full)
        with mock.patch.object(server, "_v1_chat", return_value=chat), \
                mock.patch.dict(server._SETTINGS, {"global_cap": 0}):
            h._v1_chat_completions()
            res = h._status, json.loads(h.wfile.getvalue() or b"{}")
        if getattr(h, "_cap_res", None):
            server._inflight_drop(h._cap_res)
        return res

    def test_success_counts_requests_and_tokens(self):
        e, full = self._mk_key(req_limit=10, tok_limit=100)
        st, r = self._call_v1(full)
        self.assertEqual(st, 200, r)
        self.assertEqual(e["req_used"], 1)
        self.assertEqual(e["tok_used"], 7)

    def test_request_limit_429_without_dispatch(self):
        e, full = self._mk_key(req_limit=1, tok_limit=0)
        e["req_used"] = 1
        h = self._v1(full)
        with mock.patch.object(server, "_v1_chat") as chat, \
                mock.patch.dict(server._SETTINGS, {"global_cap": 0}):
            h._v1_chat_completions()
            st = h._status
        self.assertEqual(st, 429)
        chat.assert_not_called()
        self.assertEqual(e["req_used"], 1)

    def test_token_limit_429_without_dispatch(self):
        e, full = self._mk_key(req_limit=0, tok_limit=10)
        e["tok_used"] = 10
        h = self._v1(full)
        with mock.patch.object(server, "_v1_chat") as chat, \
                mock.patch.dict(server._SETTINGS, {"global_cap": 0}):
            h._v1_chat_completions()
            st = h._status
        self.assertEqual(st, 429)
        chat.assert_not_called()
        self.assertEqual(e["tok_used"], 10)

    def test_failed_call_does_not_count(self):
        e, full = self._mk_key(req_limit=10, tok_limit=100)
        st, r = self._call_v1(full, chat=(502, {"error": "boom"}, "groq"))
        self.assertEqual(st, 502, r)
        self.assertEqual(e["req_used"], 0)
        self.assertEqual(e["tok_used"], 0)

    def test_day_roll_resets_counters(self):
        e, full = self._mk_key(req_limit=1, tok_limit=10)
        e["req_used"] = 1
        e["tok_used"] = 10
        e["used_day"] = "2000-01-01"
        self.assertIsNone(server._v1_key_limit_error(e))
        self.assertEqual(e["req_used"], 0)
        self.assertEqual(e["tok_used"], 0)
        self.assertEqual(e["used_day"], datetime.date.today().isoformat())

    def test_env_key_has_no_limits(self):
        self.assertIsNone(server._v1_key_limit_error("env"))
        self.assertIsNone(server._v1_key_limit_error(None))


class SetLimitTests(_V1KeyMixin, unittest.TestCase):
    def setUp(self):
        self._reset()
        self._proof = mock.patch.object(
            server, "_master_proof",
            lambda pw: "proof" if pw == "master-pw" else None)
        self._proof.start()
        self.addCleanup(self._proof.stop)

    def test_set_limit_updates_key(self):
        e, _ = self._mk_key(owner="friendone")
        st, r = self._post("/api/v1-access/set-limit",
                           {"id": e["id"], "req_limit": 50,
                            "tok_limit": 5000, "master_pw": "master-pw"},
                           session={"admin": True})
        self.assertEqual(st, 200, r)
        self.assertEqual(e["req_limit"], 50)
        self.assertEqual(e["tok_limit"], 5000)

    def test_set_limit_requires_master_pw(self):
        e, _ = self._mk_key(owner="friendone")
        st, r = self._post("/api/v1-access/set-limit",
                           {"id": e["id"], "req_limit": 50,
                            "tok_limit": 5000},
                           session={"admin": True})
        self.assertEqual(st, 401, r)
        st, r = self._post("/api/v1-access/set-limit",
                           {"id": e["id"], "req_limit": 50,
                            "tok_limit": 5000, "master_pw": "wrong"},
                           session={"admin": True})
        self.assertEqual(st, 401, r)
        self.assertEqual(e["req_limit"], 0)

    def test_set_limit_requires_admin_session(self):
        e, _ = self._mk_key(owner="friendone")
        st, r = self._post("/api/v1-access/set-limit",
                           {"id": e["id"], "req_limit": 50,
                            "tok_limit": 5000, "master_pw": "master-pw"},
                           session={"label": "friendone"})
        self.assertEqual(st, 403, r)

    def test_set_limit_validation(self):
        e, _ = self._mk_key(owner="friendone")
        bad = [
            {"req_limit": -1, "tok_limit": 0},
            {"req_limit": 100001, "tok_limit": 0},
            {"req_limit": 0, "tok_limit": 10000001},
            {"req_limit": True, "tok_limit": 0},
            {"req_limit": "50", "tok_limit": 0},
            {"req_limit": 0, "tok_limit": 1.5},
        ]
        for patch in bad:
            body = {"id": e["id"], "master_pw": "master-pw"}
            body.update(patch)
            st, r = self._post("/api/v1-access/set-limit", body,
                               session={"admin": True})
            self.assertEqual(st, 400, (patch, r))
        self.assertEqual(e["req_limit"], 0)
        self.assertEqual(e["tok_limit"], 0)
        st, r = self._post("/api/v1-access/set-limit",
                           {"id": "no-such-id", "req_limit": 1,
                            "tok_limit": 1, "master_pw": "master-pw"},
                           session={"admin": True})
        self.assertEqual(st, 404, r)


class ApiAccessPageTests(_V1KeyMixin, unittest.TestCase):
    """Friends get the SAME /api-access page as the admin (owner order
    2026-11-08): own keys only, never key_full, never another user's
    keys. The API KEYS section moved off My Keys; /api/mykeys stays
    as the backend the friend path on api.html calls."""

    def setUp(self):
        self._reset()

    def test_friend_get_api_access_returns_200(self):
        st, body = self._get("/api-access", session={"label": "friendone"})
        self.assertEqual(st, 200)
        self.assertIn(b"API Access", body)
        self.assertIn(b"API Keys", body)

    def test_viewer_get_api_access_403(self):
        st, _ = self._get("/api-access",
                          session={"viewer": True, "label": "viewer:x"})
        self.assertEqual(st, 403)

    def test_logged_out_get_api_access_redirects(self):
        st, _ = self._get("/api-access", session=None)
        self.assertEqual(st, 302)

    def test_moderator_get_api_access_200_own_keys_only(self):
        # Owner order 2026-11-10: moderators use /api-access like a
        # normal friend — their own keys only, never other users'.
        orig = dict(server._SETTINGS.get("roles") or {})
        server._SETTINGS["roles"] = dict(orig, friendone="moderator")
        self.addCleanup(lambda: server._SETTINGS.update({"roles": orig}))
        st, body = self._get("/api-access", session={"label": "friendone"})
        self.assertEqual(st, 200)
        self.assertIn(b"API Access", body)
        own_e, _ = self._mk_key(owner="friendone", name="mine")
        other_e, _ = self._mk_key(owner="friendtwo", name="theirs")
        st, d = self._get("/api/v1-access", session={"label": "friendone"})
        self.assertEqual(st, 200, d)
        self.assertEqual(d.get("role"), "friend")
        self.assertEqual(len(d["keys"]), 1)
        self.assertEqual(d["keys"][0]["id"], own_e["id"])
        raw = json.dumps(d)
        self.assertNotIn("key_full", raw)
        self.assertNotIn(other_e["key"], raw)
        self.assertNotIn("lanes", d)

    def test_friend_v1_access_returns_only_own_keys(self):
        admin_e, _ = self._mk_key(owner="admin", name="admin-key")
        own_e, _ = self._mk_key(owner="friendone", req_limit=200,
                                tok_limit=100000, name="mine")
        other_e, _ = self._mk_key(owner="friendtwo", name="theirs")
        st, d = self._get("/api/v1-access", session={"label": "friendone"})
        self.assertEqual(st, 200, d)
        raw = json.dumps(d)
        self.assertEqual(d.get("role"), "friend")
        self.assertEqual(len(d["keys"]), 1)
        k = d["keys"][0]
        self.assertEqual(k["id"], own_e["id"])
        self.assertEqual(k["owner"], "friendone")
        self.assertNotIn("key", k)
        self.assertNotIn("key_full", k)
        self.assertNotIn("key_full", raw)
        self.assertNotIn(admin_e["key"], raw)
        self.assertNotIn(other_e["key"], raw)
        self.assertNotIn("lanes", d)

    def test_admin_v1_access_unchanged(self):
        e, full = self._mk_key(owner="admin", name="admin-key")
        st, d = self._get("/api/v1-access", session={"admin": True})
        self.assertEqual(st, 200, d)
        self.assertEqual(d.get("role"), "admin")
        self.assertEqual(len(d["keys"]), 1)
        self.assertEqual(d["keys"][0]["key_full"], full)
        self.assertIn("lanes", d)
        self.assertIn("base_url", d)

    def test_viewer_v1_access_403(self):
        st, _ = self._get("/api/v1-access",
                          session={"viewer": True, "label": "viewer:x"})
        self.assertEqual(st, 403)

    def test_friend_generate_capped_via_api_access_flow(self):
        # The page generates through /api/mykeys v1generate; the cap
        # still holds and the info endpoint lists exactly the 3 keys.
        for _ in range(3):
            st, r = self._post("/api/mykeys", {"action": "v1generate"},
                               session={"label": "friendone"})
            self.assertEqual(st, 200, r)
        st, r = self._post("/api/mykeys", {"action": "v1generate"},
                           session={"label": "friendone"})
        self.assertEqual(st, 400, r)
        st, d = self._get("/api/v1-access", session={"label": "friendone"})
        self.assertEqual(st, 200, d)
        self.assertEqual(len(d["keys"]), 3)

    def test_admin_v1_access_lanes_list_every_model(self):
        # Supply lanes (owner order 2026-11-08): each lane lists every
        # model, default first, from the same roster as GET /v1/models.
        orig = dict(server._V1_MODELS_CACHE)
        server._V1_MODELS_CACHE.update({
            "at": time.time(),
            "ids": ["groq/openai/gpt-oss-20b",
                    "groq/qwen/qwen3.8-27b",
                    "openrouter/foo/bar"]})
        self.addCleanup(lambda: server._V1_MODELS_CACHE.update(orig))
        st, d = self._get("/api/v1-access", session={"admin": True})
        self.assertEqual(st, 200, d)
        lanes = {l["lane"]: l for l in d["lanes"]}
        groq = lanes["groq"]
        self.assertEqual(groq["model"], "openai/gpt-oss-20b")
        self.assertEqual(groq["models"][0], "openai/gpt-oss-20b")
        self.assertIn("qwen/qwen3.8-27b", groq["models"])
        self.assertEqual(len(groq["models"]),
                         len(set(groq["models"])))
        self.assertIn("foo/bar", lanes["openrouter"]["models"])
        self.assertEqual(lanes["relay_gemini"]["models"],
                         ["gemini-3.5-flash-lite"])

    def test_models_by_lane_groups_live_roster(self):
        orig = dict(server._V1_MODELS_CACHE)
        server._V1_MODELS_CACHE.update({
            "at": time.time(),
            "ids": ["nvidia/a", "nvidia/b", "nvidia/a"]})
        self.addCleanup(lambda: server._V1_MODELS_CACHE.update(orig))
        by_lane = server._v1_models_by_lane()
        self.assertEqual(by_lane["nvidia"][0],
                         "nvidia/nemotron-3-ultra-550b-a55b")
        self.assertIn("a", by_lane["nvidia"])
        self.assertIn("b", by_lane["nvidia"])
        self.assertEqual(len(by_lane["nvidia"]),
                         len(set(by_lane["nvidia"])))

    def test_api_access_page_has_no_header_card(self):
        # Owner order 2026-11-08: the "API Access" title + breadcrumb
        # head-card (and its dots divider) are removed; Supply lanes
        # stay.
        st, body = self._get("/api-access", session={"admin": True})
        self.assertEqual(st, 200)
        self.assertNotIn(b'<div class="head-card">', body)
        self.assertNotIn(b'<div class="dots">', body)
        self.assertIn(b"Supply lanes", body)
        self.assertIn(b"Models", body)


if __name__ == "__main__":
    unittest.main()
