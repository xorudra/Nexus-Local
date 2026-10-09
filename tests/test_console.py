#!/usr/bin/env python3
"""Admin console backend tests (owner-ordered design, 2026-10-10).

The 3D admin console's controls are real server functions, not demo
widgets. These tests pin: settings get/set with master gating and
validation, settings persistence across a restart (encrypted mirror),
maintenance mode + per-friend suspension blocking sign-ins AND live
sessions, provider order/disabled surfacing in /api/quotas, the
per-friend daily cap on /api/chat, the audit log (admin-only), the
analytics aggregation, admin-side friend key add / vault clear /
password reset, and factory reset.

Fixtures use only fake keys and throwaway passwords.

Run:  python3 -m unittest discover -s tests -v
"""

import datetime
import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
from key_security import decrypt_keys, encrypt_keys  # noqa: E402

MASTER = "test-master-password-123"
RESTORE = "test-restore-key-xyz"
FRIEND1 = "friendone"
FRIEND1_PW = "friend-one-pass"


def _hash_pw(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000)
    return f"pbkdf2$210000${salt.hex()}${dk.hex()}"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ConsoleTests(unittest.TestCase):
    proc = None
    log = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-console-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys"):
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND1: _hash_pw(FRIEND1_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        (cls.tmp / "userkeys").mkdir(exist_ok=True)
        # Seed today's usage: the friend already made 2 requests.
        today = datetime.datetime.now().isoformat()
        with open(cls.tmp / "usage.jsonl", "w") as f:
            for _ in range(2):
                f.write(json.dumps({
                    "ts": today, "provider": "groq", "model": "m",
                    "prompt_tokens": 10, "completion_tokens": 5,
                    "user": FRIEND1, "ms": 120, "ok": True}) + "\n")
        cls._start()
        status, body, admin = cls._login(MASTER)
        assert status == 200, body
        cls.admin = admin
        status, body, friend = cls._login(FRIEND1_PW)
        assert status == 200, body
        cls.friend = friend

    @classmethod
    def tearDownClass(cls):
        cls._stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _start(cls):
        cls._stop()
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1", "PORT": str(cls.port),
            "NEXUS_RELAY_PORT": str(_free_port()),
            "NEXUS_RESTORE_KEY": RESTORE,
            "PYTHONPATH": str(cls.tmp),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        cls.log = open(cls.tmp / "server.log", "ab")
        cls.proc = subprocess.Popen(
            [sys.executable, str(cls.tmp / "server.py")],
            cwd=str(cls.tmp), env=env,
            stdout=cls.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if cls.proc.poll() is not None:
                raise RuntimeError("server exited early")
            try:
                status, _, _, _ = cls._req("GET", "/health")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.25)
        raise RuntimeError("server did not come up in 30s")

    @classmethod
    def _stop(cls):
        if cls.proc is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=10)
            cls.proc = None
        if cls.log is not None:
            cls.log.close()
            cls.log = None

    @classmethod
    def _req(cls, method, path, body=None, cookie=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=60)
        hdrs = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body)
            hdrs.setdefault("Content-Type", "application/json")
        if cookie:
            hdrs["Cookie"] = cookie
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = None
        return resp.status, parsed, resp_headers, payload

    @classmethod
    def _login(cls, password):
        status, body, headers, _ = cls._req(
            "POST", "/api/login", {"password": password})
        cookie = headers.get("set-cookie", "").split(";")[0] or None
        return status, body, cookie

    @classmethod
    def _access(cls, action, cookie, **extra):
        body = {"action": action}
        body.update(extra)
        status, parsed, _, _ = cls._req("POST", "/api/access", body, cookie=cookie)
        return status, parsed

    # ---- settings ----

    def test_01_settings_defaults(self):
        status, j = self._access("settings_get", self.admin)
        self.assertEqual(status, 200)
        self.assertFalse(j["settings"]["maintenance"])
        self.assertEqual(j["settings"]["max_attempts"], 4)
        self.assertEqual(j["settings"]["daily_cap"], 200)
        self.assertIn("uptime_s", j["system"])
        self.assertIn("failovers_today", j)

    def test_02_settings_set_requires_master(self):
        status, j = self._access("settings_set", self.admin,
                                 master_pw="nope",
                                 patch={"daily_cap": 50})
        self.assertEqual(status, 401)
        status, j = self._access("settings_set", self.admin,
                                 master_pw=MASTER,
                                 patch={"max_attempts": 99})
        self.assertEqual(status, 400)
        status, j = self._access("settings_set", self.admin,
                                 master_pw=MASTER,
                                 patch={"bogus_key": 1})
        self.assertEqual(status, 400)

    def test_03_settings_set_and_quota_order(self):
        status, j = self._access(
            "settings_set", self.admin, master_pw=MASTER,
            patch={"provider_order": ["groq", "google"],
                   "provider_disabled": ["groq"],
                   "instance_name": "Test Instance"})
        self.assertEqual(status, 200, j)
        status, quotas, _, _ = self._req("GET", "/api/quotas",
                                         cookie=self.admin)
        self.assertEqual(status, 200)
        first = quotas["providers"][0]
        self.assertEqual(first["provider"], "groq")
        self.assertTrue(first["disabled"])
        self.assertEqual(quotas["providers"][1]["provider"], "google")
        # reset for later tests
        self._access("settings_set", self.admin, master_pw=MASTER,
                     patch={"provider_order": [], "provider_disabled": []})

    # ---- maintenance + suspension ----

    def test_04_maintenance_blocks_friend(self):
        status, j = self._access("settings_set", self.admin,
                                 master_pw=MASTER,
                                 patch={"maintenance": True})
        self.assertEqual(status, 200, j)
        # New friend sign-in refused with the maintenance error.
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "maintenance mode is on")
        # The already-signed-in friend session is fenced too.
        status, _, _, _ = self._req("GET", "/api/usage", cookie=self.friend)
        self.assertEqual(status, 401)
        # Admin sign-in is unaffected.
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 200, body)
        # Turning it off restores friend access.
        self._access("settings_set", self.admin, master_pw=MASTER,
                     patch={"maintenance": False})
        status, body, friend = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        type(self).friend = friend

    def test_05_suspension_blocks_one_friend(self):
        self._access("settings_set", self.admin, master_pw=MASTER,
                     patch={"suspended": [FRIEND1]})
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "account suspended")
        self._access("settings_set", self.admin, master_pw=MASTER,
                     patch={"suspended": []})
        status, body, friend = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        type(self).friend = friend

    # ---- daily cap ----

    def test_06_daily_cap(self):
        # The fixture seeded 2 requests today for the friend.
        self._access("settings_set", self.admin, master_pw=MASTER,
                     patch={"user_caps": {FRIEND1: 2}})
        status, j, _, _ = self._req(
            "POST", "/api/chat",
            {"provider": "groq", "model": "m", "message": "hi"},
            cookie=self.friend)
        self.assertEqual(status, 429)
        self.assertIn("daily limit reached", j["error"])
        self._access("settings_set", self.admin, master_pw=MASTER,
                     patch={"user_caps": {}})

    # ---- audit + analytics ----

    def test_07_audit_admin_only_and_records(self):
        status, _, _, _ = self._req("GET", "/api/audit", cookie=self.friend)
        self.assertEqual(status, 403)
        status, j, _, _ = self._req("GET", "/api/audit", cookie=self.admin)
        self.assertEqual(status, 200)
        events = " | ".join(e["event"] for e in j["events"])
        self.assertIn("Settings changed", events)
        self.assertIn("Sign-in blocked (maintenance)", events)
        self.assertIn("Daily cap hit", events)

    def test_08_analytics(self):
        status, _, _, _ = self._req("GET", "/api/analytics?range=7d",
                                    cookie=self.friend)
        self.assertEqual(status, 403)
        status, j, _, _ = self._req("GET", "/api/analytics?range=7d",
                                    cookie=self.admin)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(j["totals"]["requests"], 2)
        self.assertGreaterEqual(j["totals"]["tokens"], 30)
        labels = [u["label"] for u in j["per_user"]]
        self.assertIn(FRIEND1, labels)
        self.assertEqual(j["avg_ms"], 120)
        self.assertEqual(len(j["series"]), 7)

    # ---- persistence across restart ----

    def test_09_settings_survive_restart(self):
        self._access("settings_set", self.admin, master_pw=MASTER,
                     patch={"instance_name": "Persisted Name",
                            "daily_cap": 77})
        self.assertTrue((self.tmp / "settings.enc").exists())
        self._start()  # restart against the same tmp dir
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        type(self).admin = admin
        status, j = self._access("settings_get", admin)
        self.assertEqual(j["settings"]["instance_name"], "Persisted Name")
        self.assertEqual(j["settings"]["daily_cap"], 77)
        status, body, friend = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        type(self).friend = friend

    # ---- friend vault admin ops ----

    def test_10_friend_key_add_and_clear(self):
        status, j = self._access(
            "friend_key_add", self.admin, master_pw=MASTER,
            label=FRIEND1, provider="openrouter", key="sk-friend-fake",
            friend_pw="wrong-pw")
        self.assertEqual(status, 401)
        status, j = self._access(
            "friend_key_add", self.admin, master_pw=MASTER,
            label=FRIEND1, provider="openrouter", key="sk-friend-fake",
            friend_pw=FRIEND1_PW)
        self.assertEqual(status, 200, j)
        vault = decrypt_keys(self.tmp / "userkeys" / f"{FRIEND1}.enc",
                             FRIEND1_PW)
        self.assertEqual(vault.get("openrouter"), "sk-friend-fake")
        status, j = self._access("friend_vault_clear", self.admin,
                                 master_pw=MASTER, label=FRIEND1)
        self.assertEqual(status, 200)
        self.assertTrue(j["existed"])
        self.assertFalse((self.tmp / "userkeys" / f"{FRIEND1}.enc").exists())

    def test_11_friend_reset_pw(self):
        status, j = self._access(
            "friend_reset_pw", self.admin, master_pw=MASTER,
            label=FRIEND1, new_password="friend-new-pass")
        self.assertEqual(status, 200, j)
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 401)
        status, body, friend = self._login("friend-new-pass")
        self.assertEqual(status, 200, body)
        type(self).friend = friend

    # ---- factory reset (last: wipes the friend) ----

    def test_12_factory_reset(self):
        status, j = self._access("factory_reset", self.admin,
                                 master_pw=MASTER, confirm="nope")
        self.assertEqual(status, 400)
        status, j = self._access("factory_reset", self.admin,
                                 master_pw=MASTER, confirm="RESET")
        self.assertEqual(status, 200, j)
        status, j = self._access("list", self.admin)
        self.assertEqual(j["access"], [])
        status, j = self._access("settings_get", self.admin)
        self.assertEqual(j["settings"]["daily_cap"], 200)
        self.assertEqual(j["settings"]["instance_name"], "Nexus Local")


if __name__ == "__main__":
    unittest.main()
