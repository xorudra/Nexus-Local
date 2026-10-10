#!/usr/bin/env python3
"""Admin console v2 backend tests (owner-ordered design 2, 2026-10-10).

Pins the v2 surface: roles (Moderator/Viewer) and their server-side
fences, invite codes + the public redeem flow, the announcement
endpoint, the new settings (chain mode, global cap, breaker/rate
tuning, webhook guard, allowed IPs), simulate failure, session
revocation, per-friend usage reset, /api/usage_today, analytics
latency series (avg_ms / p95_ms) and the vault metadata sidecar.

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
from key_security import encrypt_keys  # noqa: E402

MASTER = "test-master-password-123"
RESTORE = "test-restore-key-xyz"
F1, F1_PW = "friendone", "friend-one-pass"
F2, F2_PW = "friendtwo", "friend-two-pass"


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


class Console2Tests(unittest.TestCase):
    proc = None
    log = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-console2-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys"):
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {F1: _hash_pw(F1_PW), F2: _hash_pw(F2_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        (cls.tmp / "userkeys").mkdir(exist_ok=True)
        today = datetime.datetime.now().isoformat()
        with open(cls.tmp / "usage.jsonl", "w") as f:
            for ms in (120, 240):
                f.write(json.dumps({
                    "ts": today, "provider": "groq", "model": "m",
                    "prompt_tokens": 10, "completion_tokens": 5,
                    "user": F1, "ms": ms, "ok": True}) + "\n")
        cls._start()
        status, body, admin = cls._login(MASTER)
        assert status == 200, body
        cls.admin = admin
        status, body, f1 = cls._login(F1_PW)
        assert status == 200, body
        cls.f1 = f1

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
        status, parsed, _, _ = cls._req("POST", "/api/access", body,
                                        cookie=cookie)
        return status, parsed

    def _set(self, patch):
        return self._access("settings_set", self.admin, master_pw=MASTER,
                            patch=patch)

    # ---- new settings validation ----

    def test_01_new_settings_validation(self):
        status, j = self._set({"chain_mode": "bogus"})
        self.assertEqual(status, 400)
        status, j = self._set({"chain_mode": "fastest"})
        self.assertEqual(status, 200, j)
        self.assertEqual(j["settings"]["chain_mode"], "fastest")
        status, j = self._set({"allowed_ips": ["not-an-ip"]})
        self.assertEqual(status, 400)
        status, j = self._set({"allowed_ips": ["10.0.0.0/8", " 127.0.0.1 "]})
        self.assertEqual(status, 200, j)
        self.assertEqual(j["settings"]["allowed_ips"],
                         ["10.0.0.0/8", "127.0.0.1"])
        # Loopback webhook must be refused by the SSRF guard.
        status, j = self._set({"webhook_url": "http://127.0.0.1:9000/hook"})
        self.assertEqual(status, 400)
        status, j = self._set({"webhook_url": "https://example.com/hook"})
        self.assertEqual(status, 200, j)
        status, j = self._access("webhook_test", self.admin,
                                 master_pw="wrong")
        self.assertEqual(status, 401)
        status, j = self._set({"pw_min": 99})
        self.assertEqual(status, 400)
        status, j = self._set({"chain_mode": "priority", "allowed_ips": [],
                               "webhook_url": ""})
        self.assertEqual(status, 200, j)

    def test_02_announcement_public(self):
        status, j, _, _ = self._req("GET", "/api/announcement")
        self.assertEqual(status, 200)
        self.assertEqual(j["announcement"], "")
        status, j = self._set({"announcement": "Hello friends"})
        self.assertEqual(status, 200, j)
        status, j, _, _ = self._req("GET", "/api/announcement")
        self.assertEqual(j["announcement"], "Hello friends")
        self._set({"announcement": ""})

    # ---- roles ----

    def test_03_moderator_flow(self):
        status, j = self._access("friend_role_set", self.admin,
                                 master_pw=MASTER, label=F1,
                                 role="moderator")
        self.assertEqual(status, 200, j)
        status, body, mod = self._login(F1_PW)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "moderator")
        type(self).mod = mod
        status, _, _, payload = self._req("GET", "/admin", cookie=mod)
        self.assertEqual(status, 200)
        self.assertIn(b"Admin", payload)
        status, j = self._access("list", mod)
        self.assertEqual(status, 200)
        self.assertEqual(j["you"]["kind"], "moderator")
        # Moderator can suspend without the master password.
        status, j = self._access("friend_set_suspended", mod, label=F2,
                                 on=True)
        self.assertEqual(status, 200, j)
        status, body, _ = self._login(F2_PW)
        self.assertEqual(status, 403)
        status, j = self._access("friend_set_suspended", mod, label=F2,
                                 on=False)
        self.assertEqual(status, 200, j)
        # But settings and granting moderator stay owner-only.
        status, j = self._access("settings_set", mod,
                                 patch={"daily_cap": 5})
        self.assertEqual(status, 403)
        status, j = self._access("friend_role_set", mod, label=F2,
                                 role="moderator")
        self.assertEqual(status, 403)
        status, j = self._access("revoke", mod, label=F2)
        self.assertEqual(status, 403)

    def test_04_viewer_role(self):
        status, j = self._access("friend_role_set", self.admin,
                                 master_pw=MASTER, label=F2, role="viewer")
        self.assertEqual(status, 200, j)
        status, body, viewer = self._login(F2_PW)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "viewer")
        status, _, _, _ = self._req("GET", "/admin", cookie=viewer)
        self.assertEqual(status, 200)
        status, j = self._access("list", viewer)
        self.assertEqual(status, 200)
        self.assertEqual(j["you"]["kind"], "viewer")
        status, j, _, _ = self._req("GET", "/api/analytics?range=7d",
                                    cookie=viewer)
        self.assertEqual(status, 200)
        status, j = self._access("friend_set_suspended", viewer, label=F1,
                                 on=True)
        self.assertEqual(status, 403)
        # Restore friend role for later tests.
        self._access("friend_role_set", self.admin, master_pw=MASTER,
                     label=F2, role="friend")

    # ---- invites ----

    def test_05_invite_lifecycle(self):
        status, j = self._access("invite_create", self.admin,
                                 master_pw=MASTER, role="friend", days=7)
        self.assertEqual(status, 200, j)
        code = j["code"]
        self.assertEqual(len(code), 6)
        status, info, _, _ = self._req("GET", "/api/invite/info")
        self.assertEqual(status, 200)
        self.assertEqual(info["registration"], "invite")
        status, _, _, payload = self._req("GET", "/invite")
        self.assertEqual(status, 200)
        self.assertIn(b"Join Nexus", payload)
        status, body, headers, _ = self._req(
            "POST", "/api/invite/redeem",
            {"code": code, "label": "newpal", "password": "newpal-pass-1"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["label"], "newpal")
        cookie = headers.get("set-cookie", "").split(";")[0]
        status, _, _, _ = self._req("GET", "/api/usage", cookie=cookie)
        self.assertEqual(status, 200)
        # Codes are single-use.
        status, body, _, _ = self._req(
            "POST", "/api/invite/redeem",
            {"code": code, "label": "otherpal",
             "password": "otherpal-pass-1"})
        self.assertEqual(status, 400)
        # Closed registration refuses even a fresh code.
        status, j = self._access("invite_create", self.admin,
                                 master_pw=MASTER, role="friend", days=7)
        code2 = j["code"]
        self._set({"registration": "closed"})
        status, body, _, _ = self._req(
            "POST", "/api/invite/redeem",
            {"code": code2, "label": "latepal",
             "password": "latepal-pass-1"})
        self.assertEqual(status, 403)
        self._set({"registration": "invite"})

    # ---- caps, simulation, sessions ----

    def test_06_global_cap(self):
        status, j = self._set({"global_cap": 1})
        self.assertEqual(status, 200, j)
        status, body, _, _ = self._req(
            "POST", "/api/chat", {"messages": [{"role": "user",
                                                "content": "hi"}]},
            cookie=self.f1)
        self.assertEqual(status, 429, body)
        self._set({"global_cap": 0})

    def test_07_simulate_failure(self):
        status, j = self._access("simulate_failure", self.admin,
                                 master_pw=MASTER)
        self.assertEqual(status, 200, j)
        prov = j["provider"]
        status, quotas, _, _ = self._req("GET", "/api/quotas",
                                         cookie=self.admin)
        entry = [p for p in quotas["providers"]
                 if p["provider"] == prov][0]
        self.assertTrue(entry["down"])
        status, j = self._access("provider_health_reset", self.admin,
                                 master_pw=MASTER)
        self.assertEqual(status, 200, j)
        status, quotas, _, _ = self._req("GET", "/api/quotas",
                                         cookie=self.admin)
        entry = [p for p in quotas["providers"]
                 if p["provider"] == prov][0]
        self.assertFalse(entry["down"])

    def test_08_session_revoke(self):
        status, j = self._access("list", self.admin)
        mine = [s for s in j["sessions"] if s["label"] == F1]
        self.assertTrue(mine)
        self.assertTrue(mine[0]["sid"])
        self.assertIn("ip", mine[0])
        self.assertIn("ua", mine[0])
        # Cannot revoke your own session.
        status, j = self._access("session_revoke", self.admin,
                                 master_pw=MASTER, sid=j["you"]["sid"])
        self.assertEqual(status, 400)
        status, j = self._access("sessions_revoke_all", self.admin,
                                 master_pw=MASTER)
        self.assertEqual(status, 200, j)
        self.assertGreaterEqual(j["revoked"], 1)
        status, _, _, _ = self._req("GET", "/api/usage", cookie=self.f1)
        self.assertEqual(status, 401)
        status, body, f1 = self._login(F1_PW)
        self.assertEqual(status, 200, body)
        type(self).f1 = f1

    # ---- vault metadata ----

    def test_09_vault_meta(self):
        status, j = self._access(
            "friend_key_add", self.admin, master_pw=MASTER, label=F1,
            provider="groq", key="sk-testkey1234abcd", friend_pw=F1_PW)
        self.assertEqual(status, 200, j)
        status, j = self._access("settings_get", self.admin)
        meta = j["settings"]["vault_meta"].get(F1, [])
        self.assertTrue(any(m["provider"] == "groq"
                            and m["last4"] == "abcd" for m in meta), meta)
        status, j = self._access("list", self.admin)
        entry = [a for a in j["access"] if a["label"] == F1][0]
        self.assertGreaterEqual(entry["keys"], 1)

    # ---- usage + analytics ----

    def test_10_usage_today(self):
        status, j, _, _ = self._req("GET", "/api/usage_today",
                                    cookie=self.admin)
        self.assertEqual(status, 200)
        mine = [u for u in j["users"] if u["label"] == F1]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["requests"], 2)
        self.assertEqual(len(mine[0]["days"]), 7)
        self.assertEqual(mine[0]["top_provider"], "groq")
        # Plain friends cannot read the instance-wide usage panel
        # (F1 is a moderator by now, so log F2 in fresh for this check).
        status, body, f2 = self._login(F2_PW)
        self.assertEqual(status, 200, body)
        status, _, _, _ = self._req("GET", "/api/usage_today", cookie=f2)
        self.assertEqual(status, 403)

    def test_11_analytics_latency(self):
        status, j, _, _ = self._req("GET", "/api/analytics?range=7d",
                                    cookie=self.admin)
        self.assertEqual(status, 200)
        self.assertIsNotNone(j["p95_ms"])
        self.assertTrue(any(s.get("avg_ms") for s in j["series"]))
        self.assertEqual(j["avg_ms"], 180)

    def test_12_usage_reset(self):
        status, j = self._access("friend_usage_reset", self.admin,
                                 master_pw=MASTER, label=F1)
        self.assertEqual(status, 200, j)
        status, j, _, _ = self._req("GET", "/api/usage_today",
                                    cookie=self.admin)
        mine = [u for u in j["users"] if u["label"] == F1]
        self.assertTrue(not mine or mine[0]["requests"] == 0)

    def test_14_signout_everywhere(self):
        # Two independent sign-ins for the same account (phone + browser).
        status, body, c1 = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, body, c2 = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, _, _, _ = self._req("GET", "/admin", cookie=c1)
        self.assertEqual(status, 200)
        status, _, _, _ = self._req("GET", "/admin", cookie=c2)
        self.assertEqual(status, 200)
        # A plain logout ends only its own session.
        status, j, _, _ = self._req("POST", "/api/logout", {}, cookie=c2)
        self.assertEqual(status, 200)
        status, _, _, _ = self._req("GET", "/admin", cookie=c2)
        self.assertEqual(status, 302)
        status, _, _, _ = self._req("GET", "/admin", cookie=c1)
        self.assertEqual(status, 200)
        # The console's sign-out (all=true) ends the account's other
        # sessions too.
        status, body, c3 = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, j, _, _ = self._req("POST", "/api/logout", {"all": True},
                                    cookie=c3)
        self.assertEqual(status, 200)
        status, _, _, _ = self._req("GET", "/admin", cookie=c1)
        self.assertEqual(status, 302)

    def test_15_console_load_sequence_no_401(self):
        # Regression: the console's on-load calls must never answer 401
        # for the owner — the page treats a bare 401 as "session dead"
        # and bounces to /login (invite_list once sat in the
        # master-gated tuple and kicked the owner out after load).
        # Fresh login: test_14's sign-out-everywhere killed cls.admin.
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        type(self).admin = admin
        for action in ("list", "settings_get", "viewpass_list",
                       "invite_list", "2fa_state"):
            status, j = self._access(action, admin)
            self.assertEqual(status, 200, (action, j))
        for path in ("/api/quotas", "/api/audit",
                     "/api/analytics?range=7d", "/api/analytics?range=24h",
                     "/api/usage_today", "/api/v1-access"):
            status, _, _, _ = self._req("GET", path, cookie=admin)
            self.assertEqual(status, 200, path)

    # ---- allowed IPs (last: needs a restart to recover) ----

    def test_13_allowed_ips_lockout_and_recovery(self):
        status, j = self._set({"allowed_ips": ["10.0.0.0/8"]})
        self.assertEqual(status, 200, j)
        status, body, _ = self._login(F1_PW)
        self.assertEqual(status, 403)
        status, _, _, _ = self._req("GET", "/admin", cookie=self.admin)
        self.assertEqual(status, 403)
        # Recovery path: wipe the settings store and restart.
        self._stop()
        for name in ("settings.enc", "settings.json"):
            p = self.tmp / name
            if p.exists():
                p.unlink()
        self._start()
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        type(self).admin = admin
        status, j = self._access("settings_get", admin)
        self.assertEqual(j["settings"]["allowed_ips"], [])


if __name__ == "__main__":
    unittest.main()
