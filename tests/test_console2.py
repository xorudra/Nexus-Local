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
        if (APP / "vendor").is_dir():
            shutil.copytree(APP / "vendor", cls.tmp / "vendor")
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

    def test_16_role_action_matrix(self):
        # The console permission table, pinned server-side: for each
        # role, the actions it may and may not perform.
        for label, role in ((F1, "moderator"), (F2, "viewer")):
            status, j = self._access("friend_role_set", self.admin,
                                     label=label, role=role,
                                     master_pw=MASTER)
            self.assertEqual(status, 200, j)
        _, _, mod = self._login(F1_PW)
        _, _, view = self._login(F2_PW)
        # reads both roles may do
        for action in ("list", "2fa_state"):
            for cookie, who in ((mod, "moderator"), (view, "viewer")):
                status, j = self._access(action, cookie)
                self.assertEqual(status, 200, (action, who, j))
        # moderator-only reads
        for action in ("settings_get", "invite_list"):
            status, j = self._access(action, mod)
            self.assertEqual(status, 200, (action, j))
            status, j = self._access(action, view)
            self.assertEqual(status, 403, (action, j))
        # owner-only writes: refused for both roles
        for action, fields in (
                ("settings_set", {"patch": {"announcement": "x"}}),
                ("settings_restore_preview",
                 {"backup": {"settings": {}}}),
                ("settings_restore_apply", {"nonce": "x"}),
                ("factory_reset", {}),
                ("audit_clear", {}),
                ("friend_role_set", {"label": F2, "role": "moderator"}),
                ("viewpass_list", {})):
            for cookie, who in ((mod, "moderator"), (view, "viewer")):
                status, j = self._access(action, cookie, **fields)
                self.assertEqual(status, 403, (action, who, j))
        # a moderator manages users on their own session (no master)
        status, j = self._access("friend_set_suspended", mod,
                                 label=F2, suspended=True)
        self.assertEqual(status, 200, j)
        status, j = self._access("friend_set_suspended", mod,
                                 label=F2, suspended=False)
        self.assertEqual(status, 200, j)

    def test_17_settings_restore(self):
        backup = {"settings": {"announcement": "Back soon",
                                "chain_mode": "fastest"}}
        # accounts/roles are never restorable from a file
        status, j = self._access(
            "settings_restore_preview", self.admin,
            backup={"settings": {"roles": {F1: "viewer"}}},
            master_pw=MASTER)
        self.assertEqual(status, 400, j)
        self.assertIn("roles", j.get("error", ""))
        # invalid values rejected by the shared settings validator
        status, j = self._access(
            "settings_restore_preview", self.admin,
            backup={"settings": {"chain_mode": "bogus"}},
            master_pw=MASTER)
        self.assertEqual(status, 400, j)
        # master password required
        status, j = self._access("settings_restore_preview", self.admin,
                                 backup=backup)
        self.assertEqual(status, 401, j)
        # preview → diff + nonce; nothing applied yet
        status, j = self._access("settings_restore_preview", self.admin,
                                 backup=backup, master_pw=MASTER)
        self.assertEqual(status, 200, j)
        keys = sorted(d["key"] for d in j["diff"])
        self.assertEqual(keys, ["announcement", "chain_mode"], j)
        nonce = j["nonce"]
        _, cur = self._access("settings_get", self.admin)
        self.assertNotEqual(cur["settings"].get("announcement"),
                            "Back soon")
        # bogus nonce refused; the real one applies exactly once
        status, j = self._access("settings_restore_apply", self.admin,
                                 nonce="nope", master_pw=MASTER)
        self.assertEqual(status, 400, j)
        status, j = self._access("settings_restore_apply", self.admin,
                                 nonce=nonce, master_pw=MASTER)
        self.assertEqual(status, 200, j)
        self.assertEqual(sorted(j["applied"]),
                         ["announcement", "chain_mode"])
        _, cur = self._access("settings_get", self.admin)
        self.assertEqual(cur["settings"].get("announcement"), "Back soon")
        self.assertEqual(cur["settings"].get("chain_mode"), "fastest")
        self.assertTrue(cur["settings"].get("backup_snapshot"))
        status, j = self._access("settings_restore_apply", self.admin,
                                 nonce=nonce, master_pw=MASTER)
        self.assertEqual(status, 400, j)

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


    # --- 18. legal pages (reel fix: docs in place, linked) --------
    def test_18_legal_pages(self):
        def page(path):
            st, _, _, payload = self._req("GET", path)
            return st, payload.decode("utf-8", "replace")
        for path, needle in (("/terms", "Terms of use"),
                             ("/privacy", "Privacy at Nexus Local")):
            st, text = page(path)
            self.assertEqual(st, 200, path)
            self.assertIn(needle, text)
            self.assertIn("invite-only", text)
        # linked from the sign-in page and the invite page
        st, login_html = page("/login")
        self.assertEqual(st, 200)
        self.assertIn('href="/terms"', login_html)
        self.assertIn('href="/privacy"', login_html)
        st, invite_html = page("/invite")
        self.assertEqual(st, 200)
        self.assertIn('href="/terms"', invite_html)
        self.assertIn('href="/privacy"', invite_html)
        # the privacy page must disclose the real data flows
        st, priv = page("/privacy")
        self.assertIn("third-party AI providers", priv)
        self.assertIn("no session recording", priv)
        self.assertIn("not stored by default", priv)


    # --- 19. 3D library is self-hosted (no CDN dependency) -------
    def test_19_vendor_three(self):
        st, _, headers, payload = self._req("GET", "/vendor/three.min.js")
        self.assertEqual(st, 200)
        self.assertIn("text/javascript", headers.get("content-type", ""))
        self.assertIn("max-age=604800", headers.get("cache-control", ""))
        self.assertGreater(len(payload), 500_000)
        self.assertIn(b"Three.js Authors", payload[:300])
        # the console page must reference the local copy, never a CDN
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request("GET", "/admin", headers={"Cookie": self.admin})
        resp = conn.getresponse()
        html = resp.read().decode("utf-8", "replace")
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn('src="/vendor/three.min.js"', html)
        self.assertNotIn("cdnjs", html)


if __name__ == "__main__":
    unittest.main()
