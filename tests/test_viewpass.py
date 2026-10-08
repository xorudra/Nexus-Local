#!/usr/bin/env python3
"""Temporary view-pass tests (owner-approved design, 2026-10-09).

A view pass is a short-lived READ-ONLY link the admin mints from the
panel: opening it creates a viewer session that can look at the pages
but cannot change anything. These tests pin: creation validation
(master password, name, duration, max count), the /view/<token> door,
the viewer's read whitelist and write denials, page gates, revocation
killing live sessions, restart death (grants are memory-only), and the
grant-expiry helper.

Fixtures use only fake keys and throwaway passwords.

Run:  python3 -m unittest discover -s tests -v
"""

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


class ViewPassTests(unittest.TestCase):
    proc = None
    log = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-viewpass-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip or name == "chats":
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND1: _hash_pw(FRIEND1_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
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
        set_cookie = resp.getheader("Set-Cookie") or ""
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload.decode(errors="replace")[:200]}
        return (resp.status, parsed, resp_headers,
                set_cookie.split(";")[0] if set_cookie.startswith("session=") else None)

    @classmethod
    def _login(cls, password):
        status, body, _, cookie = cls._req("POST", "/api/login", {"password": password})
        return status, body, cookie

    def _create(self, name="For review", hours=1, master=MASTER, cookie=None):
        return self._req("POST", "/api/access", {
            "action": "viewpass_create", "name": name, "hours": hours,
            "master_pw": master}, cookie=cookie or self.admin)

    def _open_link(self, url):
        status, body, headers, cookie = self._req("GET", url)
        return status, body, headers, cookie

    # -- creation ------------------------------------------------------
    def test_01_create_validation(self):
        status, body, _, _ = self._create(master="")
        self.assertEqual(status, 401, body)
        status, body, _, _ = self._create(master="wrong-master")
        self.assertEqual(status, 401, body)
        status, body, _, _ = self._create(name="bad!!name")
        self.assertEqual(status, 400, body)
        status, body, _, _ = self._create(name="")
        self.assertEqual(status, 400, body)
        status, body, _, _ = self._create(hours=5)
        self.assertEqual(status, 400, body)
        status, body, _, _ = self._create(hours=1)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["url"].startswith("/view/"))
        self.assertGreater(len(body["url"]), 45)
        self.__class__.url1 = body["url"]
        # Friends cannot create or list passes.
        status, body, _, _ = self._create(cookie=self.friend)
        self.assertEqual(status, 403, body)
        status, body, _, _ = self._req("POST", "/api/access",
                                       {"action": "viewpass_list"}, cookie=self.friend)
        self.assertEqual(status, 403, body)

    # -- the door + read whitelist -------------------------------------
    def test_02_open_link_and_read_pages(self):
        status, body, headers, viewer = self._open_link(self.url1)
        self.assertEqual(status, 302, body)
        self.assertEqual(headers.get("location"), "/")
        self.assertTrue(viewer)
        self.__class__.viewer = viewer
        for path in ("/", "/admin", "/settings", "/connections"):
            status, body, _, _ = self._req("GET", path, cookie=viewer)
            self.assertEqual(status, 200, (path, body))
        status, body, _, _ = self._req("GET", "/mykeys", cookie=viewer)
        self.assertEqual(status, 403, body)
        status, body, _, _ = self._req("GET", "/api/status", cookie=viewer)
        self.assertEqual(status, 200, body)
        # The two read actions the admin page needs.
        status, body, _, _ = self._req("POST", "/api/access", {"action": "list"},
                                       cookie=viewer)
        self.assertEqual(status, 200, body)
        self.assertIn(FRIEND1, [a["label"] for a in body.get("access", [])])
        # Identity: the viewer's own session shows up, clearly not admin.
        mine = [s for s in body.get("sessions", [])
                if s.get("label") == "viewer:For review"]
        self.assertEqual(len(mine), 1, body)
        self.assertFalse(mine[0].get("admin"))
        status, body, _, _ = self._req("POST", "/api/access", {"action": "2fa_state"},
                                       cookie=viewer)
        self.assertEqual(status, 200, body)

    # -- write denials ---------------------------------------------------
    def test_03_viewer_cannot_change_anything(self):
        viewer = self.viewer
        denials = [
            ("/api/access", {"action": "add", "label": "x", "password": "xxxxxx", "master_pw": MASTER}),
            ("/api/access", {"action": "viewpass_create", "name": "sneaky", "hours": 1, "master_pw": MASTER}),
            ("/api/access", {"action": "viewpass_list"}),
            ("/api/access", {"action": "change_master", "master_pw": MASTER, "new_master_pw": "newpassword123"}),
            ("/api/access", {"action": "2fa_enable", "master_pw": MASTER}),
            ("/api/chats", {"action": "list"}),
            ("/api/chats", {"action": "save", "title": "t", "messages": []}),
            ("/api/chat", {"provider": "kilo", "model": "kilo-auto/free", "message": "hi"}),
            ("/api/mykeys", {"action": "view"}),
            ("/api/routing", {"set": "save"}),
            ("/api/transcribe", {"audio": "data:audio/webm;base64,AAAA"}),
        ]
        for path, payload in denials:
            status, body, _, _ = self._req("POST", path, payload, cookie=viewer)
            self.assertEqual(status, 403, (path, body))
            self.assertEqual(body.get("error"), "read-only access", (path, body))
        status, body, _, _ = self._req("GET", "/api/2fa_qr", cookie=viewer)
        self.assertEqual(status, 403, body)
        # The master password was NOT changed by the denied attempt above.
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 200, body)
        # Logout is allowed (it only ends the viewer's own session).
        status, body, _, _ = self._req("POST", "/api/logout", {}, cookie=viewer)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("GET", "/api/status", cookie=viewer)
        self.assertEqual(status, 401, body)

    def test_04_bad_token_gets_no_session(self):
        status, body, headers, cookie = self._open_link("/view/" + "A" * 43)
        self.assertEqual(status, 404, body)
        self.assertIsNone(cookie)

    # -- revoke ----------------------------------------------------------
    def test_05_revoke_kills_link_and_live_sessions(self):
        status, body, _, _ = self._create(name="Second pass", hours=6)
        self.assertEqual(status, 200, body)
        url2 = body["url"]
        status, body, headers, viewer2 = self._open_link(url2)
        self.assertEqual(status, 302, body)
        status, body, _, _ = self._req("POST", "/api/access",
                                       {"action": "viewpass_list"}, cookie=self.admin)
        self.assertEqual(status, 200, body)
        grants = {g["name"]: g for g in body["grants"]}
        self.assertIn("Second pass", grants)
        self.assertGreaterEqual(grants["Second pass"]["watching"], 1)
        gid = grants["Second pass"]["id"]
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "viewpass_revoke", "id": gid, "master_pw": "wrong"},
            cookie=self.admin)
        self.assertEqual(status, 401, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "viewpass_revoke", "id": gid, "master_pw": MASTER},
            cookie=self.admin)
        self.assertEqual(status, 200, body)
        # The live viewer session died with the pass...
        status, body, _, _ = self._req("GET", "/api/status", cookie=viewer2)
        self.assertEqual(status, 401, body)
        # ...and the link itself is dead.
        status, body, headers, cookie = self._open_link(url2)
        self.assertEqual(status, 404, body)
        self.assertIsNone(cookie)

    # -- limits + restart death ------------------------------------------
    def test_06_max_five_and_restart_kills_passes(self):
        status, body, _, _ = self._req("POST", "/api/access",
                                       {"action": "viewpass_list"}, cookie=self.admin)
        existing = len(body["grants"])
        for i in range(5 - existing):
            status, body, _, _ = self._create(name=f"Filler {i}", hours=24)
            self.assertEqual(status, 200, body)
        status, body, _, _ = self._create(name="One too many", hours=1)
        self.assertEqual(status, 400, body)
        self.assertIn("too many", body.get("error", ""))
        status, body, _, _ = self._create(name="Dies at restart", hours=1)
        # Still full — revoke one filler via the list to make room.
        status, body, _, _ = self._req("POST", "/api/access",
                                       {"action": "viewpass_list"}, cookie=self.admin)
        gid = body["grants"][0]["id"]
        self._req("POST", "/api/access", {
            "action": "viewpass_revoke", "id": gid, "master_pw": MASTER},
            cookie=self.admin)
        status, body, _, _ = self._create(name="Dies at restart", hours=1)
        self.assertEqual(status, 200, body)
        url = body["url"]
        status, _, _, viewer = self._open_link(url)
        self.assertEqual(status, 302)
        # Restart: grants (and all sessions) are memory-only.
        self._start()
        status, body, headers, cookie = self._open_link(url)
        self.assertEqual(status, 404, body)
        self.assertIsNone(cookie)
        # Friends still log in first on the fresh instance.
        status, body, friend = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)


class ViewGrantUnitTests(unittest.TestCase):
    def test_grant_lookup_and_expiry(self):
        os.environ.pop("NEXUS_RESTORE_KEY", None)
        import server
        token = "unit-test-token-abc"
        h = hashlib.sha256(token.encode()).hexdigest()
        server._VIEW_GRANTS[h] = {"name": "unit", "created": time.time(),
                                  "expires": time.time() + 60}
        self.assertIsNotNone(server._view_grant_for(token))
        self.assertIsNone(server._view_grant_for("some-other-token"))
        self.assertIsNone(server._view_grant_for(""))
        server._VIEW_GRANTS[h]["expires"] = time.time() - 1
        self.assertIsNone(server._view_grant_for(token))  # expired...
        self.assertNotIn(h, server._VIEW_GRANTS)          # ...and dropped


if __name__ == "__main__":
    unittest.main()
