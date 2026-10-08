#!/usr/bin/env python3
"""Regression tests for the admin saved-chat unlock design (approved
2026-10-08).

The contract under test:

* Admin saved chats are encrypted under a random 256-bit DEK
  (AES-256-GCM). The DEK is stored in the chat file only WRAPPED under a
  KEK derived from the master password (PBKDF2-HMAC-SHA256, 600k,
  dedicated salt + domain separation). The master password itself is
  never stored in a pending-2FA record or a session.
* At the login password step (the only moment the password exists
  server-side, and only after it has proven itself by decrypting
  keys.enc), the DEK is unwrapped into an in-memory unlock map. The
  pending 2FA record and later the session hold only an opaque handle,
  bound to the exact session token at TOTP success.
* Wrong / replayed / expired TOTP codes mint no session and no usable
  unlock. Logout and session expiry destroy the unlock. A restart wipes
  it; the on-disk store stays sealed until the owner's next full login.
* Master-password rotation re-wraps the same DEK under the new password;
  an admin chat store that cannot be opened is never overwritten with an
  empty one (fail closed).
* Friends can never reach the admin store: /api/chats takes the label
  from the session only, unlocks are minted only in the master-password
  branch, and the restore key cannot open the admin chat envelope.
* Legacy v1 admin chats (encrypted directly with the master password)
  are migrated to v2 at the first proven password step.

Run:  python3 -m unittest discover -s tests -v
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
from key_security import encrypt_keys, decrypt_keys  # noqa: E402

MASTER = "test-master-password-123"
NEW_MASTER = "rotated-master-password-456"
RESTORE = "test-restore-key-xyz"
FRIEND1 = "friendone"
FRIEND1_PW = "friend-one-pass"
TOTP_SECRET = base64.b32encode(b"12345678901234567890").decode()
LEGACY_CHAT = {"id": "legacy1", "title": "Legacy admin chat", "ts": 1,
               "updated": 1,
               "messages": [{"r": "user", "t": "hello from before 2fa"}]}


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


def _totp(secret_b32, offset=0):
    t = int(time.time()) // 30 + offset
    key = base64.b32decode(secret_b32.upper())
    digest = hmac.new(key, struct.pack(">Q", t), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


class Harness:
    """Real-server harness: throwaway copy of app/, fixture state, real
    subprocess restarts. Subclasses provide build_fixtures()."""

    proc = None
    log = None

    @classmethod
    def build_tmp(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-chats-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip or name == "chats":
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND1: _hash_pw(FRIEND1_PW)}
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        cls.build_fixtures()

    @classmethod
    def build_fixtures(cls):
        raise NotImplementedError

    @classmethod
    def _start(cls, restore_key=RESTORE):
        cls._stop()
        cls.api_port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1",
            "PORT": str(cls.api_port),
            "NEXUS_RELAY_PORT": str(_free_port()),
            "PYTHONPATH": str(cls.tmp),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        if restore_key is None:
            env.pop("NEXUS_RESTORE_KEY", None)
        else:
            env["NEXUS_RESTORE_KEY"] = restore_key
        cls.log = open(cls.tmp / "server.log", "ab")
        cls.proc = subprocess.Popen(
            [sys.executable, str(cls.tmp / "server.py")],
            cwd=str(cls.tmp), env=env,
            stdout=cls.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if cls.proc.poll() is not None:
                raise RuntimeError("server exited early:\n"
                                   + (cls.tmp / "server.log").read_text(errors="replace")[-2000:])
            try:
                status, _, _ = cls._req("GET", "/api/friend_blob")
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
    def teardown_tmp(cls):
        cls._stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _req(cls, method, path, body=None, cookie=None, timeout=60):
        conn = http.client.HTTPConnection("127.0.0.1", cls.api_port, timeout=timeout)
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body)
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        set_cookie = resp.getheader("Set-Cookie") or ""
        conn.close()
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"_raw": raw.decode(errors="replace")[:400]}
        return resp.status, parsed, set_cookie.split(";")[0] if set_cookie.startswith("session=") else None

    @classmethod
    def _login(cls, password):
        status, body, cookie = cls._req("POST", "/api/login", {"password": password})
        return status, body, cookie

    @classmethod
    def _admin_login_2fa(cls, password=MASTER):
        """Full password+TOTP login. Returns the session cookie.
        Tries the current and next TOTP steps (replay protection may have
        consumed the current one earlier in the same server process); if
        both are spent, waits for the next step boundary and retries."""
        for attempt in range(2):
            status, body, cookie = cls._login(password)
            assert status == 200 and body.get("need_2fa"), body
            assert cookie is None, "password step must not create a session"
            tmp = body["tmp"]
            for offset in (0, 1, -1):
                status, body, cookie = cls._req(
                    "POST", "/api/login", {"tmp": tmp, "code": _totp(TOTP_SECRET, offset)})
                if status == 200 and cookie:
                    return cookie
            if attempt == 0:
                time.sleep(31 - (int(time.time()) % 30))
        raise AssertionError("2FA login did not succeed")


class TwoFAChatUnlockTests(Harness, unittest.TestCase):
    """Sequential flow — numbered on purpose."""

    @classmethod
    def build_fixtures(cls):
        encrypt_keys({"groq": "sk-shared-fake", "_totp_secret": TOTP_SECRET},
                     MASTER, cls.tmp / "keys.enc")
        # Legacy v1 admin chats: encrypted directly with the master password.
        encrypt_keys({"chats": [LEGACY_CHAT]}, MASTER, cls.tmp / "chats" / "rudra.enc")

    @classmethod
    def setUpClass(cls):
        cls.build_tmp()
        cls._start()

    @classmethod
    def tearDownClass(cls):
        cls.teardown_tmp()

    def test_01_password_step_alone_grants_nothing(self):
        status, body, cookie = self._login(MASTER)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("need_2fa"))
        self.assertIsNone(cookie)  # no session before TOTP
        tmp = body["tmp"]
        # Saved chats are unreachable without a session.
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"})
        self.assertEqual(status, 401, body)
        # A wrong code mints no session (and is not any valid window code).
        valid = {_totp(TOTP_SECRET, o) for o in (-1, 0, 1)}
        wrong = next(c for c in ("000000", "111111", "222222") if c not in valid)
        status, body, cookie = self._req("POST", "/api/login", {"tmp": tmp, "code": wrong})
        self.assertEqual(status, 401, body)
        self.assertIsNone(cookie)
        # The pending login can still be completed with a real code.
        for offset in (0, 1, -1):
            status, body, cookie = self._req(
                "POST", "/api/login", {"tmp": tmp, "code": _totp(TOTP_SECRET, offset)})
            if status == 200:
                break
        self.assertEqual(status, 200, body)
        self.assertTrue(cookie)
        self.__class__.admin_cookie = cookie
        self.__class__.used_tmp = tmp

    def test_02_2fa_session_reads_and_migrates_legacy_chats(self):
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"},
                                    cookie=self.admin_cookie)
        self.assertEqual(status, 200, body)
        titles = [c["title"] for c in body.get("chats", [])]
        self.assertIn("Legacy admin chat", titles)
        # The on-disk store was migrated to the v2 wrapped-DEK envelope:
        # no longer openable directly with the master password.
        env = json.loads((self.tmp / "chats" / "rudra.enc").read_text())
        self.assertEqual(env.get("v"), 2)
        self.assertIn("wrapped_dek", env)
        with self.assertRaises(Exception):
            decrypt_keys(self.tmp / "chats" / "rudra.enc", MASTER)
        # Save + reopen through the same 2FA session.
        status, body, _ = self._req("POST", "/api/chats", {
            "action": "save", "title": "written via 2fa session",
            "messages": [{"r": "user", "t": "stored without the password in session"}]},
            cookie=self.admin_cookie)
        self.assertEqual(status, 200, body)
        new_id = body.get("id")
        status, body, _ = self._req("POST", "/api/chats", {"action": "get", "id": new_id},
                                    cookie=self.admin_cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["chat"]["messages"][0]["t"],
                         "stored without the password in session")
        # Neither password nor plaintext titles appear in the stored file.
        raw = (self.tmp / "chats" / "rudra.enc").read_text()
        self.assertNotIn(MASTER, raw)
        self.assertNotIn("Legacy admin chat", raw)

    def test_03_pending_token_cannot_be_reused(self):
        # The consumed tmp from test_01 is dead even with a fresh valid code.
        status, body, cookie = self._req(
            "POST", "/api/login", {"tmp": self.used_tmp, "code": _totp(TOTP_SECRET, 0)})
        self.assertEqual(status, 401, body)
        self.assertIsNone(cookie)

    def test_04_friend_cannot_reach_admin_chats(self):
        status, body, friend_cookie = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        self.__class__.friend_cookie = friend_cookie
        # Friend's own store is separate and empty of admin content, even
        # when the request body tries to inject the admin's label.
        status, body, _ = self._req("POST", "/api/chats",
                                    {"action": "list", "label": "Rudra"},
                                    cookie=friend_cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("chats"), [])
        status, body, _ = self._req("POST", "/api/chats",
                                    {"action": "get", "id": "legacy1"},
                                    cookie=friend_cookie)
        self.assertEqual(status, 404, body)

    def test_05_logout_destroys_the_unlock(self):
        status, body, _ = self._req("POST", "/api/logout", {}, cookie=self.admin_cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"},
                                    cookie=self.admin_cookie)
        self.assertEqual(status, 401, body)
        # A fresh full login restores chat access (DEK unwrapped again).
        cookie = self._admin_login_2fa()
        self.__class__.admin_cookie = cookie
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body.get("chats", [])), 2)

    def test_06_master_rotation_rewraps_dek(self):
        status, body, _ = self._req("POST", "/api/access", {
            "action": "change_master", "master_pw": MASTER,
            "new_master_pw": NEW_MASTER}, cookie=self.admin_cookie)
        self.assertEqual(status, 200, body)
        # Rotation cleared every session (existing behaviour).
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"},
                                    cookie=self.admin_cookie)
        self.assertEqual(status, 401, body)
        # The old password is dead.
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 401, body)
        # The new password + TOTP opens the SAME chats (DEK re-wrapped,
        # data untouched).
        cookie = self._admin_login_2fa(password=NEW_MASTER)
        self.__class__.admin_cookie = cookie
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        titles = sorted(c["title"] for c in body.get("chats", []))
        self.assertEqual(titles, ["Legacy admin chat", "written via 2fa session"])

    def test_07_restart_seals_chats_until_full_owner_login(self):
        self._start()  # same tmp dir, fresh process: all unlocks wiped
        # Friends still log in first, exactly as designed, and still
        # cannot see admin chats.
        status, body, friend_cookie = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"},
                                    cookie=friend_cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("chats"), [])
        # Owner's full login (password + TOTP) unwraps the DEK again.
        cookie = self._admin_login_2fa(password=NEW_MASTER)
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body.get("chats", [])), 2)
        # The restore key opens the access list only — never admin chats.
        with self.assertRaises(Exception):
            decrypt_keys(self.tmp / "chats" / "rudra.enc", RESTORE)
        raw = (self.tmp / "chats" / "rudra.enc").read_text()
        self.assertNotIn(NEW_MASTER, raw)


class DirectAdminChatUnlockTests(Harness, unittest.TestCase):
    """Admin login WITHOUT 2FA must use the same unlock mechanism and
    must not fall back to storing the master password in the session."""

    @classmethod
    def build_fixtures(cls):
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys({"chats": [LEGACY_CHAT]}, MASTER, cls.tmp / "chats" / "rudra.enc")

    @classmethod
    def setUpClass(cls):
        cls.build_tmp()
        cls._start()

    @classmethod
    def tearDownClass(cls):
        cls.teardown_tmp()

    def test_01_direct_admin_login_opens_chats_via_unlock(self):
        status, body, cookie = self._login(MASTER)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("admin"))
        self.assertTrue(cookie)
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual([c["title"] for c in body.get("chats", [])],
                         ["Legacy admin chat"])
        # Migrated to v2 even on the direct path.
        env = json.loads((self.tmp / "chats" / "rudra.enc").read_text())
        self.assertEqual(env.get("v"), 2)
        # Save + delete round-trip through the unlock.
        status, body, _ = self._req("POST", "/api/chats", {
            "action": "save", "title": "direct login chat",
            "messages": [{"r": "user", "t": "hi"}]}, cookie=cookie)
        self.assertEqual(status, 200, body)
        cid = body.get("id")
        status, body, _ = self._req("POST", "/api/chats", {"action": "delete", "id": cid},
                                    cookie=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"}, cookie=cookie)
        self.assertEqual(len(body.get("chats", [])), 1)


if __name__ == "__main__":
    unittest.main()
