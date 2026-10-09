#!/usr/bin/env python3
"""Production-hardening regression tests (2026-10-08 hardening phase).

Covers the production paths the restart/2FA suites do not: security
headers, CSRF origin checks, malformed request shapes (an endpoint must
answer a JSON 500, never drop the connection), input validation limits,
admin-surface edge cases, the 2FA enable/confirm/disable cycle, relay
token enforcement, login + chat rate limits, session expiry, and
backup corruption / partial-restore behaviour (a failed restore must
never overwrite valid data with empty data).

Fixtures use only fake keys and throwaway passwords; no real secret is
read or printed anywhere in this file.

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
RESTORE = "test-restore-key-xyz"
FRIEND1 = "friendone"
FRIEND1_PW = "friend-one-pass"
FRIEND2 = "friendtwo"
FRIEND2_PW = "friend-two-pass"


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
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


class Harness:
    proc = None
    log = None
    ENV_EXTRA = {}

    @classmethod
    def build_tmp(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-hardening-"))
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
        cls.quotas_backup = (cls.tmp / "quotas.json").read_bytes()

    @classmethod
    def _start(cls):
        cls._stop()
        cls.api_port = _free_port()
        cls.relay_port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1",
            "PORT": str(cls.api_port),
            "NEXUS_RELAY_PORT": str(cls.relay_port),
            "NEXUS_RESTORE_KEY": RESTORE,
            "PYTHONPATH": str(cls.tmp),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        env.update(cls.ENV_EXTRA)
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
                status, _, _, _ = cls._req("GET", "/api/friend_blob")
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
    def _req(cls, method, path, body=None, cookie=None, headers=None,
             raw=None, timeout=60, port=None):
        conn = http.client.HTTPConnection("127.0.0.1", port or cls.api_port,
                                          timeout=timeout)
        hdrs = dict(headers or {})
        data = raw
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
            parsed = {"_raw": payload.decode(errors="replace")[:300]}
        return (resp.status, parsed,
                set_cookie.split(";")[0] if set_cookie.startswith("session=") else None,
                resp_headers)

    @classmethod
    def _login(cls, password):
        status, body, cookie, _ = cls._req("POST", "/api/login", {"password": password})
        return status, body, cookie


class ApiHardeningTests(Harness, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp()
        cls._start()
        status, body, cookie = cls._login(FRIEND1_PW)
        assert status == 200, body
        cls.friend_cookie = cookie

    @classmethod
    def tearDownClass(cls):
        cls.teardown_tmp()

    def test_01_security_headers_on_pages_and_404(self):
        for path in ("/login", "/definitely-not-a-page"):
            status, _, _, headers = self._req("GET", path)
            self.assertIn(status, (200, 404))
            self.assertIn("max-age=31536000", headers.get("strict-transport-security", ""))
            self.assertEqual(headers.get("x-frame-options"), "DENY")
            self.assertEqual(headers.get("x-content-type-options"), "nosniff")
            self.assertIn("frame-ancestors 'none'",
                          headers.get("content-security-policy", ""))

    def test_02_health_endpoint_is_public_and_minimal(self):
        status, body, _, _ = self._req("GET", "/health")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"ok": True})  # no state, no secrets

    def test_03_csrf_evil_origin_rejected(self):
        status, body, _, _ = self._req(
            "POST", "/api/routing", {"set": "auto"}, cookie=self.friend_cookie,
            headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403, body)
        self.assertEqual(body.get("error"), "origin mismatch")
        status, body, _, _ = self._req("POST", "/api/routing", {"set": "auto"},
                                       cookie=self.friend_cookie)
        self.assertEqual(status, 200, body)

    def test_04_malformed_body_shapes_return_json_500_not_a_dropped_connection(self):
        # JSON values that are not objects used to crash handlers outright
        # (the client saw a dropped connection, no response at all).
        for path, raw in (("/api/chats", "[1, 2]"),
                          ("/api/login", "[1, 2]"),
                          ("/api/routing", '"just-a-string"')):
            status, body, _, _ = self._req("POST", path, raw=raw,
                                           cookie=self.friend_cookie,
                                           headers={"Content-Type": "application/json"})
            self.assertEqual(status, 500, (path, body))
            self.assertEqual(body.get("error"), "internal error")
        # The server is unharmed afterwards.
        status, body, _, _ = self._req("GET", "/api/status", cookie=self.friend_cookie)
        self.assertEqual(status, 200, body)

    def test_05_chat_input_validation(self):
        status, body, _, _ = self._req("POST", "/api/chat", {
            "provider": "groq", "model": "m", "message": "x" * 50001},
            cookie=self.friend_cookie)
        self.assertEqual(status, 400, body)
        self.assertIn("too long", body.get("error", ""))
        status, body, _, _ = self._req("POST", "/api/chat", {
            "provider": "groq", "model": "m", "message": "hi",
            "image": "https://example.com/x.png"}, cookie=self.friend_cookie)
        self.assertEqual(status, 400, body)
        self.assertEqual(body.get("error"), "invalid image")
        status, body, _, _ = self._req("POST", "/api/chat", {"message": "hi"},
                                       cookie=self.friend_cookie)
        self.assertEqual(status, 400, body)

    def test_06_transcribe_validation_after_unlock(self):
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        self.__class__.admin_cookie = admin
        status, body, _, _ = self._req("POST", "/api/transcribe", raw="{not json",
                                       cookie=admin,
                                       headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400, body)
        # Junk audio: decodes to nothing/garbage and is rejected either by
        # local validation (400) or by the provider (502) — never a crash,
        # never a silent success.
        status, body, _, _ = self._req("POST", "/api/transcribe",
                                       {"audio": "data:audio/webm;base64,!!!"},
                                       cookie=admin)
        self.assertIn(status, (400, 500, 502), body)
        self.assertTrue(body.get("error"))
        big = base64.b64encode(b"\x00" * (8 * 1024 * 1024 + 16)).decode()
        status, body, _, _ = self._req("POST", "/api/transcribe",
                                       {"audio": "data:audio/webm;base64," + big},
                                       cookie=admin, timeout=120)
        self.assertEqual(status, 413, body)

    def test_07_settings_and_setup_guards(self):
        status, _, _, _ = self._req("GET", "/settings", cookie=self.friend_cookie)
        self.assertEqual(status, 403)
        # Setup page opened to users (owner order 2026-10-09): a friend's
        # POST /setup now saves to their OWN vault, so a wrong account
        # password is a 401 (previously the route was admin-only: 403).
        status, body, _, _ = self._req("POST", "/setup", raw="password=x&confirm=x",
                                       cookie=self.friend_cookie,
                                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 401, body)
        # Correct account password: saves into the friend's vault and
        # redirects to their My Keys page; shared setup untouched.
        status, body, _, headers = self._req(
            "POST", "/setup",
            raw="password=" + FRIEND1_PW + "&k_groq=friend-setup-key",
            cookie=self.friend_cookie,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 302, body)
        self.assertEqual(headers.get("location"), "/mykeys")
        status, body, _, _ = self._req("POST", "/api/mykeys", {"action": "view"},
                                       cookie=self.friend_cookie)
        self.assertEqual(status, 200, body)
        self.assertIn("groq", body.get("configured", []))
        # Friend GET /setup is served (200), not bounced to /login.
        status, body, _, _ = self._req("GET", "/setup", cookie=self.friend_cookie)
        self.assertEqual(status, 200)
        # Signed-out normal users get the page too (owner order 2026-10-09:
        # "allow normal user in set up your key page") — personal mode; the
        # account password authenticates the save.
        status, body, _, _ = self._req("GET", "/setup")
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("POST", "/setup", raw="password=not-the-password&k_groq=guest-key",
                                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 401, body)
        status, body, _, headers = self._req(
            "POST", "/setup",
            raw="password=" + FRIEND1_PW + "&k_openrouter=guest-setup-key",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 302, body)
        self.assertEqual(headers.get("location"), "/mykeys")
        guest_cookie = (headers.get("set-cookie") or "").split(";")[0]
        self.assertTrue(guest_cookie.startswith("session="), headers)
        # The guest save landed in the friend's own vault, and the minted
        # session works.
        status, body, _, _ = self._req("POST", "/api/mykeys", {"action": "view"},
                                       cookie=guest_cookie)
        self.assertEqual(status, 200, body)
        self.assertIn("openrouter", body.get("configured", []))
        status, body, _, _ = self._req("POST", "/settings",
                                       raw="password=wrong-password",
                                       cookie=self.admin_cookie,
                                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 401, body)

    def test_08_access_admin_edge_cases(self):
        admin = self.admin_cookie
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "add", "label": FRIEND1, "password": "whatever1",
            "master_pw": MASTER}, cookie=admin)
        self.assertEqual(status, 400, body)  # duplicate label
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "add", "label": "newfriend", "password": "short",
            "master_pw": MASTER}, cookie=admin)
        self.assertEqual(status, 400, body)  # password too short
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "add", "label": "bad label", "password": "longenough",
            "master_pw": MASTER}, cookie=admin)
        self.assertEqual(status, 400, body)  # label charset
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "add", "label": FRIEND2, "password": FRIEND2_PW,
            "master_pw": "not-the-master"}, cookie=admin)
        self.assertEqual(status, 401, body)  # wrong master password
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "add", "label": FRIEND2, "password": FRIEND2_PW,
            "master_pw": MASTER}, cookie=admin)
        self.assertEqual(status, 200, body)
        status, body, friend2_cookie = self._login(FRIEND2_PW)
        self.assertEqual(status, 200, body)
        # Revoking deletes the account AND kills its live sessions.
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "revoke", "label": FRIEND2, "master_pw": MASTER}, cookie=admin)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("GET", "/api/status", cookie=friend2_cookie)
        self.assertEqual(status, 401, body)
        status, body, _ = self._login(FRIEND2_PW)
        self.assertEqual(status, 401, body)

    def test_09_change_master_validation(self):
        admin = self.admin_cookie
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "change_master", "master_pw": MASTER,
            "new_master_pw": "short"}, cookie=admin)
        self.assertEqual(status, 400, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "change_master", "master_pw": MASTER,
            "new_master_pw": MASTER}, cookie=admin)
        self.assertEqual(status, 400, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "change_master", "master_pw": "wrong-current",
            "new_master_pw": "a-perfectly-fine-new-one"}, cookie=admin)
        self.assertEqual(status, 401, body)

    def test_10_mykeys_negative_paths(self):
        status, body, _, _ = self._req("POST", "/api/mykeys", {
            "action": "save", "password": "not-my-password",
            "keys": {"groq": "sk-x"}}, cookie=self.friend_cookie)
        self.assertEqual(status, 401, body)
        status, body, _, _ = self._req("POST", "/api/mykeys", {"action": "view"},
                                       cookie=self.admin_cookie)
        self.assertEqual(status, 403, body)  # admins are refused the friend vault API

    def test_11_models_unauthenticated_is_json_401(self):
        status, body, _, headers = self._req("GET", "/api/models?provider=groq")
        self.assertEqual(status, 401, body)
        self.assertEqual(body.get("error"), "not logged in")
        self.assertIn("application/json", headers.get("content-type", ""))

    def test_12_relay_requires_its_token(self):
        # The relay must refuse everyone except the main server process.
        status, body, _, _ = self._req("GET", "/groq/v1/models", port=self.relay_port)
        self.assertEqual(status, 403, body)
        status, body, _, _ = self._req("GET", "/groq/v1/models", port=self.relay_port,
                                       headers={"X-Relay-Token": "wrong-token"})
        self.assertEqual(status, 403, body)

    def test_13_friend_blob_contains_no_plaintext_secrets(self):
        status, body, _, _ = self._req("GET", "/api/friend_blob")
        self.assertEqual(status, 200, body)
        for field in ("blob", "keys", "access"):
            raw = base64.b64decode(body[field])
            for secret in (MASTER, FRIEND1_PW, "sk-shared-fake"):
                self.assertNotIn(secret.encode(), raw, field)
        for vault in (body.get("vaults") or {}).values():
            self.assertNotIn(b"sk-", base64.b64decode(vault))

    def test_14_twofa_enable_confirm_disable_cycle(self):
        admin = self.admin_cookie
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_enable", "master_pw": "wrong"}, cookie=admin)
        self.assertEqual(status, 401, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_enable", "master_pw": MASTER}, cookie=admin)
        self.assertEqual(status, 200, body)
        secret = body.get("secret")
        self.assertTrue(secret)
        # Wrong code does not activate.
        valid = {_totp(secret, o) for o in (-1, 0, 1)}
        wrong = next(c for c in ("000000", "111111", "222222") if c not in valid)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_confirm", "master_pw": MASTER, "code": wrong}, cookie=admin)
        self.assertEqual(status, 401, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_state"}, cookie=admin)
        self.assertFalse(body.get("enabled"))
        self.assertTrue(body.get("pending"))
        # Correct code activates; state is visible from the session.
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_confirm", "master_pw": MASTER,
            "code": _totp(secret)}, cookie=admin)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_state"}, cookie=admin)
        self.assertTrue(body.get("enabled"))
        # Disable requires master password AND a valid code.
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_disable", "master_pw": MASTER, "code": wrong}, cookie=admin)
        self.assertEqual(status, 401, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_disable", "master_pw": MASTER,
            "code": _totp(secret)}, cookie=admin)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "2fa_state"}, cookie=admin)
        self.assertFalse(body.get("enabled"))


class CorruptionTests(Harness, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp()
        cls._start()

    @classmethod
    def tearDownClass(cls):
        cls.teardown_tmp()

    def test_01_corrupt_quotas_file_is_a_json_500_and_recovers(self):
        status, body, friend = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        (self.tmp / "quotas.json").write_text("definitely not json {{{")
        try:
            status, body, _, _ = self._req("GET", "/api/quotas", cookie=friend)
            self.assertEqual(status, 500, body)
            self.assertEqual(body.get("error"), "internal error")
        finally:
            (self.tmp / "quotas.json").write_bytes(self.quotas_backup)
        status, body, _, _ = self._req("GET", "/api/quotas", cookie=friend)
        self.assertEqual(status, 200, body)

    def test_02_corrupt_keys_enc_admin_rejected_friend_unaffected(self):
        (self.tmp / "keys.enc").write_bytes(b"garbage")
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 401, body)
        status, body, cookie = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)

    def test_03_corrupt_users_enc_does_not_overwrite_valid_access(self):
        # access.json (restored at boot from access.enc) is valid; a broken
        # users.enc must not wipe it at admin login.
        (self.tmp / "keys.enc").write_bytes(b"garbage")  # undo for admin path below
        # Restore a valid keys.enc so the admin can log in again.
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, self.tmp / "keys.enc")
        (self.tmp / "users.enc").write_bytes(b"garbage")
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("POST", "/api/access", {"action": "list"},
                                       cookie=admin)
        self.assertEqual(status, 200, body)
        self.assertIn(FRIEND1, [a["label"] for a in body.get("access", [])])

    def test_04_partial_restore_access_enc_alone_is_enough(self):
        (self.tmp / "users.enc").unlink()
        (self.tmp / "access.json").unlink()
        self._start()
        status, body, cookie = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)  # boot restore from access.enc only
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)  # missing users.enc is a graceful no-op

    def test_05_corrupt_admin_chat_store_fails_closed(self):
        # This class has no TOTP in keys.enc (test_03 fixture): direct login.
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("POST", "/api/chats", {
            "action": "save", "title": "will be corrupted",
            "messages": [{"r": "user", "t": "hello"}]}, cookie=admin)
        self.assertEqual(status, 200, body)
        chat_file = self.tmp / "chats" / "rudra.enc"
        chat_file.write_bytes(b"\x00\x01corrupted-store")
        before = chat_file.read_bytes()
        status, body, _, _ = self._req("POST", "/api/chats", {"action": "list"},
                                       cookie=admin)
        self.assertEqual(status, 500, body)
        self.assertIn("could not be decrypted", body.get("error", ""))
        status, body, _, _ = self._req("POST", "/api/chats", {
            "action": "save", "title": "must not land",
            "messages": [{"r": "user", "t": "x"}]}, cookie=admin)
        self.assertEqual(status, 500, body)
        # The failed save did NOT overwrite the corrupted store.
        self.assertEqual(chat_file.read_bytes(), before)


class RateLimitTests(Harness, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp()
        cls._start()

    @classmethod
    def tearDownClass(cls):
        cls.teardown_tmp()

    def test_01_chat_rate_limit_40_per_minute(self):
        status, body, friend = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        codes = []
        for _ in range(41):
            status, body, _, _ = self._req("POST", "/api/chat", raw="{invalid",
                                           cookie=friend,
                                           headers={"Content-Type": "application/json"})
            codes.append(status)
        self.assertTrue(all(c == 400 for c in codes[:40]), codes)
        self.assertEqual(codes[40], 429, codes)

    def test_02_login_throttle_after_10_failures(self):
        codes = []
        for _ in range(11):
            status, body, _ = self._login("wrong-password-again")
            codes.append(status)
        self.assertTrue(all(c == 401 for c in codes[:10]), codes)
        self.assertEqual(codes[10], 429, codes)
        # Even the CORRECT password is throttled inside the window.
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 429, body)


class SessionExpiryTests(Harness, unittest.TestCase):
    ENV_EXTRA = {"NEXUS_SESSION_EXPIRY": "3"}

    @classmethod
    def setUpClass(cls):
        cls.build_tmp()
        cls._start()

    @classmethod
    def tearDownClass(cls):
        cls.teardown_tmp()

    def test_01_session_expires_after_idle_timeout(self):
        status, body, friend = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("GET", "/api/status", cookie=friend)
        self.assertEqual(status, 200, body)
        time.sleep(4)
        status, body, _, _ = self._req("GET", "/api/status", cookie=friend)
        self.assertEqual(status, 401, body)

    def test_02_admin_chat_unlock_dies_with_the_session(self):
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("POST", "/api/chats", {
            "action": "save", "title": "expiry test",
            "messages": [{"r": "user", "t": "hi"}]}, cookie=admin)
        self.assertEqual(status, 200, body)
        time.sleep(4)
        status, body, _, _ = self._req("POST", "/api/chats", {"action": "list"},
                                       cookie=admin)
        self.assertEqual(status, 401, body)  # session (and its unlock) gone


if __name__ == "__main__":
    unittest.main()
