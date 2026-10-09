#!/usr/bin/env python3
"""Regression tests for the restart / lockout architecture.

The contract under test (do not weaken it):

* Authentication and session availability are SEPARATE from owner-key
  availability. A restart or redeploy must never require the owner to log
  in before friends can authenticate.
* The friend access list is mirrored to access.enc encrypted under the
  server-held restore key (env NEXUS_RESTORE_KEY) and rebuilt at boot.
  The restore key decrypts ONLY friend password hashes — never provider
  keys. Provider keys still require the owner's master password; nothing
  here bypasses that.
* While locked (no admin login yet since boot), friends can use every
  feature that does not need the owner's key: saved chats (encrypted with
  their own password), their personal key vault (BYOK), keyless
  providers, routing, quotas, usage, model lists.
* Only operations that genuinely need the owner's key return the 503
  "server is locked" error — and they start working the moment the
  owner logs in (the unlock), with no restart.
* Failure states recover: corrupt access.json is repaired at boot from
  access.enc; corrupt/missing access.enc or a wrong restore key falls
  back to the classic restore-at-admin-login from users.enc.

These tests run the REAL server (subprocess) against a throwaway copy of
app/ with fixture keys, and restart it for real between phases. Provider
API calls use fake keys on purpose: assertions check the LOCK behaviour
(never a 503-locked where a provider error belongs, and vice versa),
not upstream provider health.

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
from key_security import encrypt_keys, decrypt_keys  # noqa: E402

MASTER = "test-master-password-123"
RESTORE = "test-restore-key-xyz"
FRIEND1 = "friendone"
FRIEND1_PW = "friend-one-pass"
FRIEND2 = "friendtwo"
FRIEND2_PW = "friend-two-pass"
LOCKED = "server is locked"


def _hash_pw(password):
    """Same stored format as server._hash_password (PBKDF2, salted)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000)
    return f"pbkdf2$210000${salt.hex()}${dk.hex()}"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class RestartLockoutTests(unittest.TestCase):
    """Sequential integration flow — methods are numbered on purpose."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-app-"))
        # Copy code + static assets only. Live state files (access.json,
        # *.enc, provider_status.json) are NEVER copied: fixtures below
        # create fresh ones, and a stale access.json from a checkout would
        # silently become the "existing" list the boot restore preserves.
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip:
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        # Fixture state: one friend, shared provider keys (fake values).
        cls.access = {FRIEND1: _hash_pw(FRIEND1_PW)}
        encrypt_keys({"groq": "sk-shared-fake", "google": "fake-google"},
                     MASTER, cls.tmp / "keys.enc")
        encrypt_keys(cls.access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(cls.access, RESTORE, cls.tmp / "access.enc")
        # A redeploy restores the REPO files, and a stale access.json once
        # shipped in the repo (a leftover local test entry) and shadowed the
        # mirror at boot — the panel showed only that entry and the real
        # friends vanished (2026-10-09). Seed exactly that poisoned state:
        # boot must let the mirror win.
        (cls.tmp / "access.json").write_text(
            json.dumps({"trialuser": _hash_pw("trial-user-pw-000")}))
        cls.proc = None
        cls.log = None
        cls._start(restore_key=RESTORE)

    @classmethod
    def tearDownClass(cls):
        cls._stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------- server
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
            # Localhost traffic (relay, gateway) must never hit a proxy.
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

    # ------------------------------------------------------------- client
    @classmethod
    def _req(cls, method, path, body=None, cookie=None, timeout=120):
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
        return resp.status, parsed, set_cookie

    @classmethod
    def _login(cls, password):
        status, body, set_cookie = cls._req("POST", "/api/login", {"password": password})
        cookie = set_cookie.split(";")[0] if set_cookie.startswith("session=") else None
        return status, body, cookie

    # ------------------------------------------------------------- tests
    def test_01_boot_restore_and_friend_login_pre_unlock(self):
        # Boot rebuilt access.json from access.enc (restore key) on its own,
        # discarding the stale entry that shipped in the "repo" access.json.
        on_disk = json.loads((self.tmp / "access.json").read_text())
        self.assertIn(FRIEND1, on_disk)
        self.assertNotIn("trialuser", on_disk)
        # Friend logs in BEFORE any admin login on this fresh instance.
        status, body, cookie = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("label"), FRIEND1)
        self.assertFalse(body.get("admin"))
        self.assertTrue(cookie)
        self.__class__.friend_cookie = cookie
        status, body, _ = self._req("GET", "/api/status", cookie=cookie)
        self.assertEqual(status, 200, body)

    def test_02_owner_key_operations_are_locked(self):
        cookie = self.friend_cookie
        # Text chat is NOT genuinely owner-key-bound: the failover already
        # routes around a missing key to keyless lanes, so even an explicit
        # owner-key pick (or Auto) must never produce the locked error —
        # it is answered by a keyless lane or fails as a provider error.
        for provider in ("groq", "auto"):
            status, body, _ = self._req("POST", "/api/chat", {
                "provider": provider, "model": "openai/gpt-oss-20b",
                "message": "hi", "mode": "text"}, cookie=cookie)
            self.assertNotIn(LOCKED, json.dumps(body),
                             f"{provider} chat must not be lock-blocked")
        # Voice mode needs a Groq key: locked.
        status, body, _ = self._req("POST", "/api/chat", {
            "provider": "groq", "model": "", "message": "say hello",
            "mode": "voice"}, cookie=cookie)
        self.assertEqual(status, 503, body)
        self.assertIn(LOCKED, body.get("error", ""))
        # Transcription needs a Groq key: locked.
        status, body, _ = self._req("POST", "/api/transcribe", {
            "audio": "data:audio/webm;base64,AAAA"}, cookie=cookie)
        self.assertEqual(status, 503, body)
        self.assertIn(LOCKED, body.get("error", ""))

    def test_03_auth_only_features_work_pre_unlock(self):
        cookie = self.friend_cookie
        # Saved chats: encrypted with the friend's OWN password.
        status, body, _ = self._req("POST", "/api/chats", {
            "action": "save", "title": "pre-unlock chat",
            "messages": [{"r": "user", "t": "hello before unlock"}]}, cookie=cookie)
        self.assertEqual(status, 200, body)
        chat_id = body.get("id")
        self.assertTrue(chat_id)
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(any(c["id"] == chat_id for c in body.get("chats", [])))
        status, body, _ = self._req("POST", "/api/chats", {
            "action": "get", "id": chat_id}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["chat"]["messages"][0]["t"], "hello before unlock")
        # Personal key vault view.
        status, body, _ = self._req("POST", "/api/mykeys", {"action": "view"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        # Per-session routing.
        status, body, _ = self._req("POST", "/api/routing", {"set": "auto"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req("GET", "/api/routing", cookie=cookie)
        self.assertEqual(body.get("routing"), "auto")
        # Usage + quotas are file/session state, not owner keys.
        status, body, _ = self._req("GET", "/api/usage", cookie=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req("GET", "/api/quotas", cookie=cookie)
        self.assertEqual(status, 200, body)
        configured = {p["provider"]: p["key_configured"] for p in body["providers"]}
        # Owner's Groq key is locked away; keyless lanes report configured.
        self.assertFalse(configured["groq"])
        self.assertTrue(configured["pollinations"])
        # Model list for an owner-key provider degrades to empty, not a lock.
        status, body, _ = self._req("GET", "/api/models?provider=google", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("models"), [])
        # Keyless provider model list still answers (static injections).
        status, body, _ = self._req("GET", "/api/models?provider=pollinations&cap=image",
                                    cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("models"), ["flux", "turbo"])

    def test_04_friend_byok_works_pre_unlock(self):
        cookie = self.friend_cookie
        # Friend stores their OWN Groq key (vault encrypted with their own
        # password — the owner's key is never involved).
        status, body, _ = self._req("POST", "/api/mykeys", {
            "action": "save", "password": FRIEND1_PW,
            "keys": {"groq": "sk-friend-vault-fake"}}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertIn("groq", body.get("configured", []))
        # Quotas now truthfully report the friend's own key as configured.
        status, body, _ = self._req("GET", "/api/quotas", cookie=cookie)
        configured = {p["provider"]: p["key_configured"] for p in body["providers"]}
        self.assertTrue(configured["groq"])
        # Chat with the vault key: the lock must NOT fire. The fake key gets
        # a provider error (or a keyless fallback answers) — never a 503 lock.
        status, body, _ = self._req("POST", "/api/chat", {
            "provider": "groq", "model": "openai/gpt-oss-20b",
            "message": "hi", "mode": "text"}, cookie=cookie)
        self.assertNotEqual(status, 503, body)
        self.assertNotIn(LOCKED, json.dumps(body))
        # Keyless chat lane: also never lock-blocked.
        status, body, _ = self._req("POST", "/api/chat", {
            "provider": "pollinations", "model": "openai",
            "message": "hi", "mode": "text"}, cookie=cookie)
        self.assertNotEqual(status, 503, body)
        self.assertNotIn(LOCKED, json.dumps(body))
        # Transcription with the vault Groq key: provider error, not a lock.
        status, body, _ = self._req("POST", "/api/transcribe", {
            "audio": "data:audio/webm;base64,AAAA"}, cookie=cookie)
        self.assertNotEqual(status, 503, body)
        self.assertNotIn(LOCKED, json.dumps(body))

    def test_05_authorization_is_not_weakened(self):
        cookie = self.friend_cookie
        # Friends stay out of admin surfaces while locked AND in general.
        status, body, _ = self._req("POST", "/api/access", {"action": "list"}, cookie=cookie)
        self.assertEqual(status, 403, body)
        status, body, _ = self._req("POST", "/api/refresh", {}, cookie=cookie)
        self.assertEqual(status, 403, body)
        status, body, _ = self._req("GET", "/admin", cookie=cookie)
        self.assertEqual(status, 302, body)
        # Unauthenticated requests are still rejected.
        status, body, _ = self._req("POST", "/api/chat", {
            "provider": "pollinations", "model": "openai", "message": "hi"})
        self.assertEqual(status, 401, body)
        status, body, _ = self._req("POST", "/api/chats", {"action": "list"})
        self.assertEqual(status, 401, body)
        status, body, _ = self._req("GET", "/api/quotas")
        self.assertEqual(status, 401, body)
        # Wrong passwords are still wrong.
        status, body, _ = self._login("definitely-not-the-password")
        self.assertEqual(status, 401, body)

    def test_06_owner_unlock_enables_owner_key_operations(self):
        status, body, admin_cookie = self._login(MASTER)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("admin"))
        self.__class__.admin_cookie = admin_cookie
        # Admin surfaces work off the unlocked session.
        status, body, _ = self._req("POST", "/api/access", {"action": "list"},
                                    cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        self.assertIn(FRIEND1, [a["label"] for a in body.get("access", [])])
        status, body, _ = self._req("POST", "/api/access", {"action": "2fa_state"},
                                    cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        self.assertFalse(body.get("enabled"))
        # Owner-key chat no longer reports the lock (fake shared key ->
        # provider error or keyless fallback, never the locked 503).
        status, body, _ = self._req("POST", "/api/chat", {
            "provider": "groq", "model": "openai/gpt-oss-20b",
            "message": "hi", "mode": "text"}, cookie=admin_cookie)
        self.assertNotEqual(status, 503, body)
        self.assertNotIn(LOCKED, json.dumps(body))
        status, body, _ = self._req("POST", "/api/transcribe", {
            "audio": "data:audio/webm;base64,AAAA"}, cookie=admin_cookie)
        self.assertNotEqual(status, 503, body)
        self.assertNotIn(LOCKED, json.dumps(body))

    def test_07_restart_preserves_friends_added_after_boot(self):
        # Admin adds a second friend while unlocked.
        status, body, _ = self._req("POST", "/api/access", {
            "action": "add", "label": FRIEND2, "password": FRIEND2_PW,
            "master_pw": MASTER}, cookie=self.admin_cookie)
        self.assertEqual(status, 200, body)
        # The add mirrored the access list into access.enc (restore key).
        restored = decrypt_keys(self.tmp / "access.enc", RESTORE)
        self.assertIn(FRIEND2, restored)
        # Simulate a redeploy: process killed, access.json wiped.
        (self.tmp / "access.json").unlink()
        self._start(restore_key=RESTORE)
        # BOTH friends log in on the fresh instance, pre-unlock.
        for pw, label in ((FRIEND2_PW, FRIEND2), (FRIEND1_PW, FRIEND1)):
            status, body, cookie = self._login(pw)
            self.assertEqual(status, 200, body)
            self.assertEqual(body.get("label"), label)
        self.__class__.friend_cookie = cookie

    def test_08_corrupt_access_json_is_repaired_at_boot(self):
        (self.tmp / "access.json").write_text("this is not json {{{")
        self._start(restore_key=RESTORE)
        # Boot restore fell through the corrupt file to access.enc.
        on_disk = json.loads((self.tmp / "access.json").read_text())
        self.assertIn(FRIEND1, on_disk)
        status, body, cookie = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        self.__class__.friend_cookie = cookie

    def test_09_corrupt_access_enc_falls_back_to_admin_recovery(self):
        (self.tmp / "access.enc").write_bytes(b"garbage-not-an-envelope")
        (self.tmp / "access.json").unlink()
        self._start(restore_key=RESTORE)
        # Server is up and honest: friend cannot log in yet (no crash, 401).
        status, body, _ = self._req("GET", "/api/friend_blob")
        self.assertEqual(status, 200, body)
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 401, body)
        # The owner's login recovers the list from users.enc (master key)…
        status, body, admin_cookie = self._login(MASTER)
        self.assertEqual(status, 200, body)
        # …and repairs the restore-key mirror for the next restart.
        restored = decrypt_keys(self.tmp / "access.enc", RESTORE)
        self.assertIn(FRIEND1, restored)
        self.assertIn(FRIEND2, restored)
        status, body, cookie = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        self.__class__.friend_cookie = cookie

    def test_10_wrong_restore_key_falls_back_to_admin_recovery(self):
        (self.tmp / "access.json").unlink()
        self._start(restore_key="the-wrong-restore-key")
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 401, body)
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)

    def test_11_crypto_separation_is_preserved(self):
        # Fresh fixtures, independent of server state.
        unit = Path(tempfile.mkdtemp(prefix="nexus-test-crypto-"))
        try:
            access = {FRIEND1: _hash_pw(FRIEND1_PW)}
            encrypt_keys(access, RESTORE, unit / "access.enc")
            encrypt_keys({"groq": "sk-shared"}, MASTER, unit / "keys.enc")
            # The restore key opens ONLY the access list…
            self.assertEqual(decrypt_keys(unit / "access.enc", RESTORE), access)
            # …never the provider keys, and the master password never
            # substitutes for the restore key on the access mirror.
            with self.assertRaises(Exception):
                decrypt_keys(unit / "keys.enc", RESTORE)
            with self.assertRaises(Exception):
                decrypt_keys(unit / "access.enc", MASTER)
            with self.assertRaises(Exception):
                decrypt_keys(unit / "keys.enc", "any-other-password")
            # The mirror's bytes leak neither the password nor its hash.
            raw = (unit / "access.enc").read_text()
            self.assertNotIn(FRIEND1_PW, raw)
            self.assertNotIn(access[FRIEND1], raw)
        finally:
            shutil.rmtree(unit, ignore_errors=True)

    def test_12_no_restore_key_keeps_classic_admin_recovery(self):
        # Hosts without NEXUS_RESTORE_KEY keep the pre-existing behaviour:
        # friends wait for the first admin login, which restores the list
        # from users.enc — nothing crashes and nothing is bypassed.
        (self.tmp / "access.json").unlink()
        self._start(restore_key=None)
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 401, body)
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)


if __name__ == "__main__":
    unittest.main()
