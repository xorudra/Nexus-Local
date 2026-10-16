#!/usr/bin/env python3
"""Regression tests for the 2026-10-16 security-audit fixes (run-1):
invite redemption race, friend_blob authentication, 2FA QR proof gate,
password-collision fail-closed login, My Keys blank-keeps semantics,
SSRF validators, rate-limit pruning, strict friend chat loading, and
the Mailchimp data-centre validation.

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
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))

os.environ.pop("NEXUS_RESTORE_KEY", None)

from key_security import encrypt_keys  # noqa: E402
import server  # noqa: E402

MASTER = "audit-master-123"
RESTORE = "audit-restore-key"
SYNC_TOKEN = "audit-sync-token-fixture"
SHARED_PW = "shared-password-1"
UNIQUE_PW = "unique-password-9"
FRIEND = "friendone"
FRIEND_PW = "friend-one-pass"


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


MASTER_B = "audit-master-456"


class ValidatorUnitTests(unittest.TestCase):
    def test_webhook_url_ok_rejects_encoded_and_literal_internal(self):
        for url in ("http://2130706433/hook", "http://0x7f000001/hook",
                    "http://127.0.0.1/hook", "http://localhost/hook",
                    "http://[::1]/hook", "ftp://example.com/hook",
                    "http://10.0.0.5/hook", "http://192.168.1.1/hook"):
            self.assertFalse(server._webhook_url_ok(url), url)

    def test_safe_url_rejects_non_http_and_internal(self):
        for url in ("file:///etc/passwd", "gopher://example.com/",
                    "http://127.0.0.1:8100/", "http://localhost/",
                    "http://[::1]/", "", "https://10.1.2.3/x"):
            self.assertFalse(server._safe_url(url), url)

    def test_password_taken(self):
        access = {"aa": server._hash_password("pw-alpha-111"),
                  "bb": server._hash_password("pw-beta-2222")}
        self.assertTrue(server._password_taken(access, "pw-alpha-111"))
        self.assertTrue(server._password_taken(access, "pw-beta-2222"))
        self.assertFalse(server._password_taken(access, "pw-alpha-111",
                                                 skip_label="aa"))
        self.assertFalse(server._password_taken(access, "pw-gamma-333"))

    def test_rl_prune_keeps_active_buckets(self):
        saved = dict(server._RL)
        try:
            server._RL.clear()
            now = time.time()
            server._RL[("chat", "active-label")] = [now]
            for i in range(5001):
                server._RL[("old", f"k{i}")] = [now - 5000]
            self.assertTrue(server._rl_ok("fresh", "newkey", 5, 60))
            # The active window survives; expired keys are pruned.
            self.assertIn(("chat", "active-label"), server._RL)
            self.assertLessEqual(len(server._RL), 5001)
        finally:
            server._RL.clear()
            server._RL.update(saved)

    def test_load_chats_strict(self):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-chats-"))
        old = server.CHATS_DIR
        server.CHATS_DIR = tmp
        try:
            self.assertEqual(server._load_chats_strict("ghost", "pw"),
                             {"chats": []})
            server._save_chats("friendx", {"chats": [{"id": "1"}]}, "pw-one")
            got = server._load_chats_strict("friendx", "pw-one")
            self.assertEqual(got["chats"][0]["id"], "1")
            with self.assertRaises(Exception):
                server._load_chats_strict("friendx", "pw-two")
        finally:
            server.CHATS_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mailchimp_dc_validation(self):
        calls = []
        orig = server._intg_http

        def fake(url, method, headers):
            calls.append(url)
            return 200, {"total_items": 2}
        server._intg_http = fake
        try:
            ok, acct, _ = server._intg_test_mailchimp(
                {"api_key": "deadbeef-us21"})
            self.assertTrue(ok)
            self.assertTrue(calls[0].startswith(
                "https://us21.api.mailchimp.com/"), calls[0])
            for hostile in ("x-127.0.0.1:8080/evil", "x-us21.evil.com",
                            "x-../../etc", "nodc"):
                ok2, _, _ = server._intg_test_mailchimp(
                    {"api_key": hostile})
                self.assertFalse(ok2, hostile)
            self.assertEqual(len(calls), 1)  # hostile keys never fetched
        finally:
            server._intg_http = orig


class AuditFixHarness(unittest.TestCase):
    """ Boots a fixture server (same pattern as test_hardening). """
    proc = None
    log = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-audit-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip or name == "chats":
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND: _hash_pw(FRIEND_PW),
                  "sharer1": _hash_pw(SHARED_PW),
                  "sharer2": _hash_pw(SHARED_PW),
                  "solo": _hash_pw(UNIQUE_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1", "PORT": str(cls.port),
            "NEXUS_RELAY_PORT": str(_free_port()),
            "NEXUS_RESTORE_KEY": RESTORE,
            "NEXUS_SYNC_TOKEN": SYNC_TOKEN,
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
                raise RuntimeError("server exited early:\n"
                                   + (cls.tmp / "server.log").read_text(
                                       errors="replace")[-2000:])
            try:
                status, _, _ = cls._req("GET", "/api/friend_blob")
                if status in (200, 403):
                    return
            except OSError:
                pass
            time.sleep(0.25)
        raise RuntimeError("server did not come up in 30s")

    @classmethod
    def tearDownClass(cls):
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
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _req(cls, method, path, body=None, ck=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        hdrs = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body)
            hdrs.setdefault("Content-Type", "application/json")
        if ck:
            hdrs["Cookie"] = ck
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        set_cookie = resp.getheader("Set-Cookie") or ""
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload.decode(errors="replace")[:300]}
        return (resp.status, parsed,
                set_cookie.split(";")[0]
                if set_cookie.startswith("session=") else None)

    @classmethod
    def _login(cls, password):
        return cls._req("POST", "/api/login", {"password": password})

    # -- friend_blob auth (finding: unauthenticated vault export) -----
    def test_01_friend_blob_requires_auth(self):
        status, _, _ = self._req("GET", "/api/friend_blob")
        self.assertEqual(status, 403)
        status, _, _ = self._req("GET", "/api/friend_blob",
                                 headers={"X-Sync-Token": "wrong-token"})
        self.assertEqual(status, 403)
        status, body, _ = self._req("GET", "/api/friend_blob",
                                    headers={"X-Sync-Token": SYNC_TOKEN})
        self.assertEqual(status, 200)
        self.assertIn("blob", body)

    # -- 2FA QR: GET discloses nothing any more ------------------------
    def test_02_2fa_qr_get_is_405(self):
        status, _, _ = self._req("GET", "/api/2fa_qr")
        self.assertEqual(status, 405)
        _, _, admin_cookie = self._login(MASTER)
        status, _, _ = self._req("GET", "/api/2fa_qr", ck=admin_cookie)
        self.assertEqual(status, 405)
        # POST without the master password proof is refused too.
        status, _, _ = self._req("POST", "/api/2fa_qr",
                                 {"master_pw": "not-the-master"},
                                 ck=admin_cookie)
        self.assertEqual(status, 401)

    # -- shared passwords fail closed (login confusion) ---------------
    def test_03_shared_password_login_fails_closed(self):
        status, body, _ = self._login(SHARED_PW)
        self.assertEqual(status, 401, body)
        status, body, cookie = self._login(UNIQUE_PW)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("label"), "solo")
        # …and a console add reusing a taken password is refused.
        _, _, admin_cookie = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "add", "label": "newbie", "password": SHARED_PW,
             "master_pw": MASTER}, ck=admin_cookie)
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))

    # -- invite race: one code, many parallel redeems -----------------
    def test_04_invite_redeem_is_atomic(self):
        _, _, admin_cookie = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "invite_create", "role": "friend", "days": 7,
             "master_pw": MASTER}, ck=admin_cookie)
        self.assertEqual(status, 200, body)
        code = body["code"]
        results = {}

        def redeem(i):
            results[i] = self._req(
                "POST", "/api/invite/redeem",
                {"label": f"racer{i}", "password": f"racer-pass-{i}-xyz",
                 "code": code})[0]
        # 4 racers (not 8): the endpoint's per-IP budget is 10/15 min
        # and the later wave-2 tests redeem from the same fixture IP.
        threads = [threading.Thread(target=redeem, args=(i,))
                   for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wins = [s for s in results.values() if s == 200]
        self.assertEqual(len(wins), 1, results)
        self.assertEqual([s for s in results.values() if s == 400].__len__(), 3,
                         results)
        access = json.loads((self.tmp / "access.json").read_text())
        racers = [k for k in access if k.startswith("racer")]
        self.assertEqual(len(racers), 1, racers)

    # -- My Keys: blank keeps, removal is explicit ---------------------
    def test_05_mykeys_blank_keeps_and_remove_deletes(self):
        _, _, cookie = self._login(FRIEND_PW)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "sk-fixture-one"}}, ck=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "", "google": "google-fixture-key"}},
            ck=cookie)
        self.assertEqual(status, 200, body)
        _, body, _ = self._req("POST", "/api/mykeys", {"action": "view"},
                               ck=cookie)
        self.assertIn("groq", body["configured"])   # blank kept it
        self.assertIn("google", body["configured"])
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW, "keys": {},
             "remove": ["groq"]}, ck=cookie)
        self.assertEqual(status, 200, body)
        _, body, _ = self._req("POST", "/api/mykeys", {"action": "view"},
                               ck=cookie)
        self.assertNotIn("groq", body["configured"])  # explicit removal
        self.assertIn("google", body["configured"])

    # ================= wave 2 (run-2 fixes) =================

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _invite(self, admin_cookie):
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend", "days": 7,
             "master_pw": MASTER}, admin_cookie)
        self.assertEqual(status, 200, body)
        return body["code"]

    # -- R2-5: a friend password must never equal the master ----------
    def test_06_master_password_collision_refused(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "add", "label": "collide1", "password": MASTER,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))
        code = self._invite(admin)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "collide2", "password": MASTER, "code": code})
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))
        # The refused redemption did not consume the invite.
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "collide2", "password": "collide-two-pass",
             "code": code})
        self.assertEqual(status, 200, body)
        # Password reset onto the master is refused the same way.
        status, body, _ = self._access(
            {"action": "friend_reset_pw", "label": FRIEND,
             "new_password": MASTER, "master_pw": MASTER}, admin)
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))
        # And the reverse: the master may not rotate onto a friend's.
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER,
             "new_master_pw": FRIEND_PW}, admin)
        self.assertEqual(status, 400, body)

    # -- R2-6/R2-7: no password oracle before invite validation;
    #    reserved labels are not registrable ---------------------------
    def test_07_invite_oracle_closed_and_reserved_labels(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "oracle1", "password": SHARED_PW,
             "code": "bogus-code-000000"})
        self.assertEqual(status, 400, body)
        self.assertIn("invite code is invalid", body.get("error", ""))
        self.assertNotIn("already in use", body.get("error", ""))
        code = self._invite(admin)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "_owner", "password": "owner-pass-123",
             "code": code})
        self.assertEqual(status, 400, body)
        self.assertIn("reserved", body.get("error", ""))
        # The reserved-label refusal did not consume the invite either.
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "invitedpal", "password": "invited-pass-1",
             "code": code})
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "add", "label": "_sys", "password": "sys-pass-123",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 400, body)

    # -- R2-10: provider governance binds transcription ---------------
    def test_08_transcribe_refused_when_groq_disabled(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_disabled": ["groq"]}}, admin)
        self.assertEqual(status, 200, body)
        try:
            _, _, cookie = self._login(UNIQUE_PW)
            status, body, _ = self._req(
                "POST", "/api/transcribe",
                {"audio": "data:audio/webm;base64,AAAA"}, ck=cookie)
            self.assertEqual(status, 403, body)
            self.assertIn("disabled", body.get("error", ""))
        finally:
            self._access(
                {"action": "settings_set", "master_pw": MASTER,
                 "patch": {"provider_disabled": []}}, admin)

    # -- R2-12: revoke scrubs settings-resident per-user state --------
    def test_09_revoke_scrubs_settings_state(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "add", "label": "scrubme",
             "password": "scrub-pass-123", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        self._login("scrub-pass-123")  # records terms_seen for scrubme
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"user_caps": {"scrubme": 5},
                       "suspended": ["scrubme"],
                       "oauth_links": [{"email": "scrub@example.co",
                                        "label": "scrubme"}]}}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "revoke", "label": "scrubme",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        saved = json.loads((self.tmp / "settings.json").read_text())
        self.assertNotIn("scrubme", saved.get("user_caps") or {})
        self.assertNotIn("scrubme", saved.get("suspended") or [])
        self.assertNotIn("scrubme", saved.get("terms_seen") or [])
        self.assertFalse(any(
            e.get("label") == "scrubme"
            for e in (saved.get("oauth_links") or [])
            if isinstance(e, dict)))
        # A re-created label starts clean.
        status, body, _ = self._access(
            {"action": "add", "label": "scrubme",
             "password": "scrub-pass-456", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access({"action": "list"}, admin)
        row = [a for a in body["access"] if a["label"] == "scrubme"]
        self.assertEqual(len(row), 1)
        self.assertFalse(row[0]["suspended"])
        self.assertIsNone(row[0]["cap"])
        self._access({"action": "revoke", "label": "scrubme",
                      "master_pw": MASTER}, admin)

    # -- R2-8: master rotation carries the owner integrations vault --
    def test_10_change_master_carries_owner_integrations(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "save", "service": "mailchimp",
             "fields": {"api_key": "fixturekey-us21"},
             "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER,
             "new_master_pw": MASTER_B}, admin)
        self.assertEqual(status, 200, body)
        _, _, admin_b = self._login(MASTER_B)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER_B}, ck=admin_b)
        self.assertEqual(status, 200, body)
        self.assertIn("mailchimp", json.dumps(body))
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin_b)
        self.assertEqual(status, 401, body)
        # Rotate back for the rest of the class.
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER_B,
             "new_master_pw": MASTER}, admin_b)
        self.assertEqual(status, 200, body)
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        self.assertIn("mailchimp", json.dumps(body))

    # -- R2-8b: save paths refuse a corrupt vault, never overwrite ----
    def test_11_strict_vault_saves_refuse_corruption(self):
        _, _, cookie = self._login(FRIEND_PW)
        upath = self.tmp / "userkeys" / f"{FRIEND}.enc"
        orig = upath.read_bytes()
        upath.write_bytes(b"garbage-not-a-vault")
        try:
            status, body, _ = self._req(
                "POST", "/api/mykeys",
                {"action": "save", "password": FRIEND_PW,
                 "keys": {"groq": "sk-should-not-land"}}, ck=cookie)
            self.assertEqual(status, 500, body)
            self.assertEqual(upath.read_bytes(), b"garbage-not-a-vault")
        finally:
            upath.write_bytes(orig)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "sk-fixture-restored"}}, ck=cookie)
        self.assertEqual(status, 200, body)
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        ipath = self.tmp / "userintegrations" / "_owner.enc"
        iorig = ipath.read_bytes()
        ipath.write_bytes(b"garbage-not-a-vault")
        try:
            status, body, _ = self._req(
                "POST", "/api/integrations",
                {"action": "save", "service": "mailchimp",
                 "fields": {"api_key": "otherkey-us21"},
                 "password": MASTER}, ck=admin)
            self.assertEqual(status, 500, body)
            self.assertEqual(ipath.read_bytes(), b"garbage-not-a-vault")
        finally:
            ipath.write_bytes(iorig)

    # -- R2-4: the QR encodes THIS enrollment's pending secret --------
    def test_12_qr_encodes_the_pending_secret(self):
        _, _, admin = self._login(MASTER)

        def _qr_png():
            conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                              timeout=30)
            conn.request("POST", "/api/2fa_qr",
                         body=json.dumps({"master_pw": MASTER}),
                         headers={"Content-Type": "application/json",
                                  "Cookie": admin})
            resp = conn.getresponse()
            png = resp.read()
            ctype = resp.getheader("Content-Type") or ""
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIn("image/png", ctype)
            return png

        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret1 = body["secret"]
        png1 = _qr_png()
        # Re-enabling replaces the pending secret (no code needed while
        # still pending) — the second QR must encode the NEW secret.
        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret2 = body["secret"]
        self.assertNotEqual(secret1, secret2)
        png2 = _qr_png()
        # The wave-1 defect encoded a constant string, so both QRs were
        # identical. Different pending secrets must give different QRs.
        self.assertNotEqual(png1, png2)
        # Clean up: confirm + disable the second enrollment.
        status, body, _ = self._access(
            {"action": "2fa_confirm", "master_pw": MASTER,
             "code": _totp(secret2)}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "2fa_disable", "master_pw": MASTER,
             "code": _totp(secret2, 1)}, admin)
        self.assertEqual(status, 200, body)

    # -- R2-14: factory reset wipes usage + the telemetry mirror ------
    def test_99_factory_reset_wipes_usage_and_telemetry(self):
        usage = self.tmp / "usage.jsonl"
        usage.write_text('{"provider": "groq", "user": "solo"}\n')
        tele = self.tmp / "telemetry.enc"
        tele.write_bytes(b"pretend-mirror-bytes")
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "factory_reset", "master_pw": MASTER,
             "confirm": "RESET"}, admin)
        self.assertEqual(status, 200, body)
        self.assertEqual(usage.read_text(), "")
        self.assertFalse(tele.exists())


if __name__ == "__main__":
    unittest.main()
