#!/usr/bin/env python3
"""Profile page (owner order 2026-11-10): avatar upload + friend 2FA.

Friend 2FA reuses the admin's stdlib TOTP mechanism but is a SEPARATE
flow: it lives only on /profile and the /api/profile/* endpoints,
proved by the friend's own password. The admin /api-access page and
the admin 2fa_* actions are untouched and stay admin-only.

Boots a real server.py on a temp dir (test_console.py harness) with
throwaway fixtures only. Unittest style only.

Run:  python3 -m unittest tests.test_profile -v
"""

import base64
import datetime
import hashlib
import hmac as _hmac
import http.client
import io
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
from urllib.parse import urlparse, parse_qs

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
from key_security import decrypt_keys, encrypt_keys  # noqa: E402
import server as _server_mod  # noqa: E402  (unit tests for the replay guard)

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


def _totp_code(secret, when=None):
    """TOTP code for a base32 secret (same algorithm as server.py)."""
    t = int(time.time()) // 30 if when is None else when
    digest = _hmac.new(base64.b32decode(secret), struct.pack(">Q", t),
                       hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def _secret_from_otpauth(otpauth):
    return parse_qs(urlparse(otpauth).query)["secret"][0]


def _png_bytes(w=600, h=400, color="red", fmt="PNG"):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format=fmt)
    return buf.getvalue()


class ProfileTests(unittest.TestCase):
    proc = None
    log = None

    _spent_steps = set()  # TOTP steps already accepted by the server this run

    @classmethod
    def _code(cls, secret):
        """Code for a step the server has not accepted yet this run.
        The server burns each accepted 30-second step (replay guard),
        so two successful TOTP operations in the same step would
        refuse the second one — wait for the next boundary instead."""
        while True:
            step = int(time.time()) // 30
            if step not in cls._spent_steps:
                cls._spent_steps.add(step)
                return _totp_code(secret, step)
            time.sleep(30 - (time.time() % 30) + 0.3)


    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-profile-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys", "avatars"):
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND1: _hash_pw(FRIEND1_PW),
                  FRIEND2: _hash_pw(FRIEND2_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        (cls.tmp / "userkeys").mkdir(exist_ok=True)
        today = datetime.datetime.now().isoformat()
        with open(cls.tmp / "usage.jsonl", "w") as f:
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
        status, body, friend2 = cls._login(FRIEND2_PW)
        assert status == 200, body
        cls.friend2 = friend2

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
    def _req_raw(cls, method, path, raw, content_type, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=60)
        hdrs = {"Content-Type": content_type}
        if cookie:
            hdrs["Cookie"] = cookie
        conn.request(method, path, body=raw, headers=hdrs)
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

    @classmethod
    def _profile(cls, action, cookie, **extra):
        status, parsed, _, _ = cls._req(
            "POST", f"/api/profile/{action}", extra, cookie=cookie)
        return status, parsed

    # ---- baseline ----

    def test_01_status_baseline_and_page(self):
        status, j, _, _ = self._req("GET", "/profile", cookie=self.friend)
        self.assertEqual(status, 200)
        status, _, _, _ = self._req("GET", "/profile")
        self.assertEqual(status, 302)
        status, j = self._profile("status", self.friend)
        self.assertEqual(status, 200)
        self.assertEqual(j["label"], FRIEND1)
        self.assertFalse(j["admin"])
        self.assertFalse(j["twofa"])
        self.assertFalse(j["pending"])
        self.assertFalse(j["avatar"])
        # Admin sees their own (admin-flow) 2FA state here, not a
        # friend enrollment.
        status, j = self._profile("status", self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(j["admin"])
        self.assertFalse(j["twofa"])
        # Baseline: a friend without 2FA logs in exactly as before.
        status, body, _ = self._login(FRIEND2_PW)
        self.assertEqual(status, 200)
        self.assertNotIn("need_2fa", body)

    # ---- avatar ----

    def test_02_avatar_rejects_bad_uploads(self):
        # SVG is never accepted (content-type gate).
        status, j, _, _ = self._req_raw(
            "POST", "/api/profile/avatar",
            b"<svg xmlns='http://www.w3.org/2000/svg'></svg>",
            "image/svg+xml", cookie=self.friend)
        self.assertEqual(status, 400)
        # Wrong magic bytes under a PNG content-type.
        status, j, _, _ = self._req_raw(
            "POST", "/api/profile/avatar", b"not an image at all",
            "image/png", cookie=self.friend)
        self.assertEqual(status, 400)
        # Oversize (256 KB cap).
        status, j, _, _ = self._req_raw(
            "POST", "/api/profile/avatar", b"A" * (256 * 1024 + 1),
            "image/png", cookie=self.friend)
        self.assertEqual(status, 413)
        # Traversal in the fetch label is a 404, never a file read.
        status, _, _, _ = self._req("GET", "/avatar/..%2Fkeys.enc",
                                    cookie=self.friend)
        self.assertEqual(status, 404)
        status, _, _, _ = self._req("GET", "/avatar/..%2f..%2fkeys.enc",
                                    cookie=self.friend)
        self.assertEqual(status, 404)

    def test_03_avatar_upload_fetch_reset(self):
        # Logged-out fetch is 401.
        status, _, _, _ = self._req("GET", f"/avatar/{FRIEND1}")
        self.assertEqual(status, 401)
        # No avatar yet.
        status, _, _, _ = self._req("GET", f"/avatar/{FRIEND1}",
                                    cookie=self.friend)
        self.assertEqual(status, 404)
        # An 800x600 JPEG is accepted and served back as a pinned
        # image/png, square-cropped to 512x512.
        status, j, _, _ = self._req_raw(
            "POST", "/api/profile/avatar", _png_bytes(800, 600, fmt="JPEG"),
            "image/jpeg", cookie=self.friend)
        self.assertEqual(status, 200, j)
        status, _, hdrs, payload = self._req(
            "GET", f"/avatar/{FRIEND1}", cookie=self.friend)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs["content-type"], "image/png")
        self.assertTrue(payload[:8] == b"\x89PNG\r\n\x1a\n")
        from PIL import Image
        im = Image.open(io.BytesIO(payload))
        self.assertEqual(im.size, (512, 512))
        # Reset returns to the default (initials tile = 404).
        status, j = self._profile("avatar_reset", self.friend)
        self.assertEqual(status, 200, j)
        status, _, _, _ = self._req("GET", f"/avatar/{FRIEND1}",
                                    cookie=self.friend)
        self.assertEqual(status, 404)

    # ---- friend 2FA: enable / confirm / login ----

    def test_04_2fa_enable_confirm(self):
        # Admin 2FA actions stay admin-only: the admin flow is NOT
        # the friend flow, and friends never enroll through it.
        status, j = self._profile("2fa_enable", self.admin,
                                  password=MASTER)
        self.assertEqual(status, 403)
        # QR needs the password proof.
        status, j = self._profile("2fa_enable", self.friend,
                                  password=FRIEND1_PW)
        self.assertEqual(status, 200, j)
        self.assertIn("otpauth://totp/", j["otpauth"])
        secret = _secret_from_otpauth(j["otpauth"])
        status, j = self._profile("status", self.friend)
        self.assertTrue(j["pending"])
        self.assertFalse(j["twofa"])
        status, _, _, payload = self._req(
            "POST", "/api/profile/2fa_qr", {"password": "wrong-pass"},
            cookie=self.friend)
        self.assertEqual(status, 401)
        status, _, hdrs, payload = self._req(
            "POST", "/api/profile/2fa_qr", {"password": FRIEND1_PW},
            cookie=self.friend)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs["content-type"], "image/png")
        self.assertTrue(payload[:8] == b"\x89PNG\r\n\x1a\n")
        # Wrong code fails; the right code enables.
        wrong = "000000" if _totp_code(secret) != "000000" else "111111"
        status, j = self._profile("2fa_confirm", self.friend,
                                  password=FRIEND1_PW, code=wrong)
        self.assertEqual(status, 401)
        status, j = self._profile("2fa_confirm", self.friend,
                                  password=FRIEND1_PW,
                                  code=self._code(secret))
        self.assertEqual(status, 200, j)
        self.assertTrue(j["enabled"])
        status, j = self._profile("status", self.friend)
        self.assertTrue(j["twofa"])
        self.assertFalse(j["pending"])
        self.__class__._f1_secret = secret

    def test_05_login_requires_code_and_replay_fails(self):
        secret = self.__class__._f1_secret
        # Password alone now returns a pending token, not a session.
        status, body, headers, _ = self._req(
            "POST", "/api/login", {"password": FRIEND1_PW})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("need_2fa"))
        tmp = body["tmp"]
        self.assertNotIn("set-cookie", headers)
        # Wrong code fails.
        status, body, _, _ = self._req(
            "POST", "/api/login", {"tmp": tmp, "code": "000000"})
        self.assertEqual(status, 401)
        # The right code mints a session.
        code = self._code(secret)
        status, body, headers, _ = self._req(
            "POST", "/api/login", {"tmp": tmp, "code": code})
        self.assertEqual(status, 200, body)
        self.assertFalse(body.get("need_2fa"))
        self.assertIn("set-cookie", headers)
        # Replaying the same code with a fresh pending token fails:
        # the step was burned at the successful sign-in.
        status, body, _, _ = self._req(
            "POST", "/api/login", {"password": FRIEND1_PW})
        self.assertTrue(body.get("need_2fa"))
        status, body, _, _ = self._req(
            "POST", "/api/login", {"tmp": body["tmp"], "code": code})
        self.assertEqual(status, 401)

    # ---- session revocation on enable ----

    def test_06_enable_revokes_other_sessions(self):
        # Two live sessions for friendtwo; enabling 2FA from one
        # ends the other (the enrolling session stays alive).
        _, _, cookie_a = self._login(FRIEND2_PW)
        _, _, cookie_b = self._login(FRIEND2_PW)
        status, j = self._profile("status", cookie_a)
        self.assertEqual(status, 200)
        status, j = self._profile("2fa_enable", cookie_a,
                                  password=FRIEND2_PW)
        self.assertEqual(status, 200, j)
        secret = _secret_from_otpauth(j["otpauth"])
        status, j = self._profile("2fa_confirm", cookie_a,
                                  password=FRIEND2_PW,
                                  code=self._code(secret))
        self.assertEqual(status, 200, j)
        status, j = self._profile("status", cookie_b)
        self.assertEqual(status, 401)
        status, j = self._profile("status", cookie_a)
        self.assertEqual(status, 200)
        self.assertTrue(j["twofa"])
        # Clean up: disable again so later tests see a plain login.
        status, j = self._profile("2fa_disable", cookie_a,
                                  password=FRIEND2_PW,
                                  code=self._code(secret))
        self.assertEqual(status, 200, j)
        status, j = self._profile("status", cookie_a)
        self.assertFalse(j["twofa"])

    # ---- disable ----

    def test_07_disable_requires_password_and_code(self):
        secret = self.__class__._f1_secret
        status, j = self._profile("2fa_disable", self.friend,
                                  password="wrong-pass",
                                  code="123456")
        self.assertEqual(status, 401)
        wrong = "000000" if _totp_code(secret) != "000000" else "111111"
        status, j = self._profile("2fa_disable", self.friend,
                                  password=FRIEND1_PW, code=wrong)
        self.assertEqual(status, 401)
        status, j = self._profile("2fa_disable", self.friend,
                                  password=FRIEND1_PW,
                                  code=self._code(secret))
        self.assertEqual(status, 200, j)
        self.assertFalse(j["enabled"])
        status, j = self._profile("status", self.friend)
        self.assertFalse(j["twofa"])
        # Login is back to password-only.
        status, body, headers, _ = self._req(
            "POST", "/api/login", {"password": FRIEND1_PW})
        self.assertEqual(status, 200)
        self.assertNotIn("need_2fa", body)
        self.assertIn("set-cookie", headers)

    # ---- admin reset + isolation ----

    def test_08_admin_can_reset_friend_2fa(self):
        # Re-enable 2FA for friendone.
        status, j = self._profile("2fa_enable", self.friend,
                                  password=FRIEND1_PW)
        self.assertEqual(status, 200, j)
        secret = _secret_from_otpauth(j["otpauth"])
        status, j = self._profile("2fa_confirm", self.friend,
                                  password=FRIEND1_PW,
                                  code=self._code(secret))
        self.assertEqual(status, 200, j)
        # A friend cannot reset anyone's 2FA through the admin action.
        status, j = self._access("friend_reset_2fa", self.friend,
                                 master_pw=MASTER, label=FRIEND1)
        self.assertEqual(status, 403)
        # A moderator cannot either (owner-only recovery).
        status, j = self._access("friend_role_set", self.admin,
                                 master_pw=MASTER, label=FRIEND2,
                                 role="moderator")
        self.assertEqual(status, 200, j)
        _, _, mod = self._login(FRIEND2_PW)
        status, j = self._access("friend_reset_2fa", mod,
                                 master_pw=MASTER, label=FRIEND1)
        self.assertEqual(status, 403)
        # The owner resets it: sessions revoked, and the next
        # password sign-in clears the secret (no code asked).
        status, j = self._profile("status", self.friend)
        self.assertEqual(status, 200)
        status, j = self._access("friend_reset_2fa", self.admin,
                                 master_pw=MASTER, label=FRIEND1)
        self.assertEqual(status, 200, j)
        status, j = self._profile("status", self.friend)
        self.assertEqual(status, 401)
        status, body, headers, _ = self._req(
            "POST", "/api/login", {"password": FRIEND1_PW})
        self.assertEqual(status, 200, body)
        self.assertNotIn("need_2fa", body)
        self.assertIn("set-cookie", headers)
        # The reset consumed the flag: 2FA is really gone.
        status, j = self._profile(
            "status", headers.get("set-cookie", "").split(";")[0])
        self.assertEqual(status, 200)
        self.assertFalse(j["twofa"])

    def test_09_friend_2fa_does_not_leak_across_users(self):
        # friendone's 2FA (enabled, reset, gone) never changed
        # friendtwo's login.
        status, body, _, _ = self._req(
            "POST", "/api/login", {"password": FRIEND2_PW})
        self.assertEqual(status, 200)
        self.assertNotIn("need_2fa", body)
        # The secret never appears in the plaintext settings mirror:
        # enable 2FA for friendone, then save a provider key (which
        # rebuilds vault_meta from the vault WHILE it holds the
        # secret) — the mirror may list the provider, never the
        # underscore-prefixed internal key or its last-4.
        _, _, cookie1 = self._login(FRIEND1_PW)
        status, j = self._profile("2fa_enable", cookie1,
                                  password=FRIEND1_PW)
        self.assertEqual(status, 200, j)
        secret = _secret_from_otpauth(j["otpauth"])
        status, j = self._profile("2fa_confirm", cookie1,
                                  password=FRIEND1_PW,
                                  code=self._code(secret))
        self.assertEqual(status, 200, j)
        status, j, _, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND1_PW,
             "keys": {"groq": "sk-test-fake-key-12345"}, "remove": []},
            cookie=cookie1)
        self.assertEqual(status, 200, j)
        settings = json.loads((self.tmp / "settings.json").read_text())
        meta = (settings.get("vault_meta") or {}).get(FRIEND1) or []
        providers = [str(m.get("provider", "")) for m in meta]
        self.assertIn("groq", providers)
        self.assertTrue(all(not p.startswith("_") for p in providers),
                        providers)
        self.assertNotIn(secret[-4:], json.dumps(meta))
        # Clean up: disable again.
        status, j = self._profile("2fa_disable", cookie1,
                                  password=FRIEND1_PW,
                                  code=self._code(secret))
        self.assertEqual(status, 200, j)

    # ---- unit tests: per-label replay guard + avatar helpers ----

    def test_10_per_label_replay_guard_and_avatar_helpers(self):
        # One label burning a step must not burn another label's.
        _server_mod._TOTP_LAST_STEPS.clear()
        _server_mod._totp_burn_step(FRIEND1, 100)
        self.assertTrue(_server_mod._totp_step_used(FRIEND1, 100))
        self.assertTrue(_server_mod._totp_step_used(FRIEND1, 99))
        self.assertFalse(_server_mod._totp_step_used(FRIEND2, 100))
        self.assertFalse(_server_mod._totp_step_used("Rudra", 100))
        _server_mod._totp_burn_step(FRIEND2, 100)
        self.assertTrue(_server_mod._totp_step_used(FRIEND2, 100))
        self.assertTrue(_server_mod._totp_step_used(FRIEND1, 100))
        self.assertFalse(_server_mod._totp_step_used("Rudra", 100))
        # Avatar filenames are label-derived only: traversal input
        # collapses to a safe name inside the avatars dir.
        p = _server_mod._avatar_path("../../etc/passwd")
        self.assertEqual(p.parent, _server_mod.AVATARS_DIR)
        self.assertNotIn("..", p.name)
        self.assertEqual(p.name, "etcpasswd.png")
        # Avatar processing: SVG / garbage / oversize rejected, a
        # 1000x500 PNG normalises to a 512x512 PNG with no EXIF.
        with self.assertRaises(ValueError):
            _server_mod._process_avatar(b"<svg></svg>")
        with self.assertRaises(ValueError):
            _server_mod._process_avatar(b"garbage")
        with self.assertRaises(ValueError):
            _server_mod._process_avatar(b"A" * (256 * 1024 + 1))
        out = _server_mod._process_avatar(_png_bytes(1000, 800))
        self.assertTrue(out[:8] == b"\x89PNG\r\n\x1a\n")
        from PIL import Image
        im = Image.open(io.BytesIO(out))
        self.assertEqual(im.size, (512, 512))
        self.assertIsNone(im.info.get("exif"))
        out_jpeg = _server_mod._process_avatar(_png_bytes(fmt="JPEG"))
        self.assertTrue(out_jpeg[:8] == b"\x89PNG\r\n\x1a\n")


if __name__ == "__main__":
    unittest.main()
