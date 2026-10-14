#!/usr/bin/env python3
"""OAuth sign-in for Nexus (owner order 2026-10-15): Google/GitHub as an
alternative login. A provider's VERIFIED email is resolved against
admin-configured mappings (oauth_admin_emails -> owner,
oauth_links email -> existing friend label). Unlinked emails get no
session; OAuth never creates accounts and never unlocks the key vault.

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
import urllib.request
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))

os.environ.pop("NEXUS_RESTORE_KEY", None)  # never touch the real restore key

import server  # noqa: E402
from key_security import encrypt_keys  # noqa: E402

MASTER = "oauth-master-123"
FRIEND_PW = "oauthfriend-pass-123"
RESTORE = "oauth-restore"


def _hash_pw(pw):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 210000)
    return f"pbkdf2$210000${salt.hex()}${dk.hex()}"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self._settings = dict(server._SETTINGS)
        server._SETTINGS["oauth_admin_emails"] = ["owner@example.com"]
        server._SETTINGS["oauth_links"] = [
            {"email": "pal@example.com", "label": "friendone"},
            {"email": "ghost@example.com", "label": "nosuchuser"},
        ]

    def tearDown(self):
        server._SETTINGS.clear()
        server._SETTINGS.update(self._settings)

    def test_admin_email_resolves_to_owner(self):
        self.assertEqual(server._oauth_resolve("Owner@Example.com"),
                         ("admin", "Rudra"))

    def test_linked_friend_resolves(self):
        with mock.patch.object(server, "_load_access",
                               lambda: {"friendone": "hash"}):
            self.assertEqual(server._oauth_resolve("pal@example.com"),
                             ("friend", "friendone"))
            # Linked email whose label no longer exists -> no session.
            self.assertIsNone(server._oauth_resolve("ghost@example.com"))

    def test_unlinked_email_gets_nothing(self):
        self.assertIsNone(server._oauth_resolve("stranger@example.com"))
        self.assertIsNone(server._oauth_resolve(""))


class FetchEmailTests(unittest.TestCase):
    ENV = {"NEXUS_OAUTH_GOOGLE_ID": "gid", "NEXUS_OAUTH_GOOGLE_SECRET": "gsec",
           "NEXUS_OAUTH_GITHUB_ID": "hid", "NEXUS_OAUTH_GITHUB_SECRET": "hsec"}

    def test_google_requires_verified_email(self):
        calls = []

        def fake(url, data=None, headers=None, timeout=20):
            calls.append(url)
            if "oauth2.googleapis.com" in url:
                return {"access_token": "tok"}
            return {"email": "Person@Example.com", "email_verified": True,
                    "name": "Person"}

        with mock.patch.dict(os.environ, self.ENV):
            with mock.patch.object(server, "_oauth_http_json", fake):
                email, name = server._oauth_fetch_email(
                    "google", "code123", "https://x/api/oauth/google/callback")
        self.assertEqual(email, "person@example.com")
        self.assertEqual(name, "Person")

    def test_google_unverified_email_rejected(self):
        def fake(url, data=None, headers=None, timeout=20):
            if "oauth2.googleapis.com" in url:
                return {"access_token": "tok"}
            return {"email": "p@example.com", "email_verified": False}

        with mock.patch.dict(os.environ, self.ENV):
            with mock.patch.object(server, "_oauth_http_json", fake):
                with self.assertRaises(Exception):
                    server._oauth_fetch_email("google", "c", "https://x/cb")

    def test_github_picks_primary_verified_email(self):
        def fake(url, data=None, headers=None, timeout=20):
            if "access_token" in url:
                return {"access_token": "tok"}
            return [{"email": "second@example.com", "verified": True,
                     "primary": False},
                    {"email": "main@example.com", "verified": True,
                     "primary": True},
                    {"email": "unv@example.com", "verified": False,
                     "primary": False}]

        with mock.patch.dict(os.environ, self.ENV):
            with mock.patch.object(server, "_oauth_http_json", fake):
                email, _ = server._oauth_fetch_email(
                    "github", "code123", "https://x/api/oauth/github/callback")
        self.assertEqual(email, "main@example.com")

    def test_creds_come_from_env_only(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NEXUS_OAUTH_GOOGLE_ID", None)
            os.environ.pop("NEXUS_OAUTH_GOOGLE_SECRET", None)
            self.assertIsNone(server._oauth_creds("google"))
        with mock.patch.dict(os.environ, self.ENV):
            self.assertEqual(server._oauth_creds("github"), ("hid", "hsec"))


class SettingsValidationTests(unittest.TestCase):
    def test_oauth_settings_validate(self):
        clean, err = server._validate_settings_patch(
            {"oauth_admin_emails": ["Owner@Example.com"]})
        self.assertIsNone(err)
        self.assertEqual(clean["oauth_admin_emails"], ["owner@example.com"])
        clean, err = server._validate_settings_patch(
            {"oauth_links": [{"email": "a@b.com", "label": "friendone"}]})
        self.assertIsNone(err)
        self.assertEqual(clean["oauth_links"],
                         [{"email": "a@b.com", "label": "friendone"}])

    def test_oauth_settings_reject_bad_shapes(self):
        _c, err = server._validate_settings_patch(
            {"oauth_admin_emails": ["not-an-email"]})
        self.assertIsNotNone(err)
        _c, err = server._validate_settings_patch(
            {"oauth_links": [{"email": "a@b.com", "label": "bad label!"}]})
        self.assertIsNotNone(err)


class FrontendWiringTests(unittest.TestCase):
    def test_login_page_has_oauth_buttons_and_error(self):
        html = (APP / "login.html").read_text()
        self.assertIn('id="oauthGoogle"', html)
        self.assertIn('id="oauthGithub"', html)
        self.assertIn("/api/oauth/providers", html)
        self.assertIn("oauth_error", html)

    def test_integrations_page_has_oauth_card(self):
        html = (APP / "integrations.html").read_text()
        self.assertIn('id="st-oauth"', html)
        self.assertIn('id="btn-oauth"', html)
        self.assertIn("OAuth Sign-in", html)
        self.assertIn("/api/oauth/providers", html)

    def test_admin_console_has_oauth_fields(self):
        html = (APP / "admin.html").read_text()
        self.assertIn('id="oae"', html)
        self.assertIn('id="ofl"', html)
        self.assertIn("oauth_admin_emails", html)
        self.assertIn("oauth_links", html)


class _Client:
    def __init__(self, port):
        self.port = port
        self.cookies = {}

    def call(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Content-Type": "application/json"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if headers:
            h.update(headers)
        conn.request(method, path,
                     body=json.dumps(body) if body is not None else None,
                     headers=h)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        for hdr, val in resp.getheaders():
            if hdr.lower() == "set-cookie":
                pair = val.split(";")[0]
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if v:
                        self.cookies[k.strip()] = v.strip()
                    else:
                        self.cookies.pop(k.strip(), None)
        conn.close()
        try:
            return resp.status, json.loads(raw), resp.getheader("Location")
        except Exception:
            return resp.status, {"_raw": raw[:200]}, resp.getheader("Location")


class OAuthHttpTests(unittest.TestCase):
    """Fixture server with Google OAuth configured via env. The token
    exchange against the REAL provider with a fake code must fail
    closed: redirect to /login with an error, never a session."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-oauthtest-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl", "telemetry.enc"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys"):
                continue
            src = APP / name
            if src.is_dir():
                shutil.copytree(src, cls.tmp / name)
            elif name.endswith((".py", ".json", ".html", ".ico", ".svg", ".png")):
                shutil.copy(src, cls.tmp / name)
        access = {"friendone": _hash_pw(FRIEND_PW)}
        encrypt_keys({"groq": "sk-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        (cls.tmp / "userkeys").mkdir(exist_ok=True)
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({"HOST": "127.0.0.1", "PORT": str(cls.port),
                    "NEXUS_RELAY_PORT": str(_free_port()),
                    "NEXUS_RESTORE_KEY": RESTORE,
                    "NEXUS_OAUTH_GOOGLE_ID": "fixture-gid",
                    "NEXUS_OAUTH_GOOGLE_SECRET": "fixture-gsecret",
                    "PYTHONPATH": str(cls.tmp),
                    "no_proxy": "127.0.0.1,localhost",
                    "NO_PROXY": "127.0.0.1,localhost"})
        cls.log = open(cls.tmp / "server.log", "wb")
        cls.proc = subprocess.Popen([sys.executable, str(cls.tmp / "server.py")],
                                    cwd=str(cls.tmp), env=env,
                                    stdout=cls.log, stderr=subprocess.STDOUT)
        for _ in range(80):
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{cls.port}/health", timeout=3) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("fixture server did not start")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.proc.terminate()
            cls.proc.wait(timeout=10)
        except Exception:
            try:
                cls.proc.kill()
            except Exception:
                pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_providers_endpoint_reports_configuration(self):
        c = _Client(self.port)
        st, j, _loc = c.call("GET", "/api/oauth/providers")
        self.assertEqual(st, 200)
        self.assertTrue(j["google"])
        self.assertFalse(j["github"])

    def test_02_start_redirects_to_google_with_state(self):
        c = _Client(self.port)
        st, _j, loc = c.call("GET", "/api/oauth/google/start")
        self.assertEqual(st, 302)
        self.assertIn("accounts.google.com", loc)
        self.assertIn("client_id=fixture-gid", loc)
        import urllib.parse as _up
        self.assertIn("/api/oauth/google/callback", _up.unquote(loc))
        self.assertIn("state=", loc)
        self.assertIn("oauth_state", c.cookies)

    def test_03_github_not_configured_is_404(self):
        c = _Client(self.port)
        st, _j, _loc = c.call("GET", "/api/oauth/github/start")
        self.assertEqual(st, 404)

    def test_04_callback_state_mismatch_fails_closed(self):
        c = _Client(self.port)
        c.call("GET", "/api/oauth/google/start")
        st, _j, loc = c.call(
            "GET", "/api/oauth/google/callback?code=fake&state=WRONGSTATE")
        self.assertEqual(st, 302)
        self.assertIn("/login?oauth_error=", loc)
        self.assertNotIn("session", c.cookies)

    def test_05_callback_bad_code_fails_closed(self):
        c = _Client(self.port)
        c.call("GET", "/api/oauth/google/start")
        state = c.cookies.get("oauth_state", "")
        self.assertTrue(state)
        st, _j, loc = c.call(
            "GET", f"/api/oauth/google/callback?code=fakecode&state={state}")
        self.assertEqual(st, 302)
        self.assertIn("/login?oauth_error=", loc)
        self.assertNotIn("session", c.cookies)


if __name__ == "__main__":
    unittest.main()
