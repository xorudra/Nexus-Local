#!/usr/bin/env python3
"""Wave-1 Launch Safety Standard fixes (2026-10-10) regression tests.

Covers: A5 SSRF validation of user-supplied provider/gateway URLs
(save-time in mykeys + guest /setup, and at provider registration),
A10 rate-limit ledgers keyed on the LAST X-Forwarded-For hop,
F29 per-user chat data export, F28 usage/audit purge on revoke,
F26 first-login terms notice, and the A1 dashboard escaping fixes
(source-level assertions — the renderer is browser JS).

Fixtures use only fake keys and throwaway passwords; no real secret is
read or printed anywhere in this file. Note: this sandbox's DNS maps
every hostname into a private fake-IP range, so URL-validation
positives use a literal public IP (8.8.8.8) — the same input class a
real deployment resolves public hostnames to.

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
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
from key_security import encrypt_keys  # noqa: E402
import server  # noqa: E402

MASTER = "test-master-password-123"
RESTORE = "test-restore-key-xyz"
FRIEND1 = "friendone"
FRIEND1_PW = "friend-one-pass"
FRIEND2 = "friendtwo"
FRIEND2_PW = "friend-two-pass"
PUBLIC_URL = "https://8.8.8.8:8443/v1"


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


class UrlGuardUnitTests(unittest.TestCase):
    def test_non_public_targets_rejected(self):
        for url in ("http://127.0.0.1:1234/v1", "http://localhost:3001",
                    "http://169.254.169.254/latest", "http://10.0.0.5/v1",
                    "https://192.168.1.1/v1", "https://[::1]/v1",
                    "http://example.com@127.0.0.1/", "https://svc.local/v1",
                    "ftp://example.com", "https://", "", None):
            self.assertFalse(server._public_base_url_ok(url), url)

    def test_public_literal_ip_accepted(self):
        self.assertTrue(server._public_base_url_ok(PUBLIC_URL))

    def test_registration_skips_non_public(self):
        keys = {
            "custom_relay_bad": "sk-bad",
            "custom_relay_bad_url": "http://127.0.0.1:9999/v1",
            "custom_relay_okp": "sk-ok",
            "custom_relay_okp_url": PUBLIC_URL,
        }
        try:
            server.register_custom_providers(keys)
            self.assertNotIn("bad", server.RELAY_UPSTREAMS)
            self.assertEqual(server.RELAY_UPSTREAMS.get("okp"), PUBLIC_URL)
        finally:
            server.RELAY_UPSTREAMS.pop("bad", None)
            server.RELAY_UPSTREAMS.pop("okp", None)


class DashboardEscapingSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (APP / "dashboard.html").read_text()

    def test_esc_escapes_quotes(self):
        self.assertIn('replace(/"/g,\'&quot;\')', self.html)

    def test_md_image_rule_rejects_quoted_urls(self):
        self.assertIn('&quot;', self.html)
        self.assertIn("return alt;", self.html)

    def test_showpreview_escapes_name_and_link(self):
        self.assertIn("File: ' + esc(name || 'File')", self.html)
        self.assertIn("esc(String(src).substring(0,50))", self.html)


class Harness:
    proc = None
    log = None

    @classmethod
    def build_tmp(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-wave1-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip or name == "chats":
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND1: _hash_pw(FRIEND1_PW), FRIEND2: _hash_pw(FRIEND2_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)

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
             raw=None, timeout=60):
        conn = http.client.HTTPConnection("127.0.0.1", cls.api_port,
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
        set_cookie = resp_headers.get("set-cookie", "")
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload.decode(errors="replace")[:300]}
        return (resp.status, parsed,
                set_cookie.split(";")[0] if set_cookie.startswith("session=") else None,
                resp_headers)

    @classmethod
    def _login(cls, password, headers=None):
        status, body, cookie, _ = cls._req("POST", "/api/login",
                                           {"password": password},
                                           headers=headers)
        return status, body, cookie


class Wave1ApiTests(Harness, unittest.TestCase):
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

    def test_01_mykeys_rejects_non_public_urls_accepts_public(self):
        status, body, _, _ = self._req("POST", "/api/mykeys", {
            "action": "save", "password": FRIEND1_PW,
            "keys": {"custom_relay_evil": "sk-x",
                     "custom_relay_evil_url": "http://127.0.0.1:9999/v1"}},
            cookie=self.friend_cookie)
        self.assertEqual(status, 400, body)
        status, body, _, _ = self._req("POST", "/api/mykeys", {
            "action": "save", "password": FRIEND1_PW,
            "keys": {"freellmapi_url": "http://169.254.169.254/"}},
            cookie=self.friend_cookie)
        self.assertEqual(status, 400, body)
        status, body, _, _ = self._req("POST", "/api/mykeys", {
            "action": "save", "password": FRIEND1_PW,
            "keys": {"custom_relay_okp": "sk-ok",
                     "custom_relay_okp_url": PUBLIC_URL}},
            cookie=self.friend_cookie)
        self.assertEqual(status, 200, body)
        self.assertIn("custom_relay_okp_url", body["configured"])

    def test_02_guest_setup_save_rejects_non_public_accepts_public(self):
        form = urllib.parse.urlencode({
            "password": FRIEND2_PW,
            "cr_name_0": "evil", "cr_key_0": "sk-x",
            "cr_url_0": "http://127.0.0.1:8080/v1"})
        status, body, _, _ = self._req(
            "POST", "/setup", raw=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 400, body)
        self.assertIn("public http", body.get("error", ""))
        form = urllib.parse.urlencode({
            "password": FRIEND2_PW,
            "cr_name_0": "okp", "cr_key_0": "sk-ok",
            "cr_url_0": PUBLIC_URL})
        status, body, cookie, hdrs = self._req(
            "POST", "/setup", raw=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 302, body)
        self.assertIsNotNone(cookie)  # guest save mints a session

    def test_03_chats_export_is_own_data_only(self):
        status, body, _, _ = self._req("POST", "/api/chats", {
            "action": "save",
            "messages": [{"r": "user", "t": "hello export marker"}]},
            cookie=self.friend_cookie)
        self.assertEqual(status, 200, body)
        status, body, _, hdrs = self._req("POST", "/api/chats",
                                          {"action": "export"},
                                          cookie=self.friend_cookie)
        self.assertEqual(status, 200, body)
        self.assertIn("attachment", hdrs.get("content-disposition", ""))
        self.assertIn("nexus-chats-friendone.json",
                      hdrs.get("content-disposition", ""))
        self.assertEqual(body["label"], FRIEND1)
        texts = [m["t"] for c in body["chats"] for m in c["messages"]]
        self.assertIn("hello export marker", texts)
        # The other friend's export holds only their own (empty) store.
        status, body2, cookie2 = self._login(FRIEND2_PW)
        self.assertEqual(status, 200, body2)
        status, body, _, _ = self._req("POST", "/api/chats",
                                       {"action": "export"}, cookie=cookie2)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["label"], FRIEND2)
        self.assertEqual(body["chats"], [])

    def test_04_login_ledger_keyed_on_last_xff_hop(self):
        xff_a = {"X-Forwarded-For": "203.0.113.9, 198.51.100.7"}
        codes = []
        for _ in range(11):
            status, _, _ = self._login("wrong-password-x", headers=xff_a)
            codes.append(status)
        self.assertTrue(all(c == 401 for c in codes[:10]), codes)
        self.assertEqual(codes[10], 429, codes)
        # A different LAST hop is a different ledger: not throttled.
        xff_b = {"X-Forwarded-For": "203.0.113.9, 198.51.100.8"}
        status, _, _ = self._login("wrong-password-x", headers=xff_b)
        self.assertEqual(status, 401)
        status, body, _ = self._login(FRIEND1_PW, headers=xff_b)
        self.assertEqual(status, 200, body)

    def test_05_revoke_purges_usage_and_audit_history(self):
        usage_rows = [
            {"ts": "2026-10-10T10:00:00", "provider": "groq",
             "user": FRIEND1, "prompt_tokens": 1, "completion_tokens": 2},
            {"ts": "2026-10-10T10:01:00", "provider": "groq",
             "user": FRIEND2, "prompt_tokens": 3, "completion_tokens": 4},
            {"ts": "2026-10-10T10:02:00", "provider": "v1:relay_groq",
             "prompt_tokens": 0, "completion_tokens": 0},
        ]
        (self.tmp / "usage.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in usage_rows))
        audit_rows = [
            {"ts": "2026-10-10T10:00:00", "cat": "System",
             "event": f"Signed in: {FRIEND1} (friend)"},
            {"ts": "2026-10-10T10:01:00", "cat": "System",
             "event": f"Signed in: {FRIEND2} (friend)"},
            {"ts": "2026-10-10T10:02:00", "cat": "Providers",
             "event": "groq marked down (circuit breaker, 3 min)"},
        ]
        (self.tmp / "audit.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in audit_rows))
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        status, body, _, _ = self._req("POST", "/api/access", {
            "action": "revoke", "label": FRIEND1, "master_pw": MASTER},
            cookie=admin)
        self.assertEqual(status, 200, body)
        usage_txt = (self.tmp / "usage.jsonl").read_text()
        self.assertNotIn(FRIEND1, usage_txt)
        self.assertIn(FRIEND2, usage_txt)
        self.assertIn("v1:relay_groq", usage_txt)
        audit_txt = (self.tmp / "audit.jsonl").read_text()
        self.assertNotIn(f"Signed in: {FRIEND1}", audit_txt)
        self.assertIn(f"Signed in: {FRIEND2}", audit_txt)
        self.assertIn("groq marked down", audit_txt)
        # The revoke itself stays on the admin record.
        self.assertIn(f"Friend revoked: {FRIEND1}", audit_txt)


class TermsNoticeTests(Harness, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp()
        cls._start()

    @classmethod
    def tearDownClass(cls):
        cls.teardown_tmp()

    def test_01_friend_sees_notice_once_and_it_is_audited(self):
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("terms_notice"), body)
        status, body, _ = self._login(FRIEND1_PW)
        self.assertEqual(status, 200, body)
        self.assertFalse(body.get("terms_notice"), body)
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        self.assertFalse(body.get("terms_notice"), body)
        status, body, _, _ = self._req("GET", "/api/audit", cookie=admin)
        self.assertEqual(status, 200, body)
        events = [e.get("event", "") for e in body.get("events", [])]
        self.assertIn(f"Terms notice shown: {FRIEND1}", events)


if __name__ == "__main__":
    unittest.main()
