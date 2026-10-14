"""Integrations page v2 (owner order 2026-10-15: the shadcndashboard
Integration snapshot, implemented for real, then re-aimed by the
owner at AI account connections): GET /integrations is session-gated
like /connections and renders two sections — AI accounts (ChatGPT,
Claude, Gemini and the rest of the provider roster to connect) and
Workspace tools (Gmail, Meet, Linear, Loom, Zoom, Mailchimp, Notion,
Trello, Jira plus the preserved OAuth Sign-in card) — wired to
POST /api/integrations. Endpoint behaviour lives in
test_integrations_connect.py.

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

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
sys.path.insert(0, str(APP))
from key_security import encrypt_keys  # noqa: E402

MASTER = "integ-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "integ-restore"


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


class IntegrationsPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-integ-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl", "telemetry.enc"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys", "userintegrations"):
                continue
            src = APP / name
            if src.is_dir():
                shutil.copytree(src, cls.tmp / name)
            elif name.endswith((".py", ".json", ".html", ".ico", ".svg", ".png")):
                shutil.copy(src, cls.tmp / name)
        access = {"museai": _hash_pw(FRIEND_PW)}
        encrypt_keys({"groq": "sk-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        (cls.tmp / "userkeys").mkdir(exist_ok=True)
        (cls.tmp / "userintegrations").mkdir(exist_ok=True)
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({"HOST": "127.0.0.1", "PORT": str(cls.port),
                    "NEXUS_RELAY_PORT": str(_free_port()),
                    "NEXUS_RESTORE_KEY": RESTORE,
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

    def _raw(self, method, path, cookie="", body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path,
                     body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        sc = resp.getheader("Set-Cookie") or ""
        loc = resp.getheader("Location") or ""
        conn.close()
        return resp.status, raw, sc.split(";")[0], loc

    def _login(self, password):
        st, raw, cookie, _ = self._raw("POST", "/api/login", body={"password": password})
        self.assertEqual(st, 200, raw[:200])
        self.assertTrue(json.loads(raw).get("ok"))
        return cookie

    def test_01_signed_out_redirects_to_login(self):
        st, _raw, _c, loc = self._raw("GET", "/integrations")
        self.assertIn(st, (301, 302))
        self.assertIn("/login", loc)

    def test_02_friend_gets_both_sections(self):
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw("GET", "/integrations", cookie=cookie)
        self.assertEqual(st, 200)
        # AI accounts are the main grid now (owner's correction).
        for marker in ("AI accounts", "aiGrid", "ChatGPT (OpenAI)",
                       "Claude (Anthropic)", "Gemini (Google)",
                       "AI_SERVICES", "/api/integrations"):
            self.assertIn(marker, raw, marker)
        # Workspace tools below, snapshot catalogue intact, OAuth
        # Sign-in card preserved from ce772de.
        for marker in ("Workspace tools", "Gmail", "Google Meet",
                       "Linear", "Loom", "Zoom", "Mailchimp", "Notion",
                       "Trello", "Jira", "OAuth Sign-in",
                       "Add New Integration"):
            self.assertIn(marker, raw, marker)

    def test_03_admin_gets_the_page_too(self):
        cookie = self._login(MASTER)
        st, raw, _c, _l = self._raw("GET", "/integrations", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn("AI accounts", raw)

    def test_04_sidebar_link_on_dashboard_and_connections(self):
        cookie = self._login(FRIEND_PW)
        for path in ("/", "/connections"):
            st, raw, _c, _l = self._raw("GET", path, cookie=cookie)
            self.assertEqual(st, 200, path)
            self.assertIn('href="/integrations"', raw, path)


if __name__ == "__main__":
    unittest.main()
