"""Public home page (owner order 2026-10-15: "a Home page like
other webs have", built after the supplied Aceternity Proactiv
template; owner order 2026-10-16: "make home page default page
of nexus"): GET / serves landing.html to EVERYONE — it is the
default page — and the app lives at GET /dashboard, session-
gated exactly as / was before. The page is pure presentation —
no data, no session — while everything real stays gated.

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

MASTER = "land-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "land-restore"


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


class LandingPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-land-"))
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

    def test_01_home_is_public(self):
        st, raw, _c, _l = self._raw("GET", "/home")
        self.assertEqual(st, 200)
        for marker in ("Chat with every AI,", "from one Nexus",
                       "Start chatting", 'href="/login"',
                       "One shared memory", "Automatic failover",
                       "Perfect set of tools", "An API of its own",
                       "Your providers,", "shot-frame",
                       "Frequently asked questions",
                       "Is Nexus free to use?"):
            self.assertIn(marker, raw, marker)

    def test_02_root_signed_out_gets_landing(self):
        st, raw, _c, loc = self._raw("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("from one Nexus", raw)
        self.assertNotIn("TASK COMPOSER", raw)
        self.assertEqual(loc, "")

    def test_03_root_signed_in_also_gets_landing(self):
        # The home page is the default page for everyone now
        # (owner order 2026-10-16); the app moved to /dashboard.
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw("GET", "/", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn("from one Nexus", raw)
        self.assertNotIn("TASK COMPOSER", raw)

    def test_05_dashboard_requires_login(self):
        st, _raw, _c, loc = self._raw("GET", "/dashboard")
        self.assertIn(st, (301, 302))
        self.assertIn("/login", loc)

    def test_06_dashboard_signed_in(self):
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw("GET", "/dashboard", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn("TASK COMPOSER", raw)
        self.assertNotIn("Start chatting", raw)

    def test_04_landing_leaks_no_data(self):
        # The public page must carry no usage, keys or chat content:
        # it is a static presentation page.
        st, raw, _c, _l = self._raw("GET", "/home")
        self.assertEqual(st, 200)
        for forbidden in ("combined-usage", "composer-message",
                          "key_full", "/api/chat"):
            self.assertNotIn(forbidden, raw, forbidden)


if __name__ == "__main__":
    unittest.main()
