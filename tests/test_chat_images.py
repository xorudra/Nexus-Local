"""Chat image fixes (2026-10-10, owner report):
- An explicit Image-mode provider pick (Gemini) silently fell back to
  Pollinations when it could not produce an image. Explicit picks now
  fail honestly with the reason; substitution stays for Auto only.
- Saved chats replaced every data URI over 40k chars with a placeholder
  inside the markdown, so reopened chats showed raw broken markdown
  instead of the picture. Images up to 260k chars now persist (with a
  per-chat budget); oversized ones become a clean whole-image note.
- The dashboard retries hotlinked generated images that fail to load.
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

MASTER = "img-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "img-restore"


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


class _Client:
    def __init__(self, port):
        self.port = port
        self.cookie = ""

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        conn.request(method, path,
                     body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        sc = resp.getheader("Set-Cookie")
        if sc:
            self.cookie = sc.split(";")[0]
        conn.close()
        try:
            return resp.status, json.loads(raw)
        except Exception:
            return resp.status, {"_raw": raw}


class ChatImageFixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-imgtest-"))
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
        access = {"museai": _hash_pw(FRIEND_PW)}
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
        cls.friend = _Client(cls.port)
        st, j = cls.friend.call("POST", "/api/login", {"password": FRIEND_PW})
        assert st == 200 and j.get("ok"), f"friend login failed: {st} {j}"

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

    def test_01_explicit_google_pick_fails_honestly_no_substitution(self):
        st, j = self.friend.call("POST", "/api/chat", {
            "provider": "google", "model": "gemini-2.5-flash-image",
            "mode": "image", "message": "generate a cat"})
        # No Google key is reachable in this fixture: the answer must be
        # an honest error naming Google — never a Pollinations image.
        self.assertNotIn("reply", j)
        self.assertIn(st, (400, 502))
        err = j.get("error") or ""
        self.assertIn("Google", err)
        self.assertIn("substitut", err)

    def test_02_saved_chat_keeps_fitting_images_notes_oversized(self):
        small = "data:image/jpeg;base64," + "A" * 100000
        big = "data:image/png;base64," + "B" * 300000
        bare = "data:image/png;base64," + "C" * 5000
        msgs = [
            {"r": "user", "t": "make images"},
            {"r": "ai", "t": f"![Generated image]({small})"},
            {"r": "ai", "t": f"![Generated image]({big})"},
            {"r": "ai", "t": f"prefix {bare} suffix"},
        ]
        st, j = self.friend.call("POST", "/api/chats",
                                 {"action": "save", "title": "img rules",
                                  "messages": msgs})
        self.assertEqual(st, 200)
        cid = j.get("id")
        self.assertTrue(cid)
        st, j = self.friend.call("POST", "/api/chats",
                                 {"action": "get", "id": cid})
        self.assertEqual(st, 200)
        got = j["chat"]["messages"]
        # The 100k image survives intact.
        self.assertIn("A" * 1000, got[1]["t"])
        self.assertGreater(len(got[1]["t"]), 100000)
        # The 300k image becomes a clean note — no broken markdown,
        # no old placeholder text.
        self.assertIn("too large to keep in saved chats", got[2]["t"])
        self.assertNotIn("media too large to store", got[2]["t"])
        self.assertNotIn("](", got[2]["t"])
        self.assertNotIn("B" * 1000, got[2]["t"])
        # A small bare data URI survives too.
        self.assertIn("C" * 1000, got[3]["t"])

    def test_03_dashboard_retries_failed_hotlinked_images(self):
        st, j = self.friend.call("GET", "/")
        raw = j.get("_raw", "")
        if not raw:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
            conn.request("GET", "/", headers={"Cookie": self.friend.cookie})
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", "replace")
            conn.close()
        self.assertIn("function imgRetry", raw)
        self.assertIn('onerror="imgRetry(this)"', raw)


if __name__ == "__main__":
    unittest.main()
