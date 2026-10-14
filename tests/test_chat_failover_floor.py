"""Failover floor + live defaults (2026-10-15, owner screenshot):
an Auto (quality) request burned all 4 attempts — the OpenRouter
default model had been retired upstream (apodex -> 'Model not
found' on both OpenRouter lanes), Mistral was rate-limited, and
the Gemini default (gemini-3.8-flash) hung to the timeout — and
never reached a keyless lane. Fixes pinned here:

- the retired/hanging defaults are gone from the trace a live
  request produces (OpenRouter -> nemotron-3-super free, Gemini
  -> gemini-3.5-flash-lite, both live-proven 2026-10-15);
- the attempt slice always contains a keyless lane: with every
  keyed lane holding a fake key, Auto quality must swap its last
  slot to Pollinations instead of failing outright.
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

MASTER = "floor-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "floor-restore"
FAKE_KEYS = {name: "sk-fake" for name in (
    "groq", "openrouter", "mistral", "google", "cohere",
    "relay_openrouter", "relay_gemini", "relay_groq", "nvidia")}


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


class FailoverFloor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-floor-"))
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
        encrypt_keys(FAKE_KEYS, MASTER, cls.tmp / "keys.enc")
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

    def _call(self, method, path, body=None, cookie="", timeout=300):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path,
                     body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode()
        sc = resp.getheader("Set-Cookie") or ""
        conn.close()
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"_raw": raw}
        return resp.status, parsed, sc.split(";")[0]

    def _login(self, password):
        st, j, cookie = self._call("POST", "/api/login", {"password": password})
        self.assertEqual(st, 200, str(j)[:200])
        self.assertTrue(j.get("ok"))
        return cookie

    def test_01_auto_quality_floors_to_a_keyless_lane(self):
        self._login(MASTER)  # unlock the shared (all-fake) vault
        cookie = self._login(FRIEND_PW)
        st, j, _ = self._call("POST", "/api/chat",
                              {"provider": "auto", "model": "",
                               "message": "Say hi", "mode": "chat"},
                              cookie=cookie)
        tr = j.get("trace") or []
        self.assertGreaterEqual(len(tr), 2, str(j)[:300])
        # Quality order leads, with the LIVE default models.
        self.assertEqual(tr[0]["p"], "relay_openrouter")
        self.assertEqual(tr[0]["m"], "nvidia/nemotron-3-super-120b-a12b:free")
        for step in tr:
            self.assertNotIn("apodex", step.get("m") or "")
            self.assertNotIn("gemini-3.8", step.get("m") or "")
            if step["p"] in ("google", "relay_gemini"):
                self.assertEqual(step["m"], "gemini-3.5-flash-lite")
        # Every keyed lane holds a fake key, so the first three
        # attempts fail; the 4th slot must be the keyless floor.
        self.assertTrue(all(not s["ok"] for s in tr[:3]))
        if len(tr) >= 4:
            self.assertEqual(tr[3]["p"], "pollinations")
        if st == 200:
            self.assertEqual(j.get("used_provider"), "pollinations")


if __name__ == "__main__":
    unittest.main()
