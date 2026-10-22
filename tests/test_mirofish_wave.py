"""MiroFish suggestion wave (owner order 2026-10-23, all but #4):
1. PWA — /manifest.json + /sw.js + icons served, pages link the
   manifest and register the (pass-through, cache-nothing) worker.
2. Lane health strip — GET /api/lane-health (session-gated) reports a
   per-lane state derived from server state only: up / limited / down
   / off / locked.
3. Failover notice + 4. saved favourites — dashboard-side behaviour,
   pinned here at the served-HTML level (the notice derives from the
   already-persisted trace; favourites use localStorage).
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

MASTER = "miro-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "miro-restore"
STATES = {"up", "limited", "down", "off", "locked"}
KEYLESS = {"pollinations", "kilo", "ovh", "aihorde", "relay_pollinations"}


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


class MiroFishWave(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-miro-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl", "telemetry.enc"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys"):
                continue
            src = APP / name
            if src.is_dir():
                shutil.copytree(src, cls.tmp / name)
            elif name.endswith((".py", ".json", ".html", ".ico", ".svg",
                                ".png", ".js")):
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
        cls.proc = subprocess.Popen(
            [sys.executable, str(cls.tmp / "server.py")],
            cwd=str(cls.tmp), env=env,
            stdout=cls.log, stderr=subprocess.STDOUT)
        for _ in range(80):
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{cls.port}/health",
                        timeout=2) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("fixture server did not come up")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except Exception:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _call(self, method, path, body=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=30)
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path,
                     json.dumps(body) if body is not None else None,
                     headers)
        resp = conn.getresponse()
        raw = resp.read()
        hdrs = dict(resp.getheaders())
        conn.close()
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = None
        return resp.status, parsed, raw, hdrs

    def _login(self):
        st, j, _, hdrs = self._call("POST", "/api/login",
                                    {"password": FRIEND_PW})
        self.assertEqual(st, 200, str(j)[:200])
        return hdrs.get("Set-Cookie", "").split(";")[0]

    def test_01_manifest_served(self):
        st, j, _, hdrs = self._call("GET", "/manifest.json")
        self.assertEqual(st, 200)
        self.assertEqual(j["name"], "Nexus")
        self.assertEqual(j["start_url"], "/dashboard")
        sizes = {i["sizes"] for i in j["icons"]}
        self.assertIn("512x512", sizes)
        self.assertIn("192x192", sizes)

    def test_02_service_worker_is_pass_through(self):
        st, _, raw, hdrs = self._call("GET", "/sw.js")
        self.assertEqual(st, 200)
        body = raw.decode()
        self.assertIn("fetch(event.request)", body)
        self.assertNotIn("caches.open", body)
        self.assertEqual(hdrs.get("Cache-Control"), "no-cache")

    def test_03_pwa_icons_served(self):
        for path in ("/icon-192.png", "/icon-512.png"):
            st, _, raw, _ = self._call("GET", path)
            self.assertEqual(st, 200, path)
            self.assertTrue(raw.startswith(b"\x89PNG"), path)

    def test_04_lane_health_requires_session(self):
        st, _, _, _ = self._call("GET", "/api/lane-health")
        self.assertIn(st, (401, 403))

    def test_05_lane_health_shape_and_locked_states(self):
        cookie = self._login()
        st, j, _, _ = self._call("GET", "/api/lane-health", cookie=cookie)
        self.assertEqual(st, 200)
        lanes = j["lanes"]
        self.assertEqual(len(lanes), 23)
        for lane in lanes:
            self.assertIn(lane["state"], STATES, lane)
        # Fresh fixture: nobody unlocked the shared vault, so keyed
        # lanes report locked and keyless lanes report up.
        self.assertTrue(j["vault_locked"])
        by_name = {l["provider"]: l["state"] for l in lanes}
        for name in KEYLESS:
            self.assertEqual(by_name[name], "up", name)
        self.assertEqual(by_name["groq"], "locked")

    def test_06_pages_carry_pwa_and_wave_hooks(self):
        cookie = self._login()
        st, _, raw, _ = self._call("GET", "/dashboard", cookie=cookie)
        self.assertEqual(st, 200)
        html = raw.decode()
        self.assertIn('rel="manifest"', html)
        self.assertIn("serviceWorker.register('/sw.js')", html)
        self.assertIn('id="lane-strip"', html)
        self.assertIn("function failoverNotice", html)
        self.assertIn("nexus-fav-provider", html)
        st, _, raw, _ = self._call("GET", "/", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn('rel="manifest"', raw.decode())


if __name__ == "__main__":
    unittest.main()
