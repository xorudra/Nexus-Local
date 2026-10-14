"""Composer Trace (2026-10-14, owner order with the shadcn Trace
component doc): /api/chat reports a per-attempt trace — which
providers were tried, which failed (with the reason) and which
answered, each with its duration — the dashboard renders it as the
Trace card above the reply, and saved chats keep a strictly-shaped,
capped copy so reopened chats replay the same steps."""
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

MASTER = "trace-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "trace-restore"


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


class ChatTrace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-trace-"))
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

    def _call(self, method, path, body=None, cookie=""):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
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

    def test_01_chat_response_carries_attempt_trace(self):
        cookie = self._login(FRIEND_PW)
        # The fixture's groq key is fake, so a groq pick must either
        # fail over (trace: failure(s) then a success) or fail
        # entirely (trace: all failures) — the contract holds either
        # way, online or off.
        st, j, _ = self._call("POST", "/api/chat",
                              {"provider": "groq",
                               "model": "llama-3.3-70b-versatile",
                               "message": "Say hi in three words",
                               "mode": "chat"}, cookie=cookie)
        self.assertIn("trace", j)
        tr = j["trace"]
        self.assertIsInstance(tr, list)
        self.assertGreaterEqual(len(tr), 1)
        for step in tr:
            self.assertIn("p", step)
            self.assertIn("ok", step)
            self.assertIsInstance(step["ok"], bool)
            if "ms" in step:
                self.assertIsInstance(step["ms"], int)
                self.assertGreaterEqual(step["ms"], 0)
            if not step["ok"]:
                self.assertIn("e", step)
                self.assertLessEqual(len(step["e"]), 160)
        self.assertEqual(tr[0]["p"], "groq")
        self.assertFalse(tr[0]["ok"])  # the fake key can never answer
        if st == 200:
            self.assertTrue(tr[-1]["ok"])
            self.assertEqual(j["used_provider"], tr[-1]["p"])
        else:
            self.assertTrue(all(not s["ok"] for s in tr))
            self.assertIn("error", j)

    def test_02_trace_survives_chat_save_strictly_shaped(self):
        cookie = self._login(FRIEND_PW)
        long_err = "x" * 400
        msgs = [
            {"r": "user", "t": "hello"},
            {"r": "ai", "t": "hi there", "m": "FreeLLMAPI: Pollinations",
             "p": "pollinations",
             "tr": [{"p": "groq", "m": "llama", "ok": False, "ms": 812,
                     "e": long_err, "junk": "drop me"},
                    {"p": "pollinations", "m": "openai", "ok": True,
                     "ms": 2400},
                    "not-a-dict"]},
            # traces on user messages are dropped
            {"r": "user", "t": "again",
             "tr": [{"p": "groq", "ok": True}]},
        ]
        st, j, _ = self._call("POST", "/api/chats",
                              {"action": "save", "title": "trace test",
                               "messages": msgs}, cookie=cookie)
        self.assertEqual(st, 200, str(j)[:200])
        cid = j["id"]
        st, j, _ = self._call("POST", "/api/chats",
                              {"action": "get", "id": cid}, cookie=cookie)
        self.assertEqual(st, 200)
        saved = j["chat"]["messages"]
        ai = saved[1]
        self.assertIn("tr", ai)
        self.assertEqual(len(ai["tr"]), 2)  # the non-dict entry dropped
        first = ai["tr"][0]
        self.assertEqual(first["p"], "groq")
        self.assertEqual(first["ms"], 812)
        self.assertEqual(len(first["e"]), 160)  # error capped
        self.assertNotIn("junk", first)        # unknown fields dropped
        self.assertTrue(ai["tr"][1]["ok"])
        self.assertNotIn("tr", saved[2])        # user message: no trace

    def test_03_dashboard_has_the_trace_renderer(self):
        cookie = self._login(FRIEND_PW)
        st, j, _ = self._call("GET", "/", cookie=cookie)
        self.assertEqual(st, 200)
        html = j["_raw"]
        for token in ("function buildTrace", "function startLiveTrace",
                      "trace-line", "traceSummary"):
            self.assertIn(token, html)


if __name__ == "__main__":
    unittest.main()
