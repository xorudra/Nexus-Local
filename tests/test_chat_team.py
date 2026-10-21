"""Team mode (2026-10-21, owner order): /api/chat with mode="team"
runs the request down a fixed chain of role-assigned lanes —
Planner, Researcher, Analyst, Finisher — and returns the Finisher's
text with a per-stage trace whose entries carry the stage role.
The dashboard offers Team in the mode picker, and saved chats keep
the role on trace steps so reopened chats replay who did what."""
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

MASTER = "team-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "team-restore"
ROLES = ["planner", "researcher", "analyst", "finisher"]


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


class ChatTeam(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-team-"))
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

    def _call(self, method, path, body=None, cookie="", timeout=120):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=timeout)
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
        st, j, cookie = self._call("POST", "/api/login",
                                   {"password": password})
        self.assertEqual(st, 200, str(j)[:200])
        self.assertTrue(j.get("ok"))
        return cookie

    def test_01_team_mode_trace_contract(self):
        cookie = self._login(FRIEND_PW)
        # The fixture's only key is a fake groq key, so the chain
        # either stops honestly (502 with a planner-only failure
        # trace) or keyless lanes carry it through to a real reply —
        # the contract holds either way, online or off.
        st, j, _ = self._call("POST", "/api/chat",
                              {"provider": "groq",
                               "model": "llama-3.3-70b-versatile",
                               "message": "Plan a tiny birthday party",
                               "mode": "team"},
                              cookie=cookie, timeout=600)
        self.assertIn("trace", j)
        tr = j["trace"]
        self.assertIsInstance(tr, list)
        self.assertGreaterEqual(len(tr), 1)
        for step in tr:
            self.assertIn("p", step)
            self.assertIn("m", step)
            self.assertIn("role", step)
            self.assertIn(step["role"], ROLES)
            self.assertIsInstance(step["ok"], bool)
            self.assertIsInstance(step["ms"], int)
            self.assertGreaterEqual(step["ms"], 0)
            if not step["ok"]:
                self.assertIn("e", step)
                self.assertLessEqual(len(step["e"]), 160)
        # Stages never run backwards: role order is non-decreasing.
        order = [ROLES.index(s["role"]) for s in tr]
        self.assertEqual(order, sorted(order))
        if st == 200:
            self.assertIsInstance(j["reply"], str)
            self.assertIn("Team:", j["reply"])
            last = tr[-1]
            self.assertEqual(last["role"], "finisher")
            self.assertTrue(last["ok"])
            self.assertEqual(j["used_provider"], last["p"])
            self.assertEqual(j["used_model"], last["m"])
        else:
            self.assertIn("error", j)
            self.assertFalse(tr[-1]["ok"])

    def test_02_team_option_and_saved_role(self):
        cookie = self._login(FRIEND_PW)
        st, j, _ = self._call("GET", "/dashboard", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn('<option value="team">Team</option>', j["_raw"])
        msgs = [
            {"r": "user", "t": "hello"},
            {"r": "ai", "t": "hi there", "m": "Groq: llama",
             "p": "groq",
             "tr": [{"p": "groq", "m": "llama", "ok": True, "ms": 5,
                     "role": "planner"},
                    {"p": "google", "m": "gemini", "ok": True, "ms": 7,
                     "role": "finisher", "junk": "drop me"}]},
        ]
        st, j, _ = self._call("POST", "/api/chats",
                              {"action": "save", "title": "team test",
                               "messages": msgs}, cookie=cookie)
        self.assertEqual(st, 200, str(j)[:200])
        cid = j["id"]
        st, j, _ = self._call("POST", "/api/chats",
                              {"action": "get", "id": cid}, cookie=cookie)
        self.assertEqual(st, 200)
        saved = j["chat"]["messages"]
        tr = saved[1]["tr"]
        self.assertEqual([s["role"] for s in tr], ["planner", "finisher"])
        self.assertNotIn("junk", tr[1])


if __name__ == "__main__":
    unittest.main()
