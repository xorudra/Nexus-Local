"""Integrations connect system (owner order 2026-10-15): the
per-user integrations vault (workspace tools) and AI account
connections into the userkeys vault, plus the OpenAI/Anthropic
provider lanes. Every assertion is network-tolerant in the honest
direction: a FAKE key can never verify, whether the provider answers
401 or the network drops — so verified/ok must be False while the
save itself succeeds.

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

MASTER = "intgc-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "intgc-restore"


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


class IntegrationsConnect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-intgc-"))
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
        env.pop("NEXUS_INTG_GOOGLE_ID", None)
        env.pop("NEXUS_INTG_GOOGLE_SECRET", None)
        env.pop("NEXUS_INTG_ZOOM_ID", None)
        env.pop("NEXUS_INTG_ZOOM_SECRET", None)
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

    def _raw(self, method, path, cookie="", body=None, timeout=60):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
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

    def _intg(self, cookie, body):
        st, raw, _c, _l = self._raw("POST", "/api/integrations", cookie=cookie, body=body)
        return st, json.loads(raw)

    def test_01_status_shape(self):
        cookie = self._login(FRIEND_PW)
        st, j = self._intg(cookie, {"action": "status"})
        self.assertEqual(st, 200)
        self.assertFalse(j["unlocked"])
        self.assertFalse(j["google_configured"])
        self.assertFalse(j["zoom_configured"])
        for svc in ("gmail", "meet", "linear", "zoom", "notion", "jira"):
            self.assertIn(svc, j["services"])
            self.assertFalse(j["services"][svc]["connected"])
        for prov in ("openai", "anthropic", "google", "groq"):
            self.assertIn(prov, j["ai"])
            self.assertFalse(j["ai"][prov]["own"])
        self.assertTrue(j["ai"]["pollinations"]["keyless"])

    def test_02_unlock_wrong_then_right(self):
        cookie = self._login(FRIEND_PW)
        st, j = self._intg(cookie, {"action": "unlock", "password": "nope"})
        self.assertEqual(st, 401)
        st, j = self._intg(cookie, {"action": "unlock", "password": FRIEND_PW})
        self.assertEqual(st, 200)
        self.assertTrue(j["unlocked"])

    def test_03_tools_save_test_disconnect(self):
        cookie = self._login(FRIEND_PW)
        self._intg(cookie, {"action": "unlock", "password": FRIEND_PW})
        st, j = self._intg(cookie, {"action": "save", "service": "linear",
                                    "fields": {"api_key": "lin_api_fake_test"},
                                    "password": FRIEND_PW})
        self.assertEqual(st, 200)
        self.assertTrue(j["saved"])
        self.assertFalse(j["verified"])  # a fake key can never verify
        self.assertTrue(j["services"]["linear"]["connected"])
        st, j = self._intg(cookie, {"action": "test", "service": "linear"})
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        st, j = self._intg(cookie, {"action": "disconnect", "service": "linear",
                                    "password": FRIEND_PW})
        self.assertEqual(st, 200)
        self.assertFalse(j["services"]["linear"]["connected"])

    def test_04_chat_openai_without_key_is_honest(self):
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw(
            "POST", "/api/chat", cookie=cookie, timeout=120,
            body={"provider": "openai", "model": "gpt-5-mini", "message": "hi"})
        self.assertEqual(st, 200, raw[:200])
        trace = json.loads(raw).get("trace") or []
        self.assertTrue(trace)
        self.assertEqual(trace[0]["p"], "openai")
        self.assertFalse(trace[0]["ok"])
        self.assertIn("no key", trace[0]["e"])

    def test_05_ai_save_test_disconnect(self):
        cookie = self._login(FRIEND_PW)
        st, j = self._intg(cookie, {"action": "ai_save", "service": "openai",
                                    "api_key": "sk-fake-connect-test",
                                    "password": FRIEND_PW})
        self.assertEqual(st, 200)
        self.assertTrue(j["saved"])
        self.assertFalse(j["verified"])
        self.assertTrue(j["ai"]["openai"]["own"])
        # the saved value itself is never echoed back anywhere
        st, j = self._intg(cookie, {"action": "status"})
        self.assertNotIn("sk-fake-connect-test", json.dumps(j))
        st, j = self._intg(cookie, {"action": "ai_test", "service": "openai"})
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        st, j = self._intg(cookie, {"action": "ai_save", "service": "pollinations",
                                    "api_key": "x", "password": FRIEND_PW})
        self.assertEqual(st, 400)  # keyless lanes take no key
        st, j = self._intg(cookie, {"action": "ai_disconnect", "service": "openai",
                                    "password": FRIEND_PW})
        self.assertEqual(st, 200)
        self.assertFalse(j["ai"]["openai"]["own"])

    def test_06_admin_cannot_ai_save(self):
        cookie = self._login(MASTER)
        st, j = self._intg(cookie, {"action": "ai_save", "service": "openai",
                                    "api_key": "sk-fake", "password": MASTER})
        self.assertEqual(st, 403)

    def test_07_quotas_carry_the_new_lanes(self):
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw("GET", "/api/quotas", cookie=cookie)
        self.assertEqual(st, 200)
        names = {p["provider"] for p in json.loads(raw)["providers"]}
        self.assertIn("openai", names)
        self.assertIn("anthropic", names)

    def test_08_google_start_unconfigured_redirects_with_error(self):
        cookie = self._login(FRIEND_PW)
        st, _raw, _c, loc = self._raw("GET", "/api/integrations/google/start",
                                      cookie=cookie)
        self.assertEqual(st, 302)
        self.assertIn("/integrations?error=", loc)

    def test_09_jira_site_validation(self):
        cookie = self._login(FRIEND_PW)
        self._intg(cookie, {"action": "unlock", "password": FRIEND_PW})
        st, j = self._intg(cookie, {"action": "save", "service": "jira",
                                    "fields": {"site": "not a site",
                                               "email": "a@b.co", "token": "t"},
                                    "password": FRIEND_PW})
        self.assertEqual(st, 400)
        self.assertIn("atlassian", j["error"])


if __name__ == "__main__":
    unittest.main()
