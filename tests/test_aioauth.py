"""AI account sign-ins (owner order 2026-10-15, OmniRoute-style):
Codex / Claude Code / Gemini CLI OAuth connections. A planted vault
carries FAKE tokens, so every provider call must fail honestly (the
trace names the lane and the sign-in rejection) while all the local
machinery — start redirects, status flags, static model lists,
paste guards, disconnect persistence — works for real.

Run:  python3 -m unittest discover -s tests -v
"""
import base64
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

MASTER = "aio-master-123"
FRIEND_PW = "museai-pass-123"
RESTORE = "aio-restore"


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


class AiOauth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-aio-"))
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
        future = int(time.time()) + 3600
        tok = {"access": "fake-token", "refresh": "fake-refresh",
               "expires": future, "email": "pal@example.com",
               "account_id": "acct-1", "project": "proj-1"}
        planted = {"ai_oauth": {"codex": dict(tok),
                                "claude_oauth": dict(tok),
                                "gemini_cli": dict(tok)}}
        encrypt_keys(planted, FRIEND_PW,
                     cls.tmp / "userintegrations" / "museai.enc")
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
        st, raw, cookie, _ = self._raw("POST", "/api/login",
                                       body={"password": password})
        self.assertEqual(st, 200, raw[:200])
        self.assertTrue(json.loads(raw).get("ok"))
        return cookie

    def _intg(self, cookie, body):
        st, raw, _c, _l = self._raw("POST", "/api/integrations",
                                    cookie=cookie, body=body)
        return st, json.loads(raw)

    def test_01_start_redirects(self):
        cookie = self._login(FRIEND_PW)
        st, _r, sc, loc = self._raw(
            "GET", "/api/integrations/aioauth/codex/start", cookie=cookie)
        self.assertEqual(st, 302)
        self.assertIn("auth.openai.com/oauth/authorize", loc)
        self.assertIn("app_EMoamEEZ73f0CkXaXp7hrann", loc)
        self.assertIn("localhost%3A1455", loc)
        self.assertTrue(sc.startswith("aio_state=codex:"))
        st, _r, sc, loc = self._raw(
            "GET", "/api/integrations/aioauth/claude_oauth/start",
            cookie=cookie)
        self.assertEqual(st, 302)
        self.assertIn("claude.ai/oauth/authorize", loc)
        self.assertIn("9d1c250a-e61b-44d9-88ed-5944d1962f5e", loc)
        self.assertTrue(sc.startswith("aio_state=claude_oauth:"))
        st, _r, sc, loc = self._raw(
            "GET", "/api/integrations/aioauth/gemini_cli/start", cookie=cookie)
        self.assertEqual(st, 302)
        self.assertIn("accounts.google.com", loc)
        self.assertIn("681255809395", loc)
        self.assertIn("codeassist.google.com", loc)
        st, _r, _s, loc = self._raw(
            "GET", "/api/integrations/aioauth/nope/start", cookie=cookie)
        # an unknown lane must never bounce to a provider
        self.assertNotIn("oauth/authorize", loc)
        self.assertNotIn("accounts.google.com", loc)

    def test_02_status_oauth_flags(self):
        cookie = self._login(FRIEND_PW)
        st, j = self._intg(cookie, {"action": "status"})
        self.assertEqual(st, 200)
        for prov in ("openai", "anthropic", "google"):
            self.assertTrue(j["ai"][prov]["oauth"], prov)
            self.assertEqual(j["ai"][prov]["oauth_account"],
                             "pal@example.com")

    def test_03_models_static_lists(self):
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw("GET", "/api/models?provider=codex",
                                    cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn("gpt-5.1-codex-max", json.loads(raw)["models"])
        st, raw, _c, _l = self._raw("GET", "/api/models?provider=gemini_cli",
                                    cookie=cookie)
        self.assertIn("gemini-2.5-pro", json.loads(raw)["models"])
        admin = self._login(MASTER)
        st, raw, _c, _l = self._raw("GET", "/api/models?provider=codex",
                                    cookie=admin)
        self.assertEqual(json.loads(raw)["models"], [])

    def test_04_paste_guards(self):
        cookie = self._login(FRIEND_PW)
        st, j = self._intg(cookie, {"action": "oauth_paste",
                                    "service": "codex", "text": "abc",
                                    "password": "nope"})
        self.assertEqual(st, 401)
        st, j = self._intg(cookie, {"action": "oauth_paste",
                                    "service": "codex", "text": "abc",
                                    "password": FRIEND_PW})
        self.assertEqual(st, 400)
        self.assertIn("expired", j["error"])
        st, j = self._intg(cookie, {"action": "oauth_paste",
                                    "service": "bogus", "text": "abc",
                                    "password": FRIEND_PW})
        self.assertEqual(st, 400)

    def _chat_first_step(self, provider, model):
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw(
            "POST", "/api/chat", cookie=cookie, timeout=150,
            body={"provider": provider, "model": model, "message": "hi"})
        self.assertEqual(st, 200, raw[:200])
        trace = json.loads(raw).get("trace") or []
        self.assertTrue(trace)
        return trace[0]

    # With a FAKE token the attempt can never succeed: the provider
    # either rejects the sign-in (401/403 — the strict wording) or,
    # on a bad network day, the call cannot even get out. Both are
    # honest failures; a fake success is the only unforgivable one.
    HONEST = ("sign-in", "could not reach", "provider returned")

    def _assert_honest_failure(self, step, lane):
        self.assertEqual(step["p"], lane)
        self.assertFalse(step["ok"])
        e = step["e"].lower()
        self.assertTrue(any(h in e for h in self.HONEST),
                        f"{lane} failed with an unclear reason: {e!r}")

    def test_05_chat_codex_fake_token_is_honest(self):
        step = self._chat_first_step("codex", "gpt-5.1-codex-max")
        self._assert_honest_failure(step, "codex")

    def test_06_chat_claude_fake_token_is_honest(self):
        step = self._chat_first_step("claude_oauth",
                                     "claude-sonnet-4-5-20250929")
        self._assert_honest_failure(step, "claude_oauth")

    def test_07_chat_gemini_fake_token_is_honest(self):
        step = self._chat_first_step("gemini_cli", "gemini-2.5-pro")
        self._assert_honest_failure(step, "gemini_cli")

    def test_08_disconnect_persists(self):
        cookie = self._login(FRIEND_PW)
        st, j = self._intg(cookie, {"action": "oauth_disconnect",
                                    "service": "codex",
                                    "password": FRIEND_PW})
        self.assertEqual(st, 200)
        self.assertFalse(j["ai"]["openai"]["oauth"])
        self.assertTrue(j["ai"]["anthropic"]["oauth"])
        cookie2 = self._login(FRIEND_PW)
        st, j = self._intg(cookie2, {"action": "status"})
        self.assertFalse(j["ai"]["openai"]["oauth"])

    def test_09_quotas_have_signin_lanes(self):
        cookie = self._login(FRIEND_PW)
        st, raw, _c, _l = self._raw("GET", "/api/quotas", cookie=cookie)
        self.assertEqual(st, 200)
        data = json.loads(raw)
        providers = data.get("providers") or data
        names = json.dumps(providers)
        for lane in ("codex", "claude_oauth", "gemini_cli"):
            self.assertIn(lane, names)
        self.assertIn("Sign-in", names)


class AiOauthCodexCatalog(unittest.TestCase):
    """Owner ask 2026-10-15: a signed-in user should only be SHOWN
    the models their account is eligible for. The Codex backend
    publishes a per-account catalog (visibility + available_in_plans);
    a local stub plays that catalog here. acct-live gets a filtered
    list; acct-empty's catalog is unusable, so the static list must
    come back as the honest fallback."""

    CATALOG = {"models": [
        {"slug": "gpt-free-ok", "visibility": "list",
         "available_in_plans": ["free", "plus"]},
        {"slug": "gpt-plus-only", "visibility": "list",
         "available_in_plans": ["plus", "pro"]},
        {"slug": "gpt-hidden", "visibility": "hide",
         "available_in_plans": ["free", "plus", "pro"]},
        {"slug": "gpt-noplans", "visibility": "list"}]}

    LIVE_PW = "live-pass-123"
    EMPTY_PW = "empty-pass-123"
    STORED_PW = "stored-pass-123"

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading

        class Stub(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Chatgpt-Account-Id") == "acct-empty":
                    payload = {"models": []}
                else:
                    payload = AiOauthCodexCatalog.CATALOG
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.stub = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        cls.stub_port = cls.stub.server_address[1]
        threading.Thread(target=cls.stub.serve_forever, daemon=True).start()

        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-catalog-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl", "telemetry.enc"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys",
                                       "userintegrations"):
                continue
            src = APP / name
            if src.is_dir():
                shutil.copytree(src, cls.tmp / name)
            elif name.endswith((".py", ".json", ".html", ".ico", ".svg",
                                ".png")):
                shutil.copy(src, cls.tmp / name)
        access = {"livepal": _hash_pw(cls.LIVE_PW),
                  "emptypal": _hash_pw(cls.EMPTY_PW),
                  "storedpal": _hash_pw(cls.STORED_PW)}
        encrypt_keys({"groq": "sk-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        (cls.tmp / "userkeys").mkdir(exist_ok=True)
        (cls.tmp / "userintegrations").mkdir(exist_ok=True)
        future = int(time.time()) + 3600

        def b64(o):
            return base64.urlsafe_b64encode(
                json.dumps(o).encode()).rstrip(b"=").decode()

        # livepal: no stored plan — the plan rides inside the access
        # token JWT, like a real Codex token.
        jwt_access = (b64({"alg": "none"}) + "." + b64(
            {"https://api.openai.com/auth":
             {"chatgpt_plan_type": "free",
              "chatgpt_account_id": "acct-live"}}) + ".sig")
        for label, pw, acct, plan, acc in (
                ("livepal", cls.LIVE_PW, "acct-live", "", jwt_access),
                ("emptypal", cls.EMPTY_PW, "acct-empty", "free",
                 "fake-token"),
                ("storedpal", cls.STORED_PW, "acct-stored", "plus",
                 "fake-token")):
            tok = {"access": acc, "refresh": "fake-refresh",
                   "expires": future, "email": label + "@example.com",
                   "account_id": acct, "project": "", "plan": plan}
            encrypt_keys({"ai_oauth": {"codex": tok}}, pw,
                         cls.tmp / "userintegrations" / (label + ".enc"))
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({"HOST": "127.0.0.1", "PORT": str(cls.port),
                    "NEXUS_RELAY_PORT": str(_free_port()),
                    "NEXUS_RESTORE_KEY": RESTORE,
                    "NEXUS_CODEX_MODELS_URL":
                        f"http://127.0.0.1:{cls.stub_port}/models",
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
                        timeout=3) as r:
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
        cls.stub.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _raw(self, method, path, cookie="", body=None, timeout=60):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=timeout)
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path,
                     body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        sc = resp.getheader("Set-Cookie") or ""
        conn.close()
        return resp.status, raw, sc.split(";")[0]

    def _login(self, password):
        st, raw, cookie = self._raw("POST", "/api/login",
                                    body={"password": password})
        self.assertEqual(st, 200, raw[:200])
        return cookie

    def _models(self, cookie):
        st, raw, _c = self._raw("GET", "/api/models?provider=codex",
                                cookie=cookie)
        self.assertEqual(st, 200)
        return json.loads(raw)["models"]

    def test_01_only_eligible_models_shown(self):
        cookie = self._login(self.LIVE_PW)
        # hidden entry dropped, plus-only entry dropped for a free
        # plan, plan-less + free entries kept, catalog order kept
        self.assertEqual(self._models(cookie),
                         ["gpt-free-ok", "gpt-noplans"])

    def test_02_unusable_catalog_falls_back_to_static(self):
        cookie = self._login(self.EMPTY_PW)
        models = self._models(cookie)
        self.assertIn("gpt-5.1-codex-max", models)
        self.assertIn("gpt-5.2-codex", models)

    def test_03_stored_plan_filters_the_other_way(self):
        cookie = self._login(self.STORED_PW)
        # a plus plan keeps the free + plus entries, still drops
        # the hidden one — the stored-plan capture path
        self.assertEqual(self._models(cookie),
                         ["gpt-free-ok", "gpt-plus-only", "gpt-noplans"])


if __name__ == "__main__":
    unittest.main()
