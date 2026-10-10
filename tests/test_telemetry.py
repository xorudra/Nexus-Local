#!/usr/bin/env python3
"""Durable telemetry tests (owner order 2026-10-10, post-review).

usage.jsonl / audit.jsonl live on the host's ephemeral disk; their
tails are kept in a restore-key-encrypted telemetry.enc, flushed by a
daemon thread, carried in the friend blob, and hydrated back at boot
— so a redeploy no longer zeroes the console's numbers or the daily
caps that are counted from usage.jsonl.

Run:  python3 -m unittest discover -s tests -v
"""

import base64
import datetime
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
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
from key_security import decrypt_keys, encrypt_keys  # noqa: E402

MASTER = "test-master-password-123"
RESTORE = "test-restore-key-xyz"
F1, F1_PW = "friendone", "friend-one-pass"


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


class TelemetryTests(unittest.TestCase):
    proc = None
    log = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-telemetry-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json", "settings.json", "settings.enc",
                "audit.jsonl", "usage.jsonl", "telemetry.enc"}
        for name in os.listdir(APP):
            if name in skip or name in ("chats", "userkeys"):
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {F1: _hash_pw(F1_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER,
                     cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        (cls.tmp / "userkeys").mkdir(exist_ok=True)
        today = datetime.datetime.now().isoformat()
        with open(cls.tmp / "usage.jsonl", "w") as f:
            for i in range(3):
                f.write(json.dumps({
                    "ts": today, "provider": "groq", "model": "m",
                    "prompt_tokens": 10, "completion_tokens": 5,
                    "user": F1, "ms": 100 + i, "ok": True}) + "\n")
        cls._start()

    @classmethod
    def tearDownClass(cls):
        cls._stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _start(cls):
        cls._stop()
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1", "PORT": str(cls.port),
            "NEXUS_RELAY_PORT": str(_free_port()),
            "NEXUS_RESTORE_KEY": RESTORE,
            "NEXUS_TELEMETRY_FLUSH_S": "2",
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
                raise RuntimeError("server exited early")
            try:
                status, _, _, _ = cls._req("GET", "/health")
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
    def _req(cls, method, path, body=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port,
                                          timeout=60)
        hdrs = {}
        data = None
        if body is not None:
            data = json.dumps(body)
            hdrs["Content-Type"] = "application/json"
        if cookie:
            hdrs["Cookie"] = cookie
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = None
        return resp.status, parsed, resp_headers, payload

    @classmethod
    def _login(cls, password):
        status, body, headers, _ = cls._req(
            "POST", "/api/login", {"password": password})
        cookie = None
        sc = headers.get("set-cookie")
        if sc:
            cookie = sc.split(";")[0]
        return status, body, cookie

    @classmethod
    def _access(cls, action, cookie, **extra):
        body = {"action": action}
        body.update(extra)
        status, parsed, _, _ = cls._req("POST", "/api/access", body,
                                        cookie=cookie)
        return status, parsed

    def test_01_flush_blob_and_redeploy_restore(self):
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        # an audited admin action, so the audit tail has content
        status, j = self._access("settings_set", admin,
                                 patch={"announcement": "Telemetry probe"},
                                 master_pw=MASTER)
        self.assertEqual(status, 200, j)
        # the flusher (2s cadence in this fixture) publishes telemetry
        # through the friend blob
        blob = None
        deadline = time.time() + 45
        while time.time() < deadline:
            _, blob, _, _ = self._req("GET", "/api/friend_blob")
            if blob and blob.get("telemetry"):
                break
            time.sleep(1)
        self.assertTrue(blob and blob.get("telemetry"),
                        "telemetry.enc never reached the friend blob")
        # the payload really is the usage/audit tails, encrypted under
        # the restore key
        raw = base64.b64decode(blob["telemetry"])
        probe = self.tmp / "probe.enc"
        probe.write_bytes(raw)
        data = decrypt_keys(probe, RESTORE)
        self.assertIn("groq", data.get("usage", ""))
        self.assertIn("Settings changed", data.get("audit", ""))
        self.assertTrue(data.get("saved"))
        # simulate a redeploy: fresh disk, only the encrypted mirrors
        # (here: the local telemetry.enc) survive
        type(self)._stop()
        (self.tmp / "usage.jsonl").unlink()
        (self.tmp / "audit.jsonl").unlink()
        type(self)._start()
        status, body, admin = self._login(MASTER)
        self.assertEqual(status, 200, body)
        # audit history is back
        status, j, _, _ = self._req("GET", "/api/audit", cookie=admin)
        self.assertEqual(status, 200)
        events = json.dumps(j)
        self.assertIn("Settings changed", events)
        # usage history is back (the 3 seeded rows feed analytics,
        # which is also what the daily caps count from)
        status, j, _, _ = self._req("GET", "/api/analytics?range=7d",
                                    cookie=admin)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(j["totals"]["requests"], 3)


if __name__ == "__main__":
    unittest.main()
