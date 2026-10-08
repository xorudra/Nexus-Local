#!/usr/bin/env python3
"""Horizon hero page tests (owner request, 2026-10-09).

The /horizon page is a public, visual-only page: a vanilla port of the
React horizon-hero-section component (Three.js scene vendored under
app/vendor). These tests pin: the page serves without a session, the
vendored libraries serve with a JS content type, and the /vendor route
is confined to .js files inside app/vendor (no traversal, no other
file types).

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
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
from key_security import encrypt_keys  # noqa: E402

MASTER = "test-master-password-123"
RESTORE = "test-restore-key-xyz"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class HorizonTests(unittest.TestCase):
    proc = None
    log = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-horizon-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip or name == "chats":
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        shutil.copytree(APP / "vendor", cls.tmp / "vendor")
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1", "PORT": str(cls.port),
            "NEXUS_RELAY_PORT": str(_free_port()),
            "NEXUS_RESTORE_KEY": RESTORE,
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
                status, _, _ = cls._get("/health")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.25)
        raise RuntimeError("server did not come up in 30s")

    @classmethod
    def tearDownClass(cls):
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
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _get(cls, path):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=60)
        conn.request("GET", path)
        resp = conn.getresponse()
        payload = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, payload.decode(errors="replace"), headers

    def test_01_page_is_public_and_complete(self):
        status, body, headers = self._get("/horizon")
        self.assertEqual(status, 200)
        self.assertIn("HORIZON", body)
        self.assertIn("COSMOS", body)
        self.assertIn("INFINITY", body)
        self.assertIn("/vendor/three.module.js", body)
        self.assertIn("importmap", body)
        self.assertIn("text/html", headers.get("content-type", ""))

    def test_02_vendored_libraries_serve(self):
        status, body, headers = self._get("/vendor/three.module.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers.get("content-type", ""))
        self.assertGreater(len(body), 100000)
        status, body, headers = self._get(
            "/vendor/jsm/postprocessing/EffectComposer.js")
        self.assertEqual(status, 200)
        self.assertIn("EffectComposer", body)
        status, body, headers = self._get("/vendor/gsap.min.js")
        self.assertEqual(status, 200)
        self.assertGreater(len(body), 10000)
        # three.module.js is a thin wrapper: it imports ./three.core.js.
        # That file MUST be vendored too (its 404 killed the whole module
        # graph on the first live deploy — pinned here so it cannot
        # regress silently).
        status, body, headers = self._get("/vendor/three.core.js")
        self.assertEqual(status, 200)
        self.assertGreater(len(body), 1000000)

    def test_03_vendor_route_is_confined(self):
        # Traversal out of the vendor dir must not serve app files...
        status, _, _ = self._get("/vendor/../server.py")
        self.assertEqual(status, 404)
        status, _, _ = self._get("/vendor/../../etc/passwd")
        self.assertEqual(status, 404)
        # ...and only .js files are served at all.
        status, _, _ = self._get("/vendor/three.module.js.map")
        self.assertEqual(status, 404)
        status, _, _ = self._get("/vendor/nonexistent.js")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
