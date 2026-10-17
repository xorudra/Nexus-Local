#!/usr/bin/env python3
"""Regression tests for the 2026-10-16 security-audit fixes (run-1):
invite redemption race, friend_blob authentication, 2FA QR proof gate,
password-collision fail-closed login, My Keys blank-keeps semantics,
SSRF validators, rate-limit pruning, strict friend chat loading, and
the Mailchimp data-centre validation.

Fixtures use only fake keys and throwaway passwords; no real secret is
read or printed anywhere in this file.

Run:  python3 -m unittest discover -s tests -v
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))

os.environ.pop("NEXUS_RESTORE_KEY", None)

from key_security import encrypt_keys  # noqa: E402
import server  # noqa: E402

MASTER = "audit-master-123"
RESTORE = "audit-restore-key"
SYNC_TOKEN = "audit-sync-token-fixture"
SHARED_PW = "shared-password-1"
UNIQUE_PW = "unique-password-9"
FRIEND = "friendone"
FRIEND_PW = "friend-one-pass"


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


def _totp(secret_b32, offset=0):
    t = int(time.time()) // 30 + offset
    key = base64.b32decode(secret_b32.upper())
    digest = hmac.new(key, struct.pack(">Q", t), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


MASTER_B = "audit-master-456"


class ValidatorUnitTests(unittest.TestCase):
    def test_webhook_url_ok_rejects_encoded_and_literal_internal(self):
        for url in ("http://2130706433/hook", "http://0x7f000001/hook",
                    "http://127.0.0.1/hook", "http://localhost/hook",
                    "http://[::1]/hook", "ftp://example.com/hook",
                    "http://10.0.0.5/hook", "http://192.168.1.1/hook"):
            self.assertFalse(server._webhook_url_ok(url), url)

    def test_safe_url_rejects_non_http_and_internal(self):
        for url in ("file:///etc/passwd", "gopher://example.com/",
                    "http://127.0.0.1:8100/", "http://localhost/",
                    "http://[::1]/", "", "https://10.1.2.3/x"):
            self.assertFalse(server._safe_url(url), url)

    def test_public_predicates_reject_special_ranges(self):
        # Run-3 vectors: CGNAT (100.64/10 — is_private is False for it
        # on CPython 3.12, only is_global catches it), its IPv4-mapped
        # form, fec0::/10 site-local (is_global is True for it — only
        # is_site_local catches it), documentation and benchmarking
        # ranges must all read as NOT public in every predicate.
        for url in ("http://100.64.0.1/x", "http://[::ffff:100.64.0.1]/x",
                    "http://[fec0::1]/x", "http://192.0.2.1/x",
                    "http://198.18.0.5/x", "http://169.254.169.254/x"):
            self.assertFalse(server._safe_url(url), url)
            self.assertFalse(server._public_base_url_ok(url), url)
        for addr in ("100.64.0.1", "fec0::1", "192.0.2.1", "198.18.0.5"):
            self.assertFalse(server._addr_is_public(addr), addr)
        # Control: an ordinary public address stays public.
        self.assertTrue(server._safe_url("https://93.184.216.34/x"))
        self.assertTrue(server._addr_is_public("93.184.216.34"))

    def test_password_taken(self):
        access = {"aa": server._hash_password("pw-alpha-111"),
                  "bb": server._hash_password("pw-beta-2222")}
        self.assertTrue(server._password_taken(access, "pw-alpha-111"))
        self.assertTrue(server._password_taken(access, "pw-beta-2222"))
        self.assertFalse(server._password_taken(access, "pw-alpha-111",
                                                 skip_label="aa"))
        self.assertFalse(server._password_taken(access, "pw-gamma-333"))

    def test_rl_prune_keeps_active_buckets(self):
        saved = dict(server._RL)
        try:
            server._RL.clear()
            now = time.time()
            server._RL[("chat", "active-label")] = [now]
            for i in range(5001):
                server._RL[("old", f"k{i}")] = [now - 5000]
            self.assertTrue(server._rl_ok("fresh", "newkey", 5, 60))
            # The active window survives; expired keys are pruned.
            self.assertIn(("chat", "active-label"), server._RL)
            self.assertLessEqual(len(server._RL), 5001)
        finally:
            server._RL.clear()
            server._RL.update(saved)

    def test_load_chats_strict(self):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-chats-"))
        old = server.CHATS_DIR
        server.CHATS_DIR = tmp
        try:
            self.assertEqual(server._load_chats_strict("ghost", "pw"),
                             {"chats": []})
            server._save_chats("friendx", {"chats": [{"id": "1"}]}, "pw-one")
            got = server._load_chats_strict("friendx", "pw-one")
            self.assertEqual(got["chats"][0]["id"], "1")
            with self.assertRaises(Exception):
                server._load_chats_strict("friendx", "pw-two")
        finally:
            server.CHATS_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mailchimp_dc_validation(self):
        calls = []
        orig = server._intg_http

        def fake(url, method, headers):
            calls.append(url)
            return 200, {"total_items": 2}
        server._intg_http = fake
        try:
            ok, acct, _ = server._intg_test_mailchimp(
                {"api_key": "deadbeef-us21"})
            self.assertTrue(ok)
            self.assertTrue(calls[0].startswith(
                "https://us21.api.mailchimp.com/"), calls[0])
            for hostile in ("x-127.0.0.1:8080/evil", "x-us21.evil.com",
                            "x-../../etc", "nodc"):
                ok2, _, _ = server._intg_test_mailchimp(
                    {"api_key": hostile})
                self.assertFalse(ok2, hostile)
            self.assertEqual(len(calls), 1)  # hostile keys never fetched
        finally:
            server._intg_http = orig


    def test_encrypt_keys_write_is_atomic_shaped(self):
        # R3-6: encrypt_keys writes via tmp + os.replace (the
        # _write_chat_file_atomic pattern). A torn single-shot write
        # used to leave a store the strict loaders refuse on every
        # later save - a permanent lockout. Observable contract:
        # round-trips, lands mode 600, no tmp file left behind, and
        # overwriting an existing store works.
        import stat as _stat
        from key_security import decrypt_keys
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "vault.enc"
            encrypt_keys({"a": "one"}, "pw-fixture-1", p)
            self.assertEqual(decrypt_keys(p, "pw-fixture-1"),
                             {"a": "one"})
            self.assertEqual(_stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertFalse((Path(td) / "vault.enc.tmp").exists())
            encrypt_keys({"a": "two"}, "pw-fixture-1", p)
            self.assertEqual(decrypt_keys(p, "pw-fixture-1"),
                             {"a": "two"})
            self.assertFalse((Path(td) / "vault.enc.tmp").exists())

    def test_encrypt_keys_failed_replace_keeps_old_store(self):
        # R3-6 contract: if the write dies before the replace lands,
        # the previous store must survive untouched (the old
        # single-shot write_text truncated the target first, so a
        # crash mid-write destroyed it). Patching os.replace to
        # raise stands in for that crash: new code never touched the
        # target; old code did not call replace at all and would
        # have overwritten the store before this point.
        from unittest import mock
        from key_security import decrypt_keys
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "vault.enc"
            encrypt_keys({"a": "original"}, "pw-fixture-1", p)
            with mock.patch.object(os, "replace",
                                   side_effect=OSError("simulated crash")):
                with self.assertRaises(OSError):
                    encrypt_keys({"a": "replacement"}, "pw-fixture-1", p)
            self.assertEqual(decrypt_keys(p, "pw-fixture-1"),
                             {"a": "original"})

    def test_encrypt_keys_concurrent_saves_same_store(self):
        # R4 (run-4): concurrent saves of the SAME store must never
        # raise and never tear. The first atomic version used one
        # fixed <name>.tmp for every call, so two threads truncated
        # each other's tmp mid-write (FileNotFoundError at replace,
        # lost saves, one observed interleaved-content corruption).
        # A small chmod delay widens the write/replace window so the
        # old code fails here deterministically, not by luck.
        from unittest import mock
        from key_security import decrypt_keys
        real_chmod = os.chmod

        def slow_chmod(path, mode):
            if ".tmp" in str(path):
                time.sleep(0.02)
            return real_chmod(path, mode)

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "vault.enc"
            encrypt_keys({"n": -1}, "pw-fixture-1", p)
            errors = []

            def worker(n):
                try:
                    for i in range(12):
                        encrypt_keys({"n": n * 100 + i},
                                     "pw-fixture-1", p)
                except Exception as e:  # noqa: BLE001
                    errors.append(repr(e))

            with mock.patch.object(os, "chmod",
                                   side_effect=slow_chmod):
                threads = [threading.Thread(target=worker, args=(n,))
                           for n in range(8)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=60)
            self.assertEqual(errors, [])
            final = decrypt_keys(p, "pw-fixture-1")
            self.assertIn("n", final)
            self.assertEqual(list(Path(td).glob("*.tmp")), [])


    # -- run-5: model ids become URL path segments with shared keys --
    def test_safe_model_path(self):
        import server as srv
        ok = srv._safe_model_path
        self.assertEqual(ok("@cf/meta/llama-3-8b-instruct"),
                         "@cf/meta/llama-3-8b-instruct")
        self.assertEqual(ok("gemini-2.5-flash"), "gemini-2.5-flash")
        for bad in ("../../../zones", "..%2f..%2fuser", "x?injected=1",
                    "a b", "", "..", "a/./b", "a//b", "x#frag", "a\\b"):
            self.assertIsNone(ok(bad), bad)

    # -- run-5: the custom-provider registry mirrors the vault -------
    def test_register_custom_providers_replaces_and_purges(self):
        import server as srv
        name = "unittestdemo"
        try:
            srv.register_custom_providers(
                {f"custom_relay_{name}": "k1",
                 f"custom_relay_{name}_url": "https://93.184.216.34/v1"})
            self.assertEqual(srv.RELAY_UPSTREAMS.get(name),
                             "https://93.184.216.34/v1")
            # A changed URL replaces the upstream - the rotated key
            # must not keep flowing to the previous host.
            srv.register_custom_providers(
                {f"custom_relay_{name}": "k2",
                 f"custom_relay_{name}_url": "https://93.184.216.35/v1"})
            self.assertEqual(srv.RELAY_UPSTREAMS.get(name),
                             "https://93.184.216.35/v1")
            # Removal unregisters.
            srv.register_custom_providers({"groq": "x"})
            self.assertNotIn(name, srv.RELAY_UPSTREAMS)
        finally:
            srv.RELAY_UPSTREAMS.pop(name, None)
            srv._CUSTOM_RELAY_NAMES.discard(name)

    # -- run-5: an empty access mirror is authoritative at boot ------
    def test_boot_restore_empty_mirror_is_authoritative(self):
        import server as srv
        tmp = Path(tempfile.mkdtemp(prefix="nexus-unit-boot-"))
        saved = (srv.ACCESS_PATH, srv.ACCESS_ENC_PATH, srv.RESTORE_KEY)
        try:
            srv.ACCESS_PATH = tmp / "access.json"
            srv.ACCESS_ENC_PATH = tmp / "access.enc"
            srv.RESTORE_KEY = "unit-restore-key"
            srv.ACCESS_PATH.write_text(json.dumps({"ghost": "h"}))
            encrypt_keys({}, "unit-restore-key", srv.ACCESS_ENC_PATH)
            srv._boot_restore_access()
            # The mirror says the list is empty; the stale working
            # file must not resurrect the ghost.
            self.assertEqual(json.loads(srv.ACCESS_PATH.read_text()), {})
        finally:
            srv.ACCESS_PATH, srv.ACCESS_ENC_PATH, srv.RESTORE_KEY = saved
            shutil.rmtree(tmp, ignore_errors=True)

    # -- run-5: /v1 honors provider_limits and meters under the lane -
    def test_v1_chat_limits_and_metering(self):
        import server as srv
        calls, rows = [], []
        real_relay, real_append = srv._v1_relay_call, srv._append_usage
        real_limits = srv._SETTINGS.get("provider_limits")
        real_counts = srv._today_counts

        def fake_relay(lane, path, payload, timeout=90):
            calls.append(lane)
            return {"choices": [{"message": {"content": "hi"}}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 4}}
        srv._v1_relay_call, srv._append_usage = fake_relay, rows.append
        # Deterministic usage oracle: every lane already spent 5
        # requests today. (A limit of 0 disables the cap in the
        # shared predicate - the same semantics chat has always had -
        # so the limits here are positive.)
        srv._today_counts = lambda fresh=False: {
            "providers": {lane: 5 for lane, _m in srv._V1_LANES}}
        # Wave 15 (CAPS14-4): the /v1 reserve's completed term reads
        # the in-memory provider counter — stub it as the oracle too.
        real_pcounts = srv._provider_counts_today
        srv._provider_counts_today = lambda: {
            lane: 5 for lane, _m in srv._V1_LANES}
        try:
            srv._SETTINGS["provider_limits"] = {
                lane: 3 for lane, _m in srv._V1_LANES}
            status, _payload, _lane = srv._v1_chat(
                [{"role": "user", "content": "hi"}], "nexus-auto")
            self.assertEqual(status, 502)
            self.assertEqual(calls, [])  # every lane blocked pre-flight
            srv._SETTINGS["provider_limits"] = {}
            status, _payload, lane = srv._v1_chat(
                [{"role": "user", "content": "hi"}], "nexus-auto")
            self.assertEqual(status, 200)
            self.assertEqual(calls, [lane])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["provider"], lane)
            self.assertEqual(rows[0].get("via"), "v1")
        finally:
            srv._v1_relay_call, srv._append_usage = real_relay, real_append
            srv._SETTINGS["provider_limits"] = real_limits
            srv._today_counts = real_counts
            srv._provider_counts_today = real_pcounts

    # -- run-6: credential strip list covers Cookie + account id -----
    def test_strip_cred_headers_covers_cookie_and_account(self):
        from urllib.request import Request
        req = Request("https://a.example/x")
        req.add_header("Authorization", "Bearer t")
        req.add_header("Cookie", "session=abc")
        req.add_header("Chatgpt-Account-Id", "acct-1")
        req.add_header("X-Other", "keep")
        server._strip_cred_headers(req)
        keys = {k.lower() for k in req.headers}
        self.assertNotIn("authorization", keys)
        self.assertNotIn("cookie", keys)
        self.assertNotIn("chatgpt-account-id", keys)
        self.assertIn("x-other", keys)

    # -- run-6: guarded redirect strips on origin change ------------
    def test_guarded_redirect_strips_cross_origin(self):
        from urllib.request import Request
        req = Request("https://a.example/x")
        req.add_header("Authorization", "Bearer t")
        req.add_header("Cookie", "session=abc")
        h = server._GuardedRedirect()
        # Literal public IPs: the sandbox resolver maps every name
        # into a private range, which _safe_url rightly refuses.
        req = Request("https://93.184.216.34/x")
        req.add_header("Authorization", "Bearer t")
        req.add_header("Cookie", "session=abc")
        new = h.redirect_request(req, None, 302, "Found", {},
                                 "https://93.184.215.14/y")
        self.assertIsNotNone(new)
        keys = {k.lower() for k in new.headers}
        self.assertNotIn("authorization", keys)
        self.assertNotIn("cookie", keys)
        new2 = h.redirect_request(req, None, 302, "Found", {},
                                  "https://93.184.216.34/z")
        self.assertIn("authorization",
                      {k.lower() for k in new2.headers})

    # -- run-6: capped byte reads truncate ---------------------------
    def test_read_capped_bytes_truncates(self):
        import io
        big = io.BytesIO(b"x" * 100)
        self.assertEqual(len(server._read_capped_bytes(big, cap=10)), 10)
        small = io.BytesIO(b"abc")
        self.assertEqual(server._read_capped_bytes(small), b"abc")

    # -- run-6: deadline reader enforces a total budget --------------
    def test_deadline_reader_budget(self):
        import io

        class _Conn:
            def __init__(self):
                self.timeouts = []

            def settimeout(self, v):
                self.timeouts.append(v)

        conn = _Conn()
        raw = io.BytesIO(b"hello\nworld")
        r = server._DeadlineReader(raw, conn, 60)
        self.assertEqual(r.readline(), b"hello\n")
        self.assertTrue(all(t <= 10 for t in conn.timeouts))
        dead = server._DeadlineReader(io.BytesIO(b"x"), _Conn(), 0)
        self.assertRaises(TimeoutError, dead.read)

    # -- run-6: Gemini sign-in lane runs PKCE -------------------------
    def test_gemini_lane_uses_pkce(self):
        self.assertTrue(server._AIOAUTH_CLIENTS["gemini_cli"]["pkce"])
        url = server._aioauth_url("gemini_cli", "state-x", "chal-y")
        self.assertIn("code_challenge=chal-y", url)
        self.assertIn("code_challenge_method=S256", url)

    # -- run-6: in-flight reservations feed the provider gate --------
    def test_inflight_reservation_blocks_provider(self):
        saved = server._SETTINGS.get("provider_limits")
        server._SETTINGS["provider_limits"] = {"groq": 1}
        try:
            self.assertFalse(server._provider_blocked("groq"))
            res = server._inflight_add("someone", "groq")
            try:
                self.assertTrue(server._provider_blocked("groq"))
            finally:
                server._inflight_drop(res)
            self.assertFalse(server._provider_blocked("groq"))
        finally:
            if saved is None:
                server._SETTINGS.pop("provider_limits", None)
            else:
                server._SETTINGS["provider_limits"] = saved

    # -- run-6: password-proof failure budget ------------------------
    def test_pw_failure_budget(self):
        kind, key = "unittest-kind", "unittest-key"
        server._PW_FAILS.pop((kind, key), None)
        try:
            self.assertFalse(server._pw_throttled(kind, key))
            for _ in range(10):
                server._pw_failed(kind, key)
            self.assertTrue(server._pw_throttled(kind, key))
        finally:
            server._PW_FAILS.pop((kind, key), None)

    # -- run-7: /v1 rows count toward the instance total -------------
    def test_v1_rows_count_toward_total(self):
        import datetime
        import tempfile
        from pathlib import Path as _P
        saved_path = server.USAGE_PATH
        saved_ts = server._TODAY_CACHE["ts"]
        try:
            with tempfile.TemporaryDirectory() as td:
                p = _P(td) / "usage.jsonl"
                today = datetime.date.today().isoformat()
                rows = [
                    {"ts": today, "provider": "groq", "user": "u1"},
                    {"ts": today, "provider": "groq", "user": "u1"},
                    {"ts": today, "provider": "freellmapi", "via": "v1"},
                    {"ts": today, "provider": "freellmapi", "via": "v1"},
                    {"ts": today, "provider": "freellmapi", "via": "v1"},
                    {"ts": today, "provider": "v1:groq"},
                ]
                p.write_text("".join(json.dumps(r) + "\n" for r in rows))
                server.USAGE_PATH = p
                self.assertEqual(
                    server._today_total_requests(fresh=True), 6)
        finally:
            server.USAGE_PATH = saved_path
            server._TODAY_CACHE["ts"] = saved_ts

    # -- run-7 functional: _intg_http serializes dict bodies ---------
    def test_intg_http_serializes_dict_body(self):
        import http.server
        import threading as _th
        seen = {}

        class _H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                seen["body"] = self.rfile.read(n)
                out = json.dumps({"echo": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), _H)
        port = httpd.server_address[1]
        _th.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            st, payload = server._intg_http(
                f"http://127.0.0.1:{port}/token", "POST",
                {"Content-Type": "application/json"},
                {"grant_type": "authorization_code", "code": "abc"})
            self.assertEqual(st, 200)
            self.assertEqual(payload, {"echo": True})
            self.assertEqual(json.loads(seen["body"])["code"], "abc")
        finally:
            httpd.shutdown()

    # -- run-7: loopback redirects strip on ORIGIN change ------------
    def test_loopback_redirect_strips_cross_port(self):
        import http.server
        import threading as _th
        import urllib.request
        seen = {}
        holder = {}

        def _mk():
            class _H(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path == "/jump":
                        self.send_response(302)
                        self.send_header(
                            "Location",
                            f"http://127.0.0.1:{holder['b']}/land")
                        self.end_headers()
                    elif self.path == "/self":
                        self.send_response(302)
                        self.send_header("Location", "/land")
                        self.end_headers()
                    else:
                        seen[self.server.server_address[1]] = {
                            k.lower(): v for k, v in self.headers.items()}
                        out = b"ok"
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(out)))
                        self.end_headers()
                        self.wfile.write(out)

                def log_message(self, *a):
                    pass
            return _H

        a = http.server.HTTPServer(("127.0.0.1", 0), _mk())
        b = http.server.HTTPServer(("127.0.0.1", 0), _mk())
        holder["a"] = a.server_address[1]
        holder["b"] = b.server_address[1]
        for srv in (a, b):
            _th.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{holder['a']}/jump",
                headers={"Authorization": "Bearer TOK7",
                         "X-Relay-Token": "RT7"})
            with server._open_loopback(req, 5) as r:
                r.read()
            landed = seen[holder["b"]]
            self.assertNotIn("authorization", landed)
            self.assertNotIn("x-relay-token", landed)
            req = urllib.request.Request(
                f"http://127.0.0.1:{holder['a']}/self",
                headers={"Authorization": "Bearer TOK7"})
            with server._open_loopback(req, 5) as r:
                r.read()
            self.assertEqual(seen[holder["a"]].get("authorization"),
                             "Bearer TOK7")
        finally:
            a.shutdown()
            b.shutdown()

    # -- run-7: _save_settings is atomic and honest ------------------
    def test_save_settings_atomic_and_honest(self):
        import tempfile
        from pathlib import Path as _P
        saved = (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH)
        try:
            with tempfile.TemporaryDirectory() as td:
                p = _P(td) / "settings.json"
                server.SETTINGS_PATH = p
                server.SETTINGS_ENC_PATH = _P(td) / "settings.enc"
                self.assertTrue(server._save_settings())
                json.loads(p.read_text())
                self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
                server.SETTINGS_PATH = _P(td)  # a directory: cannot land
                self.assertFalse(server._save_settings())
        finally:
            server.SETTINGS_PATH, server.SETTINGS_ENC_PATH = saved

    # -- run-7: a v1 key that cannot persist is never handed out -----
    def test_create_v1key_rolls_back_on_save_failure(self):
        saved_keys = list(server._V1KEYS["keys"])
        saved_fn = server._save_v1keys
        saved_rk = server.RESTORE_KEY
        try:
            server.RESTORE_KEY = "unit-test"
            server._save_v1keys = lambda: False
            self.assertIsNone(server._create_v1key("doomed"))
            self.assertEqual(server._V1KEYS["keys"], saved_keys)
        finally:
            server._V1KEYS["keys"] = saved_keys
            server._save_v1keys = saved_fn
            server.RESTORE_KEY = saved_rk

    # -- run-8: inflight counting rules -------------------------------
    def test_inflight_counting_rules(self):
        server._INFLIGHT.clear()
        try:
            base = server._inflight_add("alice")
            att = server._inflight_add("alice", "groq", attempt=True)
            server._inflight_add("bob")
            # Logical counts skip per-attempt entries (they belong to
            # a request already counted by its base reservation) and
            # can exclude the caller's own reservation — wave 8
            # counted it, so cap=1 refused the first request.
            self.assertEqual(server._inflight_n(user="alice"), 1)
            self.assertEqual(server._inflight_n(user="alice",
                                                 exclude=base), 0)
            self.assertEqual(server._inflight_n(), 2)
            # Provider-filtered counts include attempts.
            self.assertEqual(server._inflight_n(provider="groq"), 1)
            self.assertEqual(server._inflight_n(provider="groq",
                                                exclude=att), 0)
            # Expired entries are pruned, not counted forever.
            base["ts"] -= 1000
            self.assertEqual(server._inflight_n(user="alice"), 0)
            self.assertNotIn(base, server._INFLIGHT)
        finally:
            server._INFLIGHT.clear()

    # -- run-8: _ts_or never raises on malformed stored state ---------
    def test_ts_or_never_raises(self):
        self.assertEqual(server._ts_or("3600"), 3600)
        self.assertEqual(server._ts_or("not-a-number"), 0)
        self.assertEqual(server._ts_or("not-a-number", 3600), 3600)
        self.assertEqual(server._ts_or(None), 0)

    # -- run-8: a failed settings mirror fails the save ---------------
    def test_save_settings_mirror_failure_is_honest(self):
        import tempfile
        from pathlib import Path as _P
        saved = (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
                 server.RESTORE_KEY)
        try:
            with tempfile.TemporaryDirectory() as td:
                plain = _P(td) / "settings.json"
                encp = _P(td) / "settings.enc"
                server.SETTINGS_PATH = plain
                server.SETTINGS_ENC_PATH = encp
                server.RESTORE_KEY = "unit-restore-8"
                self.assertTrue(server._save_settings())
                self.assertTrue(plain.exists())
                self.assertTrue(encp.exists())
                # The mirror becomes unwritable (a directory): the
                # save must FAIL now — wave 8 swallowed the mirror
                # error, returned True, and the next boot silently
                # reverted to the stale mirror.
                encp.unlink()
                encp.mkdir()
                self.assertFalse(server._save_settings())
        finally:
            (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
             server.RESTORE_KEY) = saved

    # -- run-8: a deleted v1 key stays deleted across a reload --------
    def test_v1key_delete_survives_reload(self):
        import tempfile
        from pathlib import Path as _P
        saved = (list(server._V1KEYS["keys"]), server.V1KEY_PATH,
                 server.RESTORE_KEY)
        try:
            with tempfile.TemporaryDirectory() as td:
                server.V1KEY_PATH = _P(td) / "v1key.enc"
                server.RESTORE_KEY = "unit-restore-8"
                server._V1KEYS["keys"] = []
                entry = server._create_v1key("unit")
                self.assertIsNotNone(entry)
                self.assertIsNotNone(server._v1_match(entry["key"]))
                with server._V1KEYS_LOCK:
                    server._V1KEYS["keys"] = []
                    self.assertTrue(server._save_v1keys())
                self.assertIsNone(server._v1_match(entry["key"]))
                server._V1KEYS["keys"] = [{"id": "poison"}]
                server._load_v1key()
                self.assertEqual(server._V1KEYS["keys"], [])
        finally:
            (server._V1KEYS["keys"], server.V1KEY_PATH,
             server.RESTORE_KEY) = saved[0], saved[1], saved[2]
            server._V1KEYS_TOUCH["at"] = 0.0

    # -- run-9 (S1): a partial newer save still advances the mirror --
    # watermark, so a slower older save cannot overwrite the mirror
    # that already landed (verifier proof, re-derived in-process).
    def test_w10_settings_mirror_watermark_partial_save(self):
        import tempfile
        from pathlib import Path as _P
        saved = (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
                 server.RESTORE_KEY, server.encrypt_keys,
                 server._SETTINGS_GEN[0], server._SETTINGS_WRITTEN_GEN[0],
                 server._SETTINGS.get("announcement"))
        orig_encrypt = server.encrypt_keys
        gate = threading.Event()

        def gated(data, pw, path):
            if isinstance(data, dict) \
                    and data.get("announcement") == "OLD44":
                gate.wait(10)
            return orig_encrypt(data, pw, path)

        try:
            with tempfile.TemporaryDirectory() as td:
                plain = _P(td) / "settings.json"
                encp = _P(td) / "settings.enc"
                server.SETTINGS_PATH = plain
                server.SETTINGS_ENC_PATH = encp
                server.RESTORE_KEY = "unit-restore-10"
                server.encrypt_keys = gated
                gen0 = server._SETTINGS_GEN[0]
                # Save A snapshots OLD and is held inside encrypt.
                server._SETTINGS["announcement"] = "OLD44"
                res_a = []
                ta = threading.Thread(
                    target=lambda: res_a.append(server._save_settings()))
                ta.start()
                deadline = time.time() + 10
                while server._SETTINGS_GEN[0] == gen0 \
                        and time.time() < deadline:
                    time.sleep(0.02)
                self.assertGreater(server._SETTINGS_GEN[0], gen0)
                # Save B (this thread) snapshots NEW; its mirror
                # replace lands but its PLAIN write faults (a
                # directory sits at B's exact plain-tmp path).
                server._SETTINGS["announcement"] = "NEW44"
                blocker = _P("%s.%d.tmp" % (plain, threading.get_ident()))
                blocker.mkdir()
                try:
                    self.assertFalse(server._save_settings())
                finally:
                    blocker.rmdir()
                from key_security import decrypt_keys as _dec
                self.assertEqual(_dec(encp, "unit-restore-10")
                                 .get("announcement"), "NEW44")
                # A finally lands: it must be recognised as stale
                # and leave the NEWER mirror alone (pre-fix it
                # overwrote the mirror with OLD and returned True).
                gate.set()
                ta.join(10)
                self.assertEqual(res_a, [True])
                self.assertEqual(_dec(encp, "unit-restore-10")
                                 .get("announcement"), "NEW44")
        finally:
            gate.set()
            (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
             server.RESTORE_KEY, server.encrypt_keys) = saved[:4]
            server._SETTINGS_GEN[0] = saved[4]
            server._SETTINGS_WRITTEN_GEN[0] = saved[5]
            if saved[6] is None:
                server._SETTINGS.pop("announcement", None)
            else:
                server._SETTINGS["announcement"] = saved[6]

    # -- run-9 (L1-L5): launcher gates / verify shape ----------------
    def test_w10_launcher_fixes_present_and_syntax_ok(self):
        js = (REPO / "bin" / "nexuslocal.js").read_text()
        # L4: npm gate needs the completeness marker npm ci writes,
        # and the engine child's exit is logged, never silent.
        self.assertIn('path.join(nodeModules, ".package-lock.json")', js)
        self.assertIn("engine process exited", js)
        # L5: the venv probe imports every pinned-requirements module.
        self.assertIn("import cryptography, qrcode, PIL", js)
        # L1: inconclusive verify outcomes end in a named WARNING.
        self.assertIn("could not verify the engine admin claim", js)
        # L2: verifyClaim falls back to the default email, and the
        # claim path records the email for a pre-existing password.
        self.assertIn('email = "owner@example.com"', js)
        self.assertIn("ENGINE_ADMIN_EMAIL=${email}", js)
        # L3: the cap warning names the last failure and the loop
        # continues at a slow cadence instead of stopping forever.
        self.assertIn("last failure:", js)
        self.assertIn("5 * 60 * 1000", js)
        node = shutil.which("node")
        if node:
            r = subprocess.run([node, "--check",
                                str(REPO / "bin" / "nexuslocal.js")],
                               capture_output=True)
            self.assertEqual(r.returncode, 0,
                             r.stderr.decode(errors="replace"))


class Wave11UnitTests(unittest.TestCase):
    """Wave 11 (run-10 fixes): outcome-check helper, inflight lock,
    redeemprobe refund, and launcher source shape."""

    # -- F1/F2: _settings_outcome verifies the outcome --------------
    def test_w11_settings_outcome_shapes(self):
        import tempfile
        from pathlib import Path as _P
        saved = (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
                 server.RESTORE_KEY)
        orig_settings = dict(server._SETTINGS)
        try:
            with tempfile.TemporaryDirectory() as td:
                server.SETTINGS_PATH = _P(td) / "settings.json"
                server.SETTINGS_ENC_PATH = _P(td) / "settings.enc"
                server.RESTORE_KEY = "unit-restore-11"
                pred = lambda s: s.get("announcement") == "W11"
                # True + mutation is the live state -> ok.
                server._SETTINGS["announcement"] = "W11"
                self.assertEqual(
                    server._settings_outcome(True, pred), "ok")
                # True (generation-guard branch) but a concurrent save
                # superseded the mutation -> conflict, never ok.
                server._SETTINGS["announcement"] = "OTHER"
                self.assertEqual(
                    server._settings_outcome(True, pred), "conflict")
                # False, but the mutation already landed in the
                # mirror via a concurrent save -> honest ok, and the
                # rollback must NOT run.
                self.assertTrue(server._save_settings.__wrapped__
                                if hasattr(server._save_settings,
                                           "__wrapped__")
                                else server._save_settings())
                server._SETTINGS["announcement"] = "W11"
                self.assertTrue(server._save_settings())
                rolled = []
                self.assertEqual(
                    server._settings_outcome(
                        False, pred, lambda: rolled.append(1)), "ok")
                self.assertEqual(rolled, [])
                # False and genuinely unpersisted (the GHOST
                # mutation never landed anywhere) -> failed, with the
                # in-memory mutation rolled back.
                server._SETTINGS["announcement"] = "GHOST"
                self.assertEqual(
                    server._settings_outcome(
                        False,
                        lambda s: s.get("announcement") == "GHOST",
                        lambda: server._SETTINGS.__setitem__(
                            "announcement", "W11")),
                    "failed")
                self.assertEqual(server._SETTINGS["announcement"], "W11")
        finally:
            (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
             server.RESTORE_KEY) = saved
            server._SETTINGS.clear()
            server._SETTINGS.update(orig_settings)

    # -- F11: a refunded hit frees the budget -------------------------
    def test_w11_rl_refund(self):
        saved = dict(server._RL)
        try:
            server._RL.clear()
            key = "open:10.11.0.1"
            for _i in range(10):
                self.assertTrue(
                    server._rl_ok("redeemprobe", key, 10, 900))
            self.assertFalse(server._rl_ok("redeemprobe", key, 10, 900))
            server._rl_refund("redeemprobe", key)
            self.assertTrue(server._rl_ok("redeemprobe", key, 10, 900))
        finally:
            server._RL.clear()
            server._RL.update(saved)

    # -- F5: inflight prune/drop are identity-based and locked -------
    def test_w11_inflight_identity_and_prune(self):
        saved = list(server._INFLIGHT)
        try:
            server._INFLIGHT.clear()
            expired = server._inflight_add("old11")
            expired["ts"] = time.time() - 1000
            keep = server._inflight_add("keep11")
            self.assertEqual(server._inflight_n(), 1)
            self.assertIn(keep, server._INFLIGHT)
            self.assertNotIn(expired, server._INFLIGHT)
            # Two EQUAL entries: dropping one by identity must leave
            # the other (the old list.remove dropped by equality).
            server._INFLIGHT.clear()
            a = server._inflight_add("dup11", "groq", attempt=True)
            b = server._inflight_add("dup11", "groq", attempt=True)
            b["ts"] = a["ts"]
            self.assertEqual(a, b)
            server._inflight_drop(b)
            self.assertTrue(any(x is a for x in server._INFLIGHT))
            self.assertFalse(any(x is b for x in server._INFLIGHT))
            # Concurrent adds are never lost to a racing prune/count.
            server._INFLIGHT.clear()
            stale = server._inflight_add("stale11")
            stale["ts"] = time.time() - 1000

            def worker(n):
                for _i in range(50):
                    e = server._inflight_add("stress11")
                    server._inflight_n()
                    if n % 2:
                        server._inflight_drop(e)
            threads = [threading.Thread(target=worker, args=(n,))
                       for n in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(30)
            # Odd workers dropped theirs; even workers' 4x50 remain.
            self.assertEqual(server._inflight_n(user="stress11"), 200)
        finally:
            server._INFLIGHT.clear()
            server._INFLIGHT.extend(saved)

    # -- F3/F4/F6/F7-F10/F12-F15: source shape of the fixes ----------
    def test_w11_source_shapes(self):
        src = (APP / "server.py").read_text()
        self.assertIn("_INFLIGHT_LOCK", src)
        self.assertIn('def _lane_spend_ok', src)
        self.assertIn('_inflight_add("v1:test")', src)
        self.assertIn('_inflight_n(user="v1:test") > 4', src)
        self.assertIn("_settings_outcome(", src)
        self.assertIn("_rl_refund(\"redeemprobe\", _probe_key)", src)
        # F10: the first-run re-check sits AFTER the gateway-URL
        # validation in the /setup handler and inside _KEYS_LOCK.
        i_chk = src.index("if not _entry_keys_exist and key_path.exists():")
        i_gw = src.index("gateway URL must be a public http(s) address")
        self.assertGreater(i_chk, i_gw)
        self.assertIn("with _KEYS_LOCK:", src[max(0, i_chk - 200):i_chk])
        # F7-F9 sit inside the /setup rotation block (before the
        # audit line that follows it).
        i = src.index('"Shared keys replaced via /setup')
        block = src[max(0, i - 4000):i]
        self.assertIn("_PENDING_2FA.clear()", block)
        self.assertIn("_VIEW_GRANTS.clear()", block)
        self.assertIn('V1KEY_PATH.unlink()', block)
        js = (REPO / "bin" / "nexuslocal.js").read_text()
        self.assertIn("let shuttingDown = false", js)
        self.assertIn("shuttingDown = true", js)
        self.assertIn("emEmpty", js)
        self.assertIn("pmEmpty", js)
        self.assertIn("_depsMissing", js)
        node = shutil.which("node")
        if node:
            r = subprocess.run([node, "--check",
                                str(REPO / "bin" / "nexuslocal.js")],
                               capture_output=True)
            self.assertEqual(r.returncode, 0,
                             r.stderr.decode(errors="replace"))

    # -- F12/F13/F15: launcher against a stub engine -----------------
    def _launcher_fixture(self, env_text, with_express=True):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w11-launcher-"))
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        app = tmp / "app"
        srv = app / "engine" / "server"
        (srv / "dist").mkdir(parents=True)
        (app / "engine-data").mkdir()
        # Dashboard stub: just stays alive until killed.
        (app / "server.py").write_text(
            "import time\ntime.sleep(120)\n")
        (app / ".env").write_text(env_text)
        (srv / "package.json").write_text(json.dumps({
            "name": "stub", "dependencies": {
                "dotenv": "^17.0.0", "express": "^5.0.0"}}))
        (srv / "package-lock.json").write_text("{}")
        nm = srv / "node_modules"
        nm.mkdir()
        (nm / "dotenv").mkdir()
        # Wave 12 (L4): a bare directory is NOT an installed dep —
        # the gate probes package.json, so a fixture simulating an
        # installed tree must carry one per dependency.
        (nm / "dotenv" / "package.json").write_text("{}")
        (nm / "dotenv" / "index.js").write_text("")
        (nm / ".package-lock.json").write_text("{}")
        if with_express:
            (nm / "express").mkdir()
            (nm / "express" / "package.json").write_text("{}")
            (nm / "express" / "index.js").write_text("")
        (srv / "dist" / "index.js").write_text(
            "const http=require('http');const fs=require('fs');"
            "let claimed=false;"
            "http.createServer((req,res)=>{"
            "let b='';req.on('data',c=>b+=c);req.on('end',()=>{"
            "res.setHeader('Content-Type','application/json');"
            "if(req.url==='/api/auth/status'){"
            "res.end(JSON.stringify({needsSetup:!claimed}));}"
            "else if(req.url==='/api/auth/setup'){"
            "claimed=true;fs.writeFileSync(process.env.CLAIM_FILE,b);"
            "res.statusCode=201;res.end('{}');}"
            "else if(req.url==='/api/auth/login'){"
            "res.end(JSON.stringify({ok:true}));}"
            "else{res.statusCode=404;res.end('{}');}});"
            "}).listen(3001,'127.0.0.1');\n")
        return tmp

    def test_w11_launcher_empty_env_lines_and_shutdown(self):
        import signal as _signal
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        tmp = self._launcher_fixture(
            "ENGINE_ADMIN_EMAIL=\nENGINE_ADMIN_PASSWORD=\n")
        claim_file = tmp / "claim.json"
        env = dict(os.environ)
        env["CLAIM_FILE"] = str(claim_file)
        env["no_proxy"] = "127.0.0.1,localhost"
        # The launcher hardcodes engine port 3001, which the host's
        # real gateway already owns on this VM — run inside a private
        # network namespace (loopback only) so the stub engine binds
        # it cleanly and no real service is ever touched.
        if shutil.which("unshare"):
            cmd = ["unshare", "-n", "bash", "-c",
                   "ip link set lo up 2>/dev/null; exec "
                   f"{node} {tmp / 'bin' / 'nexuslocal.js'}"]
        else:
            cmd = [node, str(tmp / "bin" / "nexuslocal.js")]
        proc = subprocess.Popen(
            cmd, cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.time() + 30
            while time.time() < deadline and not claim_file.exists():
                if proc.poll() is not None:
                    break
                time.sleep(0.25)
            self.assertTrue(claim_file.exists(),
                            (tmp / "startup.log").read_text(
                                errors="replace")[-1500:])
            claim = json.loads(claim_file.read_text())
            # F13: the claim used the default email, not "".
            self.assertEqual(claim["email"], "owner@example.com")
            self.assertTrue(claim["password"])
            # F12: exactly ONE email and ONE password line, both
            # non-empty, and the password is the claimed one.
            env_txt = (tmp / "app" / ".env").read_text()
            emails = [ln for ln in env_txt.splitlines()
                      if ln.startswith("ENGINE_ADMIN_EMAIL=")]
            pws = [ln for ln in env_txt.splitlines()
                   if ln.startswith("ENGINE_ADMIN_PASSWORD=")]
            self.assertEqual(len(emails), 1, env_txt)
            self.assertEqual(len(pws), 1, env_txt)
            self.assertEqual(emails[0],
                             "ENGINE_ADMIN_EMAIL=owner@example.com")
            self.assertEqual(pws[0], "ENGINE_ADMIN_PASSWORD="
                             + claim["password"])
            # F15: SIGINT shutdown must not log the gateway-down
            # WARNING for the engine exit it causes itself.
            proc.send_signal(_signal.SIGINT)
            proc.wait(timeout=15)
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertIn("Engine stopped", log)
            self.assertNotIn("WARNING: engine process exited", log)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- F14: sentinel-surviving partial tree triggers npm ci -------
    def test_w11_launcher_npm_gate_partial_tree(self):
        node = shutil.which("node")
        npm = shutil.which("npm")
        if not node or not npm:
            self.skipTest("node/npm not available")
        tmp = self._launcher_fixture(
            "ENGINE_ADMIN_EMAIL=owner@example.com\n"
            "ENGINE_ADMIN_PASSWORD=abc123\n",
            with_express=False)
        proc = subprocess.Popen(
            [node, str(tmp / "bin" / "nexuslocal.js")],
            cwd=str(tmp), env=dict(os.environ),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.time() + 60
            seen = ""
            while time.time() < deadline:
                if (tmp / "startup.log").exists():
                    seen = (tmp / "startup.log").read_text(
                        errors="replace")
                    if "Installing engine dependencies" in seen:
                        break
                if proc.poll() is not None:
                    break
                time.sleep(0.5)
            self.assertIn("Installing engine dependencies", seen)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)


class AuditFixHarness(unittest.TestCase):
    """ Boots a fixture server (same pattern as test_hardening). """
    proc = None
    log = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-audit-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip or name == "chats":
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND: _hash_pw(FRIEND_PW),
                  "sharer1": _hash_pw(SHARED_PW),
                  "sharer2": _hash_pw(SHARED_PW),
                  "solo": _hash_pw(UNIQUE_PW)}
        encrypt_keys({"groq": "sk-shared-fake"}, MASTER, cls.tmp / "keys.enc")
        encrypt_keys(access, MASTER, cls.tmp / "users.enc")
        encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1", "PORT": str(cls.port),
            "NEXUS_RELAY_PORT": str(_free_port()),
            "NEXUS_RESTORE_KEY": RESTORE,
            "NEXUS_SYNC_TOKEN": SYNC_TOKEN,
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
                raise RuntimeError("server exited early:\n"
                                   + (cls.tmp / "server.log").read_text(
                                       errors="replace")[-2000:])
            try:
                status, _, _ = cls._req("GET", "/api/friend_blob")
                if status in (200, 403):
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
    def _req(cls, method, path, body=None, ck=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        hdrs = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body)
            hdrs.setdefault("Content-Type", "application/json")
        if ck:
            hdrs["Cookie"] = ck
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        set_cookie = resp.getheader("Set-Cookie") or ""
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload.decode(errors="replace")[:300]}
        return (resp.status, parsed,
                set_cookie.split(";")[0]
                if set_cookie.startswith("session=") else None)

    @classmethod
    def _login(cls, password):
        return cls._req("POST", "/api/login", {"password": password})

    @staticmethod
    def _wait_next_step():
        # Land just past the next 30s TOTP step boundary. Successful
        # verifications burn their step in a watermark shared by the
        # whole server process (and every test in this class), so a
        # code is only guaranteed fresh - strictly above every burn
        # so far - when it targets the step after a boundary wait.
        time.sleep(31 - (time.time() % 30))

    # -- friend_blob auth (finding: unauthenticated vault export) -----
    def test_01_friend_blob_requires_auth(self):
        status, _, _ = self._req("GET", "/api/friend_blob")
        self.assertEqual(status, 403)
        status, _, _ = self._req("GET", "/api/friend_blob",
                                 headers={"X-Sync-Token": "wrong-token"})
        self.assertEqual(status, 403)
        status, body, _ = self._req("GET", "/api/friend_blob",
                                    headers={"X-Sync-Token": SYNC_TOKEN})
        self.assertEqual(status, 200)
        self.assertIn("blob", body)

    # -- 2FA QR: GET discloses nothing any more ------------------------
    def test_02_2fa_qr_get_is_405(self):
        status, _, _ = self._req("GET", "/api/2fa_qr")
        self.assertEqual(status, 405)
        _, _, admin_cookie = self._login(MASTER)
        status, _, _ = self._req("GET", "/api/2fa_qr", ck=admin_cookie)
        self.assertEqual(status, 405)
        # POST without the master password proof is refused too.
        status, _, _ = self._req("POST", "/api/2fa_qr",
                                 {"master_pw": "not-the-master"},
                                 ck=admin_cookie)
        self.assertEqual(status, 401)

    # -- shared passwords fail closed (login confusion) ---------------
    def test_03_shared_password_login_fails_closed(self):
        status, body, _ = self._login(SHARED_PW)
        self.assertEqual(status, 401, body)
        status, body, cookie = self._login(UNIQUE_PW)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("label"), "solo")
        # …and a console add reusing a taken password is refused.
        _, _, admin_cookie = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "add", "label": "newbie", "password": SHARED_PW,
             "master_pw": MASTER}, ck=admin_cookie)
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))

    # -- invite race: one code, many parallel redeems -----------------
    def test_04_invite_redeem_is_atomic(self):
        _, _, admin_cookie = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "invite_create", "role": "friend", "days": 7,
             "master_pw": MASTER}, ck=admin_cookie)
        self.assertEqual(status, 200, body)
        code = body["code"]
        results = {}

        def redeem(i):
            results[i] = self._req(
                "POST", "/api/invite/redeem",
                {"label": f"racer{i}", "password": f"racer-pass-{i}-xyz",
                 "code": code})[0]
        # 4 racers (not 8): the endpoint's per-IP budget is 10/15 min
        # and the later wave-2 tests redeem from the same fixture IP.
        threads = [threading.Thread(target=redeem, args=(i,))
                   for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wins = [s for s in results.values() if s == 200]
        self.assertEqual(len(wins), 1, results)
        self.assertEqual([s for s in results.values() if s == 400].__len__(), 3,
                         results)
        access = json.loads((self.tmp / "access.json").read_text())
        racers = [k for k in access if k.startswith("racer")]
        self.assertEqual(len(racers), 1, racers)

    # -- My Keys: blank keeps, removal is explicit ---------------------
    def test_05_mykeys_blank_keeps_and_remove_deletes(self):
        _, _, cookie = self._login(FRIEND_PW)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "sk-fixture-one"}}, ck=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "", "google": "google-fixture-key"}},
            ck=cookie)
        self.assertEqual(status, 200, body)
        _, body, _ = self._req("POST", "/api/mykeys", {"action": "view"},
                               ck=cookie)
        self.assertIn("groq", body["configured"])   # blank kept it
        self.assertIn("google", body["configured"])
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW, "keys": {},
             "remove": ["groq"]}, ck=cookie)
        self.assertEqual(status, 200, body)
        _, body, _ = self._req("POST", "/api/mykeys", {"action": "view"},
                               ck=cookie)
        self.assertNotIn("groq", body["configured"])  # explicit removal
        self.assertIn("google", body["configured"])

    # ================= wave 2 (run-2 fixes) =================

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _invite(self, admin_cookie):
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend", "days": 7,
             "master_pw": MASTER}, admin_cookie)
        self.assertEqual(status, 200, body)
        return body["code"]

    # -- R2-5: a friend password must never equal the master ----------
    def test_06_master_password_collision_refused(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "add", "label": "collide1", "password": MASTER,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))
        code = self._invite(admin)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "collide2", "password": MASTER, "code": code})
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))
        # The refused redemption did not consume the invite.
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "collide2", "password": "collide-two-pass",
             "code": code})
        self.assertEqual(status, 200, body)
        # Password reset onto the master is refused the same way.
        status, body, _ = self._access(
            {"action": "friend_reset_pw", "label": FRIEND,
             "new_password": MASTER, "master_pw": MASTER}, admin)
        self.assertEqual(status, 400, body)
        self.assertIn("already in use", body.get("error", ""))
        # And the reverse: the master may not rotate onto a friend's.
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER,
             "new_master_pw": FRIEND_PW}, admin)
        self.assertEqual(status, 400, body)

    # -- R2-6/R2-7: no password oracle before invite validation;
    #    reserved labels are not registrable ---------------------------
    def test_07_invite_oracle_closed_and_reserved_labels(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "oracle1", "password": SHARED_PW,
             "code": "bogus-code-000000"})
        self.assertEqual(status, 400, body)
        self.assertIn("invite code is invalid", body.get("error", ""))
        self.assertNotIn("already in use", body.get("error", ""))
        code = self._invite(admin)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "_owner", "password": "owner-pass-123",
             "code": code})
        self.assertEqual(status, 400, body)
        self.assertIn("reserved", body.get("error", ""))
        # The reserved-label refusal did not consume the invite either.
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "invitedpal", "password": "invited-pass-1",
             "code": code})
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "add", "label": "_sys", "password": "sys-pass-123",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 400, body)

    # -- R2-10: provider governance binds transcription ---------------
    def test_08_transcribe_refused_when_groq_disabled(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_disabled": ["groq"]}}, admin)
        self.assertEqual(status, 200, body)
        try:
            _, _, cookie = self._login(UNIQUE_PW)
            status, body, _ = self._req(
                "POST", "/api/transcribe",
                {"audio": "data:audio/webm;base64,AAAA"}, ck=cookie)
            self.assertEqual(status, 403, body)
            self.assertIn("disabled", body.get("error", ""))
        finally:
            self._access(
                {"action": "settings_set", "master_pw": MASTER,
                 "patch": {"provider_disabled": []}}, admin)

    # -- R2-12: revoke scrubs settings-resident per-user state --------
    def test_09_revoke_scrubs_settings_state(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "add", "label": "scrubme",
             "password": "scrub-pass-123", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        self._login("scrub-pass-123")  # records terms_seen for scrubme
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"user_caps": {"scrubme": 5},
                       "suspended": ["scrubme"],
                       "oauth_links": [{"email": "scrub@example.co",
                                        "label": "scrubme"}]}}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "revoke", "label": "scrubme",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        saved = json.loads((self.tmp / "settings.json").read_text())
        self.assertNotIn("scrubme", saved.get("user_caps") or {})
        self.assertNotIn("scrubme", saved.get("suspended") or [])
        self.assertNotIn("scrubme", saved.get("terms_seen") or [])
        self.assertFalse(any(
            e.get("label") == "scrubme"
            for e in (saved.get("oauth_links") or [])
            if isinstance(e, dict)))
        # A re-created label starts clean.
        status, body, _ = self._access(
            {"action": "add", "label": "scrubme",
             "password": "scrub-pass-456", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access({"action": "list"}, admin)
        row = [a for a in body["access"] if a["label"] == "scrubme"]
        self.assertEqual(len(row), 1)
        self.assertFalse(row[0]["suspended"])
        self.assertIsNone(row[0]["cap"])
        self._access({"action": "revoke", "label": "scrubme",
                      "master_pw": MASTER}, admin)

    # -- R2-8: master rotation carries the owner integrations vault --
    def test_10_change_master_carries_owner_integrations(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "save", "service": "mailchimp",
             "fields": {"api_key": "fixturekey-us21"},
             "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER,
             "new_master_pw": MASTER_B}, admin)
        self.assertEqual(status, 200, body)
        _, _, admin_b = self._login(MASTER_B)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER_B}, ck=admin_b)
        self.assertEqual(status, 200, body)
        # The saved Mailchimp entry must have CARRIED OVER: present in
        # the vault that the NEW master opens (connected flag comes
        # from the decrypted store, not the static service list).
        self.assertTrue(
            (body.get("services") or {}).get("mailchimp", {})
            .get("connected"), body)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin_b)
        self.assertEqual(status, 401, body)
        # Rotate back for the rest of the class.
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER_B,
             "new_master_pw": MASTER}, admin_b)
        self.assertEqual(status, 200, body)
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        self.assertTrue(
            (body.get("services") or {}).get("mailchimp", {})
            .get("connected"), body)

    # -- R2-8b: save paths refuse a corrupt vault, never overwrite ----
    def test_11_strict_vault_saves_refuse_corruption(self):
        _, _, cookie = self._login(FRIEND_PW)
        upath = self.tmp / "userkeys" / f"{FRIEND}.enc"
        orig = upath.read_bytes()
        upath.write_bytes(b"garbage-not-a-vault")
        try:
            status, body, _ = self._req(
                "POST", "/api/mykeys",
                {"action": "save", "password": FRIEND_PW,
                 "keys": {"groq": "sk-should-not-land"}}, ck=cookie)
            self.assertEqual(status, 500, body)
            self.assertEqual(upath.read_bytes(), b"garbage-not-a-vault")
        finally:
            upath.write_bytes(orig)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "sk-fixture-restored"}}, ck=cookie)
        self.assertEqual(status, 200, body)
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        ipath = self.tmp / "userintegrations" / "_owner.enc"
        iorig = ipath.read_bytes()
        ipath.write_bytes(b"garbage-not-a-vault")
        try:
            status, body, _ = self._req(
                "POST", "/api/integrations",
                {"action": "save", "service": "mailchimp",
                 "fields": {"api_key": "otherkey-us21"},
                 "password": MASTER}, ck=admin)
            self.assertEqual(status, 500, body)
            self.assertEqual(ipath.read_bytes(), b"garbage-not-a-vault")
        finally:
            ipath.write_bytes(iorig)

    # -- R2-4: the QR encodes THIS enrollment's pending secret --------
    def test_12_qr_encodes_the_pending_secret(self):
        _, _, admin = self._login(MASTER)

        def _qr_png():
            conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                              timeout=30)
            conn.request("POST", "/api/2fa_qr",
                         body=json.dumps({"master_pw": MASTER}),
                         headers={"Content-Type": "application/json",
                                  "Cookie": admin})
            resp = conn.getresponse()
            png = resp.read()
            ctype = resp.getheader("Content-Type") or ""
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIn("image/png", ctype)
            return png

        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret1 = body["secret"]
        png1 = _qr_png()
        # Re-enabling replaces the pending secret (no code needed while
        # still pending) — the second QR must encode the NEW secret.
        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret2 = body["secret"]
        self.assertNotEqual(secret1, secret2)
        png2 = _qr_png()
        # The wave-1 defect encoded a constant string, so both QRs were
        # identical. Different pending secrets must give different QRs.
        self.assertNotEqual(png1, png2)
        # Clean up: confirm + disable the second enrollment.
        status, body, _ = self._access(
            {"action": "2fa_confirm", "master_pw": MASTER,
             "code": _totp(secret2)}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "2fa_disable", "master_pw": MASTER,
             "code": _totp(secret2, 1)}, admin)
        self.assertEqual(status, 200, body)

    # -- R3-5: a password reset must not resurrect a revoked friend --
    def test_13_reset_pw_cannot_resurrect_revoked_friend(self):
        _, _, admin = self._login(MASTER)
        # A crowd of friends widens the reset handler's pre-lock
        # password scan (one PBKDF2 verify per stored friend), which
        # is the window in which the revoke below lands mid-reset.
        for i in range(10):
            status, body, _ = self._access(
                {"action": "add", "label": f"crowd{i}",
                 "password": f"crowd-pass-{i}-zz", "master_pw": MASTER},
                admin)
            self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "add", "label": "racevictim",
             "password": "victim-pass-123", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        outcome = {}

        def do_reset():
            outcome["reset"] = self._access(
                {"action": "friend_reset_pw", "label": "racevictim",
                 "new_password": "reset-pass-456", "master_pw": MASTER},
                admin)[0]
        t = threading.Thread(target=do_reset)
        t.start()
        time.sleep(0.5)  # the reset is inside its pre-lock scan now
        status, body, _ = self._access(
            {"action": "revoke", "label": "racevictim",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        t.join(timeout=30)
        self.assertFalse(t.is_alive())
        # No assertion on the reset's own status: 404 (revoke won) and
        # 200 (reset landed first, revoke then removed the account)
        # are both correct. The bug's signature is resurrection - the
        # victim must stay gone either way.
        status, body, _ = self._access({"action": "list"}, admin)
        self.assertNotIn("racevictim",
                         [a["label"] for a in body["access"]])
        status, body, _ = self._login("reset-pass-456")
        self.assertEqual(status, 401, body)
        for i in range(10):
            self._access({"action": "revoke", "label": f"crowd{i}",
                          "master_pw": MASTER}, admin)

    # -- R4: cleanup incarnation guards keep the NORMAL path working -
    def test_14_reset_and_revoke_cleanup_still_remove_files(self):
        # The run-4 guards make the reset/revoke cleanups fire only
        # while the account is still the incarnation they acted on.
        # This pins the other direction: in the normal (unraced) case
        # the cleanup must still remove the vault + integrations
        # files - an over-eager guard would leave them behind. (The
        # races themselves are fixture-proven by the audit agents;
        # their windows are not HTTP-reproducible in this harness.)
        upath = self.tmp / "userkeys" / f"{FRIEND}.enc"
        ipath = self.tmp / "userintegrations" / f"{FRIEND}.enc"
        _, _, cookie = self._login(FRIEND_PW)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "sk-cleanme0"}}, ck=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(upath.exists())
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": FRIEND_PW}, ck=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "save", "service": "mailchimp",
             "fields": {"api_key": "cleanme-us21"},
             "password": FRIEND_PW}, ck=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(ipath.exists())
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "friend_reset_pw", "label": FRIEND,
             "new_password": "reset-pass-789", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        self.assertFalse(upath.exists())
        self.assertFalse(ipath.exists())
        # Rebuild both files under the new password, then revoke.
        _, _, cookie = self._login("reset-pass-789")
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": "reset-pass-789",
             "keys": {"groq": "sk-cleanme"}}, ck=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "unlock", "password": "reset-pass-789"},
            ck=cookie)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/integrations",
            {"action": "save", "service": "mailchimp",
             "fields": {"api_key": "cleanme2-us21"},
             "password": "reset-pass-789"}, ck=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(upath.exists())
        self.assertTrue(ipath.exists())
        status, body, _ = self._access(
            {"action": "revoke", "label": FRIEND,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        self.assertFalse(upath.exists())
        self.assertFalse(ipath.exists())
        status, body, _ = self._login("reset-pass-789")
        self.assertEqual(status, 401, body)

    # -- R2-14: factory reset wipes usage + the telemetry mirror ------
    # -- run-5: /v1 keys die with a factory reset --------------------
    def test_98_factory_reset_revokes_v1_key(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "wave5probe",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        v1key = body["key"]
        hdr = {"Authorization": f"Bearer {v1key}"}
        status, _, _ = self._req("GET", "/v1/models", headers=hdr)
        self.assertEqual(status, 200)
        status, body, _ = self._access(
            {"action": "factory_reset", "master_pw": MASTER,
             "confirm": "RESET"}, admin)
        self.assertEqual(status, 200, body)
        self.assertFalse((self.tmp / "v1key.enc").exists())
        status, _, _ = self._req("GET", "/v1/models", headers=hdr)
        # Dead either way: 401 (key rejected) or 404 (the post-reset
        # server has no key store at all, so the surface is gone).
        self.assertIn(status, (401, 404))

    # -- run-5: provider_limits bind /v1 exactly like chat -----------
    def test_15_v1_provider_limits_enforced(self):
        import server as srv
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "wave5limits",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        hdr = {"Authorization": f"Bearer {body['key']}"}
        status, _, _ = self._req("GET", "/v1/models", headers=hdr)
        self.assertEqual(status, 200)
        limits = {lane: 3 for lane, _m in srv._V1_LANES}
        # Seed today's usage directly in the fixture's usage file:
        # every lane already spent 5 requests, so a limit of 3 must
        # block them all pre-flight. (Limit 0 disables the cap in
        # the shared predicate, exactly as in chat - not used here.)
        import datetime as _dt
        with open(self.tmp / "usage.jsonl", "a") as f:
            for lane, _m in srv._V1_LANES:
                for _ in range(5):
                    f.write(json.dumps(
                        {"ts": _dt.datetime.now().isoformat(),
                         "provider": lane, "prompt_tokens": 0,
                         "completion_tokens": 0}) + "\n")
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_limits": limits}}, admin)
        self.assertEqual(status, 200, body)
        try:
            t0 = time.time()
            status, body, _ = self._req(
                "POST", "/v1/chat/completions",
                {"model": "nexus-auto",
                 "messages": [{"role": "user", "content": "hi"}]},
                headers=hdr)
            # Every lane is limit-blocked pre-flight: a fast 502 with
            # no upstream fetch (the unit test proves zero relay calls
            # and the unified metering name-for-name).
            self.assertEqual(status, 502, body)
            self.assertLess(time.time() - t0, 20)
        finally:
            self._access({"action": "settings_set", "master_pw": MASTER,
                          "patch": {"provider_limits": {}}}, admin)

    # -- run-5: a pending 2FA completion dies with master rotation ---
    def test_17_pending_2fa_dies_with_master_rotation(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret = body["secret"]
        self._wait_next_step()
        status, body, _ = self._access(
            {"action": "2fa_confirm", "master_pw": MASTER,
             "code": _totp(secret, 1)}, admin)
        self.assertEqual(status, 200, body)
        # Password step of a fresh login mints a pending completion.
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 200, body)
        tmp_b = body["tmp"]
        # Rotate the master password (admin cookie predates 2FA and
        # stays valid - enabling never signed it out).
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER,
             "new_master_pw": MASTER_B}, admin)
        self.assertEqual(status, 200, body)
        # The pre-rotation pending must not complete any more, even
        # with a genuinely valid code for the next step.
        status, body, _ = self._req(
            "POST", "/api/login", {"tmp": tmp_b, "code": _totp(secret, 1)})
        self.assertEqual(status, 401, body)
        # Cleanup: full login under the new password, disable 2FA,
        # rotate back - in that order, one step-boundary wait so the
        # disable code's step clears the watermark.
        status, body, _ = self._login(MASTER_B)
        tmp_c = body["tmp"]
        self._wait_next_step()
        status, body, cookie_c = self._req(
            "POST", "/api/login", {"tmp": tmp_c, "code": _totp(secret, 1)})
        self.assertEqual(status, 200, body)
        self._wait_next_step()
        status, body, _ = self._access(
            {"action": "2fa_disable", "master_pw": MASTER_B,
             "code": _totp(secret, 1)}, cookie_c)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER_B,
             "new_master_pw": MASTER}, cookie_c)
        self.assertEqual(status, 200, body)

    # -- run-5: vault clear/add reach the friend's LIVE session ------
    def test_18_vault_clear_and_add_refresh_live_session(self):
        _, _, admin = self._login(MASTER)
        # test_14 leaves friendone revoked - re-provision so this
        # test is order-independent (add simply fails if it exists).
        self._access({"action": "add", "label": FRIEND,
                      "password": FRIEND_PW, "master_pw": MASTER}, admin)
        _, _, friend = self._login(FRIEND_PW)

        def _cohere_configured():
            status, body, _ = self._req("GET", "/api/quotas", ck=friend)
            self.assertEqual(status, 200, body)
            for p in body["providers"]:
                if p["provider"] == "cohere":
                    return p["key_configured"]
            raise AssertionError("cohere missing from quotas")

        self.assertFalse(_cohere_configured())
        status, body, _ = self._access(
            {"action": "friend_key_add", "label": FRIEND,
             "provider": "cohere", "key": "friend-cohere-1",
             "friend_pw": FRIEND_PW, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        # No re-login: the live session's cached vault must see it.
        self.assertTrue(_cohere_configured())
        status, body, _ = self._access(
            {"action": "friend_vault_clear", "label": FRIEND,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        # And a clear must stop the cleared key in the same session.
        self.assertFalse(_cohere_configured())

    # -- run-5: the guest /setup mint honors suspension --------------
    def test_19_setup_mint_refused_while_suspended(self):
        _, _, admin = self._login(MASTER)
        # test_14 leaves friendone revoked - re-provision first.
        self._access({"action": "add", "label": FRIEND,
                      "password": FRIEND_PW, "master_pw": MASTER}, admin)

        def _setup_post():
            conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                              timeout=30)
            conn.request(
                "POST", "/setup",
                body=urllib.parse.urlencode({"password": FRIEND_PW}),
                headers={"Content-Type":
                         "application/x-www-form-urlencoded"})
            resp = conn.getresponse()
            resp.read()
            cookie = resp.getheader("Set-Cookie") or ""
            conn.close()
            return (resp.status,
                    cookie.split(";")[0] if cookie.startswith("session=")
                    else None)

        status, body, _ = self._access(
            {"action": "friend_set_suspended", "label": FRIEND,
             "on": True, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        try:
            status, cookie = _setup_post()
            self.assertEqual(status, 403)
            self.assertIsNone(cookie)
        finally:
            self._access(
                {"action": "friend_set_suspended", "label": FRIEND,
                 "on": False, "master_pw": MASTER}, admin)
        # Control: unsuspended, the same request mints a session.
        status, cookie = _setup_post()
        self.assertEqual(status, 302)
        self.assertTrue(cookie)

    # -- run-5: a view pass gets no session forensics ----------------
    def test_20_viewer_list_strips_session_metadata(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "friend_role_set", "label": "solo",
             "role": "viewer", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        try:
            _, _, solo = self._login(UNIQUE_PW)
            status, body, _ = self._access({"action": "list"}, solo)
            self.assertEqual(status, 200, body)
            self.assertTrue(body["sessions"])
            for s in body["sessions"]:
                self.assertNotIn("sid", s)
                self.assertNotIn("ip", s)
                self.assertNotIn("ua", s)
            status, body, _ = self._access({"action": "list"}, admin)
            self.assertEqual(status, 200, body)
            self.assertIn("sid", body["sessions"][0])
        finally:
            self._access(
                {"action": "friend_role_set", "label": "solo",
                 "role": "friend", "master_pw": MASTER}, admin)

    # -- run-5: the TOTP guess budget is account-wide ----------------
    def test_21_totp_guess_budget_is_global(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret = body["secret"]
        self._wait_next_step()
        status, body, _ = self._access(
            {"action": "2fa_confirm", "master_pw": MASTER,
             "code": _totp(secret, 1)}, admin)
        self.assertEqual(status, 200, body)
        wrong = "000000" if _totp(secret) != "000000" else "111111"
        tmps = []
        for _ in range(3):
            status, body, _ = self._login(MASTER)
            self.assertEqual(status, 200, body)
            tmps.append(body["tmp"])
        # Ten wrong guesses spread across three pendings: under the
        # old per-token cap every one is a plain 401 and an eleventh
        # guess (a fourth pending's budget) would still be open.
        for i in range(10):
            status, body, _ = self._req(
                "POST", "/api/login",
                {"tmp": tmps[i % 3], "code": wrong})
            self.assertEqual(status, 401, (i, body))
        status, body, _ = self._login(MASTER)
        tmp_d = body["tmp"]
        status, body, _ = self._req(
            "POST", "/api/login", {"tmp": tmp_d, "code": wrong})
        self.assertEqual(status, 429, body)
        # Cleanup: the budget this test just exhausted also blocks
        # fresh login completions (by design), so disable 2FA with
        # the admin session minted at the top of this test, before
        # 2FA was enabled - enabling never signed it out. The code
        # only has to clear the confirm's watermark step.
        self._wait_next_step()
        status, body, _ = self._access(
            {"action": "2fa_disable", "master_pw": MASTER,
             "code": _totp(secret, 1)}, admin)
        self.assertEqual(status, 200, body)

    def test_99_factory_reset_wipes_usage_and_telemetry(self):
        usage = self.tmp / "usage.jsonl"
        usage.write_text('{"provider": "groq", "user": "solo"}\n')
        tele = self.tmp / "telemetry.enc"
        tele.write_bytes(b"pretend-mirror-bytes")
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "factory_reset", "master_pw": MASTER,
             "confirm": "RESET"}, admin)
        self.assertEqual(status, 200, body)
        self.assertEqual(usage.read_text(), "")
        self.assertFalse(tele.exists())

    # -- run-6: /v1 key management needs the master proof -----------
    def test_22_v1_access_requires_master_proof(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "nopw"}, admin)
        self.assertEqual(status, 401, body)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "wrongpw",
                                     "master_pw": "not-the-master"},
                                    admin)
        self.assertEqual(status, 401, body)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "withpw",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        kid = body["id"]
        status, body, _ = self._req("POST", "/api/v1-access/delete",
                                    {"id": kid}, admin)
        self.assertEqual(status, 401, body)
        status, body, _ = self._req("POST", "/api/v1-access/delete",
                                    {"id": kid, "master_pw": MASTER},
                                    admin)
        self.assertEqual(status, 200, body)

    # -- run-6: parallel chat saves must all survive -----------------
    def test_23_concurrent_chat_saves_all_survive(self):
        import concurrent.futures as cf
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": FRIEND,
                      "password": FRIEND_PW, "master_pw": MASTER}, admin)
        _, _, friend = self._login(FRIEND_PW)
        barrier = threading.Barrier(6)

        def _save(i):
            barrier.wait(timeout=10)
            return self._req("POST", "/api/chats",
                             {"action": "save",
                              "messages": [{"r": "user",
                                            "t": f"parallel chat {i}"}]},
                             ck=friend)
        with cf.ThreadPoolExecutor(6) as ex:
            results = list(ex.map(_save, range(6)))
        ids = set()
        for status, body, _ in results:
            self.assertEqual(status, 200, body)
            ids.add(body["id"])
        self.assertEqual(len(ids), 6)
        status, body, _ = self._req("POST", "/api/chats",
                                    {"action": "list"}, ck=friend)
        self.assertEqual(status, 200, body)
        have = {c["id"] for c in body["chats"]}
        self.assertTrue(ids <= have,
                        f"lost chats: {sorted(ids - have)}")

    # -- run-6: parallel My Keys saves merge, not clobber ------------
    def test_24_concurrent_mykeys_saves_both_survive(self):
        import concurrent.futures as cf
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": FRIEND,
                      "password": FRIEND_PW, "master_pw": MASTER}, admin)
        _, _, friend = self._login(FRIEND_PW)
        barrier = threading.Barrier(2)

        def _save(keys):
            barrier.wait(timeout=10)
            return self._req("POST", "/api/mykeys",
                             {"action": "save", "password": FRIEND_PW,
                              "keys": keys}, ck=friend)
        with cf.ThreadPoolExecutor(2) as ex:
            results = list(ex.map(_save, [{"groq": "g-key-1"},
                                          {"cohere": "c-key-2"}]))
        for status, body, _ in results:
            self.assertEqual(status, 200, body)
        status, body, _ = self._req("POST", "/api/mykeys",
                                    {"action": "view"}, ck=friend)
        self.assertEqual(status, 200, body)
        self.assertIn("groq", body["configured"])
        self.assertIn("cohere", body["configured"])

    # -- run-6: My Keys value length cap ------------------------------
    def test_25_mykeys_value_too_long_refused(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": FRIEND,
                      "password": FRIEND_PW, "master_pw": MASTER}, admin)
        _, _, friend = self._login(FRIEND_PW)
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "x" * 600}}, ck=friend)
        self.assertEqual(status, 400, body)

    # -- run-6: settings validator survives hostile numbers ----------
    def test_26_settings_validator_survives_nonfinite(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_limits": {"groq": float("nan")}}}, admin)
        self.assertNotEqual(status, 500, body)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"daily_cap": True}}, admin)
        self.assertEqual(status, 400, body)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"session_minutes": 60.0}}, admin)
        self.assertEqual(status, 400, body)

    # -- run-6: a moderator cannot revoke the owner's session ---------
    def test_27_moderator_cannot_revoke_admin_session(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": FRIEND,
                      "password": FRIEND_PW, "master_pw": MASTER}, admin)
        status, body, _ = self._access(
            {"action": "friend_role_set", "label": FRIEND,
             "role": "moderator", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        _, _, mod = self._login(FRIEND_PW)
        status, body, _ = self._access({"action": "list"}, admin)
        self.assertEqual(status, 200, body)
        admin_sid = body["you"]["sid"]
        status, body, _ = self._access(
            {"action": "session_revoke", "sid": admin_sid}, mod)
        self.assertEqual(status, 403, body)
        # The owner's session is untouched.
        status, body, _ = self._access({"action": "list"}, admin)
        self.assertEqual(status, 200, body)
        # Reset the role for the rest of the class.
        self._access({"action": "friend_role_set", "label": FRIEND,
                      "role": "friend", "master_pw": MASTER}, admin)

    # -- run-6: HEAD must not mint a viewer session -------------------
    def test_28_head_view_mints_nothing(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "viewpass_create", "name": "headprobe",
             "hours": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        url = body["url"]
        status, _, cookie = self._req("HEAD", url)
        self.assertEqual(status, 405)
        self.assertIsNone(cookie)
        # Control: the same link over GET still works exactly once.
        status, _, cookie = self._req("GET", url)
        self.assertEqual(status, 302)
        self.assertIsNotNone(cookie)

    # -- run-6: view grants die with a master rotation ----------------
    def test_29_view_grant_dies_with_change_master(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "viewpass_create", "name": "rotprobe",
             "hours": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        url = body["url"]
        status, _, cookie = self._req("GET", url)
        self.assertEqual(status, 302)
        self.assertIsNotNone(cookie)
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER,
             "new_master_pw": MASTER_B}, admin)
        self.assertEqual(status, 200, body)
        # The pre-rotation link must not mint a session any more.
        status, _, cookie = self._req("GET", url)
        self.assertIsNone(cookie)
        # Rotate back for the rest of the class.
        _, _, admin_b = self._login(MASTER_B)
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER_B,
             "new_master_pw": MASTER}, admin_b)
        self.assertEqual(status, 200, body)

    # -- run-6 critic: My Keys entry cap actually runs on a save -----
    def test_30_mykeys_entry_cap_enforced(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": FRIEND,
                      "password": FRIEND_PW, "master_pw": MASTER}, admin)
        _, _, friend = self._login(FRIEND_PW)
        many = {f"k{i:03d}": "v" for i in range(201)}
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW, "keys": many},
            ck=friend)
        self.assertEqual(status, 400, body)
        # Nothing was saved by the refused save.
        status, body, _ = self._req("POST", "/api/mykeys",
                                    {"action": "view"}, ck=friend)
        self.assertEqual(status, 200, body)
        self.assertNotIn("k000", body["configured"])
        # A normal save still works afterwards.
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": FRIEND_PW,
             "keys": {"groq": "g-key-30"}}, ck=friend)
        self.assertEqual(status, 200, body)

    # -- run-6: settings_get hides invite hashes; restore skips -------
    def test_31_settings_get_redacts_and_restore_skips(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "invite_create", "master_pw": MASTER,
             "days": 7}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access({"action": "settings_get"}, admin)
        self.assertEqual(status, 200, body)
        invites = (body.get("settings") or {}).get("invites") or []
        self.assertTrue(invites)
        for inv in invites:
            self.assertEqual(inv.get("h"), "")
        backup = {"settings": {"daily_cap": 7,
                                "invites": [{"h": "deadbeef"}],
                                "roles": {"x": "viewer"}}}
        status, body, _ = self._access(
            {"action": "settings_restore_preview", "master_pw": MASTER,
             "backup": backup}, admin)
        self.assertEqual(status, 200, body)
        self.assertIn("invites", body.get("skipped") or [])
        self.assertTrue(any(d["key"] == "daily_cap"
                            for d in body.get("diff") or []))

    # -- run-6 critic: stored v1 keys die with change_master ----------
    def test_32_v1_keys_die_with_change_master(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "rotprobe32",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        hdr = {"Authorization": f"Bearer {body['key']}"}
        status, _, _ = self._req("GET", "/v1/models", headers=hdr)
        self.assertEqual(status, 200)
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER,
             "new_master_pw": MASTER_B}, admin)
        self.assertEqual(status, 200, body)
        # The pre-rotation key no longer authenticates (401, or 404
        # when no key source remains at all).
        status, _, _ = self._req("GET", "/v1/models", headers=hdr)
        self.assertIn(status, (401, 404))
        _, _, admin_b = self._login(MASTER_B)
        status, body, _ = self._req("GET", "/api/v1-access", ck=admin_b)
        self.assertEqual(status, 200, body)
        self.assertFalse(any(k.get("source") == "generated"
                             for k in body.get("keys") or []))
        # Rotate back for the rest of the class.
        status, body, _ = self._access(
            {"action": "change_master", "master_pw": MASTER_B,
             "new_master_pw": MASTER}, admin_b)
        self.assertEqual(status, 200, body)

    # -- run-7: moderator password probes are capped -----------------
    def test_33_moderator_pwprobe_bucket(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": "probetarget",
                      "password": "target-pw-33", "master_pw": MASTER}, admin)
        self._access({"action": "add", "label": "probebystander",
                      "password": "bystand-pw-33", "master_pw": MASTER}, admin)
        self._access({"action": "add", "label": "probemod",
                      "password": "mod-pw-33", "master_pw": MASTER}, admin)
        status, body, _ = self._access(
            {"action": "friend_role_set", "label": "probemod",
             "role": "moderator", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        _, _, mod = self._login("mod-pw-33")
        # Oracle hit: the bystander's password reads "already in use".
        status, body, _ = self._access(
            {"action": "friend_reset_pw", "label": "probetarget",
             "new_password": "bystand-pw-33"}, mod)
        self.assertEqual(status, 400, body)
        # Misses land (and reset) — until the probe budget runs out.
        for i in range(9):
            status, body, _ = self._access(
                {"action": "friend_reset_pw", "label": "probetarget",
                 "new_password": f"cand-{i}-pw-33"}, mod)
            self.assertEqual(status, 200, (i, body))
        status, body, _ = self._access(
            {"action": "friend_reset_pw", "label": "probetarget",
             "new_password": "cand-99-pw-33"}, mod)
        self.assertEqual(status, 429, body)

    # -- run-7: moderators cannot reset or clear a peer moderator ----
    def test_34_moderator_peer_reset_and_clear_guarded(self):
        _, _, admin = self._login(MASTER)
        for label, pw in (("modone34", "modone-pw-34"),
                          ("modtwo34", "modtwo-pw-34"),
                          ("plain34", "plain-pw-34")):
            self._access({"action": "add", "label": label,
                          "password": pw, "master_pw": MASTER}, admin)
        for label in ("modone34", "modtwo34"):
            status, body, _ = self._access(
                {"action": "friend_role_set", "label": label,
                 "role": "moderator", "master_pw": MASTER}, admin)
            self.assertEqual(status, 200, body)
        _, _, mod = self._login("modone-pw-34")
        status, body, _ = self._access(
            {"action": "friend_reset_pw", "label": "modtwo34",
             "new_password": "seized-pw-34"}, mod)
        self.assertEqual(status, 403, body)
        status, body, _ = self._access(
            {"action": "friend_vault_clear", "label": "modtwo34"}, mod)
        self.assertEqual(status, 403, body)
        # Control: a plain friend is still fair game for a moderator.
        status, body, _ = self._access(
            {"action": "friend_reset_pw", "label": "plain34",
             "new_password": "plain-new-34"}, mod)
        self.assertEqual(status, 200, body)

    # -- run-7: revoke proves the master before the label lookup -----
    def test_35_revoke_ghost_wrong_master_refused(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "revoke", "label": "ghost35",
             "master_pw": "wrong-pw-35"}, admin)
        self.assertEqual(status, 401, body)
        self._access({"action": "add", "label": "real35",
                      "password": "real-pw-35", "master_pw": MASTER}, admin)
        status, body, _ = self._access(
            {"action": "revoke", "label": "real35",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "revoke", "label": "real35",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 404, body)

    # -- run-7: console key-add honors the vault entry cap -----------
    def test_36_friend_key_add_respects_cap(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": "capfriend36",
                      "password": "cap-pw-36", "master_pw": MASTER}, admin)
        _, _, friend = self._login("cap-pw-36")
        keys = {f"k{i:03d}": "v" for i in range(200)}
        status, body, _ = self._req(
            "POST", "/api/mykeys",
            {"action": "save", "password": "cap-pw-36", "keys": keys},
            ck=friend)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "friend_key_add", "label": "capfriend36",
             "provider": "onemore", "key": "x",
             "friend_pw": "cap-pw-36", "master_pw": MASTER}, admin)
        self.assertEqual(status, 400, body)

    # -- run-7: chat eviction at 50 is disclosed ----------------------
    def test_37_chats_eviction_disclosed(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": "chatfriend37",
                      "password": "chat-pw-37", "master_pw": MASTER}, admin)
        _, _, friend = self._login("chat-pw-37")
        last = None
        for i in range(51):
            status, body, _ = self._req(
                "POST", "/api/chats",
                {"action": "save",
                 "messages": [{"r": "user", "t": f"chat {i}"}]},
                ck=friend)
            self.assertEqual(status, 200, body)
            last = body
        self.assertIn("evicted", last)
        self.assertTrue(last["evicted"])
        status, body, _ = self._req("POST", "/api/chats",
                                    {"action": "list"}, ck=friend)
        self.assertEqual(len(body["chats"]), 50)

    # -- run-6: password proofs share one failure budget --------------
    # Named to sort last in this class: tripping the fixture server's
    # master-proof budget must not starve any later master-gated call.
    @classmethod
    def _form(cls, path, fields, ck=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        if ck:
            hdrs["Cookie"] = ck
        conn.request("POST", path,
                     body=urllib.parse.urlencode(fields), headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload.decode(errors="replace")[:300]}
        return resp.status, parsed

    # -- run-8: /setup replacement requires the current master -------
    def test_38_setup_requires_current_master(self):
        _, _, admin = self._login(MASTER)
        # No current_master at all: refused, vault untouched.
        status, body = self._form("/setup", {
            "password": "attacker-new-38", "confirm": "attacker-new-38",
            "k_groq": "sk-attacker"}, admin)
        self.assertEqual(status, 401, body)
        # Wrong current master: refused.
        status, body = self._form("/setup", {
            "password": "attacker-new-38", "confirm": "attacker-new-38",
            "current_master": "not-the-master-38",
            "k_groq": "sk-attacker"}, admin)
        self.assertEqual(status, 401, body)
        # The real master still signs in (vault unchanged).
        status, _, _ = self._login(MASTER)
        self.assertEqual(status, 200)
        # A proven replacement works and the new password takes over.
        status, body = self._form("/setup", {
            "password": MASTER_B, "confirm": MASTER_B,
            "current_master": MASTER,
            "k_groq": "sk-rotated-38"}, admin)
        self.assertEqual(status, 302, body)
        status, _, _ = self._login(MASTER)
        self.assertEqual(status, 401)
        _, _, admin_b = self._login(MASTER_B)
        self.assertTrue(admin_b)
        # Rotate back for the rest of the class.
        status, body = self._form("/setup", {
            "password": MASTER, "confirm": MASTER,
            "current_master": MASTER_B,
            "k_groq": "sk-shared-fake"}, admin_b)
        self.assertEqual(status, 302, body)
        status, _, _ = self._login(MASTER)
        self.assertEqual(status, 200)

    # -- run-8: cap=1 admits the first request of the day -------------
    def test_39_daily_cap_one_admits_first_request(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": "capone39",
                      "password": "capone-pw-39", "master_pw": MASTER}, admin)
        status, body, _ = self._access(
            {"action": "friend_set_cap", "label": "capone39",
             "cap": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        _, _, friend = self._login("capone-pw-39")
        # Admission is the assertion: wave 8 counted the request's
        # own reservation against it, so cap=1 refused the very
        # first chat with the cap's 429. Upstream fails on fixture
        # keys — anything but that 429 proves admission.
        status, body, _ = self._req("POST", "/api/chat",
                                    {"provider": "groq", "model": "x",
                                     "message": "hi"}, ck=friend)
        self.assertNotEqual(status, 429, body)
        self.assertNotIn("daily limit reached", json.dumps(body))

    # -- run-8: moderator cap/usage/session peer guards ---------------
    def test_40_moderator_cap_usage_session_guards(self):
        _, _, admin = self._login(MASTER)
        for label, pw in (("modone40", "modone-pw-40"),
                          ("modtwo40", "modtwo-pw-40"),
                          ("plain40", "plain-pw-40")):
            self._access({"action": "add", "label": label,
                          "password": pw, "master_pw": MASTER}, admin)
        for label in ("modone40", "modtwo40"):
            status, body, _ = self._access(
                {"action": "friend_role_set", "label": label,
                 "role": "moderator", "master_pw": MASTER}, admin)
            self.assertEqual(status, 200, body)
        _, _, mod = self._login("modone-pw-40")
        _, _, mod2 = self._login("modtwo-pw-40")
        # Self-escalation and peer edits refused; plain friend is fine.
        status, body, _ = self._access(
            {"action": "friend_set_cap", "label": "modone40",
             "cap": 100000}, mod)
        self.assertEqual(status, 403, body)
        status, body, _ = self._access(
            {"action": "friend_set_cap", "label": "modtwo40",
             "cap": 100000}, mod)
        self.assertEqual(status, 403, body)
        status, body, _ = self._access(
            {"action": "friend_set_cap", "label": "plain40",
             "cap": 50}, mod)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "friend_usage_reset", "label": "modtwo40"}, mod)
        self.assertEqual(status, 403, body)
        # A peer moderator's session cannot be revoked either.
        status, body, _ = self._access({"action": "list"}, admin)
        peer = [s for s in body.get("sessions") or []
                if s.get("label") == "modtwo40"]
        self.assertTrue(peer, body)
        status, body, _ = self._access(
            {"action": "session_revoke", "sid": peer[0]["sid"]}, mod)
        self.assertEqual(status, 403, body)
        status, body, _ = self._access({"action": "list"}, mod2)
        self.assertEqual(status, 200, body)

    # -- run-8: redeem taken-verdicts are budgeted per invite code -----
    def test_41_redeem_taken_oracle_budgeted_per_code(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend", "days": 1,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        code = body["code"]
        # Taken-password verdicts from ROTATING source addresses:
        # the per-IP route ledger never trips (each last XFF hop is
        # fresh), but the per-code budget caps verdicts at 10.
        for i in range(10):
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": f"probe41_{i}", "password": SHARED_PW,
                 "code": code},
                headers={"X-Forwarded-For": f"10.41.0.{i + 1}"})
            self.assertEqual(status, 400, (i, body))
            self.assertIn("already in use", json.dumps(body))
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "probe41_z", "password": SHARED_PW, "code": code},
            headers={"X-Forwarded-For": "10.41.9.9"})
        self.assertEqual(status, 429, body)
        # Run-9 (S5): the budget is consumed BEFORE the verdict, so
        # a FREE password on the exhausted code gets the same 429 —
        # pre-fix it sailed through to account creation, which made
        # the 429 itself the taken-verdict (the oracle this budget
        # exists to close). The refusals still never consume the
        # invite itself, and the legitimate flow works within
        # budget on a fresh code.
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "real41", "password": "real41-unique-pw",
             "code": code},
            headers={"X-Forwarded-For": "10.41.9.10"})
        self.assertEqual(status, 429, body)
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend", "days": 1,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "real41", "password": "real41-unique-pw",
             "code": body["code"]},
            headers={"X-Forwarded-For": "10.41.9.11"})
        self.assertEqual(status, 200, body)

    # -- run-8: /v1-access self-test spends are throttled --------------
    def test_42_v1_access_test_throttled(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "thr42",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        codes = []
        for _i in range(11):
            status, body, _ = self._req("POST", "/api/v1-access/test",
                                        {}, admin)
            codes.append(status)
        self.assertNotIn(429, codes[:10], codes)
        self.assertEqual(codes[10], 429, codes)

    # -- run-8: moderator probes no longer burn the master budget -----
    def test_43_moderator_probes_spare_master_budget(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": "burntarget43",
                      "password": "burn-pw-43", "master_pw": MASTER}, admin)
        self._access({"action": "add", "label": "burnmod43",
                      "password": "burnmod-pw-43",
                      "master_pw": MASTER}, admin)
        self._access({"action": "friend_role_set", "label": "burnmod43",
                      "role": "moderator", "master_pw": MASTER}, admin)
        _, _, mod = self._login("burnmod-pw-43")
        for i in range(10):
            status, body, _ = self._access(
                {"action": "friend_reset_pw", "label": "burntarget43",
                 "new_password": f"burn-cand-{i}-43"}, mod)
            self.assertEqual(status, 200, (i, body))
        # Pre-fix, every miss recorded a GLOBAL master-budget failure
        # (the taken-check fell through to the recording proof), so
        # the owner's correct master was refused right here.
        status, body, _ = self._access(
            {"action": "2fa_status", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)

    # ================= wave 10 (run-9 fixes) =================

    # -- run-9 (S8): a proven /setup replacement rotates for real ---
    def test_44_setup_rotation_clears_sessions(self):
        _, _, admin = self._login(MASTER)
        _, _, friend = self._login(FRIEND_PW)
        status, body = self._form("/setup", {
            "password": MASTER_B, "confirm": MASTER_B,
            "current_master": MASTER,
            "k_groq": "sk-rotated-44"}, admin)
        self.assertEqual(status, 302, body)
        # Every session minted under the old master is dead —
        # pre-fix they all survived a proven replacement. (A dead
        # session is refused by the console gate: 403 "admin only".)
        status, body, _ = self._access({"action": "list"}, admin)
        self.assertEqual(status, 403, body)
        status, body, _ = self._access({"action": "list"}, friend)
        self.assertEqual(status, 403, body)
        # The old master is dead; the new one is live immediately
        # (the in-memory vault is the newly written one).
        status, _, _ = self._login(MASTER)
        self.assertEqual(status, 401)
        _, _, admin_b = self._login(MASTER_B)
        self.assertTrue(admin_b)
        # Rotate back for the rest of the class.
        status, body = self._form("/setup", {
            "password": MASTER, "confirm": MASTER,
            "current_master": MASTER_B,
            "k_groq": "sk-shared-fake"}, admin_b)
        self.assertEqual(status, 302, body)
        status, _, _ = self._login(MASTER)
        self.assertEqual(status, 200)

    # -- run-9 (S5): post-budget, free candidates get the same 429 --
    def test_45_redeemprobe_budget_before_verdict(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend", "days": 1,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        code = body["code"]
        # Ten taken-password verdicts exhaust the per-code budget.
        for i in range(10):
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": f"probe45_{i}", "password": SHARED_PW,
                 "code": code},
                headers={"X-Forwarded-For": f"10.45.0.{i + 1}"})
            self.assertEqual(status, 400, (i, body))
            self.assertIn("already in use", json.dumps(body))
        # The 11th attempt carries a FREE password: pre-fix it
        # created the account (the refusal was the verdict); now it
        # receives the identical generic 429 as a taken candidate.
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "sneak45", "password": "sneak45-unique-pw",
             "code": code},
            headers={"X-Forwarded-For": "10.45.0.99"})
        self.assertEqual(status, 429, body)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "probe45_z", "password": SHARED_PW, "code": code},
            headers={"X-Forwarded-For": "10.45.0.98"})
        self.assertEqual(status, 429, body)
        # No account was created by the refused free attempt.
        status, _, _ = self._login("sneak45-unique-pw")
        self.assertEqual(status, 401)
        # The legitimate flow still works within budget: a fresh
        # code + a free password signs up cleanly.
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend", "days": 1,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "legit45", "password": "legit45-unique-pw",
             "code": body["code"]},
            headers={"X-Forwarded-For": "10.45.0.97"})
        self.assertEqual(status, 200, body)

    # -- run-9 (S6): friend_key_add budget is keyed by the caller ---
    def test_46_friend_key_add_budget_caller_keyed(self):
        _, _, admin = self._login(MASTER)
        self._access({"action": "add", "label": "victim46",
                      "password": "victim-pw-46", "master_pw": MASTER},
                     admin)
        self._access({"action": "add", "label": "mod46",
                      "password": "mod-pw-46", "master_pw": MASTER},
                     admin)
        self._access({"action": "friend_role_set", "label": "mod46",
                      "role": "moderator", "master_pw": MASTER}, admin)
        _, _, mod = self._login("mod-pw-46")
        # The moderator burns ten wrong guesses against the victim.
        for i in range(10):
            status, body, _ = self._access(
                {"action": "friend_key_add", "label": "victim46",
                 "provider": "groq", "key": "sk-guess-46",
                 "friend_pw": f"wrong-guess-{i}-46"}, mod)
            self.assertEqual(status, 401, (i, body))
        # The moderator's OWN bucket is now exhausted (brute force
        # against the attacker still throttles).
        status, body, _ = self._access(
            {"action": "friend_key_add", "label": "victim46",
             "provider": "groq", "key": "sk-guess-46",
             "friend_pw": "wrong-guess-z-46"}, mod)
        self.assertEqual(status, 429, body)
        # But the victim's budget was never touched: the OWNER can
        # still add a key for the victim with the correct password
        # (pre-fix this was a 429 — the bucket was keyed on the
        # victim, so the attacker's guesses locked the victim out).
        status, body, _ = self._access(
            {"action": "friend_key_add", "label": "victim46",
             "provider": "groq", "key": "sk-real-46",
             "friend_pw": "victim-pw-46", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)

    # -- run-9 (S7): no key adds to a peer moderator's vault --------
    def test_47_friend_key_add_peer_guard(self):
        _, _, admin = self._login(MASTER)
        for label, pw in (("moda47", "moda-pw-47"),
                          ("modb47", "modb-pw-47"),
                          ("plain47", "plain-pw-47")):
            self._access({"action": "add", "label": label,
                          "password": pw, "master_pw": MASTER}, admin)
        for label in ("moda47", "modb47"):
            status, body, _ = self._access(
                {"action": "friend_role_set", "label": label,
                 "role": "moderator", "master_pw": MASTER}, admin)
            self.assertEqual(status, 200, body)
        _, _, moda = self._login("moda-pw-47")
        # Peer moderator: refused even with the peer's CORRECT
        # password (pre-fix the add went through).
        status, body, _ = self._access(
            {"action": "friend_key_add", "label": "modb47",
             "provider": "groq", "key": "sk-peer-47",
             "friend_pw": "modb-pw-47"}, moda)
        self.assertEqual(status, 403, body)
        # A plain friend is fine, and so is the moderator's OWN vault.
        status, body, _ = self._access(
            {"action": "friend_key_add", "label": "plain47",
             "provider": "groq", "key": "sk-plain-47",
             "friend_pw": "plain-pw-47"}, moda)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "friend_key_add", "label": "moda47",
             "provider": "groq", "key": "sk-self-47",
             "friend_pw": "moda-pw-47"}, moda)
        self.assertEqual(status, 200, body)

    # -- run-9 (S10): /v1 per-key in-flight ceiling of 4 ------------
    def test_48_v1_per_key_inflight_ceiling(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "ceil48",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        key = body["key"]
        held = []
        try:
            # Four requests trickle their bodies: each holds a base
            # reservation for this key (taken before the body read).
            for _i in range(4):
                s = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=30)
                s.sendall((
                    "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Content-Type: application/json\r\n"
                    f"Authorization: Bearer {key}\r\n"
                    "Content-Length: 200\r\n"
                    "Connection: close\r\n\r\n"
                    '{"messages": [{"role": "user", "content": "hi"}]'
                    ).encode())
                held.append(s)
            time.sleep(1.0)
            # The fifth request on the SAME key is refused at
            # admission (pre-fix it proceeded and held a base too).
            conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                              timeout=30)
            conn.request("POST", "/v1/chat/completions",
                         body=json.dumps(
                             {"messages": [{"role": "user",
                                            "content": "hi"}]}),
                         headers={"Content-Type": "application/json",
                                  "Authorization": f"Bearer {key}"})
            resp = conn.getresponse()
            payload = json.loads(resp.read())
            conn.close()
            self.assertEqual(resp.status, 429, payload)
            self.assertIn("in flight", json.dumps(payload))
        finally:
            for s in held:
                try:
                    s.close()
                except Exception:
                    pass
        # Once the held requests die, the key admits again (the
        # refusal was the ceiling, not a ban): the request now
        # reaches dispatch and fails on the fixture's dead lanes.
        deadline = time.time() + 15
        status = 429
        while time.time() < deadline and status == 429:
            status, body, _ = self._req(
                "POST", "/v1/chat/completions",
                {"messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": f"Bearer {key}"})
            if status == 429:
                time.sleep(0.5)
        self.assertNotEqual(status, 429, body)

    def test_zz_pw_proof_throttle(self):
        _, _, admin = self._login(MASTER)
        # Run-7: console 2FA guesses have their own budget — eleven
        # wrong confirms against a PENDING secret (never activated,
        # so no cleanup is owed) must end in a 429, not endless 401s.
        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret = body["secret"]
        wrong = "000000" if _totp(secret) != "000000" else "111111"
        seen = []
        for i in range(11):
            status, body, _ = self._access(
                {"action": "2fa_confirm", "master_pw": MASTER,
                 "code": wrong}, admin)
            seen.append(status)
        self.assertEqual(seen[:10], [401] * 10, seen)
        self.assertEqual(seen[10], 429, seen)
        for i in range(10):
            status, body, _ = self._access(
                {"action": "2fa_status", "master_pw": f"wrong-{i}"},
                admin)
            self.assertEqual(status, 401, body)
        # The CORRECT password is refused too while the budget is out.
        status, body, _ = self._access(
            {"action": "2fa_status", "master_pw": MASTER}, admin)
        self.assertEqual(status, 401, body)
        # Run-6 critic: the 2FA actions were a parallel oracle outside
        # the budget — with the budget out, even the CORRECT password
        # must fail there too (pre-fix this returned 200).
        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 401, body)


class _FixtureServerBase(unittest.TestCase):
    """Shared fixture-boot for the wave-10 harness classes: a
    disposable copy of the app in a temp dir, booted as a subprocess
    (the AuditFixHarness pattern). Subclasses set FIXTURE_FILES to
    control which vault files exist at boot."""
    proc = None
    log = None
    FIXTURE_FILES = ("keys", "access")
    KEYS = {"groq": "sk-shared-fake"}

    @classmethod
    def _boot(cls, extra_env=None):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w10-"))
        skip = {"access.json", "keys.enc", "users.enc", "access.enc",
                "provider_status.json"}
        for name in os.listdir(APP):
            if name in skip or name == "chats":
                continue
            if name.endswith((".py", ".json", ".html")):
                shutil.copy(APP / name, cls.tmp / name)
        access = {FRIEND: _hash_pw(FRIEND_PW),
                  "solo": _hash_pw(UNIQUE_PW)}
        if "keys" in cls.FIXTURE_FILES:
            encrypt_keys(cls.KEYS, MASTER, cls.tmp / "keys.enc")
        if "access" in cls.FIXTURE_FILES:
            encrypt_keys(access, MASTER, cls.tmp / "users.enc")
            encrypt_keys(access, RESTORE, cls.tmp / "access.enc")
        (cls.tmp / "chats").mkdir(exist_ok=True)
        cls.port = _free_port()
        env = dict(os.environ)
        env.update({
            "HOST": "127.0.0.1", "PORT": str(cls.port),
            "NEXUS_RELAY_PORT": str(_free_port()),
            "NEXUS_RESTORE_KEY": RESTORE,
            "NEXUS_SYNC_TOKEN": SYNC_TOKEN,
            "PYTHONPATH": str(cls.tmp),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        if extra_env:
            env.update(extra_env)
        cls.log = open(cls.tmp / "server.log", "ab")
        cls.proc = subprocess.Popen(
            [sys.executable, str(cls.tmp / "server.py")],
            cwd=str(cls.tmp), env=env,
            stdout=cls.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if cls.proc.poll() is not None:
                raise RuntimeError("server exited early:\n"
                                   + (cls.tmp / "server.log").read_text(
                                       errors="replace")[-2000:])
            try:
                status, _, _ = cls._req("GET", "/api/friend_blob")
                if status in (200, 403):
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
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _req(cls, method, path, body=None, ck=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port,
                                          timeout=30)
        hdrs = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body)
            hdrs.setdefault("Content-Type", "application/json")
        if ck:
            hdrs["Cookie"] = ck
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        set_cookie = resp.getheader("Set-Cookie") or ""
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload.decode(errors="replace")[:300]}
        return (resp.status, parsed,
                set_cookie.split(";")[0]
                if set_cookie.startswith("session=") else None)

    @classmethod
    def _login(cls, password):
        return cls._req("POST", "/api/login", {"password": password})

    @classmethod
    def _form(cls, path, fields, ck=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port,
                                          timeout=30)
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        if ck:
            hdrs["Cookie"] = ck
        conn.request("POST", path,
                     body=urllib.parse.urlencode(fields), headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        conn.close()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload.decode(errors="replace")[:300]}
        return resp.status, parsed


class Wave10SetupHarness(_FixtureServerBase):
    """Boots with NO keys.enc: the first-run setup surface."""
    FIXTURE_FILES = ()

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    # -- run-9 (S4): a held first-run request may not land as an ---
    # unproven replacement once a real first setup has completed.
    def test_01_setup_first_run_toctou_recheck(self):
        victim_pw = "victim-master-44"
        attacker_pw = "attacker-master-44"
        body_a = urllib.parse.urlencode({
            "password": attacker_pw, "confirm": attacker_pw,
            "k_groq": "sk-attacker"}).encode()
        sock = socket.create_connection(("127.0.0.1", self.port),
                                        timeout=30)
        try:
            sock.sendall((
                "POST /setup HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body_a)}\r\n"
                "Connection: close\r\n\r\n").encode() + body_a[:8])
            time.sleep(0.5)
            # The genuine first setup completes meanwhile — still
            # proof-free, exactly as a first run should be.
            status, _ = self._form("/setup", {
                "password": victim_pw, "confirm": victim_pw,
                "k_groq": "sk-victim"})
            self.assertEqual(status, 302)
            # The held request now finishes its body carrying NO
            # current-master proof: refused like any unproven
            # rotation (pre-fix it landed, 302, and replaced the
            # vault under the attacker's password).
            sock.sendall(body_a[8:])
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            status_line = resp.split(b"\r\n", 1)[0].decode(
                errors="replace")
            self.assertIn("401", status_line, resp[:400])
        finally:
            sock.close()
        # The victim's master is the live one; the attacker's is not.
        status, _, _ = self._login(victim_pw)
        self.assertEqual(status, 200)
        status, _, _ = self._login(attacker_pw)
        self.assertEqual(status, 401)


class _StubRelayHandler(http.server.BaseHTTPRequestHandler):
    """Loopback relay stub: every chat completion answers with a
    tool call, so an agent loop keeps spending until something
    stops it. Hits are counted per path."""
    hits = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        type(self).hits.append(self.path)
        body = json.dumps({
            "choices": [{"message": {"content":
                "```tool\n{\"name\": \"calculate\", \"args\": "
                "{\"expression\": \"1+1\"}}\n```"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = b'{"data": []}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Wave10AgentHarness(_FixtureServerBase):
    """Agent mode against a stub gateway that always answers with a
    tool call: without a provider-limit recheck the loop spends
    round after round on a lane limited to 1. The lane is
    freellmapi, whose gateway URL lives in the fixture keys.enc —
    pointed at the stub (the integrated relay's own port stays a
    free port the fixture binds for itself)."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        _StubRelayHandler.hits = []
        cls.stub = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _StubRelayHandler)
        cls.stub_port = cls.stub.server_address[1]
        cls.stub_thread = threading.Thread(target=cls.stub.serve_forever,
                                           daemon=True)
        cls.stub_thread.start()
        cls.KEYS = {"groq": "sk-shared-fake",
                    "freellmapi": "sk-gateway-fixture",
                    "freellmapi_url": f"http://127.0.0.1:{cls.stub_port}"}
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()
        cls.stub.shutdown()
        cls.stub.server_close()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    # -- run-9 (S13): the agent mid-loop recheck honours the -------
    # provider limit (including its in-flight/completed accounting).
    def test_01_agent_recheck_honours_provider_limit(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_limits": {"freellmapi": 1},
                       # Every other lane the attempt builder could
                       # add is disabled, so the agent list is exactly
                       # the one limited lane.
                       "provider_disabled": ["groq", "pollinations",
                                             "relay_pollinations"]}},
            admin)
        self.assertEqual(status, 200, body)
        _StubRelayHandler.hits = []
        status, body, _ = self._req(
            "POST", "/api/chat",
            {"provider": "freellmapi", "model": "openai",
             "message": "agent limit test", "mode": "agent"}, ck=admin)
        # Round 0 spends the lane's single allowance; the round-1
        # recheck must stop the loop BEFORE a second spend (pre-fix
        # it spent 3+ rows against a limit of 1 and answered 200).
        self.assertEqual(status, 429, body)
        spends = [h for h in _StubRelayHandler.hits
                  if h.endswith("/chat/completions")]
        self.assertEqual(len(spends), 1, _StubRelayHandler.hits)


class Wave11Harness(_FixtureServerBase):
    """Wave 11 (run-10 fixes) over real HTTP."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    @staticmethod
    def _wait_next_step():
        time.sleep(31 - (time.time() % 30))

    # -- F1: create-vs-revoke race never hands out a dead code -------
    def test_49_invite_create_revoke_race_no_stillborn(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        for trial in range(6):
            res = {}
            revokes = []  # (invite id, finish time) of 200 revokes

            def create():
                res["r"] = self._access(
                    {"action": "invite_create", "role": "friend",
                     "days": 1, "master_pw": MASTER}, admin)
                res["t"] = time.time()
            t = threading.Thread(target=create)
            t.start()
            # Revoke whatever appears while the create is in flight.
            deadline = time.time() + 20
            while t.is_alive() and time.time() < deadline:
                _, lst, _ = self._access({"action": "invite_list"},
                                         admin)
                for inv in (lst.get("invites") or []):
                    st_r, _, _ = self._access(
                        {"action": "invite_revoke",
                         "id": inv["id"], "master_pw": MASTER}, admin)
                    if st_r == 200:
                        revokes.append((inv["id"], time.time()))
                time.sleep(0.02)
            t.join(20)
            status, body, _ = res["r"]
            if status == 200:
                h8 = hashlib.sha256(
                    body["code"].encode()).hexdigest()[:8]
                # A revoke of THIS invite that completed before the
                # create answered (50 ms grace for the thread's own
                # bookkeeping) would make the handout stillborn —
                # that is the bug. A revoke landing only afterwards
                # legitimately kills the code; skip the redeem check
                # for that trial.
                during = any(rid == h8 and rt <= res["t"] - 0.05
                             for rid, rt in revokes)
                after = any(rid == h8 and rt > res["t"] - 0.05
                            for rid, rt in revokes)
                self.assertFalse(during, (trial, body, revokes))
                if after:
                    continue
                # A handed-out code must actually redeem.
                st2, body2, _ = self._req(
                    "POST", "/api/invite/redeem",
                    {"label": f"race49_{trial}",
                     "password": f"race49-pw-{trial}", "code": body["code"]},
                    headers={"X-Forwarded-For": f"10.49.1.{trial + 1}"})
                self.assertEqual(st2, 200, (trial, body2))
            else:
                # Supersession is an honest 409, never a 200 handout
                # of a dead code and never a misleading 500.
                self.assertEqual(status, 409, (trial, body))

    # -- F11: open-mode junk cannot block a legitimate signup --------
    def test_50_open_mode_junk_does_not_block_legit(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"registration": "open"}}, admin)
        self.assertEqual(status, 200, body)
        try:
            for i in range(10):
                status, body, _ = self._req(
                    "POST", "/api/invite/redeem",
                    {"label": f"junk50_{i}",
                     "password": f"junk50-pw-{i}"},
                    headers={"X-Forwarded-For": f"10.50.0.{i + 1}"})
                self.assertEqual(status, 200, (i, body))
            # Pre-fix the flat "open" bucket was exhausted by the
            # junk above and this legitimate signup got a 429.
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "legit50", "password": "legit50-pw"},
                headers={"X-Forwarded-For": "10.50.9.1"})
            self.assertEqual(status, 200, body)
            # A same-source oracle still exhausts: ten taken verdicts
            # from ONE source, then taken and free are the same 429.
            # (FRIEND_PW is the taken password in this fixture.)
            for i in range(10):
                status, body, _ = self._req(
                    "POST", "/api/invite/redeem",
                    {"label": f"orc50_{i}", "password": FRIEND_PW},
                    headers={"X-Forwarded-For": "10.50.7.7"})
                self.assertEqual(status, 400, (i, body))
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "orc50_free", "password": "orc50-free-pw"},
                headers={"X-Forwarded-For": "10.50.7.7"})
            self.assertEqual(status, 429, body)
        finally:
            self._access(
                {"action": "settings_set", "master_pw": MASTER,
                 "patch": {"registration": "invite"}}, admin)

    # -- F6: the self-test gate counts in-flight /v1 requests --------
    def test_51_v1_access_test_gate_counts_inflight(self):
        _, _, admin = self._login(MASTER)
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "gate51",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        key = body["key"]
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 2}}, admin)
        self.assertEqual(status, 200, body)
        held = []
        try:
            for _i in range(2):
                s = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=30)
                s.sendall((
                    "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Content-Type: application/json\r\n"
                    f"Authorization: Bearer {key}\r\n"
                    "Content-Length: 200\r\n"
                    "Connection: close\r\n\r\n"
                    '{"messages": [{"role": "user", "content": "hi"}]'
                    ).encode())
                held.append(s)
            time.sleep(1.0)
            # Two /v1 bases are in flight against a cap of 2 and ZERO
            # rows have completed: the real /v1 gate refuses here, so
            # the self-test must refuse too (pre-fix it spent).
            status, body, _ = self._req("POST", "/api/v1-access/test",
                                        {}, admin)
            self.assertEqual(status, 200, body)
            self.assertFalse(body.get("ok"), body)
            self.assertIn("daily limit", json.dumps(body), body)
        finally:
            for s in held:
                try:
                    s.close()
                except Exception:
                    pass
            self._access(
                {"action": "settings_set", "master_pw": MASTER,
                 "patch": {"global_cap": 0}}, admin)

    # -- F7/F8/F9: a proven /setup rotation revokes like change_master
    def test_52_setup_rotation_revokes_credentials(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        # A stored /v1 key (dies on rotation — F7).
        status, body, _ = self._req("POST", "/api/v1-access/generate",
                                    {"name": "rot52",
                                     "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        v1key = body["key"]
        status, _, _ = self._req("GET", "/v1/models", None,
                                 headers={"Authorization":
                                          f"Bearer {v1key}"})
        self.assertEqual(status, 200)
        # A live view grant (dies on rotation — F9).
        status, body, _ = self._access(
            {"action": "viewpass_create", "name": "rot52", "hours": 24,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        view_url = body["url"]
        status, _, _ = self._req("GET", view_url)
        self.assertEqual(status, 302)
        # 2FA on, then a pending completion minted pre-rotation (F8).
        status, body, _ = self._access(
            {"action": "2fa_enable", "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        secret = body["secret"]
        self._wait_next_step()
        status, body, _ = self._access(
            {"action": "2fa_confirm", "master_pw": MASTER,
             "code": _totp(secret)}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._login(MASTER)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("need_2fa"), body)
        tmp = body["tmp"]
        # The proven /setup rotation.
        status, body = self._form("/setup", {
            "password": MASTER_B, "confirm": MASTER_B,
            "current_master": MASTER, "k_groq": "sk-rotated-52"},
            admin)
        self.assertEqual(status, 302, body)
        # F7: the pre-rotation /v1 key is dead (no stored keys and no
        # env fallback in the fixture -> the surface is 404).
        status, _, _ = self._req("GET", "/v1/models", None,
                                 headers={"Authorization":
                                          f"Bearer {v1key}"})
        self.assertEqual(status, 404)
        # F9: the pre-rotation view link no longer mints a session.
        status, _, _ = self._req("GET", view_url)
        self.assertEqual(status, 404)
        # F8: the pending 2FA completion minted under the old master
        # is dead even with a fresh, correct code.
        status, body, _ = self._req(
            "POST", "/api/login", {"tmp": tmp, "code": _totp(secret)})
        self.assertEqual(status, 401, body)
        # Rotate back (2FA rides along) and switch 2FA off again so
        # the rest of the class is unaffected.
        self._wait_next_step()
        status, body, _ = self._login(MASTER_B)
        self.assertTrue(body.get("need_2fa"), body)
        self._wait_next_step()
        status, body, ck = self._req(
            "POST", "/api/login",
            {"tmp": body["tmp"], "code": _totp(secret)})
        self.assertEqual(status, 200, body)
        status, body = self._form("/setup", {
            "password": MASTER, "confirm": MASTER,
            "current_master": MASTER_B, "k_groq": "sk-shared-fake"},
            ck)
        self.assertEqual(status, 302, body)
        self._wait_next_step()
        status, body, _ = self._login(MASTER)
        self.assertTrue(body.get("need_2fa"), body)
        self._wait_next_step()
        status, body, ck = self._req(
            "POST", "/api/login",
            {"tmp": body["tmp"], "code": _totp(secret)})
        self.assertEqual(status, 200, body)
        self._wait_next_step()
        status, body, _ = self._access(
            {"action": "2fa_disable", "master_pw": MASTER,
             "code": _totp(secret)}, ck)
        self.assertEqual(status, 200, body)
        status, _, _ = self._login(MASTER)
        self.assertEqual(status, 200)


class Wave11VoiceHarness(_FixtureServerBase):
    """F3: the voice branch governs the funding lane."""
    FIXTURE_FILES = ("keys", "access")
    KEYS = {"groq": "sk-groq-fake-11"}

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _voice(self, ck):
        try:
            status, body, _ = self._req(
                "POST", "/api/chat",
                {"provider": "relay_groq", "mode": "voice",
                 "message": "hello nexus"}, ck=ck)
            return status
        except Exception:
            # A timeout here means the request passed the governance
            # gate and is waiting on the (fake-key) upstream.
            return "passed-gate"

    def test_01_voice_fallback_funding_lane_governed(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        # Funding lane (groq) disabled: a relay_groq pick that would
        # fall back to the groq key is refused BEFORE any spend.
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_disabled": ["groq"]}}, admin)
        self.assertEqual(status, 200, body)
        self.assertEqual(self._voice(admin), 403)
        # Re-enabled: the same pick passes the gate (and then fails
        # or succeeds at the upstream with the fake key — never 403).
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_disabled": []}}, admin)
        self.assertEqual(status, 200, body)
        self.assertNotEqual(self._voice(admin), 403)

    def test_02_voice_own_key_lane_not_blocked_by_groq(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        # Give relay_groq its OWN key via a proven /setup replacement
        # (master unchanged): now the pick funds from relay_groq, so
        # a disabled groq lane must not block it.
        status, body = self._form("/setup", {
            "password": MASTER, "confirm": MASTER,
            "current_master": MASTER, "k_groq": "sk-groq-fake-11",
            "k_relay_groq": "sk-relay-groq-fake-11"}, admin)
        self.assertEqual(status, 302, body)
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_disabled": ["groq"]}}, admin)
        self.assertEqual(status, 200, body)
        self.assertNotEqual(self._voice(admin), 403)
        self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_disabled": []}}, admin)


class Wave11SetupStallHarness(_FixtureServerBase):
    """F10: a held first-run request whose post-recheck work stalls
    (here: a gateway URL whose resolution is slow) still may not land
    as an unproven replacement once a genuine setup completed."""
    FIXTURE_FILES = ()

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def test_01_setup_stall_between_recheck_and_encrypt(self):
        import socket as _socket
        victim_pw = "victim-master-11"
        attacker_pw = "attacker-master-11"
        # The attacker's form carries a gateway URL on a .invalid
        # name: validation fails for THEM eventually, but the point
        # is the ordering — with a resolvable-but-slow name the stall
        # is longer. Use a real public URL so validation can pass,
        # and hold the body instead: the recheck-to-encrypt window
        # must simply not exist.
        body_a = urllib.parse.urlencode({
            "password": attacker_pw, "confirm": attacker_pw,
            "k_groq": "sk-attacker",
            # A literal public IP: validation passes instantly with
            # no DNS, so the request reaches the deferred re-check —
            # which must now answer 401 from inside _KEYS_LOCK.
            "url_freellmapi": "https://93.184.216.34/gw"}).encode()
        sock = _socket.create_connection(("127.0.0.1", self.port),
                                         timeout=30)
        try:
            sock.sendall((
                "POST /setup HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body_a)}\r\n"
                "Connection: close\r\n\r\n").encode() + body_a[:8])
            time.sleep(0.5)
            status, _ = self._form("/setup", {
                "password": victim_pw, "confirm": victim_pw,
                "k_groq": "sk-victim"})
            self.assertEqual(status, 302)
            sock.sendall(body_a[8:])
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            status_line = resp.split(b"\r\n", 1)[0].decode(
                errors="replace")
            self.assertIn("401", status_line, resp[:400])
        finally:
            sock.close()
        status, _, _ = self._login(victim_pw)
        self.assertEqual(status, 200)
        status, _, _ = self._login(attacker_pw)
        self.assertEqual(status, 401)



def _respawn_fixture(cls):
    """Restart a fixture server IN PLACE (same tmp dir, same port):
    on-disk state survives, in-memory state reloads from it."""
    if cls.proc is not None:
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
            cls.proc.wait(timeout=10)
    env = dict(os.environ)
    env.update({
        "HOST": "127.0.0.1", "PORT": str(cls.port),
        "NEXUS_RELAY_PORT": str(_free_port()),
        "NEXUS_RESTORE_KEY": RESTORE,
        "NEXUS_SYNC_TOKEN": SYNC_TOKEN,
        "PYTHONPATH": str(cls.tmp),
        "no_proxy": "127.0.0.1,localhost",
        "NO_PROXY": "127.0.0.1,localhost",
    })
    cls.proc = subprocess.Popen(
        [sys.executable, str(cls.tmp / "server.py")],
        cwd=str(cls.tmp), env=env,
        stdout=cls.log, stderr=subprocess.STDOUT)
    deadline = time.time() + 30
    while time.time() < deadline:
        if cls.proc.poll() is not None:
            raise RuntimeError("fixture respawn exited early:\n"
                               + (cls.tmp / "server.log").read_text(
                                   errors="replace")[-2000:])
        try:
            status, _, _ = cls._req("GET", "/api/friend_blob")
            if status in (200, 403):
                return
        except OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError("fixture respawn did not come up in 30s")


class Wave12UnitTests(unittest.TestCase):
    """Wave 12 (run-11 fixes): D1/D2/D3 outcome + CAS rollback, C1
    reserve-then-count, and source shapes for the rest."""

    def _temp_settings(self):
        import tempfile
        from pathlib import Path as _P
        td = tempfile.TemporaryDirectory()
        saved = (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
                 server.RESTORE_KEY)
        server.SETTINGS_PATH = _P(td.name) / "settings.json"
        server.SETTINGS_ENC_PATH = _P(td.name) / "settings.enc"
        server.RESTORE_KEY = "unit-restore-12"
        return td, saved

    def _restore_settings_env(self, saved, orig):
        (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
         server.RESTORE_KEY) = saved
        server._SETTINGS.clear()
        server._SETTINGS.update(orig)

    # -- D3: the True branch verifies the persisted state -----------
    def test_w12_outcome_true_branch_verifies_persisted(self):
        orig = dict(server._SETTINGS)
        td, saved = self._temp_settings()
        try:
            server._SETTINGS["announcement"] = "OTHER12"
            self.assertTrue(server._save_settings())  # persisted OTHER
            # A third writer's UNSAVED same-value mutation masks the
            # supersession in live memory: pre-fix the True branch
            # read live only and answered "ok" for a value that was
            # never the persisted state at any instant.
            server._SETTINGS["announcement"] = "MINE12"
            self.assertEqual(
                server._settings_outcome(
                    True, lambda s: s.get("announcement") == "MINE12"),
                "conflict")
            # When the mutation IS the persisted state, a diverged
            # live value does not matter: ok.
            self.assertTrue(server._save_settings())  # persisted MINE12
            server._SETTINGS["announcement"] = "DIVERGED12"
            self.assertEqual(
                server._settings_outcome(
                    True, lambda s: s.get("announcement") == "MINE12"),
                "ok")
        finally:
            self._restore_settings_env(saved, orig)
            td.cleanup()

    # -- D2: the False branch waits for an in-flight covering save --
    def test_w12_outcome_false_branch_waits_for_inflight(self):
        orig = dict(server._SETTINGS)
        td, saved = self._temp_settings()
        try:
            server._SETTINGS["announcement"] = "BASE12"
            self.assertTrue(server._save_settings())
            server._SETTINGS["announcement"] = "GHOST12"  # A live only
            # Simulate B's save being in flight (its snapshot carries
            # A's mutation); it lands ~0.5s from now.
            server._SETTINGS_ACTIVE[0] += 1

            def land():
                time.sleep(0.5)
                try:
                    server._save_settings()
                finally:
                    server._SETTINGS_ACTIVE[0] -= 1
            t = threading.Thread(target=land)
            t.start()
            rolled = []
            oc = server._settings_outcome(
                False, lambda s: s.get("announcement") == "GHOST12",
                lambda: rolled.append(1))
            t.join(10)
            # Pre-fix: the check read the stale persisted state at
            # once, answered "failed" and rolled the invite back —
            # while B's save then persisted it (a restart-resurrected
            # ghost). Post-fix the wait lets it land: ok, no rollback.
            self.assertEqual(oc, "ok")
            self.assertEqual(rolled, [])
            # Control: nothing in flight and the mutation truly never
            # landed -> failed, with rollback.
            server._SETTINGS["announcement"] = "NEVER12"
            self.assertEqual(
                server._settings_outcome(
                    False, lambda s: s.get("announcement") == "NEVER12",
                    lambda: rolled.append(1)),
                "failed")
            self.assertEqual(rolled, [1])
        finally:
            server._SETTINGS_ACTIVE[0] = 0
            self._restore_settings_env(saved, orig)
            td.cleanup()

    # -- D1: compare-and-restore never clobbers a concurrent change -
    def test_w12_cas_rollback_concurrent_change_survives(self):
        orig = dict(server._SETTINGS)
        td, saved = self._temp_settings()
        try:
            # Suspension shape (the verifier's A1): A suspends alice;
            # B (concurrent, acknowledged) suspends bob instead and
            # its real save lands; A's faulted save must NOT restore
            # the whole list — bob's suspension survives.
            server._SETTINGS["suspended"] = []
            self.assertTrue(server._save_settings())
            server._SETTINGS["suspended"] = ["alice"]       # A live
            server._SETTINGS["suspended"] = ["bob"]         # B live
            self.assertTrue(server._save_settings())        # B lands
            oc = server._settings_outcome(
                False,
                lambda s: "alice" in (s.get("suspended") or []),
                lambda: server._cas_rollback_list_entry(
                    "suspended", "alice", [], ["alice"]))
            self.assertEqual(oc, "failed")
            self.assertEqual(server._SETTINGS["suspended"], ["bob"])
            self.assertTrue(server._save_settings())
            self.assertEqual(
                server._persisted_settings()["suspended"], ["bob"])
            # When live still equals the caller's own mutation, the
            # compare-and-restore DOES restore the prior entry.
            server._SETTINGS["suspended"] = ["alice"]
            server._cas_rollback_list_entry(
                "suspended", "alice", [], ["alice"])
            self.assertEqual(server._SETTINGS["suspended"], [])
            # Dict entry: a peer's entry survives; the caller's own
            # entry is restored; a same entry since re-saved by a
            # peer (different value) is left alone.
            server._SETTINGS["user_caps"] = {"x": 1, "alice": 111,
                                             "bob": 222}
            server._cas_rollback_dict_entry(
                "user_caps", "alice", {"x": 1},
                {"x": 1, "alice": 111})
            self.assertEqual(server._SETTINGS["user_caps"],
                             {"x": 1, "bob": 222})
            server._SETTINGS["user_caps"] = {"alice": 999}
            server._cas_rollback_dict_entry(
                "user_caps", "alice", {}, {"alice": 111})
            self.assertEqual(server._SETTINGS["user_caps"],
                             {"alice": 999})
            # Invites: add-rollback removes only the caller's invite;
            # remove-rollback re-adds only the caller's removal.
            server._SETTINGS["invites"] = [{"h": "H1"}, {"h": "H2"}]
            server._cas_rollback_invite_add("H1")
            self.assertEqual(server._SETTINGS["invites"], [{"h": "H2"}])
            server._cas_rollback_invite_remove([{"h": "H1"}])
            self.assertEqual(
                {i["h"] for i in server._SETTINGS["invites"]},
                {"H1", "H2"})
            # Keys: per-key compare — a key the peer re-saved with a
            # different value survives; the caller's untouched-by-peer
            # key is restored.
            server._SETTINGS["daily_cap"] = 700
            server._SETTINGS["announcement"] = "A-val"
            server._cas_rollback_keys(
                {"daily_cap": 200, "announcement": ""},
                {"daily_cap": 500, "announcement": "A-val"})
            self.assertEqual(server._SETTINGS["daily_cap"], 700)
            self.assertEqual(server._SETTINGS["announcement"], "")
        finally:
            self._restore_settings_env(saved, orig)
            td.cleanup()

    # -- C1: a natural burst against a lane limit of 1 spends once -
    def test_w12_v1_burst_limit_one(self):
        orig_settings = dict(server._SETTINGS)
        saved = (server._v1_route, server._v1_relay_call,
                 server._today_counts, server._append_usage,
                 server._provider_down, server.Handler.keys,
                 server._provider_counts_today)
        hits = []
        try:
            server._INFLIGHT.clear()
            server._SETTINGS["provider_limits"] = {"relay_gemini": 1}
            server._SETTINGS["provider_disabled"] = []
            server._v1_route = lambda model: [("relay_gemini", "m1")]
            server._provider_down = lambda lane: False
            server._today_counts = lambda fresh=False: {
                "providers": {}, "users": {}, "total": 0}
            # Wave 15 (CAPS14-4): the reserve's completed term reads
            # the in-memory counter — keep it at zero for the burst.
            server._provider_counts_today = lambda: {}

            def fake_call(lane, path, payload):
                hits.append(lane)
                time.sleep(0.3)
                return {"choices": [{"message": {"content": "hi"}}],
                        "usage": {}}
            server._v1_relay_call = fake_call
            server._append_usage = lambda row: None
            server.Handler.keys = {"relay_gemini": "fixture"}
            barrier = threading.Barrier(8)
            results = []

            def worker():
                barrier.wait(10)
                results.append(server._v1_chat(
                    [{"role": "user", "content": "hi"}], "nexus-auto"))
            threads = [threading.Thread(target=worker)
                       for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(20)
            # Pre-fix this burst overshot to as many as 4 upstream
            # hits against a limit of 1 (check-then-add).
            self.assertEqual(len(hits), 1, hits)
            self.assertEqual(
                len([r for r in results if r[0] == 200]), 1, results)
        finally:
            (server._v1_route, server._v1_relay_call,
             server._today_counts, server._append_usage,
             server._provider_down, server.Handler.keys,
             server._provider_counts_today) = saved
            server._SETTINGS.clear()
            server._SETTINGS.update(orig_settings)
            server._INFLIGHT.clear()

    # -- Source shapes for C2/C3/A1/A2/A3/D4 + launcher L1-L8 --------
    def test_w12_source_shapes(self):
        src = (APP / "server.py").read_text()
        # D1/D2: CAS helpers + in-flight tracking exist.
        self.assertIn("_cas_rollback_dict_entry", src)
        self.assertIn("_cas_rollback_invite_claim", src)
        self.assertIn("_SETTINGS_ACTIVE", src)
        self.assertIn("_wait_settings_settled(", src)
        # C1: /v1 reserves before its counted check (no bare
        # check-then-add left in _v1_chat).
        v1seg = src[src.index("def _v1_chat"):src.index(
            "return 502", src.index("def _v1_chat"))]
        self.assertNotIn("_provider_blocked(lane)", v1seg)
        self.assertIn('_inflight_add("v1", lane, attempt=True)', v1seg)
        # C2: media checks exclude the born-tagged base reservation.
        self.assertGreaterEqual(src.count("exclude=self._cap_res"), 6)
        # C3: no build-time governance captures remain.
        self.assertNotIn("_pcounts = ", src)
        self.assertNotIn("_lims = ", src)
        self.assertNotIn("_dis = _disabled_providers()", src)
        # A1: ONE shared carry-over helper, called by both rotations.
        self.assertGreaterEqual(
            src.count("_carry_over_master_rotation("), 3)
        # A2: the flat global ceiling rides alongside per-source.
        self.assertIn('_rl_ok("redeemprobe", "open:all"', src)
        # Wave 13: the global refund is GONE (free verdicts accrue
        # against the ceiling again); only the per-source refund stays.
        self.assertNotIn('_rl_refund("redeemprobe", "open:all")', src)
        # A3: the deferred first-run re-check is a quiet decrypt in
        # the window between the entry snapshot and the encrypt.
        i = src.index("if not _entry_keys_exist and key_path.exists():")
        seg = src[i:src.index("encrypt_keys(keys, pw, key_path)", i)]
        self.assertIn("decrypt_keys(", seg)
        self.assertNotIn("_master_proof(", seg)
        # D4: claim + factory-reset outcome checks exist.
        self.assertIn("signup could not be saved", src)
        self.assertIn("_reset_oc", src)
        self.assertIn("could not be saved — set it again", src)
        js = (REPO / "bin" / "nexuslocal.js").read_text()
        # L1/L2/L3: one shared parser; no private regex readers left.
        self.assertGreaterEqual(js.count("parseEngineAdminCreds"), 3)
        self.assertIn("readEngineAdminCreds(envFile)", js)
        self.assertIn("removeEngineAdminCreds(envFile)", js)
        self.assertNotIn("envTxt.match(/^ENGINE_ADMIN", js)
        # L4: the gate probes package.json per dependency.
        # Wave 13: the probe is loadability (require.resolve), not
        # existence.
        self.assertIn("require.resolve(d, { paths: [engineServer] })", js)
        # L5: an unparseable manifest logs loudly and fails the gate.
        self.assertIn("could not read the engine package.json", js)
        # L6: optionalDependencies never feed the gate.
        # Wave 13: exactly ONE optional is gated — better-sqlite3,
        # which the engine hard-requires on non-Android platforms.
        self.assertIn('(_epkg.optionalDependencies || {})["better-sqlite3"]',
                      js)
        self.assertNotIn("Object.keys({\n      ...(_epkg.dependencies",
                         js)
        # L7/L8: one shutdown path for SIGINT/SIGTERM/SIGHUP and for
        # a dashboard that dies on its own, with SIGKILL escalation.
        self.assertIn('process.on("SIGTERM"', js)
        self.assertIn('process.on("SIGHUP"', js)
        self.assertIn("SIGKILL", js)
        self.assertIn("shutdown(code || 0)", js)
        node = shutil.which("node")
        if node:
            r = subprocess.run([node, "--check",
                                str(REPO / "bin" / "nexuslocal.js")],
                               capture_output=True)
            self.assertEqual(r.returncode, 0,
                             r.stderr.decode(errors="replace"))


class Wave12LauncherTests(unittest.TestCase):
    """Wave 12 launcher fixes over real boots against a stub engine:
    L1/L2/L3 shared .env grammar, L4/L5/L6 npm gate, L7/L8 shutdown."""

    ENGINE_PW = "correct-pw-12"
    ENGINE_EMAIL = "boss@example.com"

    def _fixture(self, env_text, gate="ok", dash_exit=False):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w12-launcher-"))
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        app = tmp / "app"
        srv = app / "engine" / "server"
        (srv / "dist").mkdir(parents=True)
        (app / "engine-data").mkdir()
        (app / "server.py").write_text(
            "import os, time\n"
            "with open(os.environ['DASH_PID'], 'w') as f:\n"
            "    f.write(str(os.getpid()))\n"
            f"time.sleep({2.5 if dash_exit else 120})\n")
        (app / ".env").write_text(env_text, encoding="utf-8")
        if gate == "corrupt":
            (srv / "package.json").write_text("{ this is not json")
        else:
            deps = {"dotenv": "^17.0.0", "express": "^5.0.0"}
            pkg = {"name": "stub", "dependencies": deps}
            if gate == "optional":
                pkg["dependencies"] = {"dotenv": "^17.0.0"}
                pkg["optionalDependencies"] = {"bettr": "^1.0.0"}
            (srv / "package.json").write_text(json.dumps(pkg))
        (srv / "package-lock.json").write_text("{}")
        nm = srv / "node_modules"
        nm.mkdir()
        (nm / "dotenv").mkdir()
        (nm / "dotenv" / "package.json").write_text("{}")
        (nm / "dotenv" / "index.js").write_text("")
        (nm / ".package-lock.json").write_text("{}")
        if gate == "ok":
            (nm / "express").mkdir()
            (nm / "express" / "package.json").write_text("{}")
            (nm / "express" / "index.js").write_text("")
        elif gate == "empty-dep":
            (nm / "express").mkdir()  # directory only: NOT installed
        (srv / "dist" / "index.js").write_text(
            "const http=require('http');const fs=require('fs');"
            "fs.writeFileSync(process.env.ENGINE_PID,"
            "String(process.pid));"
            "http.createServer((req,res)=>{"
            "let b='';req.on('data',c=>b+=c);req.on('end',()=>{"
            "res.setHeader('Content-Type','application/json');"
            "if(req.url==='/api/auth/status'){"
            "res.end(JSON.stringify({needsSetup:false}));}"
            "else if(req.url==='/api/auth/login'){"
            "fs.appendFileSync(process.env.LOGIN_FILE,b+'\\n');"
            "let ok=false;try{const j=JSON.parse(b);"
            f"ok=j.email==='{self.ENGINE_EMAIL}'"
            f"&&j.password==='{self.ENGINE_PW}';}}catch(e){{}}"
            "if(ok){res.end(JSON.stringify({ok:true}));}"
            "else{res.statusCode=401;res.end('{}');}}"
            "else{res.statusCode=404;res.end('{}');}});"
            "}).listen(3001,'127.0.0.1');\n")
        return tmp

    def _boot(self, tmp):
        node = shutil.which("node")
        if not node or not shutil.which("unshare"):
            self.skipTest("node/unshare not available")
        env = dict(os.environ)
        env.update({
            "LOGIN_FILE": str(tmp / "logins.jsonl"),
            "ENGINE_PID": str(tmp / "engine.pid"),
            "DASH_PID": str(tmp / "dash.pid"),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        cmd = ["unshare", "-n", "bash", "-c",
               "ip link set lo up 2>/dev/null; exec "
               f"{node} {tmp / 'bin' / 'nexuslocal.js'}"]
        proc = subprocess.Popen(
            cmd, cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc

    def _wait_for(self, proc, tmp, pred, timeout=30, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        log = ""
        if (tmp / "startup.log").exists():
            log = (tmp / "startup.log").read_text(errors="replace")
        self.fail(f"launcher {what} not reached; log tail:\n"
                  + log[-1200:])

    def _logins(self, tmp):
        f = tmp / "logins.jsonl"
        if not f.exists():
            return []
        out = []
        for line in f.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return out

    def _pid_dead(self, pidfile, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                pid = int(Path(pidfile).read_text().strip())
            except Exception:
                time.sleep(0.2)
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                return False
            time.sleep(0.2)
        return False

    def _verify_variant(self, env_text):
        tmp = self._fixture(env_text)
        proc = self._boot(tmp)
        try:
            self._wait_for(proc, tmp,
                           lambda: len(self._logins(tmp)) >= 1,
                           what="verify login")
            login = self._logins(tmp)[0]
            self.assertEqual(login["email"], self.ENGINE_EMAIL)
            self.assertEqual(login["password"], self.ENGINE_PW)
            # The stub answered 200 (credentials are ours): nothing
            # may be removed and no foreign-claim warning may fire.
            time.sleep(1)
            env_after = (tmp / "app" / ".env").read_text(
                encoding="utf-8")
            self.assertIn("ENGINE_ADMIN_PASSWORD", env_after)
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertNotIn("NOT the ones from app/.env", log)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- L1: an empty first line no longer shadows valid creds ------
    def test_w12_verify_empty_first_line_falls_through(self):
        self._verify_variant(
            "ENGINE_ADMIN_PASSWORD=\n"
            f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
            f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n")

    # -- L2: quoted + spaced values parse like dotenv ---------------
    def test_w12_verify_quoted_and_spaced(self):
        self._verify_variant(
            f'ENGINE_ADMIN_EMAIL = "{self.ENGINE_EMAIL}"\n'
            f"ENGINE_ADMIN_PASSWORD = '{self.ENGINE_PW}'\n")

    # -- L3: a BOM-prefixed first line is visible --------------------
    def test_w12_verify_bom_first_line(self):
        self._verify_variant(
            f"\ufeffENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n"
            f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n")

    # -- L7: SIGTERM runs the shared shutdown (no orphans) ---------
    def test_w12_sigterm_stops_both_children(self):
        import signal as _signal
        tmp = self._fixture(
            f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
            f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n")
        proc = self._boot(tmp)
        try:
            self._wait_for(proc, tmp,
                           lambda: len(self._logins(tmp)) >= 1,
                           what="verify login")
            self._wait_for(proc, tmp,
                           lambda: (tmp / "engine.pid").exists()
                           and (tmp / "dash.pid").exists(),
                           what="pid files")
            proc.send_signal(_signal.SIGTERM)
            proc.wait(timeout=15)
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertIn("Shutting down...", log)
            self.assertTrue(self._pid_dead(tmp / "engine.pid"),
                            "engine orphaned by SIGTERM")
            self.assertTrue(self._pid_dead(tmp / "dash.pid"),
                            "dashboard orphaned by SIGTERM")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- L8: a dashboard that dies on its own stops the engine ------
    def test_w12_dashboard_exit_stops_engine(self):
        tmp = self._fixture(
            f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
            f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n",
            dash_exit=True)
        proc = self._boot(tmp)
        try:
            self._wait_for(proc, tmp,
                           lambda: (tmp / "engine.pid").exists(),
                           what="engine pid")
            proc.wait(timeout=20)
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertIn("Dashboard exited", log)
            self.assertIn("Shutting down...", log)
            self.assertTrue(self._pid_dead(tmp / "engine.pid"),
                            "engine orphaned by dashboard exit")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- L4: an empty dependency directory triggers the install -----
    def test_w12_gate_empty_dep_dir_installs(self):
        tmp = self._fixture("ENGINE_ADMIN_PASSWORD=x\n",
                            gate="empty-dep")
        proc = self._boot(tmp)
        try:
            self._wait_for(
                proc, tmp,
                lambda: (tmp / "startup.log").exists()
                and "Installing engine dependencies"
                in (tmp / "startup.log").read_text(errors="replace"),
                timeout=60, what="npm gate on empty dep dir")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- L5: an unparseable manifest logs loudly and fails the gate -
    def test_w12_gate_corrupt_manifest_loud(self):
        tmp = self._fixture("ENGINE_ADMIN_PASSWORD=x\n",
                            gate="corrupt")
        proc = self._boot(tmp)
        try:
            self._wait_for(
                proc, tmp,
                lambda: (tmp / "startup.log").exists()
                and "Installing engine dependencies"
                in (tmp / "startup.log").read_text(errors="replace"),
                timeout=60, what="npm gate on corrupt manifest")
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertIn("could not read the engine package.json",
                          log)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- L6: a missing OPTIONAL dependency never triggers install --
    def test_w12_gate_optional_dep_ignored(self):
        tmp = self._fixture(
            f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
            f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n",
            gate="optional")
        proc = self._boot(tmp)
        try:
            self._wait_for(proc, tmp,
                           lambda: len(self._logins(tmp)) >= 1,
                           what="verify login")
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertNotIn("Installing engine dependencies", log)
            self.assertIsNone(proc.poll())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)


class Wave12FaultHarness(_FixtureServerBase):
    """D4 over real HTTP, with _save_settings fault-injected in the
    disposable copy (a flag file makes every settings save fail)."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        sp = cls.tmp / "server.py"
        txt = sp.read_text()
        anchor = "def _save_settings():\n"
        assert txt.count(anchor) == 1
        sp.write_text(txt.replace(
            anchor,
            anchor + "    if (Path(__file__).parent / "
                     "\"SAVE_FAULT\").exists():\n"
                     "        return False\n", 1))
        _respawn_fixture(cls)

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _fault(self, on):
        flag = self.tmp / "SAVE_FAULT"
        if on:
            flag.write_text("x")
        else:
            flag.unlink(missing_ok=True)

    # -- D4: a faulted used_by save cannot mint a second account ----
    def test_61_invite_claim_faulted_save(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend", "days": 1,
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        code = body["code"]
        self._fault(True)
        try:
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "claim61", "password": "claim61-pw",
                 "code": code},
                headers={"X-Forwarded-For": "10.61.0.1"})
            # Pre-fix: 200 ok, and the SAME code minted a second
            # account after a restart.
            self.assertEqual(status, 500, body)
        finally:
            self._fault(False)
        # No account was created by the faulted claim.
        status, _, _ = self._login("claim61-pw")
        self.assertEqual(status, 401)
        # The claim was rolled back: the code still redeems, once.
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "claim61b", "password": "claim61b-pw",
             "code": code},
            headers={"X-Forwarded-For": "10.61.0.2"})
        self.assertEqual(status, 200, body)
        _respawn_fixture(self.__class__)
        # After a restart the invite is used by claim61b only, the
        # account exists exactly once, and the code is spent.
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, _, _ = self._login("claim61b-pw")
        self.assertEqual(status, 200)
        status, _, _ = self._login("claim61-pw")
        self.assertEqual(status, 401)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "claim61c", "password": "claim61c-pw",
             "code": code},
            headers={"X-Forwarded-For": "10.61.0.3"})
        self.assertEqual(status, 400, body)

    # -- D4: add-friend role/cap saves are outcome-checked ----------
    def test_62_add_friend_role_cap_faulted_save(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "add", "label": "fault62",
                 "password": "fault62-pw", "master_pw": MASTER,
                 "role": "moderator", "cap": 1234}, admin)
            self.assertEqual(status, 500, body)
        finally:
            self._fault(False)
        # The account itself persisted (it is saved before the role),
        # but neither the role nor the cap may pretend to have.
        status, _, _ = self._login("fault62-pw")
        self.assertEqual(status, 200)
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 0}}, admin)
        self.assertEqual(status, 200, body)
        settings = body.get("settings") or {}
        self.assertNotIn("fault62", settings.get("roles") or {})
        self.assertNotIn("fault62", settings.get("user_caps") or {})

    # -- D4: a faulted factory-reset save answers an honest 500 -----
    def test_63_factory_reset_faulted_save(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"announcement": "PRE-RESET-63"}}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "friend_set_cap", "label": FRIEND,
             "cap": 4321, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "factory_reset", "master_pw": MASTER,
                 "confirm": "RESET"}, admin)
            # Pre-fix: 200 ok:true, then the pre-reset settings
            # silently resurrected at restart.
            self.assertEqual(status, 500, body)
            self.assertIn("revert at restart",
                          body.get("error", ""), body)
        finally:
            self._fault(False)
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 0}}, admin)
        self.assertEqual(status, 200, body)
        settings = body.get("settings") or {}
        # The 500 was honest: the persisted (pre-reset) settings are
        # exactly what a restart resurrects.
        self.assertEqual(settings.get("announcement"), "PRE-RESET-63")
        self.assertEqual(
            (settings.get("user_caps") or {}).get(FRIEND), 4321)


class Wave12RotationHarness(_FixtureServerBase):
    """A1: a proven /setup rotation carries the master-encrypted
    artefacts over to the new master, like change_master does."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def test_71_setup_rotation_carry_over(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        # An admin saved chat under the current master.
        status, body, _ = self._req(
            "POST", "/api/chats",
            {"action": "save", "title": "w12 canary chat",
             "messages": [{"r": "user", "t": "canary-71"}]}, ck=admin)
        self.assertEqual(status, 200, body)
        # An owner integrations vault under the current master.
        intg_dir = self.tmp / "userintegrations"
        intg_dir.mkdir(exist_ok=True)
        encrypt_keys({"linear": {"api_key": "lin-fixture-71"}},
                     MASTER, intg_dir / "_owner.enc")
        # The proven /setup rotation to a new master.
        status, body = self._form("/setup", {
            "password": MASTER_B, "confirm": MASTER_B,
            "current_master": MASTER, "k_groq": "sk-rotated-71"},
            admin)
        self.assertEqual(status, 302, body)
        # users.enc (friend-list disaster backup) opens under the
        # NEW master now — pre-fix it stayed under the old one.
        from key_security import decrypt_keys as _dec
        users = _dec(self.tmp / "users.enc", MASTER_B)
        self.assertIn(FRIEND, users)
        with self.assertRaises(Exception):
            _dec(self.tmp / "users.enc", MASTER)
        # The owner integrations vault carried over too.
        vault = _dec(intg_dir / "_owner.enc", MASTER_B)
        self.assertEqual(vault["linear"]["api_key"], "lin-fixture-71")
        # Admin chats open under the new master (pre-fix: 400
        # "chat storage unavailable in this session").
        _, _, admin_b = self._login(MASTER_B)
        self.assertTrue(admin_b)
        status, body, _ = self._req("POST", "/api/chats",
                                    {"action": "list"}, ck=admin_b)
        self.assertEqual(status, 200, body)
        titles = [c["title"] for c in body.get("chats", [])]
        self.assertIn("w12 canary chat", titles)
        # Disaster path: wipe the working access files, restart —
        # the friend list restores from users.enc under the NEW
        # master at the admin's login, so the friend can sign in.
        (self.tmp / "access.json").unlink(missing_ok=True)
        (self.tmp / "access.enc").unlink(missing_ok=True)
        _respawn_fixture(self.__class__)
        _, _, admin_b = self._login(MASTER_B)
        self.assertTrue(admin_b)
        status, _, _ = self._login(FRIEND_PW)
        self.assertEqual(status, 200)
        # Rotate back so the fixture ends on the original master.
        status, body = self._form("/setup", {
            "password": MASTER, "confirm": MASTER,
            "current_master": MASTER_B, "k_groq": "sk-shared-fake"},
            admin_b)
        self.assertEqual(status, 302, body)


class Wave12FirstRunHarness(_FixtureServerBase):
    """A3: first-run race losers (unproven deferred re-checks) must
    not burn the owner's global master-proof budget."""
    FIXTURE_FILES = ()

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def test_81_first_run_losers_dont_burn_budget(self):
        victim_pw = "victim-master-81"
        loser_pw = "loser-master-81"
        body_a = urllib.parse.urlencode({
            "password": loser_pw, "confirm": loser_pw,
            "current_master": "wrong-master-81",
            "k_groq": "sk-loser"}).encode()
        socks = []
        try:
            for _i in range(12):
                sock = socket.create_connection(
                    ("127.0.0.1", self.port), timeout=30)
                sock.sendall((
                    "POST /setup HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body_a)}\r\n"
                    "Connection: close\r\n\r\n").encode() + body_a[:8])
                socks.append(sock)
            time.sleep(0.5)
            # The genuine first setup completes meanwhile.
            status, _ = self._form("/setup", {
                "password": victim_pw, "confirm": victim_pw,
                "k_groq": "sk-victim"})
            self.assertEqual(status, 302)
            # Every held loser now lands on the deferred re-check:
            # all get the same 401 as any unproven rotation.
            for sock in socks:
                sock.sendall(body_a[8:])
                resp = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                status_line = resp.split(b"\r\n", 1)[0].decode(
                    errors="replace")
                self.assertIn("401", status_line, resp[:400])
        finally:
            for sock in socks:
                try:
                    sock.close()
                except Exception:
                    pass
        # Pre-fix, the losers' deferred proofs debited the shared
        # ("master", "") budget 10 times and this CORRECT-master
        # console proof was refused (401) for up to 900s.
        _, _, admin = self._login(victim_pw)
        self.assertTrue(admin)
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "2fa_status", "master_pw": victim_pw},
            ck=admin)
        self.assertEqual(status, 200, body)


class Wave12OpenHarness(_FixtureServerBase):
    """A2: open mode keeps per-source signups working while a flat
    global ceiling restores the cross-source oracle bound."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def test_91_open_mode_global_ceiling_binds(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"registration": "open"}}, admin)
        self.assertEqual(status, 200, body)
        try:
            # Wave 13 semantics (run-12 auth fixes): a successful
            # signup refunds its PER-SOURCE hit but NOT its global
            # hit, so creations accrue against the global ceiling
            # exactly like taken verdicts; and each candidate has a
            # 10/900 per-candidate global sub-bucket, so ONE
            # candidate can no longer burn the ceiling alone. The
            # ceiling is therefore exhausted with TWENTY-FIVE
            # distinct candidates: 25 creations (25 global hits) +
            # 9 taken probes each (225 more) = 250. (Wave 14 raised
            # the ceiling 100 -> 250 as a mitigation — successes
            # still accrue, no refund returned. Pre-wave-13 this
            # test used one candidate x100 — the very burn fix 15
            # kills — and relied on the global refund fix 14
            # removes.)
            cands = []
            for i, label in enumerate(("legit91a", "legit91b")):
                pw = f"{label}-pw"
                status, body, _ = self._req(
                    "POST", "/api/invite/redeem",
                    {"label": label, "password": pw},
                    headers={"X-Forwarded-For": f"10.91.0.{i + 1}"})
                self.assertEqual(status, 200, (label, body))
                cands.append(pw)
            for i in range(23):
                label = f"cand91_{i}"
                pw = f"cand91-pw-{i}"
                status, body, _ = self._req(
                    "POST", "/api/invite/redeem",
                    {"label": label, "password": pw},
                    headers={"X-Forwarded-For": f"10.91.2.{i}"})
                self.assertEqual(status, 200, (label, body))
                cands.append(pw)
            import concurrent.futures

            def probe(job):
                ci, k = job
                return self._req(
                    "POST", "/api/invite/redeem",
                    {"label": f"taken91_{ci}_{k}", "password": cands[ci]},
                    headers={"X-Forwarded-For":
                             f"10.91.1.{ci * 9 + k}"})[0]
            jobs = [(ci, k) for ci in range(25) for k in range(9)]
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=8) as ex:
                codes = list(ex.map(probe, jobs))
            self.assertEqual(codes, [400] * 225)
            # The 251st verdict — taken or free, from a brand-new
            # source — is the same generic 429.
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "taken91_x", "password": FRIEND_PW},
                headers={"X-Forwarded-For": "10.91.9.9"})
            self.assertEqual(status, 429, body)
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "free91", "password": "free91-pw-999"},
                headers={"X-Forwarded-For": "10.91.9.10"})
            self.assertEqual(status, 429, body)
        finally:
            self._access(
                {"action": "settings_set", "master_pw": MASTER,
                 "patch": {"registration": "invite"}}, admin)


class Wave13UnitTests(unittest.TestCase):
    """Wave 13 (run-12 fixes): governance snapshot, locked
    reserve+count primitive, settle barrier, CAS persisted-context,
    firstrun ledger separation, and source shapes."""

    def _temp_settings(self):
        import tempfile
        from pathlib import Path as _P
        td = tempfile.TemporaryDirectory()
        saved = (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
                 server.RESTORE_KEY)
        server.SETTINGS_PATH = _P(td.name) / "settings.json"
        server.SETTINGS_ENC_PATH = _P(td.name) / "settings.enc"
        server.RESTORE_KEY = "unit-restore-13"
        return td, saved

    def _restore_settings_env(self, saved, orig):
        (server.SETTINGS_PATH, server.SETTINGS_ENC_PATH,
         server.RESTORE_KEY) = saved
        server._SETTINGS.clear()
        server._SETTINGS.update(orig)

    # -- Fix 3: _governance returns ONE consistent snapshot --------
    def test_w13_governance_snapshot_never_torn(self):
        orig = dict(server._SETTINGS)
        try:
            state_a = ({"x13"}, {"y13": 1})
            state_b = ({"y13"}, {"x13": 1})
            stop = []

            def writer():
                flip = False
                while not stop:
                    with server._SETTINGS_LOCK:
                        if flip:
                            server._SETTINGS["provider_disabled"] = ["x13"]
                            server._SETTINGS["provider_limits"] = {"y13": 1}
                        else:
                            server._SETTINGS["provider_disabled"] = ["y13"]
                            server._SETTINGS["provider_limits"] = {"x13": 1}
                    flip = not flip

            with server._SETTINGS_LOCK:
                server._SETTINGS["provider_disabled"] = ["x13"]
                server._SETTINGS["provider_limits"] = {"y13": 1}
            t = threading.Thread(target=writer)
            t.start()
            try:
                for _i in range(3000):
                    dis, lims = server._governance()
                    snap = (set(dis), dict(lims))
                    self.assertIn(snap, (state_a, state_b),
                                  f"torn snapshot: {snap}")
            finally:
                stop.append(True)
                t.join(10)
            # The returned limits are a copy, not the live dict.
            _d, lims = server._governance()
            lims["zz13"] = 5
            self.assertNotIn("zz13",
                             server._SETTINGS.get("provider_limits") or {})
        finally:
            server._SETTINGS.clear()
            server._SETTINGS.update(orig)

    # -- Fix 2: reserve+count admits exactly one at limit 1 -------
    def test_w13_reserve_capped_admits_exactly_one(self):
        saved = list(server._INFLIGHT)
        try:
            server._INFLIGHT.clear()
            barrier = threading.Barrier(8)
            got = []

            def worker():
                barrier.wait(10)
                got.append(server._inflight_reserve_capped(
                    "u13", "prov13", 0, 1))
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(20)
            # Pre-fix shape (add -> count -> drop as separate ops)
            # let rendezvoused spends refuse EACH OTHER (0 admitted).
            admitted = [r for r in got if r is not None]
            self.assertEqual(len(admitted), 1, got)
            self.assertEqual(server._inflight_n(provider="prov13"), 1)
            # A completed spend already at the limit refuses.
            self.assertIsNone(server._inflight_reserve_capped(
                "u13", "prov13", 1, 1))
            for r in admitted:
                server._inflight_drop(r)
        finally:
            server._INFLIGHT.clear()
            server._INFLIGHT.extend(saved)

    # -- Fix 9: a save starting DURING the check re-opens the verdict
    def test_w13_outcome_barrier_save_starts_during_check(self):
        orig = dict(server._SETTINGS)
        td, saved = self._temp_settings()
        orig_persisted = server._persisted_settings
        try:
            server._SETTINGS["announcement"] = "BASE13"
            self.assertTrue(server._save_settings())
            server._SETTINGS["announcement"] = "GHOST13"  # caller live
            calls = []

            def patched():
                calls.append(1)
                if len(calls) == 1:
                    # A covering save starts during this read and
                    # lands the caller's GHOST mutation; this read
                    # itself still returns the stale BASE snapshot.
                    def land():
                        server._save_settings()
                    threading.Thread(target=land).start()
                    # The save must have STARTED (its activity
                    # counter incremented) before this read returns,
                    # exactly as a real covering save starting during
                    # a ~0.7s mirror decrypt would have.
                    _dl = time.time() + 5
                    while server._SETTINGS_ACTIVE[0] == 0 \
                            and time.time() < _dl:
                        time.sleep(0.005)
                    return {"announcement": "BASE13"}
                return orig_persisted()
            server._persisted_settings = patched
            rolled = []
            oc = server._settings_outcome(
                False, lambda s: s.get("announcement") == "GHOST13",
                lambda: rolled.append(1))
            # Pre-fix: the one-shot wait had already returned, the
            # stale read answered "failed" and rolled back — then
            # the covering save landed GHOST anyway (the ghost).
            self.assertEqual(oc, "ok")
            self.assertEqual(rolled, [])
            self.assertEqual(
                orig_persisted().get("announcement"), "GHOST13")
        finally:
            server._persisted_settings = orig_persisted
            self._restore_settings_env(saved, orig)
            td.cleanup()

    # -- Fix 9b: bound expiry with a save in flight -> conflict -----
    def test_w13_outcome_bound_expiry_conflict_no_rollback(self):
        orig = dict(server._SETTINGS)
        td, saved = self._temp_settings()
        try:
            server._SETTINGS["announcement"] = "BASE13"
            self.assertTrue(server._save_settings())
            server._SETTINGS["announcement"] = "NEVER13"
            server._SETTINGS_ACTIVE[0] += 1  # a save that never lands
            rolled = []
            try:
                oc = server._settings_outcome(
                    False,
                    lambda s: s.get("announcement") == "NEVER13",
                    lambda: rolled.append(1))
            finally:
                server._SETTINGS_ACTIVE[0] -= 1
            # Pre-fix: "failed" + rollback after the 3s wait, even
            # though the in-flight save might still land the change.
            self.assertEqual(oc, "conflict")
            self.assertEqual(rolled, [])
        finally:
            server._SETTINGS_ACTIVE[0] = 0
            self._restore_settings_env(saved, orig)
            td.cleanup()

    # -- Fix 10: CAS rollback spares a peer's identical change ------
    def test_w13_cas_persisted_identical_peer_survives(self):
        orig = dict(server._SETTINGS)
        td, saved = self._temp_settings()
        try:
            # The peer's IDENTICAL suspension of alice landed and
            # persisted (the peer was told ok). The caller's own
            # patch {suspended+alice, announcement=A13} faulted: its
            # announcement never persisted.
            server._SETTINGS["suspended"] = ["alice"]
            server._SETTINGS["announcement"] = ""
            self.assertTrue(server._save_settings())  # persisted peer
            server._SETTINGS["announcement"] = "A13"  # caller live only

            def rollback():
                server._cas_rollback_list_entry(
                    "suspended", "alice", [], ["alice"])
                server._cas_rollback_keys(
                    {"announcement": ""}, {"announcement": "A13"})
            oc = server._settings_outcome(
                False,
                lambda s: "alice" in (s.get("suspended") or [])
                and s.get("announcement") == "A13",
                rollback)
            self.assertEqual(oc, "failed")
            # Pre-fix the value-equality CAS removed alice: live
            # presence equalled the caller's value, which was ALSO
            # the peer's acknowledged, persisted value.
            self.assertEqual(server._SETTINGS["suspended"], ["alice"])
            self.assertEqual(server._SETTINGS["announcement"], "")
        finally:
            self._restore_settings_env(saved, orig)
            td.cleanup()

    # -- Fix 16: the firstrun ledger is its own bucket --------------
    def test_w13_firstrun_ledger_separate_from_master(self):
        saved = dict(server._PW_FAILS)
        try:
            server._PW_FAILS.clear()
            for _i in range(10):
                self.assertFalse(server._pw_throttled("firstrun", ""))
                server._pw_failed("firstrun", "")
            self.assertTrue(server._pw_throttled("firstrun", ""))
            # A3 property: the shared master budget is untouched —
            # the owner's correct master still proves afterwards.
            self.assertNotIn(("master", ""), server._PW_FAILS)
            self.assertFalse(server._pw_throttled("master", ""))
        finally:
            server._PW_FAILS.clear()
            server._PW_FAILS.update(saved)

    # -- Source shapes for the whole wave ---------------------------
    def test_w13_source_shapes(self):
        src = (APP / "server.py").read_text()
        js = (REPO / "bin" / "nexuslocal.js").read_text()
        # Caps: governance snapshot used at every check site.
        self.assertGreaterEqual(src.count("_governance()"), 5)
        self.assertIn("def _inflight_reserve_capped", src)
        v1seg = src[src.index("def _v1_chat"):src.index(
            "return 502", src.index("def _v1_chat"))]
        self.assertIn("_inflight_reserve_capped(", v1seg)
        self.assertGreaterEqual(src.count("_lane_spend_reserve("), 4)
        # Caps fix 1: the pollinations born-tag keeps the pick name.
        self.assertIn('self._cap_res["provider"] = provider', src)
        # Wave 16 (CAPS15-3): the substitution check+retag is one
        # locked helper call, not the wave-13/15 two-statement
        # check-then-assign pair this assertion used to pin.
        self.assertIn("_provider_blocked_and_tag(_sub_p, self._cap_res)",
                      src)
        # Auth: per-candidate bucket; firstrun ledger wired BEFORE
        # the quiet decrypt, debiting only on failure.
        self.assertIn('"open:cand:"', src)
        i = src.index("if not _entry_keys_exist and key_path.exists():")
        seg = src[i:src.index("encrypt_keys(keys, pw, key_path)", i)]
        self.assertLess(seg.index('_pw_throttled("firstrun", "")'),
                        seg.index("decrypt_keys("))
        self.assertIn('_pw_failed("firstrun", "")', seg)
        self.assertNotIn('_pw_failed("master", "")', seg)
        # Auth fix 17: collision guard on /setup (both proof sites)
        # and the floor raised to 10.
        self.assertGreaterEqual(
            src.count("_password_taken(_load_access(), pw)"), 2)
        self.assertIn("len(pw) < 10", src)
        # Settings: whole-document factory pred, honest revoke and
        # signup-role outcomes.
        self.assertIn("_SETTINGS_DEFAULTS.items()", src)
        self.assertIn("cleanup could not be saved", src)
        self.assertIn("signed up, but the role could not be saved", src)
        # Launcher: export prefix everywhere, comment rule, early
        # handlers, tracked installs.
        # Wave 18 (run-17 L17-1): the four .env WRITE-BACK regexes
        # (claimStep x3 literals, removeEngineAdminCreds x1) now
        # anchor the export prefix with horizontal whitespace —
        # (?:export[ \t]+)? — so a match can only start at a true
        # line start on CRLF files; the read-side parser keeps
        # the \s form. The export-prefix-everywhere property is
        # the SUM over both forms.
        # Wave 19 (run-18 L18-L2): the write-back classes widened
        # again — [ \t] became [^\S\r\n] (every whitespace the
        # parser accepts: VT/FF/NBSP leads included; still never
        # CR/LF) — so the write-back export prefix is now the
        # (?:export[^\S\r\n]+)? form and the property is the SUM
        # over all three forms.
        self.assertGreaterEqual(
            js.count("(?:export\\s+)?")
            + js.count("(?:export[ \\t]+)?")
            + js.count("(?:export[^\\S\\r\\n]+)?"), 4)
        # Wave 14 (run-13 L13-2): the unquoted '#' rule is the
        # whitespace-aware match now, and the parser records the
        # alternate form for verify's one retry — the wave-13
        # first-'#' indexOf is gone by design.
        self.assertIn("v.match(/\\s+#|^#/)", js)
        self.assertIn("passwordAlt", js)
        self.assertIn("runInstall(_npmCmd", js)
        self.assertLess(js.index('process.on("SIGTERM"'),
                        js.index("Installing engine dependencies"))
        node = shutil.which("node")
        if node:
            r = subprocess.run([node, "--check",
                                str(REPO / "bin" / "nexuslocal.js")],
                               capture_output=True)
            self.assertEqual(r.returncode, 0,
                             r.stderr.decode(errors="replace"))


class Wave13LauncherTests(unittest.TestCase):
    """Wave 13 launcher fixes over real boots: export prefix,
    inline comments, loadability gate, better-sqlite3 gate, and
    shutdown during the install phase. Fixture/boot/verify helpers
    are borrowed from a Wave12LauncherTests instance (so the wave-12
    tests themselves are not re-run under this class)."""

    ENGINE_EMAIL = Wave12LauncherTests.ENGINE_EMAIL
    ENGINE_PW = Wave12LauncherTests.ENGINE_PW

    def _h(self):
        return Wave12LauncherTests()

    # -- Fix 5: export-prefixed credentials parse -------------------
    def test_w13_verify_export_prefix(self):
        self._h()._verify_variant(
            f"export ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
            f"export ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n")

    # -- Fix 4: inline comments follow dotenv -----------------------
    def test_w13_verify_inline_comments(self):
        # Wave 14 post-fix semantics (run-13 L13-2): a '#' NOT
        # preceded by whitespace is password DATA in the primary
        # parse now (this wave-13 variant's `pw#tail` line is
        # exactly that ambiguity class), so the first login carries
        # the full value; the stub (holding the dotenv form)
        # refuses it, and verifyClaim's alternate-form retry — the
        # dotenv-truncated value — is accepted. Credentials are
        # kept and no foreign-claim alarm fires. (A `# comment`
        # after whitespace still truncates in the primary parse —
        # see the wave-14 parser tests.)
        h = self._h()
        tmp = h._fixture(
            f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL} # the owner\n"
            f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}#tail\n")
        proc = h._boot(tmp)
        try:
            h._wait_for(proc, tmp,
                        lambda: len(h._logins(tmp)) >= 2,
                        what="verify login + dotenv-form retry")
            logins = h._logins(tmp)
            self.assertEqual(logins[0]["password"],
                             self.ENGINE_PW + "#tail")
            self.assertEqual(logins[1]["password"], self.ENGINE_PW)
            self.assertEqual(logins[1]["email"], self.ENGINE_EMAIL)
            time.sleep(1)
            env_after = (tmp / "app" / ".env").read_text(
                encoding="utf-8")
            self.assertIn("ENGINE_ADMIN_PASSWORD", env_after)
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertNotIn("NOT the ones from app/.env", log)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_w13_verify_comment_only_value_is_absent(self):
        self._h()._verify_variant(
            "ENGINE_ADMIN_PASSWORD= # none yet\n"
            f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
            f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n")

    # -- Fix 5: a foreign claim removes EXPORT lines too ------------
    def test_w13_export_lines_removed_on_foreign_claim(self):
        tmp = self._h()._fixture(
            f"export ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
            "export ENGINE_ADMIN_PASSWORD=wrong-pw-13\n")
        proc = self._h()._boot(tmp)
        try:
            self._h()._wait_for(proc, tmp,
                           lambda: len(self._h()._logins(tmp)) >= 1,
                           what="verify login")
            # The stub refused (401, definitive, email not defaulted):
            # the credentials are removed — export lines included.
            time.sleep(1)
            env_after = (tmp / "app" / ".env").read_text(
                encoding="utf-8")
            self.assertNotIn("ENGINE_ADMIN_PASSWORD", env_after)
            self.assertNotIn("ENGINE_ADMIN_EMAIL", env_after)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 6: a dep with no entry point fails the gate ------------
    def test_w13_gate_missing_entry_point_installs(self):
        tmp = self._h()._fixture("ENGINE_ADMIN_PASSWORD=x\n")
        (tmp / "app" / "engine" / "server" / "node_modules"
         / "express" / "index.js").unlink()
        proc = self._h()._boot(tmp)
        try:
            self._h()._wait_for(
                proc, tmp,
                lambda: (tmp / "startup.log").exists()
                and "Installing engine dependencies"
                in (tmp / "startup.log").read_text(errors="replace"),
                timeout=60, what="npm gate on entry-less dep")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 7: missing better-sqlite3 (non-Android) fails the gate -
    def test_w13_gate_better_sqlite3_installs(self):
        if sys.platform == "android":
            self.skipTest("Android keeps the exemption")
        tmp = self._h()._fixture("ENGINE_ADMIN_PASSWORD=x\n")
        srv = tmp / "app" / "engine" / "server"
        pkg = json.loads((srv / "package.json").read_text())
        pkg["optionalDependencies"] = {"better-sqlite3": "^11.0.0"}
        (srv / "package.json").write_text(json.dumps(pkg))
        proc = self._h()._boot(tmp)
        try:
            self._h()._wait_for(
                proc, tmp,
                lambda: (tmp / "startup.log").exists()
                and "Installing engine dependencies"
                in (tmp / "startup.log").read_text(errors="replace"),
                timeout=60, what="npm gate on missing better-sqlite3")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 8: SIGTERM during install kills the npm child ----------
    def test_w13_sigterm_during_install_kills_npm(self):
        import signal as _signal
        node = shutil.which("node")
        if not node or not shutil.which("unshare"):
            self.skipTest("node/unshare not available")
        tmp = self._h()._fixture("ENGINE_ADMIN_PASSWORD=x\n")
        (tmp / "app" / "engine" / "server" / "node_modules"
         / "express" / "index.js").unlink()  # gate -> install phase
        fakebin = tmp / "fakebin"
        fakebin.mkdir()
        npm_stub = fakebin / "npm"
        npm_stub.write_text(
            "#!/bin/sh\n"
            "echo $$ > \"$NPM_PID_FILE\"\n"
            "exec sleep 120\n")
        npm_stub.chmod(0o755)
        env = dict(os.environ)
        env.update({
            "NPM_PID_FILE": str(tmp / "npm.pid"),
            "PATH": str(fakebin) + os.pathsep + env.get("PATH", ""),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        cmd = ["unshare", "-n", "bash", "-c",
               "ip link set lo up 2>/dev/null; exec "
               f"{node} {tmp / 'bin' / 'nexuslocal.js'}"]
        proc = subprocess.Popen(
            cmd, cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self._h()._wait_for(proc, tmp, lambda: (tmp / "npm.pid").exists(),
                           timeout=60, what="npm install in flight")
            proc.send_signal(_signal.SIGTERM)
            proc.wait(timeout=15)
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertIn("Shutting down...", log)
            self.assertTrue(self._h()._pid_dead(tmp / "npm.pid"),
                            "npm child orphaned by SIGTERM during install")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)


class Wave13FaultHarness(_FixtureServerBase):
    """Run-12 data fixes over real HTTP with settings saves
    fault-injected in the disposable copy: SAVE_FAULT fails every
    save; SAVE_FAIL2 fails from the second save onwards (the claim
    save lands, the role save faults)."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        sp = cls.tmp / "server.py"
        txt = sp.read_text()
        anchor = "def _save_settings():\n"
        assert txt.count(anchor) == 1
        sp.write_text(txt.replace(
            anchor,
            anchor + "    if (Path(__file__).parent / "
                     "\"SAVE_FAULT\").exists():\n"
                     "        return False\n"
                     "    _f13 = Path(__file__).parent / \"SAVE_FAIL2\"\n"
                     "    if _f13.exists():\n"
                     "        try:\n"
                     "            _n13 = int(_f13.read_text() or \"0\")\n"
                     "        except Exception:\n"
                     "            _n13 = 0\n"
                     "        _n13 += 1\n"
                     "        _f13.write_text(str(_n13))\n"
                     "        if _n13 >= 2:\n"
                     "            return False\n", 1))
        _respawn_fixture(cls)

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _fault(self, on):
        flag = self.tmp / "SAVE_FAULT"
        if on:
            flag.write_text("x")
        else:
            flag.unlink(missing_ok=True)

    def _fail2(self, on):
        flag = self.tmp / "SAVE_FAIL2"
        if on:
            flag.write_text("0")
        else:
            flag.unlink(missing_ok=True)

    # -- Fix 12: a faulted revoke cleanup save answers 500 ----------
    def test_11_revoke_faulted_cleanup_save(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "add", "label": "rev13", "password": "rev13-pw",
             "master_pw": MASTER, "role": "moderator", "cap": 777},
            admin)
        self.assertEqual(status, 200, body)
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "revoke", "label": "rev13",
                 "master_pw": MASTER}, admin)
            # Pre-fix: 200 ok, and the role/cap resurrected at
            # restart to be inherited by a re-created friend.
            self.assertEqual(status, 500, body)
            self.assertIn("cleanup could not be saved",
                          body.get("error", ""), body)
        finally:
            self._fault(False)
        # The account itself really is revoked.
        status, _, _ = self._login("rev13-pw")
        self.assertEqual(status, 401)

    # -- Fix 11: a faulted reset with empty collections but dirty
    #    scalars answers 500 (the old pred answered 200) -------------
    def test_12_factory_reset_faulted_save_scalars(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"maintenance": True, "daily_cap": 999,
                       "instance_name": "PRE13-NAME",
                       "provider_disabled": ["groq"]}}, admin)
        self.assertEqual(status, 200, body)
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "factory_reset", "master_pw": MASTER,
                 "confirm": "RESET"}, admin)
            # Pre-fix: the 5-collection pred saw empty collections
            # and answered 200 while maintenance/daily_cap/
            # instance_name/provider_disabled resurrected.
            self.assertEqual(status, 500, body)
        finally:
            self._fault(False)

    # -- Fix 13: claim lands, role save faults -> honest 500 --------
    def test_13_signup_role_faulted_save(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "invite_create", "role": "moderator",
             "days": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        code = body["code"]
        self._fail2(True)
        try:
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "role13", "password": "role13-pw",
                 "code": code},
                headers={"X-Forwarded-For": "10.13.0.1"})
            # Pre-fix: 200 ok, and the moderator role silently
            # downgraded to friend at restart.
            self.assertEqual(status, 500, body)
            self.assertIn("role could not be saved",
                          body.get("error", ""), body)
        finally:
            self._fail2(False)
        # The account exists (the claim and creation were durable) —
        # only the role is missing, exactly as the 500 says.
        status, _, _ = self._login("role13-pw")
        self.assertEqual(status, 200)


class Wave13SetupHarness(_FixtureServerBase):
    """Fix 17: /setup rotation applies change_master's collision
    guard and its 10-char floor; same-master stays allowed."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def test_21_setup_rotation_collision_and_floor(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        # 9-char new master: refused (pre-fix the floor was 8).
        status, body = self._form("/setup", {
            "password": "short-99x", "confirm": "short-99x",
            "current_master": MASTER, "k_groq": "sk-x21"}, admin)
        self.assertEqual(status, 400, body)
        # New master == a friend's password: refused AFTER the
        # proof, like change_master (pre-fix: 302, and the friend's
        # password then signed in as admin "Rudra").
        status, body = self._form("/setup", {
            "password": FRIEND_PW, "confirm": FRIEND_PW,
            "current_master": MASTER, "k_groq": "sk-x21"}, admin)
        self.assertEqual(status, 400, body)
        self.assertIn("already in use by a friend",
                      body.get("error", ""), body)
        # The master is unchanged and the friend is NOT shadowed:
        # the friend's password still signs in as the friend.
        _, _, admin2 = self._login(MASTER)
        self.assertTrue(admin2)
        status, body, _ = self._login(FRIEND_PW)
        self.assertEqual(status, 200)
        self.assertFalse(body.get("admin"), body)
        # Same-master key replacement still works (302).
        status, body = self._form("/setup", {
            "password": MASTER, "confirm": MASTER,
            "current_master": MASTER, "k_groq": "sk-shared-fake"},
            admin2)
        self.assertEqual(status, 302, body)


class Wave13OpenHarness(_FixtureServerBase):
    """Fix 15: one known-taken candidate cannot burn the global
    signup ceiling across rotating sources."""
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def test_31_single_candidate_cannot_burn_global(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"registration": "open"}}, admin)
        self.assertEqual(status, 200, body)
        try:
            # Manufacture a known-taken candidate via a normal
            # open signup (the verifier's leg M).
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "burnsrc13", "password": "burn-cand-13"},
                headers={"X-Forwarded-For": "10.31.0.1"})
            self.assertEqual(status, 200, body)
            codes = []
            for i in range(15):
                status, _b, _ = self._req(
                    "POST", "/api/invite/redeem",
                    {"label": f"burn13_{i}", "password": "burn-cand-13"},
                    headers={"X-Forwarded-For": f"10.31.1.{i}"})
                codes.append(status)
            # 10 verdicts (the creation already spent 1 sub-bucket
            # hit, so verdicts 1-9 here are 400 and the rest 429)...
            self.assertEqual(codes[:9], [400] * 9, codes)
            self.assertEqual(codes[9:], [429] * 6, codes)
            # ...and the global ceiling is NOT burned: a legitimate
            # free signup from a fresh source still succeeds.
            status, body, _ = self._req(
                "POST", "/api/invite/redeem",
                {"label": "free13", "password": "free13-pw-999"},
                headers={"X-Forwarded-For": "10.31.9.9"})
            self.assertEqual(status, 200, body)
        finally:
            self._access(
                {"action": "settings_set", "master_pw": MASTER,
                 "patch": {"registration": "invite"}}, admin)


class Wave14UnitTests(unittest.TestCase):
    """Wave 14 (run-13 fixes): media spend-leg admission, completed
    inside the reserve lock, invite-remove rollback union removal,
    redeem-role rollback placement, the open:all mitigation bound,
    and the add-friend clean slate."""

    # -- Fix 1: a born-tagged pair at limit 1 admits exactly one ---
    def test_w14_media_pair_admits_exactly_one(self):
        orig_settings = dict(server._SETTINGS)
        # Wave 15 (CAPS14-4): _provider_blocked's completed term now
        # comes from the in-memory provider counter, so the oracle
        # stubbed here is _provider_counts_today, not _today_counts.
        saved_counts = server._provider_counts_today
        saved_inflight = list(server._INFLIGHT)
        try:
            server._SETTINGS["provider_limits"] = {"prov14": 1}
            server._SETTINGS["provider_disabled"] = []
            server._provider_counts_today = lambda: {}
            server._INFLIGHT.clear()
            r1 = server._inflight_add("u14", "prov14")
            r2 = server._inflight_add("u14", "prov14")
            # Pre-fix (>= form, peer counted in full): BOTH True.
            self.assertFalse(
                server._provider_blocked("prov14", exclude=r1))
            self.assertTrue(
                server._provider_blocked("prov14", exclude=r2))
            # Solo at limit 1 is admitted; with one completed spend
            # even the first reservation is refused.
            server._INFLIGHT.clear()
            r = server._inflight_add("u14", "prov14")
            self.assertFalse(
                server._provider_blocked("prov14", exclude=r))
            server._provider_counts_today = lambda: {"prov14": 1}
            self.assertTrue(
                server._provider_blocked("prov14", exclude=r))
            # The untagged pre-check form is unchanged: one
            # in-flight spend at limit 1 blocks a fresh caller.
            server._provider_counts_today = lambda: {}
            self.assertTrue(server._provider_blocked("prov14"))
        finally:
            server._provider_counts_today = saved_counts
            server._INFLIGHT.clear()
            server._INFLIGHT.extend(saved_inflight)
            server._SETTINGS.clear()
            server._SETTINGS.update(orig_settings)

    # -- Fix 2: completed is evaluated INSIDE the reserve lock -----
    def test_w14_reserve_completed_inside_lock(self):
        saved_inflight = list(server._INFLIGHT)
        try:
            server._INFLIGHT.clear()
            seen = {}

            def completed_fn():
                seen["locked"] = server._INFLIGHT_LOCK.locked()
                return 1  # a peer completed in the old pre-lock gap

            # Pre-fix the primitive took a precomputed int; a stale
            # 0 computed before the peer completed admitted a second
            # spend against limit 1. The callable form is judged on
            # the value read under the lock: refused.
            self.assertIsNone(server._inflight_reserve_capped(
                "u14", "prov14", completed_fn, 1))
            self.assertTrue(seen.get("locked"))
            self.assertEqual(server._inflight_n(provider="prov14"), 0)
            # A callable reporting room admits exactly one, and the
            # plain int form keeps working for existing callers.
            res = server._inflight_reserve_capped(
                "u14", "prov14", lambda: 0, 1)
            self.assertIsNotNone(res)
            server._inflight_drop(res)
            self.assertIsNotNone(server._inflight_reserve_capped(
                "u14", "prov14", 0, 1))
            server._INFLIGHT.clear()
            # Both callsites pass the callable form now.
            # Wave 15 (CAPS14-4): the callable reads the in-memory
            # provider counter — a full usage scan never runs
            # inside the reserve lock again.
            src = (REPO / "app" / "server.py").read_text()
            self.assertNotIn("_completed = _today_counts(", src)
            self.assertNotIn("lambda: _today_counts(", src)
            self.assertEqual(
                src.count("lambda: _provider_counts_today()"), 2)
        finally:
            server._INFLIGHT.clear()
            server._INFLIGHT.extend(saved_inflight)

    # -- Fix 3: invite-remove rollback has no persisted union ------
    def test_w14_invite_remove_rollback_restores(self):
        orig = dict(server._SETTINGS)
        saved_stack = list(server._OUTCOME_PERSISTED)
        try:
            server._SETTINGS["invites"] = [{"h": "KEEP14"}]
            # The judged persisted snapshot still CONTAINS the
            # removed invite (the revoke save faulted). Wave 13
            # unioned it into the skip set and the rollback was an
            # exact no-op; wave 14 re-adds it live.
            server._OUTCOME_PERSISTED.append(
                {"invites": [{"h": "KEEP14"}, {"h": "GONE14"}]})
            server._cas_rollback_invite_remove([{"h": "GONE14"}])
            self.assertEqual(
                {i["h"] for i in server._SETTINGS["invites"]},
                {"KEEP14", "GONE14"})
            # An entry already live is not duplicated.
            server._cas_rollback_invite_remove([{"h": "GONE14"}])
            self.assertEqual(len(server._SETTINGS["invites"]), 2)
        finally:
            server._OUTCOME_PERSISTED[:] = saved_stack
            server._SETTINGS.clear()
            server._SETTINGS.update(orig)

    # -- Fix 4: the redeem role rollback rides INTO the outcome ----
    def test_w14_redeem_role_rollback_in_outcome(self):
        src = (REPO / "app" / "server.py").read_text()
        i = src.index("_roc13 = _settings_outcome(")
        seg = src[i:i + 900]
        # The rollback is the outcome's third argument now...
        self.assertIn("lambda: _cas_rollback_dict_entry(", seg)
        # ...and the manual post-hoc block (which fired even on
        # "conflict", with an empty _OUTCOME_PERSISTED) is gone:
        # after the outcome call, a non-ok verdict goes straight to
        # the status mapping.
        j = seg.index('if _roc13 != "ok":')
        self.assertNotIn("_cas_rollback_dict_entry",
                         seg[j:j + 200])

    # -- Fix 9 (MITIGATION): open:all bound is 250/900 -------------
    def test_w14_open_all_bound_250(self):
        import re as _re14
        src = (REPO / "app" / "server.py").read_text()
        flat = _re14.sub(r"\s+", " ", src)
        self.assertIn(
            '_rl_ok("redeemprobe", "open:all", 250, 900)', flat)
        self.assertNotIn(
            '_rl_ok("redeemprobe", "open:all", 100, 900)', flat)
        # No refund of the global hit returned with the raise.
        self.assertNotIn('_rl_refund("redeemprobe", "open:all")',
                         src)


class Wave14LauncherTests(unittest.TestCase):
    """Wave 14 launcher fixes: escape-aware .env parsing, the
    unquoted-'#' claim/verify shapes, the shutdown SIGKILL
    escalation capture, and the native-dep loadability gate."""

    def _h(self):
        return Wave12LauncherTests()

    def _parse(self, env_text):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        script = (
            "const fs=require('fs');"
            "const src=fs.readFileSync(process.argv[1],'utf8');"
            "const i=src.indexOf('function parseEngineAdminCreds');"
            "const j=src.indexOf('\\n}\\n',i);"
            "eval(src.slice(i,j+3));"
            "const r=parseEngineAdminCreds(process.argv[2]);"
            "const codes=s=>s===undefined?null:"
            "[...s].map(c=>c.charCodeAt(0));"
            "console.log(JSON.stringify({pw:codes(r.password),"
            "alt:codes(r.passwordAlt)}));")
        r = subprocess.run(
            [node, "-e", script, str(REPO / "bin" / "nexuslocal.js"),
             env_text], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    @staticmethod
    def _codes(s):
        return [ord(c) for c in s]

    # -- Fix 5: quoted values scan escape-aware (dotenv-exact) -----
    def test_w14_parse_escaped_quote(self):
        # dotenv: "a\"b#c" -> a\"b#c (the escaped quote is data).
        out = self._parse(
            'ENGINE_ADMIN_PASSWORD="a\\"b#c"\n')
        self.assertEqual(out["pw"], self._codes('a\\"b#c'))
        # Escaped backslash before the quote: the quote DOES close,
        # and the trailing comment is dropped.
        out = self._parse(
            'ENGINE_ADMIN_PASSWORD="a\\\\" # tail\n')
        self.assertEqual(out["pw"], self._codes('a\\\\'))
        # Quote-then-comment (wave-13 case, must not regress).
        out = self._parse('ENGINE_ADMIN_PASSWORD="abc" # c\n')
        self.assertEqual(out["pw"], self._codes("abc"))
        # Adjacent quotes are data throughout (dotenv greedy).
        out = self._parse('ENGINE_ADMIN_PASSWORD="abc""def"\n')
        self.assertEqual(out["pw"], self._codes('abc""def'))

    # -- Fix 6 (claim shape): '#' is data unless at start / after
    #    whitespace; run-12 comment cases keep working --------------
    def test_w14_parse_unquoted_hash(self):
        out = self._parse("ENGINE_ADMIN_PASSWORD=p@ss#w0rd!\n")
        self.assertEqual(out["pw"], self._codes("p@ss#w0rd!"))
        # Symmetrically, the alternate form is the dotenv
        # truncation, for records whose engine holds that form.
        self.assertEqual(out["alt"], self._codes("p@ss"))
        out = self._parse(
            "ENGINE_ADMIN_PASSWORD=abc123 # comment\n")
        self.assertEqual(out["pw"], self._codes("abc123"))
        # The untruncated form is recorded as the verify alternate.
        self.assertEqual(out["alt"],
                         self._codes("abc123 # comment"))
        out = self._parse("ENGINE_ADMIN_PASSWORD= # none yet\n")
        self.assertIsNone(out["pw"])

    # -- Fix 5 E2E: verify keeps dotenv-valid escaped credentials --
    def test_w14_verify_escaped_quote_kept(self):
        h = self._h()
        h.ENGINE_PW = 'a\\"b#c'  # chars: a \ " b # c
        tmp = h._fixture(
            f"ENGINE_ADMIN_EMAIL={h.ENGINE_EMAIL}\n"
            'ENGINE_ADMIN_PASSWORD="a\\"b#c"\n')
        # The fixture stub embeds the expected password in a JS
        # string literal, which would eat the backslash (\" -> "):
        # double it in the generated stub so the stub really holds
        # the 6-char password a \ " b # c.
        dist = tmp / "app" / "engine" / "server" / "dist" / "index.js"
        stub = dist.read_text()
        assert 'a\\"b#c' in stub
        dist.write_text(stub.replace('a\\"b#c', 'a\\\\"b#c'))
        proc = h._boot(tmp)
        try:
            h._wait_for(proc, tmp,
                        lambda: len(h._logins(tmp)) >= 1,
                        what="verify login")
            time.sleep(1)
            env_after = (tmp / "app" / ".env").read_text(
                encoding="utf-8")
            # Pre-fix the truncated parse 401'd and BOTH credential
            # lines were deleted behind a false foreign-claim alarm.
            self.assertIn("ENGINE_ADMIN_PASSWORD", env_after)
            self.assertIn("ENGINE_ADMIN_EMAIL", env_after)
            self.assertEqual(h._logins(tmp)[0]["password"],
                             'a\\"b#c')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 6 E2E: verify retries the untruncated form before
    #    anything may be deleted ------------------------------------
    def test_w14_verify_untruncated_retry_keeps_creds(self):
        h = self._h()
        h.ENGINE_PW = "p@ss #w0rd"  # the engine's real password
        tmp = h._fixture(
            f"ENGINE_ADMIN_EMAIL={h.ENGINE_EMAIL}\n"
            "ENGINE_ADMIN_PASSWORD=p@ss #w0rd\n")
        proc = h._boot(tmp)
        try:
            # Primary parse (dotenv form "p@ss") is refused; the
            # alternate (raw) form is then tried and accepted.
            h._wait_for(proc, tmp,
                        lambda: len(h._logins(tmp)) >= 2,
                        what="verify login + alternate retry")
            time.sleep(1)
            self.assertEqual(h._logins(tmp)[0]["password"], "p@ss")
            self.assertEqual(h._logins(tmp)[1]["password"],
                             "p@ss #w0rd")
            env_after = (tmp / "app" / ".env").read_text(
                encoding="utf-8")
            self.assertIn("ENGINE_ADMIN_PASSWORD", env_after)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 7: the SIGKILL escalation keeps its captured target ---
    def test_w14_sigkill_escalation_kills_term_ignoring_grandchild(
            self):
        import signal as _signal
        node = shutil.which("node")
        if not node or not shutil.which("unshare"):
            self.skipTest("node/unshare not available")
        h = self._h()
        tmp = h._fixture("ENGINE_ADMIN_PASSWORD=<redacted>\n")
        (tmp / "app" / "engine" / "server" / "node_modules"
         / "express" / "index.js").unlink()  # gate -> install phase
        fakebin = tmp / "fakebin"
        fakebin.mkdir()
        gc = fakebin / "gc.sh"
        gc.write_text(
            "#!/bin/sh\n"
            "trap '' TERM\n"
            "echo $$ > \"$GC_PID_FILE\"\n"
            "while true; do sleep 1; done\n")
        gc.chmod(0o755)
        npm_stub = fakebin / "npm"
        npm_stub.write_text(
            "#!/bin/sh\n"
            "echo $$ > \"$NPM_PID_FILE\"\n"
            "sh \"$GC_SCRIPT\" &\n"
            "wait\n")
        npm_stub.chmod(0o755)
        env = dict(os.environ)
        env.update({
            "NPM_PID_FILE": str(tmp / "npm.pid"),
            "GC_PID_FILE": str(tmp / "gc.pid"),
            "GC_SCRIPT": str(gc),
            "PATH": str(fakebin) + os.pathsep + env.get("PATH", ""),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        cmd = ["unshare", "-n", "bash", "-c",
               "ip link set lo up 2>/dev/null; exec "
               f"{node} {tmp / 'bin' / 'nexuslocal.js'}"]
        proc = subprocess.Popen(
            cmd, cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        gc_pid = None
        try:
            h._wait_for(proc, tmp, lambda: (tmp / "gc.pid").exists(),
                        timeout=60, what="install grandchild running")
            gc_pid = int((tmp / "gc.pid").read_text().strip())
            proc.send_signal(_signal.SIGTERM)
            proc.wait(timeout=15)
            # The direct child dies on the group SIGTERM (nulling
            # the global); the grandchild ignores TERM. Only the
            # captured-pgid SIGKILL escalation can kill it.
            self.assertTrue(
                h._pid_dead(tmp / "gc.pid", timeout=8),
                "TERM-ignoring install grandchild survived "
                "launcher exit (SIGKILL escalation lost its target)")
        finally:
            if gc_pid is not None:
                try:
                    os.kill(gc_pid, 9)
                except Exception:
                    pass
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 8: a binding-less better-sqlite3 fails the gate -------
    def test_w14_gate_bindingless_better_sqlite3_installs(self):
        if sys.platform == "android":
            self.skipTest("Android keeps the exemption")
        h = self._h()
        tmp = h._fixture("ENGINE_ADMIN_PASSWORD=<redacted>\n")
        srv = tmp / "app" / "engine" / "server"
        pkg = json.loads((srv / "package.json").read_text())
        pkg["optionalDependencies"] = {"better-sqlite3": "^11.0.0"}
        (srv / "package.json").write_text(json.dumps(pkg))
        bsq = srv / "node_modules" / "better-sqlite3"
        bsq.mkdir()
        (bsq / "package.json").write_text("{}")
        # Resolves fine, but require() dies exactly like a tree
        # whose native binding was never built.
        (bsq / "index.js").write_text(
            "throw new Error('Could not locate the bindings file');\n")
        proc = h._boot(tmp)
        try:
            h._wait_for(
                proc, tmp,
                lambda: (tmp / "startup.log").exists()
                and "Installing engine dependencies"
                in (tmp / "startup.log").read_text(errors="replace"),
                timeout=60,
                what="npm gate on binding-less better-sqlite3")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)


class Wave14FaultHarness(_FixtureServerBase):
    """Carried item A (run-12 revoke-cleanup residual): a friend
    re-created after a faulted revoke + restart must NOT inherit
    the stranded per-user settings. Fault injection is the wave-13
    harness's SAVE_FAULT shape, re-injected on this class's own
    disposable copy."""

    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        sp = cls.tmp / "server.py"
        txt = sp.read_text()
        anchor = "def _save_settings():\n"
        assert txt.count(anchor) == 1
        sp.write_text(txt.replace(
            anchor,
            anchor + "    if (Path(__file__).parent / "
                     "\"SAVE_FAULT\").exists():\n"
                     "        return False\n", 1))
        _respawn_fixture(cls)

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _fault(self, on):
        flag = self.tmp / "SAVE_FAULT"
        if on:
            flag.write_text("x")
        else:
            flag.unlink(missing_ok=True)

    def test_w14_recreated_friend_starts_clean(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "add", "label": "inh14",
             "password": "inh14-pw", "master_pw": MASTER,
             "role": "moderator", "cap": 777}, admin)
        self.assertEqual(status, 200, body)
        # The revoke's cleanup save faults: honest 500, the cleanup
        # lives only in memory.
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "revoke", "label": "inh14",
                 "master_pw": MASTER}, admin)
            self.assertEqual(status, 500, body)
            self.assertIn("cleanup could not be saved",
                          body.get("error", ""), body)
        finally:
            self._fault(False)
        # Restart BEFORE any successful save: the stranded role/cap
        # resurrect from the persisted settings.
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 0}}, admin)
        self.assertEqual(status, 200, body)
        stranded = body.get("settings") or {}
        self.assertEqual(
            (stranded.get("roles") or {}).get("inh14"), "moderator")
        self.assertEqual(
            (stranded.get("user_caps") or {}).get("inh14"), 777)
        # Re-create the friend with NO role/cap of its own: the add
        # must start from a clean slate, not inherit the stranded
        # entries. Pre-fix the settings below still showed
        # moderator/777 for the new account.
        status, body, _ = self._access(
            {"action": "add", "label": "inh14",
             "password": "inh14-new-pw", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 0}}, admin)
        self.assertEqual(status, 200, body)
        settings = body.get("settings") or {}
        self.assertNotIn("inh14", settings.get("roles") or {})
        self.assertNotIn("inh14", settings.get("user_caps") or {})
        status, _, _ = self._login("inh14-new-pw")
        self.assertEqual(status, 200)
        # And the clean slate persists across another restart.
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 0}}, admin)
        settings = body.get("settings") or {}
        self.assertNotIn("inh14", settings.get("roles") or {})
        self.assertNotIn("inh14", settings.get("user_caps") or {})



class Wave15UnitTests(unittest.TestCase):
    """Wave 15 (run-14 fixes): untagged-trickler rank visibility,
    substitution check-before-retag, _provider_blocked's single
    in-lock snapshot, the in-memory provider counter, the TTS
    funding-lane sum, and rank-form user/global caps."""

    def _env(self):
        orig = dict(server._SETTINGS)
        saved_inflight = list(server._INFLIGHT)
        saved_counts = server._provider_counts_today
        server._INFLIGHT.clear()
        return orig, saved_inflight, saved_counts

    def _restore(self, orig, saved_inflight, saved_counts):
        server._provider_counts_today = saved_counts
        server._INFLIGHT.clear()
        server._INFLIGHT.extend(saved_inflight)
        server._SETTINGS.clear()
        server._SETTINGS.update(orig)

    # -- CAPS14-1: an untagged trickler occupies a rank slot ------
    def test_w15_trickler_untagged_counts_as_rank(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"prov15": 1}
            server._SETTINGS["provider_disabled"] = []
            server._provider_counts_today = lambda: {}
            # Handler order: the trickler's base reservation is
            # born UNTAGGED; the peer tags and checks first.
            trick = server._inflight_add("u15")
            peer = server._inflight_add("u15", "prov15")
            # Pre-fix the untagged trickler was invisible to the
            # peer's rank check (peer admitted) and then ranked
            # 1st itself after tagging: 2 admitted at limit 1.
            self.assertTrue(
                server._provider_blocked("prov15", exclude=peer))
            # The trickler tags (its body finally arrived) and is
            # admitted: exactly one spend total.
            trick["provider"] = "prov15"
            self.assertFalse(
                server._provider_blocked("prov15", exclude=trick))
        finally:
            self._restore(orig, saved_i, saved_c)

    # -- CAPS14-2: substitution is checked BEFORE the re-tag ------
    def test_w15_substitution_check_before_retag(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"pollinations": 1}
            server._SETTINGS["provider_disabled"] = []
            server._provider_counts_today = lambda: {}
            q1 = server._inflight_add("u15", "google")
            q2 = server._inflight_add("u15", "pollinations")
            # q2 (born under the substitute) is admitted...
            self.assertFalse(
                server._provider_blocked("pollinations", exclude=q2))
            # ...and q1, checked while still tagged with its birth
            # provider (the post-fix handler order), takes the
            # full-count form and is refused. Pre-fix the handler
            # re-tagged q1 FIRST, so it ranked 1st in the
            # substitute's queue and was admitted too.
            self.assertTrue(
                server._provider_blocked("pollinations", exclude=q1))
            # Source: in the substitution block the check now runs
            # before the re-tag assignment. Wave 16 (CAPS15-3):
            # check + retag are one locked helper call — the
            # wave-15 two-statement form had a forced-interleave
            # TOCTOU between them.
            src = (REPO / "app" / "server.py").read_text()
            seg = src[src.index("_sub_p = provider if provider in ("):]
            seg = seg[:seg.index("_pollinations(model")]
            self.assertIn(
                "_provider_blocked_and_tag(_sub_p, self._cap_res)",
                seg)
            self.assertNotIn('self._cap_res["provider"] = _sub_p',
                             seg)
        finally:
            self._restore(orig, saved_i, saved_c)

    # -- CAPS14-3: completed is read INSIDE the rank lock ---------
    def test_w15_provider_blocked_completed_inside_lock(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"groq": 1}
            server._SETTINGS["provider_disabled"] = []
            seen = {}

            def spy():
                seen["locked"] = server._INFLIGHT_LOCK.locked()
                return {}
            server._provider_counts_today = spy
            res = server._inflight_add("u15", "groq")
            # Pre-fix the completed term was a full scan read
            # BEFORE the lock hold (locked() False at read time).
            self.assertFalse(
                server._provider_blocked("groq", exclude=res))
            self.assertTrue(seen.get("locked"))
        finally:
            self._restore(orig, saved_i, saved_c)

    # -- CAPS14-4: the counter IS the scan, with no scan on read --
    def test_w15_counter_matches_scan(self):
        import datetime as _dt
        saved_path = server.USAGE_PATH
        saved_cache_ts = server._TODAY_CACHE["ts"]
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w15-counter-"))
        try:
            server.USAGE_PATH = tmp / "usage.jsonl"
            server._PROVIDER_COUNTS["date"] = None
            server._PROVIDER_COUNTS["providers"] = {}
            today = _dt.datetime.now().isoformat()
            server._append_usage({"ts": today, "provider": "provA",
                                  "user": "u15"})
            server._append_usage({"ts": today, "provider": "provA",
                                  "user": "u15"})
            server._append_usage({"ts": today, "provider": "provB",
                                  "user": "u15"})
            server._append_usage({"ts": "2020-01-01T00:00:00",
                                  "provider": "provOld", "user": "u15"})
            server._append_usage({"ts": today, "type": "audit",
                                  "provider": "provTyped"})
            want = server._today_counts(fresh=True)["providers"]
            self.assertEqual(want, {"provA": 2, "provB": 1})
            self.assertEqual(server._provider_counts_today(), want)
            # The read path needs no file at all: with the log
            # "gone", the counter still answers (a scan would
            # return {}). Pre-fix the callsites' callable scanned
            # the file on every reserve, inside _INFLIGHT_LOCK.
            server.USAGE_PATH = tmp / "missing.jsonl"
            self.assertEqual(server._provider_counts_today(), want)
            # The reserve primitive over the counter callable
            # refuses a second spend at limit 2 with 2 completed.
            res = server._inflight_reserve_capped(
                "u15", "provA",
                lambda: server._provider_counts_today().get(
                    "provA", 0), 2)
            self.assertIsNone(res)
            # Source: neither callsite scans any more.
            src = (REPO / "app" / "server.py").read_text()
            self.assertNotIn("lambda: _today_counts(", src)
            self.assertEqual(
                src.count("lambda: _provider_counts_today()"), 2)
        finally:
            server.USAGE_PATH = saved_path
            server._TODAY_CACHE["ts"] = saved_cache_ts
            server._PROVIDER_COUNTS["date"] = None
            server._PROVIDER_COUNTS["providers"] = {}
            shutil.rmtree(tmp, ignore_errors=True)

    # -- CAPS14-5: the TTS funding lane is judged on the sum ------
    def test_w15_tts_funding_lane_sum(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"groq": 1}
            server._SETTINGS["provider_disabled"] = []
            # Five prior TTS spends, metered as the handler meters
            # them: under the PICKED lane's name.
            server._provider_counts_today = lambda: {"relay_groq": 5}
            res = server._inflight_add("u15", "relay_groq")
            # The wave-14 groq-named check reads zero forever...
            self.assertFalse(
                server._provider_blocked("groq", exclude=res))
            # ...the sum form (what the TTS branch now passes via
            # also=) binds the lane that actually pays.
            self.assertTrue(server._provider_blocked(
                "groq", exclude=res, also="relay_groq"))
            # The disabled term still binds through the sum form.
            server._SETTINGS["provider_disabled"] = ["groq"]
            self.assertTrue(server._provider_blocked(
                "groq", exclude=res, also="relay_groq"))
            # Source: the TTS dual check passes the funding sum.
            src = (REPO / "app" / "server.py").read_text()
            self.assertIn('or _prov == "groq" else _prov):', src)
        finally:
            self._restore(orig, saved_i, saved_c)

    # -- CAPS14-6: rank form for the per-user / global scopes -----
    def test_w15_user_global_rank_pair(self):
        orig, saved_i, saved_c = self._env()
        try:
            a = server._inflight_add("u15")
            b = server._inflight_add("u15")
            other = server._inflight_add("someoneelse")
            # Per-user scope at cap 1, completed 0: a is admitted
            # (0 + rank 1 > 1 is False), b is refused. The old
            # exclude-self + count-peers form refused BOTH.
            self.assertEqual(server._inflight_rank(a, user="u15"), 1)
            self.assertEqual(server._inflight_rank(b, user="u15"), 2)
            self.assertFalse(0 + server._inflight_rank(a, user="u15") > 1)
            self.assertTrue(0 + server._inflight_rank(b, user="u15") > 1)
            # Global scope ranks across users, in birth order.
            self.assertEqual(server._inflight_rank(a), 1)
            self.assertEqual(server._inflight_rank(other), 3)
            # Attempt entries belong to a base request and never
            # take a base-scope rank slot.
            server._inflight_add("u15", "prov15", attempt=True)
            self.assertEqual(server._inflight_rank(b, user="u15"), 2)
            # Source: all six predicates use the rank form now.
            src = (REPO / "app" / "server.py").read_text()
            self.assertGreaterEqual(
                src.count("_inflight_rank(self._cap_res"), 6)
            self.assertNotIn(
                "_inflight_n(user=_chat_label, exclude=self._cap_res)"
                " >= int(_cap)", src)
            self.assertNotIn(
                "_inflight_n(user=_label_t, exclude=self._cap_res)"
                " >= int(_cap)", src)
        finally:
            self._restore(orig, saved_i, saved_c)


class Wave15FaultHarness(_FixtureServerBase):
    """Run-14 settings fixes over the wave-14 fault shape: BOTH
    creation paths (invite redeem / open signup, and console add)
    start from the shared clean slate, and a faulted clear on the
    add path creates NO account."""

    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        sp = cls.tmp / "server.py"
        txt = sp.read_text()
        anchor = "def _save_settings():\n"
        assert txt.count(anchor) == 1
        sp.write_text(txt.replace(
            anchor,
            anchor + "    if (Path(__file__).parent / "
                     "\"SAVE_FAULT\").exists():\n"
                     "        return False\n", 1))
        _respawn_fixture(cls)

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _fault(self, on):
        flag = self.tmp / "SAVE_FAULT"
        if on:
            flag.write_text("x")
        else:
            flag.unlink(missing_ok=True)

    def _settings_read(self, admin):
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 0}}, admin)
        self.assertEqual(status, 200, body)
        return body.get("settings") or {}

    def _strand(self, admin, label, role=None, cap=None, suspend=False):
        """Create + revoke `label` under a settings-save fault so
        its per-user entries strand in the persisted settings,
        then restart so they are the live state too."""
        payload = {"action": "add", "label": label,
                   "password": f"{label}-pw-1", "master_pw": MASTER}
        if role:
            payload["role"] = role
        if cap is not None:
            payload["cap"] = cap
        status, body, _ = self._access(payload, admin)
        self.assertEqual(status, 200, body)
        if suspend:
            status, body, _ = self._access(
                {"action": "friend_set_suspended", "label": label,
                 "on": True, "master_pw": MASTER}, admin)
            self.assertEqual(status, 200, body)
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "revoke", "label": label,
                 "master_pw": MASTER}, admin)
            self.assertEqual(status, 500, body)
        finally:
            self._fault(False)
        _respawn_fixture(self.__class__)
        _, _, admin2 = self._login(MASTER)
        self.assertTrue(admin2)
        return admin2

    # -- Item 7: redeem / signup clears the stranded slate --------
    def test_w15_redeem_starts_clean(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        admin = self._strand(admin, "ghost15", role="moderator",
                             cap=777)
        settings = self._settings_read(admin)
        self.assertEqual(
            (settings.get("roles") or {}).get("ghost15"),
            "moderator")
        self.assertEqual(
            (settings.get("user_caps") or {}).get("ghost15"), 777)
        # A FRIEND-role invite redeemed under the stranded label:
        # pre-fix the new account logged in as moderator with the
        # stranded cap; the clear must run before the claim.
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend",
             "days": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        code = body["code"]
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "ghost15", "password": "ghost15-new-pw",
             "code": code})
        self.assertEqual(status, 200, body)
        status, body, _ = self._login("ghost15-new-pw")
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "friend", body)
        settings = self._settings_read(admin)
        self.assertNotIn("ghost15", settings.get("roles") or {})
        self.assertNotIn("ghost15", settings.get("user_caps") or {})
        # Suspension leg: a stranded suspension must not brick the
        # new account (pre-fix: redeem 200, login 403 suspended).
        admin = self._strand(admin, "brick15", suspend=True)
        settings = self._settings_read(admin)
        self.assertIn("brick15", settings.get("suspended") or [])
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend",
             "days": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "brick15", "password": "brick15-new-pw",
             "code": body["code"]})
        self.assertEqual(status, 200, body)
        status, body, _ = self._login("brick15-new-pw")
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "friend", body)
        # Control: a legitimate MODERATOR invite still grants the
        # role — the invite's own role set runs AFTER the clear.
        status, body, _ = self._access(
            {"action": "invite_create", "role": "moderator",
             "days": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "mod15", "password": "mod15-new-pw",
             "code": body["code"]})
        self.assertEqual(status, 200, body)
        status, body, _ = self._login("mod15-new-pw")
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "moderator", body)

    # -- Item 8: a faulted add-side clear creates NO account ------
    def test_w15_add_fault_creates_no_account(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        admin = self._strand(admin, "wraith15", role="moderator",
                             cap=9)
        settings = self._settings_read(admin)
        self.assertEqual(
            (settings.get("roles") or {}).get("wraith15"),
            "moderator")
        # Fault the clear's save: wave 14 answered "friend added,
        # but..." and left a LIVE account whose persisted settings
        # resurrected it as moderator at restart. The honest end
        # state now is NO account.
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "add", "label": "wraith15",
                 "password": "wraith15-new-pw",
                 "master_pw": MASTER}, admin)
            self.assertEqual(status, 500, body)
            self.assertIn("friend not added",
                          body.get("error", ""), body)
        finally:
            self._fault(False)
        status, _, _ = self._login("wraith15-new-pw")
        self.assertEqual(status, 401)
        # Still no account after a restart, and a retry succeeds
        # clean once storage recovers.
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        status, _, _ = self._login("wraith15-new-pw")
        self.assertEqual(status, 401)
        status, body, _ = self._access(
            {"action": "add", "label": "wraith15",
             "password": "wraith15-new-pw", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._login("wraith15-new-pw")
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "friend", body)
        settings = self._settings_read(admin)
        self.assertNotIn("wraith15", settings.get("roles") or {})
        self.assertNotIn("wraith15", settings.get("user_caps") or {})


class Wave15LauncherTests(unittest.TestCase):
    """Wave 15 launcher fixes: dotenv \\n/\\r expansion (L14-1),
    no passwordAlt for quoted lines (L14-2 leg a), and the gate
    cluster (surviving run-13 gate item + L14-3 + L14-4) tested
    against REAL tree shapes — a lazy-loading better-sqlite3 tree
    that require()s fine with no .node file, and a garbage-.node
    tree — not just require-throwing stubs."""

    def _h(self):
        return Wave12LauncherTests()

    def _parse(self, env_text):
        return Wave14LauncherTests()._parse(env_text)

    @staticmethod
    def _codes(s):
        return [ord(c) for c in s]

    # -- L14-1: double-quoted \\n / \\r expand exactly like dotenv -
    def test_w15_parse_dq_escape_expansion(self):
        out = self._parse('ENGINE_ADMIN_PASSWORD="a\\nb"\n')
        self.assertEqual(out["pw"], self._codes("a\nb"))
        out = self._parse('ENGINE_ADMIN_PASSWORD="a\\rb"\n')
        self.assertEqual(out["pw"], self._codes("a\rb"))
        out = self._parse('ENGINE_ADMIN_PASSWORD="x\\ny\\rz"\n')
        self.assertEqual(out["pw"], self._codes("x\ny\rz"))
        # The \\\\n edge: dotenv's regex matches the SECOND
        # backslash — a + backslash + LF + b.
        out = self._parse('ENGINE_ADMIN_PASSWORD="a\\\\nb"\n')
        self.assertEqual(out["pw"], self._codes("a\\\nb"))
        # \\t, \\\\ and \\" stay literal in double quotes...
        out = self._parse('ENGINE_ADMIN_PASSWORD="a\\tb"\n')
        self.assertEqual(out["pw"], self._codes('a\\tb'))
        # ...and single-quoted values are never expanded.
        out = self._parse("ENGINE_ADMIN_PASSWORD='a\\nb'\n")
        self.assertEqual(out["pw"], self._codes('a\\nb'))

    # -- L14-2 (a): quoted lines get NO passwordAlt ----------------
    def test_w15_parse_quoted_line_no_alt(self):
        # Pre-fix the alt was the raw tail '"p@ss" # comment' — a
        # candidate that can never succeed, submitted verbatim on
        # every verify cycle.
        out = self._parse('ENGINE_ADMIN_PASSWORD="p@ss" # comment\n')
        self.assertEqual(out["pw"], self._codes("p@ss"))
        self.assertIsNone(out["alt"])
        out = self._parse('ENGINE_ADMIN_PASSWORD="p@ss #1"\n')
        self.assertEqual(out["pw"], self._codes("p@ss #1"))
        self.assertIsNone(out["alt"])
        # Unquoted shapes keep their genuine alternates.
        out = self._parse("ENGINE_ADMIN_PASSWORD=p@ss#w0rd!\n")
        self.assertEqual(out["alt"], self._codes("p@ss"))
        out = self._parse("ENGINE_ADMIN_PASSWORD=abc123 # comment\n")
        self.assertEqual(out["alt"],
                         self._codes("abc123 # comment"))

    # -- L14-1 E2E: verify keeps dotenv-escaped credentials -------
    def test_w15_verify_dq_escaped_newline_kept(self):
        h = self._h()
        h.ENGINE_PW = "a\nb"  # the engine holds a real newline
        tmp = h._fixture(
            f"ENGINE_ADMIN_EMAIL={h.ENGINE_EMAIL}\n"
            'ENGINE_ADMIN_PASSWORD="a\\nb"\n')
        # The fixture stub embeds the expected password in a JS
        # string literal; make the source carry the \n ESCAPE so
        # the stub really holds a<LF>b at runtime.
        dist = tmp / "app" / "engine" / "server" / "dist" / "index.js"
        stub = dist.read_text()
        assert "a\nb" in stub
        dist.write_text(stub.replace("a\nb", "a\\nb"))
        proc = h._boot(tmp)
        try:
            h._wait_for(proc, tmp,
                        lambda: len(h._logins(tmp)) >= 1,
                        what="verify login")
            time.sleep(1)
            # Pre-fix: ONE login POST with the literal backslash
            # form, 401, both credential lines DELETED behind a
            # false foreign-claim alarm.
            self.assertEqual(h._logins(tmp)[0]["password"], "a\nb")
            env_after = (tmp / "app" / ".env").read_text(
                encoding="utf-8")
            self.assertIn("ENGINE_ADMIN_PASSWORD", env_after)
            self.assertIn("ENGINE_ADMIN_EMAIL", env_after)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Gate cluster fixtures -------------------------------------
    def _gate_fixture(self, bsq_index, binding=None):
        """A healthy stub tree whose better-sqlite3 (an optional
        dependency) has the given entry point and, optionally, a
        build/Release/better_sqlite3.node with the given content."""
        h = self._h()
        tmp = h._fixture(
            f"ENGINE_ADMIN_EMAIL={h.ENGINE_EMAIL}\n"
            f"ENGINE_ADMIN_PASSWORD={h.ENGINE_PW}\n")
        srv = tmp / "app" / "engine" / "server"
        pkg = json.loads((srv / "package.json").read_text())
        pkg["optionalDependencies"] = {"better-sqlite3": "^12.0.0"}
        (srv / "package.json").write_text(json.dumps(pkg))
        bsq = srv / "node_modules" / "better-sqlite3"
        bsq.mkdir()
        (bsq / "package.json").write_text(
            json.dumps({"name": "better-sqlite3",
                        "main": "index.js"}))
        (bsq / "index.js").write_text(bsq_index)
        if binding is not None:
            rel = bsq / "build" / "Release"
            rel.mkdir(parents=True)
            (rel / "better_sqlite3.node").write_text(binding)
        return tmp

    def _boot15(self, tmp, extra_env=None):
        """Boot inside a network namespace, with the logged
        pre-check that 127.0.0.1:3001 refuses inside it (the live
        FreeLLMAPI gateway on the host is never contacted)."""
        node = shutil.which("node")
        if not node or not shutil.which("unshare"):
            self.skipTest("node/unshare not available")
        pre = subprocess.run(
            ["unshare", "-n", "bash", "-c",
             "ip link set lo up 2>/dev/null; "
             "curl -s -m 2 http://127.0.0.1:3001/ >/dev/null 2>&1; "
             "echo curl_exit=$?"],
            capture_output=True, text=True, timeout=30)
        (tmp / "netns_precheck.log").write_text(pre.stdout)
        self.assertIn("curl_exit=7", pre.stdout,
                      "namespace pre-check: 3001 must refuse inside")
        env = dict(os.environ)
        env.update({
            "LOGIN_FILE": str(tmp / "logins.jsonl"),
            "ENGINE_PID": str(tmp / "engine.pid"),
            "DASH_PID": str(tmp / "dash.pid"),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        if extra_env:
            env.update(extra_env)
        cmd = ["unshare", "-n", "bash", "-c",
               "ip link set lo up 2>/dev/null; exec "
               f"{node} {tmp / 'bin' / 'nexuslocal.js'}"]
        return subprocess.Popen(
            cmd, cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _wait_install(self, h, proc, tmp, timeout=60):
        h._wait_for(
            proc, tmp,
            lambda: (tmp / "startup.log").exists()
            and "Installing engine dependencies"
            in (tmp / "startup.log").read_text(errors="replace"),
            timeout=timeout,
            what="npm gate declaring dependencies missing")

    _BSQ_MAGIC = (
        "const fs=require('fs');const path=require('path');"
        "class DB{constructor(){"
        "const b=fs.readFileSync(path.join(__dirname,'build',"
        "'Release','better_sqlite3.node'),'utf8');"
        "if(!b.startsWith('GOODBIN'))"
        "throw new Error('ERR_DLOPEN_FAILED');}"
        "close(){}}"
        "module.exports=DB;\n")

    # -- Gate (i): a lazy tree with NO .node fails WITHOUT running -
    def test_w15_gate_lazy_tree_no_binding_installs_unexecuted(self):
        if sys.platform == "android":
            self.skipTest("Android keeps the exemption")
        h = self._h()
        # require() succeeds (better-sqlite3@12 loads lazily) and
        # the entry WRITES A MARKER if anything ever executes it.
        tmp = self._gate_fixture(
            "require('fs').writeFileSync(process.env.GATE_MARKER,"
            "'executed');\nmodule.exports = class {};\n")
        proc = self._boot15(
            tmp, {"GATE_MARKER": str(tmp / "probe_marker.txt")})
        try:
            self._wait_install(h, proc, tmp)
            # The gate failed on PRESENCE alone: the tree was never
            # executed (pre-fix the require-probe ran it, passed
            # it, and no install ever happened).
            self.assertFalse((tmp / "probe_marker.txt").exists())
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertIn("better-sqlite3", log)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Gate (ii): a garbage .node fails the instantiate probe ---
    def test_w15_gate_garbage_binding_installs(self):
        if sys.platform == "android":
            self.skipTest("Android keeps the exemption")
        h = self._h()
        tmp = self._gate_fixture(self._BSQ_MAGIC, binding="GARBAGE")
        proc = self._boot15(tmp)
        try:
            # Presence is fooled by the garbage file; only the
            # require+instantiate probe catches it (the wave-14
            # require-only probe certified this tree).
            self._wait_install(h, proc, tmp)
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertIn("better-sqlite3", log)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Gate (ii): a good binding passes, probe env is scrubbed --
    def test_w15_gate_good_binding_passes_env_scrubbed(self):
        if sys.platform == "android":
            self.skipTest("Android keeps the exemption")
        h = self._h()
        tmp = self._gate_fixture(
            "require('fs').writeFileSync(require('path').join("
            "__dirname,'sentinel.txt'),"
            "String(process.env.GATE_SENTINEL));\n"
            + self._BSQ_MAGIC,
            binding="GOODBIN-fixture")
        proc = self._boot15(tmp, {
            "GATE_SENTINEL": "sentinel15-secret"})
        try:
            h._wait_for(proc, tmp,
                        lambda: len(h._logins(tmp)) >= 1,
                        timeout=60, what="engine verify login")
            time.sleep(1)
            # The gate passed: no reinstall was triggered.
            log = (tmp / "startup.log").read_text(errors="replace")
            self.assertNotIn("Installing engine dependencies", log)
            # The probe DID execute the entry (a binding is
            # present), but with a scrubbed environment: the
            # launcher's sentinel never reached it.
            marker = (tmp / "app" / "engine" / "server"
                      / "node_modules" / "better-sqlite3"
                      / "sentinel.txt").read_text()
            self.assertEqual(marker, "undefined")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Gate (iii)/L14-4: a SIGTERM-ignoring probe is bounded ----
    def test_w15_gate_sigterm_ignoring_probe_bounded(self):
        if sys.platform == "android":
            self.skipTest("Android keeps the exemption")
        h = self._h()
        tmp = self._gate_fixture(
            "process.on('SIGTERM',()=>{});"
            "setInterval(()=>{},1000);\n" + self._BSQ_MAGIC,
            binding="GOODBIN-fixture")
        proc = self._boot15(tmp)
        try:
            # The probe child keeps a handle and ignores SIGTERM:
            # with the default killSignal spawnSync waited forever
            # (pre-fix this boot never progressed). SIGKILL makes
            # the 15s timeout a real bound — the gate verdict and
            # the install line arrive well inside the wait.
            self._wait_install(h, proc, tmp, timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)



if __name__ == "__main__":
    unittest.main()
