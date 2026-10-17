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


if __name__ == "__main__":
    unittest.main()
