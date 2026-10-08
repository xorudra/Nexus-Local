#!/usr/bin/env python3
"""Unit tests for the crypto helpers, log redaction, usage-log rotation,
password hashing and TOTP — the pieces that must never regress silently.

No real secrets anywhere: every password/key below is a throwaway fixture.

Run:  python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))

os.environ.pop("NEXUS_RESTORE_KEY", None)  # never touch the real restore key

from key_security import encrypt_keys, decrypt_keys, encrypt_raw, decrypt_raw  # noqa: E402
import server  # noqa: E402


class KeySecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-units-"))
        self.path = self.tmp / "keys.enc"

    def test_roundtrip(self):
        data = {"groq": "sk-fixture", "_totp_secret": "JBSWY3DPEHPK3PXP"}
        encrypt_keys(data, "pw-fixture-1", self.path)
        self.assertEqual(decrypt_keys(self.path, "pw-fixture-1"), data)

    def test_envelope_shape(self):
        encrypt_keys({"a": "b"}, "pw-fixture-1", self.path)
        env = json.loads(self.path.read_text())
        self.assertEqual(sorted(env.keys()), ["ciphertext", "nonce", "salt"])

    def test_wrong_password_raises(self):
        encrypt_keys({"a": "b"}, "pw-fixture-1", self.path)
        with self.assertRaises(Exception):
            decrypt_keys(self.path, "pw-fixture-2")

    def test_tampered_ciphertext_raises(self):
        encrypt_keys({"a": "b"}, "pw-fixture-1", self.path)
        env = json.loads(self.path.read_text())
        env["ciphertext"] = ("A" if env["ciphertext"][0] != "A" else "B") + env["ciphertext"][1:]
        self.path.write_text(json.dumps(env))
        with self.assertRaises(Exception):
            decrypt_keys(self.path, "pw-fixture-1")

    def test_raw_roundtrip_and_aad_binding(self):
        key = os.urandom(32)
        nonce, ct = encrypt_raw(key, b"payload", aad=b"ctx:a")
        self.assertEqual(decrypt_raw(key, nonce, ct, aad=b"ctx:a"), b"payload")
        with self.assertRaises(Exception):
            decrypt_raw(key, nonce, ct, aad=b"ctx:b")  # wrong context must fail
        with self.assertRaises(Exception):
            decrypt_raw(os.urandom(32), nonce, ct, aad=b"ctx:a")


class RedactTests(unittest.TestCase):
    def test_secret_fields_are_wholesale_redacted(self):
        self.assertEqual(server._redact("hunter2", "password"), "[redacted]")
        self.assertEqual(server._redact("abc", "master_pw"), "[redacted]")
        self.assertEqual(server._redact("abc", "totp_secret"), "[redacted]")
        self.assertEqual(server._redact("123456", "code"), "[redacted]")

    def test_plain_fields_pass_through(self):
        self.assertEqual(server._redact("friendone", "label"), "friendone")
        self.assertEqual(server._redact(200, "status"), 200)
        self.assertEqual(server._redact(True, "ok"), True)

    def test_secret_shaped_values_inside_strings_are_masked(self):
        out = server._redact("Authorization: Bearer abcdef0123456789xyz")
        self.assertNotIn("abcdef0123456789xyz", out)
        out = server._redact("key was sk-abcdefgh12345678 ok")
        self.assertNotIn("sk-abcdefgh12345678", out)
        out = server._redact("session " + "a" * 64)
        self.assertNotIn("a" * 64, out)

    def test_nested_structures(self):
        out = server._redact({"user": {"label": "x", "api_key": "sk-zzzzzzzz9999"},
                              "n": 3})
        self.assertEqual(out["user"]["api_key"], "[redacted]")
        self.assertEqual(out["user"]["label"], "x")
        self.assertEqual(out["n"], 3)

    def test_log_event_never_prints_secrets(self):
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            server._log_event("error", "test_event", password="hunter2",
                              note="Bearer abcdef0123456789xyz", path="/api/login")
        text = buf.getvalue()
        self.assertNotIn("hunter2", text)
        self.assertNotIn("abcdef0123456789xyz", text)
        self.assertIn("test_event", text)
        record = json.loads(text.strip())
        self.assertEqual(record["event"], "test_event")


class UsageRotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-usage-"))
        self.path = self.tmp / "usage.jsonl"
        self._old = (server.USAGE_PATH, server._USAGE_MAX_BYTES,
                     server._USAGE_KEEP_LINES)
        server.USAGE_PATH = self.path

    def tearDown(self):
        (server.USAGE_PATH, server._USAGE_MAX_BYTES,
         server._USAGE_KEEP_LINES) = self._old

    def test_append_writes_valid_json_lines(self):
        server._append_usage({"ts": "2026-10-08T00:00:00", "provider": "groq",
                              "prompt_tokens": 3, "completion_tokens": 4})
        lines = self.path.read_text().strip().split("\n")
        self.assertEqual(json.loads(lines[0])["provider"], "groq")

    def test_rotation_keeps_only_the_newest_lines(self):
        server._USAGE_MAX_BYTES = 400
        server._USAGE_KEEP_LINES = 5
        for i in range(40):
            server._append_usage({"ts": "2026-10-08T00:00:00", "provider": "groq",
                                  "seq": i, "prompt_tokens": 1,
                                  "completion_tokens": 1})
        lines = self.path.read_text().strip().split("\n")
        self.assertLessEqual(len(lines), 6)
        seqs = [json.loads(l)["seq"] for l in lines]
        self.assertEqual(seqs[-1], 39)  # the newest record survives
        self.assertEqual(seqs, sorted(seqs))

    def test_history_tolerates_corrupt_lines(self):
        self.path.write_text(
            '{"ts": "not-a-date", "provider": "groq"}\n'
            "garbage line\n"
            '{"ts": "' + time.strftime("%Y-%m-%d") + 'T10:00:00", '
            '"provider": "groq", "prompt_tokens": 5, "completion_tokens": 6}\n')
        history = server.get_usage_history()
        self.assertEqual(history["groq"]["requests"][6], 1)
        self.assertEqual(history["groq"]["tokens"][6], 11)


class PasswordAndTotpTests(unittest.TestCase):
    def test_pbkdf2_roundtrip_and_wrong_password(self):
        stored = server._hash_password("fixture-pass")
        self.assertTrue(stored.startswith("pbkdf2$210000$"))
        ok, upgrade = server._verify_password("fixture-pass", stored)
        self.assertTrue(ok)
        self.assertFalse(upgrade)
        ok, _ = server._verify_password("other-pass", stored)
        self.assertFalse(ok)

    def test_legacy_hash_verifies_and_flags_upgrade(self):
        legacy = hashlib.sha256(b"fixture-pass").hexdigest()
        ok, upgrade = server._verify_password("fixture-pass", legacy)
        self.assertTrue(ok)
        self.assertTrue(upgrade)  # login path re-hashes on this flag

    def test_totp_verify_accepts_current_rejects_wrong(self):
        import base64
        import hmac as _hmac
        import struct
        secret = base64.b32encode(b"fixture-secret-123").decode()
        t = int(time.time()) // 30
        digest = _hmac.new(base64.b32decode(secret), struct.pack(">Q", t),
                           hashlib.sha1).digest()
        o = digest[-1] & 0x0F
        code = f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"
        self.assertTrue(server._totp_verify(secret, code))
        wrong = "000000" if code != "000000" else "111111"
        self.assertFalse(server._totp_verify(secret, wrong))
        self.assertFalse(server._totp_verify(secret, ""))
        self.assertFalse(server._totp_verify("", code))


if __name__ == "__main__":
    unittest.main()
