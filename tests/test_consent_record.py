#!/usr/bin/env python3
"""DPDP consent record (owner order 2026-11-18): a successful
invite signup writes a permanent row to consent.jsonl (who, what,
when); a refused signup (no 18+ confirmation) writes nothing.
consent.jsonl is never trimmed, unlike audit.jsonl (~30 days),
because the DPDP Rules 2025 require one year of processing logs.

Run:  python3 -m unittest tests.test_consent_record -v
"""

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
sys.path.insert(0, str(REPO / "tests"))

import test_security_audit_2026_10_16 as _a16  # noqa: E402

MASTER = _a16.MASTER
_FixtureServerBase = _a16._FixtureServerBase


class ConsentRecordHttpTests(_FixtureServerBase):
    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        _, _, admin = cls._login(MASTER)
        assert admin
        cls.admin = admin

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _invite(self, role="friend"):
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "invite_create", "role": role, "days": 1,
             "master_pw": MASTER}, ck=self.admin)
        assert status == 200, body
        return body["code"]

    def _rows(self):
        p = self.tmp / "consent.jsonl"
        if not p.exists():
            return []
        return [json.loads(ln) for ln in
                p.read_text().splitlines() if ln.strip()]

    def test_successful_signup_writes_consent_row(self):
        code = self._invite()
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"age_ok": True, "label": "consentok",
             "password": "consentok-pw-1", "code": code},
            headers={"X-Forwarded-For": "198.51.100.7"})
        self.assertEqual(status, 200, body)
        rows = [r for r in self._rows() if r.get("user") == "consentok"]
        self.assertEqual(len(rows), 1, self._rows())
        self.assertEqual(rows[0]["kind"], "signup")
        self.assertIn("18+", rows[0]["agreed"])
        self.assertTrue(rows[0]["ts"])

    def test_admin_sees_consent_records_friend_cannot(self):
        code = self._invite()
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"age_ok": True, "label": "consentvis",
             "password": "consentvis-pw-1", "code": code},
            headers={"X-Forwarded-For": "198.51.100.9"})
        self.assertEqual(status, 200, body)
        status, body, _ = self._req("GET", "/api/consent", ck=self.admin)
        self.assertEqual(status, 200, body)
        users = [r.get("user") for r in body["records"]]
        self.assertIn("consentvis", users)
        _, _, friend = self._login(_a16.FRIEND_PW)
        self.assertTrue(friend)
        status, body, _ = self._req("GET", "/api/consent", ck=friend)
        self.assertNotEqual(status, 200, body)

    def test_refused_signup_writes_nothing(self):
        code = self._invite()
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "consentno", "password": "consentno-pw-1",
             "code": code},
            headers={"X-Forwarded-For": "198.51.100.8"})
        self.assertEqual(status, 400, body)
        rows = [r for r in self._rows() if r.get("user") == "consentno"]
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
