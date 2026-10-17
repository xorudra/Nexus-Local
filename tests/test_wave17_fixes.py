#!/usr/bin/env python3
"""Regression tests for the wave-17 fixes (security audit run-16:
4 confirmed findings).

Fix 1 (settings TOCTOU, MEDIUM): _clear_stranded_label holds
_ACCESS_LOCK across its whole body and re-verifies account
existence BEFORE any mutation, returning "conflict".
Fix 2 (caps): the image pair is judged by the two also= calls
OR'd, so a relay_gemini-only limit binds image spends.
Fix 3 (caps): parse-time surface tagging replaces the 45s age
bound — unstamped provider=None bases rank regardless of age,
stamped non-media bases never rank.
Fix 4 (settings): the in-lock creation recheck is guarded by the
settings generation triple recorded at the clear's return, so a
clean creation pays ONE persisted decrypt, not two.

Run:  python3 -m unittest tests.test_wave17_fixes -v
   or python3 -m unittest discover -s tests
"""

import hashlib
import json
import os
import shutil
import sys
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
sys.path.insert(0, str(REPO / "tests"))

os.environ.pop("NEXUS_RESTORE_KEY", None)

from key_security import decrypt_keys, encrypt_keys  # noqa: E402
import server  # noqa: E402

import test_security_audit_2026_10_16 as _a16  # noqa: E402

MASTER = _a16.MASTER
RESTORE = _a16.RESTORE
_FixtureServerBase = _a16._FixtureServerBase
_respawn_fixture = _a16._respawn_fixture


def _judged_triple():
    obj = getattr(server, "_CLEAR_JUDGED17", None)
    return getattr(obj, "triple", None) if obj is not None else None


class Wave17ClearUnitTests(unittest.TestCase):
    """Fix 1 at unit level: an account that NOW exists makes the
    clear a pure no-op "conflict" — no mutation, no save."""

    def _env(self, label, with_account):
        saved_settings = dict(server._SETTINGS)
        saved = (server._save_settings, server._persisted_settings,
                 server._load_access)
        state = {"persisted": None, "saves": 0}
        stranded = {"roles": {label: "moderator"},
                    "user_caps": {label: 777},
                    "vault_meta": {label: []},
                    "suspended": [label], "terms_seen": [label],
                    "oauth_links": [{"email": "g@example.co",
                                     "label": label}]}
        for k in ("roles", "user_caps", "vault_meta"):
            d = dict(server._SETTINGS.get(k) or {})
            d[label] = stranded[k][label]
            server._SETTINGS[k] = d
        for k in ("suspended", "terms_seen"):
            cur = list(server._SETTINGS.get(k) or [])
            if label not in cur:
                cur.append(label)
            server._SETTINGS[k] = cur
        links = list(server._SETTINGS.get("oauth_links") or [])
        links.append({"email": "g@example.co", "label": label})
        server._SETTINGS["oauth_links"] = links
        state["persisted"] = stranded

        def fake_persisted():
            return state["persisted"]

        def fake_save():
            state["saves"] += 1
            import copy
            state["persisted"] = copy.deepcopy(
                {k: server._SETTINGS.get(k) for k in
                 ("roles", "user_caps", "vault_meta",
                  "suspended", "terms_seen", "oauth_links")})
            return True

        server._persisted_settings = fake_persisted
        server._save_settings = fake_save
        server._load_access = (
            lambda: {label: "pbkdf2$fake"} if with_account
            else {})
        return saved_settings, saved, state

    def _restore(self, saved_settings, saved):
        (server._save_settings, server._persisted_settings,
         server._load_access) = saved
        server._SETTINGS.clear()
        server._SETTINGS.update(saved_settings)

    def test_w17_clear_conflict_when_account_exists(self):
        label = "w17ghost"
        saved_settings, saved, state = self._env(label, True)
        try:
            verdict = server._clear_stranded_label(label)
            # Pre-fix: the helper never re-verified existence —
            # it mutated memory, saved, and returned "ok".
            self.assertEqual(verdict, "conflict")
            self.assertEqual(state["saves"], 0)
            self.assertEqual(
                (server._SETTINGS.get("roles") or {}).get(label),
                "moderator")
            self.assertIn(label,
                          server._SETTINGS.get("terms_seen") or [])
            # Fix 4 interaction: a conflict judgement must NOT arm
            # the generation guard (no recheck may be skipped on
            # the strength of it).
            self.assertIsNone(_judged_triple())
        finally:
            self._restore(saved_settings, saved)

    def test_w17_clear_ok_records_generation_triple(self):
        label = "w17ghost"
        saved_settings, saved, state = self._env(label, False)
        try:
            verdict = server._clear_stranded_label(label)
            self.assertEqual(verdict, "ok")
            self.assertTrue(
                server._label_settings_absent(
                    state["persisted"], label))
            triple = _judged_triple()
            self.assertIsNotNone(triple)
            self.assertEqual(
                triple,
                (server._SETTINGS_GEN[0],
                 server._SETTINGS_WRITTEN_GEN[0],
                 server._SETTINGS_ACTIVE[0]))
        finally:
            self._restore(saved_settings, saved)


class Wave17CapsUnitTests(unittest.TestCase):
    """Fixes 2-3 at unit level, real _provider_blocked shapes."""

    def _env(self):
        orig = dict(server._SETTINGS)
        saved_inflight = list(server._INFLIGHT)
        saved_counts = server._provider_counts_today
        server._INFLIGHT.clear()
        server._SETTINGS["provider_disabled"] = []
        return orig, saved_inflight, saved_counts

    def _restore(self, orig, saved_inflight, saved_counts):
        server._provider_counts_today = saved_counts
        server._INFLIGHT.clear()
        server._INFLIGHT.extend(saved_inflight)
        server._SETTINGS.clear()
        server._SETTINGS.update(orig)

    @staticmethod
    def _pair(res):
        # The wave-17 _img_blocked pair form, verbatim shape.
        return (server._provider_blocked(
                    "google", exclude=res, also="relay_gemini")
                or server._provider_blocked(
                    "relay_gemini", exclude=res, also="google"))

    @staticmethod
    def _pair_prefix(res):
        # The wave-16 single summed call (the regression).
        return server._provider_blocked(
            "google", exclude=res, also="relay_gemini")

    # -- Fix 2: both names' limits bind the pair, all directions -
    def test_w17_image_pair_judges_both_limits(self):
        orig, saved_i, saved_c = self._env()
        try:
            res = server._inflight_add("u17", "google")
            cases = [
                # (limits, counts, wave-16 single call's verdict)
                # — the pair form must BLOCK in all three; the
                # single call judges only google's limit, so the
                # relay-only and stricter-relay cases slip through
                # it (the CAPS16-1 regression), while the
                # google-limit case is the direction wave 16 did
                # close.
                ({"relay_gemini": 2}, {"relay_gemini": 7}, False),
                ({"google": 2}, {"relay_gemini": 7}, True),
                ({"google": 50, "relay_gemini": 3},
                 {"relay_gemini": 9}, False),
            ]
            for limits, counts, prefix in cases:
                server._SETTINGS["provider_limits"] = limits
                server._provider_counts_today = (
                    lambda c=counts: dict(c))
                self.assertTrue(self._pair(res), (limits, counts))
                self.assertEqual(self._pair_prefix(res), prefix,
                                 (limits, counts))
            # Twin-metered spend against a relay-only limit: the
            # pair form binds; a literal TTS transplant (single-
            # name pick-leg) does NOT — the verifier's proof.
            res2 = server._inflight_add("u17", "relay_gemini")
            server._SETTINGS["provider_limits"] = {"relay_gemini": 2}
            server._provider_counts_today = lambda: {"google": 7}
            self.assertTrue(self._pair(res2))
            transplant = (
                server._provider_blocked("relay_gemini", exclude=res2)
                or server._provider_blocked(
                    "google", exclude=res2, also="relay_gemini"))
            self.assertFalse(transplant)
            # Controls: below both limits admits; no limits admits.
            server._SETTINGS["provider_limits"] = {
                "google": 5, "relay_gemini": 5}
            server._provider_counts_today = lambda: {"google": 2}
            self.assertFalse(self._pair(res))
            server._SETTINGS["provider_limits"] = {}
            server._provider_counts_today = lambda: {"google": 99}
            self.assertFalse(self._pair(res))
            # Source: _img_blocked is the two also= calls OR'd.
            src = (REPO / "app" / "server.py").read_text()
            seg = src[src.index("def _img_blocked(p):"):]
            seg = seg[:seg.index("# Wave 12 (C2): born-tagged")]
            self.assertIn('_provider_blocked("google", '
                          'exclude=self._cap_res, '
                          'also="relay_gemini")', seg)
            self.assertIn('_provider_blocked("relay_gemini", '
                          'exclude=self._cap_res, '
                          'also="google")', seg)
        finally:
            self._restore(orig, saved_i, saved_c)

    # -- Fix 3: stamp, not age, decides whether a None base ranks -
    def test_w17_none_base_surface_stamp(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"huggingface": 1}
            server._provider_counts_today = lambda: {}
            base = server._inflight_add("peer17")  # provider=None
            base["ts"] = time.time() - 300  # body long arrived
            caller = server._inflight_add("u17", "huggingface")
            # An OLD UNSTAMPED base still occupies its slot —
            # pre-fix the 45s age bound dropped it (CAPS16-2's
            # trickle leapfrog: peer AND slow spend admitted).
            self.assertTrue(server._provider_blocked(
                "huggingface", exclude=caller))
            # The trickle property: once the slow base tags, IT
            # ranks first and is admitted — exactly 1 of the pair.
            base["provider"] = "huggingface"
            self.assertFalse(server._provider_blocked(
                "huggingface", exclude=base))
            self.assertTrue(server._provider_blocked(
                "huggingface", exclude=caller))
        finally:
            self._restore(orig, saved_i, saved_c)

    def test_w17_stamped_text_base_never_ranks(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"huggingface": 1}
            server._provider_counts_today = lambda: {}
            base = server._inflight_add("peer17")
            base["surface"] = "text"  # stamped at parse time
            base["ts"] = time.time() - 300
            caller = server._inflight_add("u17", "huggingface")
            # CAPS15-5's shape: a post-parse text base can never
            # spend this lane and must not block a media spend.
            self.assertFalse(server._provider_blocked(
                "huggingface", exclude=caller))
            # A YOUNG unstamped base (body still arriving) still
            # blocks — the wave-15 trickle fix stands. (Fresh
            # list: rank order is birth order, so the young base
            # must precede its caller.)
            server._INFLIGHT.clear()
            young = server._inflight_add("peer17b")
            caller2 = server._inflight_add("u17", "huggingface")
            self.assertIsNone(young["provider"])
            self.assertTrue(server._provider_blocked(
                "huggingface", exclude=caller2))
        finally:
            self._restore(orig, saved_i, saved_c)


class Wave17RaceHttpTests(_FixtureServerBase):
    """Fix 1 over HTTP, the verify-auth16 shape at friends scale
    with NO filler: staggered same-label creations in both path
    orders. The winner's persisted role/terms (and cap) survive,
    the loser aborts cleanly and its invite stays unconsumed."""

    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        _, _, admin = cls._login(MASTER)
        assert admin
        # Friends scale: friendone + solo ship with the fixture;
        # add three PBKDF2 friends so the loser's pre-lock window
        # is seconds wide (the verifier's 5-account shape).
        for i in range(3):
            status, body, _ = cls._req(
                "POST", "/api/access",
                {"action": "add", "label": f"seed17{i}",
                 "password": f"seed17-{i}-pw", "master_pw": MASTER},
                ck=admin)
            assert status == 200, body
        # Measure a solo moderator redeem's duration to centre
        # the stagger sweep.
        code = cls._invite(admin, "moderator")
        t0 = time.time()
        status, body, _ = cls._req(
            "POST", "/api/invite/redeem",
            {"label": "solo17v", "password": "solo17v-pw-1",
             "code": code},
            headers={"X-Forwarded-For": "198.51.100.1"})
        assert status == 200, body
        cls.victim_dur = time.time() - t0

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    @classmethod
    def _invite(cls, admin, role):
        status, body, _ = cls._req(
            "POST", "/api/access",
            {"action": "invite_create", "role": role, "days": 1,
             "master_pw": MASTER}, ck=admin)
        assert status == 200, body
        return body["code"]

    def _admin(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        return admin

    def _persisted(self):
        return decrypt_keys(self.tmp / "settings.enc", RESTORE)

    def _invite_used(self, persisted, code):
        h = hashlib.sha256(code.encode()).hexdigest()
        for inv in (persisted.get("invites") or []):
            if inv.get("h") == h:
                return inv.get("used_by")
        return "MISSING"

    def _redeem(self, label, pw, code, ip):
        return self._req("POST", "/api/invite/redeem",
                         {"label": label, "password": pw,
                          "code": code},
                         headers={"X-Forwarded-For": ip})

    # -- redeem vs redeem, staggered ------------------------------
    # Outcome-based: under CPU contention either thread may be
    # the one whose creation lands first, so the winner is
    # whichever got 200 — the safety property (the loser's clear
    # never wipes the winner's persisted state, the loser aborts
    # cleanly, its invite stays unconsumed) must hold for both.
    def test_w17_redeem_race_winner_keeps_role(self):
        admin = self._admin()
        base = self.victim_dur - 2.2
        for k, off in enumerate((-1.0, -0.5, 0.0, 0.5, 1.0)):
            label = f"race17{k}"
            pw_m, pw_f = f"Race17-Mod-{k}-pw", f"Race17-Fri-{k}-pw"
            code_m = self._invite(admin, "moderator")
            code_f = self._invite(admin, "friend")
            out = {}

            def run(tag, pw, code, ip):
                out[tag] = self._redeem(label, pw, code, ip)

            t = threading.Thread(
                target=run, args=("m", pw_m, code_m,
                                  f"198.51.100.{10 + k}"))
            t.start()
            time.sleep(max(0.0, base + off))
            t2 = threading.Thread(
                target=run, args=("f", pw_f, code_f,
                                  f"198.51.100.{110 + k}"))
            t2.start()
            t.join(120)
            t2.join(120)
            sts = {tag: out[tag][0] for tag in ("m", "f")}
            # Exactly one creation lands; the loser aborts
            # cleanly (400 taken in-lock, or 409 when its clear
            # finds the account already exists — the wave-17
            # conflict path; never a 409 WITH an account, which
            # is the pre-fix role-save poisoning).
            self.assertEqual(list(sts.values()).count(200), 1,
                             (k, sts, out))
            win = "m" if sts["m"] == 200 else "f"
            self.assertIn(sts["f" if win == "m" else "m"],
                          (400, 409), (k, sts))
            lose = "f" if win == "m" else "m"
            pw = {"m": pw_m, "f": pw_f}
            code = {"m": code_m, "f": code_f}
            persisted = self._persisted()
            # The winner's own persisted state survived the
            # loser's clear: terms_seen always; the role when the
            # moderator thread won.
            self.assertIn(label, persisted.get("terms_seen") or [])
            if win == "m":
                self.assertEqual(
                    (persisted.get("roles") or {}).get(label),
                    "moderator")
            else:
                self.assertNotIn(
                    label, persisted.get("roles") or {})
            self.assertEqual(
                self._invite_used(persisted, code[win]), label)
            self.assertFalse(
                self._invite_used(persisted, code[lose]))
            status, body, _ = self._login(pw[win])
            self.assertEqual(status, 200, body)
            self.assertEqual(
                body.get("role"),
                "moderator" if win == "m" else "friend", body)
            status, _, _ = self._login(pw[lose])
            self.assertEqual(status, 401)

    # -- redeem vs console-add, staggered (mirror order) ---------
    def test_w17_add_loser_cannot_wipe_redeem_winner(self):
        admin = self._admin()
        base = self.victim_dur - 2.2
        for k, off in enumerate((-1.0, -0.5, 0.0, 0.5, 1.0)):
            label = f"mrace17{k}"
            pw_r, pw_a = f"Mrace17-Red-{k}-pw", f"Mrace17-Add-{k}-pw"
            code_r = self._invite(admin, "moderator")
            out = {}

            def winner():
                out["r"] = self._redeem(label, pw_r, code_r,
                                        f"203.0.113.{10 + k}")

            t = threading.Thread(target=winner)
            t.start()
            time.sleep(max(0.0, base + off))
            st_a, body_a, _ = self._req(
                "POST", "/api/access",
                {"action": "add", "label": label, "password": pw_a,
                 "master_pw": MASTER, "role": "moderator",
                 "cap": 42}, ck=admin)
            t.join(120)
            st_r, body_r, _ = out["r"]
            self.assertIn(st_r, (200, 400, 409), (k, body_r))
            self.assertIn(st_a, (200, 400, 409), (k, body_a))
            # The account owner is whoever's password logs in —
            # exactly one may. (The verifier's third composition
            # — the loser's clear poisoning the winner's role
            # save — surfaces as a 409 WITH a live account whose
            # persisted role is gone; the role assertion below
            # and the st==200 requirement catch it.)
            st_lr, body_lr, _ = self._login(pw_r)
            st_la, body_la, _ = self._login(pw_a)
            self.assertEqual(sorted([st_lr, st_la]), [200, 401],
                             (k, st_r, st_a))
            persisted = self._persisted()
            # Whoever won, the moderator state BOTH paths intended
            # is what persisted — never wiped by the loser's clear.
            self.assertEqual(
                (persisted.get("roles") or {}).get(label),
                "moderator")
            if st_lr == 200:
                self.assertEqual(st_r, 200, (k, body_r))
                self.assertEqual(body_lr.get("role"), "moderator")
                self.assertIn(label,
                              persisted.get("terms_seen") or [])
                self.assertEqual(
                    self._invite_used(persisted, code_r), label)
            else:
                self.assertEqual(st_a, 200, (k, body_a))
                self.assertEqual(body_la.get("role"), "moderator")
                self.assertEqual(
                    (persisted.get("user_caps") or {}).get(label),
                    42)
                self.assertFalse(
                    self._invite_used(persisted, code_r))


class Wave17DecryptCountHttpTests(_FixtureServerBase):
    """Fix 4 over HTTP: the fixture copy of server.py counts
    _persisted_settings calls to a file, and can re-strand a label
    inside the clear->recheck window on demand."""

    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        sp = cls.tmp / "server.py"
        txt = sp.read_text()
        anchor = "def _persisted_settings():\n"
        assert txt.count(anchor) == 1
        txt = txt.replace(
            anchor,
            "_PS_COUNT17 = [0]\n\n\n"
            "def _ps_bump17():\n"
            "    _PS_COUNT17[0] += 1\n"
            "    try:\n"
            "        (Path(__file__).parent / \"PS_COUNT17\")"
            ".write_text(str(_PS_COUNT17[0]))\n"
            "    except Exception:\n"
            "        pass\n\n\n"
            "def _persisted_settings():\n"
            "    _ps_bump17()\n", 1)
        # Restrand injection in the ADD path only: after its
        # clear returns, a "concurrent writer" persists a stranded
        # role for the label (generation moves) while RESTRAND17
        # exists.
        seg_at = txt.index('if action == "add":')
        clr_at = txt.index("_clr15 = _clear_stranded_label(label)",
                           seg_at)
        line_end = txt.index("\n", clr_at)
        txt = txt[:line_end] + (
            "\n                if (Path(__file__).parent / "
            "\"RESTRAND17\").exists():\n"
            "                    with _SETTINGS_LOCK:\n"
            "                        _r17 = dict("
            "_SETTINGS.get(\"roles\") or {})\n"
            "                        _r17[label] = \"moderator\"\n"
            "                        _SETTINGS[\"roles\"] = _r17\n"
            "                    _save_settings()") + txt[line_end:]
        sp.write_text(txt)
        _respawn_fixture(cls)

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _count(self):
        f = self.tmp / "PS_COUNT17"
        return int(f.read_text()) if f.exists() else 0

    def _admin(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        return admin

    # -- a clean creation pays ONE persisted decrypt -------------
    def test_w17_clean_add_one_persisted_decrypt(self):
        admin = self._admin()
        before = self._count()
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "add", "label": "clean17",
             "password": "clean17-pw-1", "master_pw": MASTER},
            ck=admin)
        self.assertEqual(status, 200, body)
        # Pre-fix: 2 (clear fast path + in-lock recheck).
        self.assertEqual(self._count() - before, 1)

    def test_w17_clean_redeem_two_persisted_decrypts(self):
        admin = self._admin()
        status, body, _ = self._req(
            "POST", "/api/access",
            {"action": "invite_create", "role": "friend", "days": 1,
             "master_pw": MASTER}, ck=admin)
        self.assertEqual(status, 200, body)
        before = self._count()
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "cleanr17", "password": "cleanr17-pw-1",
             "code": body["code"]},
            headers={"X-Forwarded-For": "198.51.100.200"})
        self.assertEqual(status, 200, body)
        # Clear fast path + the pre-existing wave-12 claim-outcome
        # read. Pre-fix: 3 (the in-lock recheck decrypted too).
        self.assertEqual(self._count() - before, 2)

    # -- a generation-moving interleave still forces the recheck -
    def test_w17_restrand_in_window_aborts_creation(self):
        admin = self._admin()
        flag = self.tmp / "RESTRAND17"
        flag.write_text("x")
        try:
            status, body, _ = self._req(
                "POST", "/api/access",
                {"action": "add", "label": "restrand17",
                 "password": "restrand17-pw-1",
                 "master_pw": MASTER}, ck=admin)
            self.assertEqual(status, 500, body)
        finally:
            flag.unlink(missing_ok=True)
        status, _, _ = self._login("restrand17-pw-1")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
