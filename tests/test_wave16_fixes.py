#!/usr/bin/env python3
"""Regression tests for the wave-16 fixes (security audit run-15:
13 confirmed findings). Counter tests use the REAL
_provider_counts_note / _provider_counts_resync / _append_usage and
a real usage file; clear tests judge PERSISTED state, not memory;
launcher engine-boot tests run inside `unshare -rn` with a logged
pre-check that 127.0.0.1:3001 refuses inside the namespace (the
host's live FreeLLMAPI gateway is never contacted).

Run:  python3 -m unittest tests.test_wave16_fixes -v
   or python3 -m unittest discover -s tests
"""

import datetime
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
sys.path.insert(0, str(REPO / "tests"))

os.environ.pop("NEXUS_RESTORE_KEY", None)

from key_security import encrypt_keys  # noqa: E402
import server  # noqa: E402

import test_security_audit_2026_10_16 as _a16  # noqa: E402

# Module-qualified references throughout: importing the classes
# by name would make the unittest loader collect the audit
# file's classes a second time under this module.
MASTER = _a16.MASTER
RESTORE = _a16.RESTORE
FRIEND = _a16.FRIEND
FRIEND_PW = _a16.FRIEND_PW
UNIQUE_PW = _a16.UNIQUE_PW
_FixtureServerBase = _a16._FixtureServerBase
_respawn_fixture = _a16._respawn_fixture


def _today_row(provider, user="u16"):
    return {"ts": datetime.datetime.now().isoformat(),
            "provider": provider, "user": user}


class Wave16CounterUnitTests(unittest.TestCase):
    """Fixes 1-2 (caps counter drift) at unit level, real shapes."""

    def _swap_usage(self):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w16-"))
        saved = (server.USAGE_PATH, server._TODAY_CACHE["ts"],
                 dict(server._PROVIDER_COUNTS))
        server.USAGE_PATH = tmp / "usage.jsonl"
        server._PROVIDER_COUNTS["date"] = None
        server._PROVIDER_COUNTS["providers"] = {}
        return tmp, saved

    def _restore_usage(self, tmp, saved):
        (server.USAGE_PATH, server._TODAY_CACHE["ts"],
         counts) = saved
        server._PROVIDER_COUNTS["date"] = counts["date"]
        server._PROVIDER_COUNTS["providers"] = counts["providers"]
        shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 2: foreign-date / missing-ts rows are IGNORED --------
    def test_w16_note_foreign_date_rows_ignored(self):
        tmp, saved = self._swap_usage()
        try:
            today = datetime.datetime.now().isoformat()
            server._append_usage({"ts": today, "provider": "provA"})
            server._append_usage({"ts": today, "provider": "provA"})
            # A request straddling midnight lands backdated; a
            # missing-ts row has date "". Pre-fix each RESET the
            # counter's day and wiped today's counts, and the
            # follow-on today row locked the wipe in.
            server._append_usage({"ts": "2020-01-01T00:00:00",
                                  "provider": "provA"})
            server._append_usage({"provider": "provA"})  # no ts
            server._append_usage({"ts": today, "provider": "provA"})
            want = server._today_counts(fresh=True)["providers"]
            self.assertEqual(want, {"provA": 3})
            self.assertEqual(server._provider_counts_today(), want)
            self.assertEqual(server._PROVIDER_COUNTS["date"],
                             datetime.date.today().isoformat())
            # A genuine rollover still reseeds: a row dated today
            # when the counter's day is stale resets, then counts.
            server._PROVIDER_COUNTS["date"] = "2020-01-01"
            server._PROVIDER_COUNTS["providers"] = {"provA": 99}
            server._provider_counts_note(
                {"ts": today, "provider": "provB"})
            self.assertEqual(server._provider_counts_today(),
                             {"provB": 1})
        finally:
            self._restore_usage(tmp, saved)

    # -- Fix 1: boot telemetry restore resyncs the counter --------
    def test_w16_boot_restore_resyncs_counter(self):
        tmp, saved = self._swap_usage()
        saved_tel = (server.TELEMETRY_ENC_PATH, server.AUDIT_PATH,
                     server.RESTORE_KEY, dict(server._TELEMETRY))
        try:
            rows = "".join(
                json.dumps({"ts": datetime.datetime.now().isoformat(),
                            "provider": "groq", "user": "u16"}) + "\n"
                for _ in range(3))
            enc = tmp / "telemetry.enc"
            encrypt_keys({"v": 1, "saved": "x", "usage": rows,
                          "audit": ""}, RESTORE, enc)
            server.TELEMETRY_ENC_PATH = enc
            server.RESTORE_KEY = RESTORE
            audit = tmp / "audit.jsonl"
            audit.write_text("{}\n")  # audit present, usage absent
            server.AUDIT_PATH = audit
            # Simulate the import-time seed on an absent usage
            # file: counter stamped today, providers empty.
            server._PROVIDER_COUNTS["date"] = \
                datetime.date.today().isoformat()
            server._PROVIDER_COUNTS["providers"] = {}
            server._boot_restore_telemetry()
            self.assertTrue(server.USAGE_PATH.exists())
            # Pre-fix the restored rows were on disk but the
            # counter stayed {} for the rest of the day.
            self.assertEqual(server._provider_counts_today(),
                             {"groq": 3})
        finally:
            (server.TELEMETRY_ENC_PATH, server.AUDIT_PATH,
             server.RESTORE_KEY, tel) = saved_tel
            server._TELEMETRY.clear()
            server._TELEMETRY.update(tel)
            self._restore_usage(tmp, saved)

    # -- Fix 1/3/4 callsites exist in the prescribed spots --------
    def test_w16_resync_callsites(self):
        src = (REPO / "app" / "server.py").read_text()
        seg = src[src.index("def _boot_restore_telemetry"):]
        seg = seg[:seg.index("def _audit_count_today")]
        self.assertLess(seg.index('USAGE_PATH.write_text(data["usage"])'),
                        seg.index("_provider_counts_resync("
                                  "data['usage'].splitlines(keepends=True))"))
        seg = src[src.index('if action == "friend_usage_reset":'):]
        seg = seg[:seg.index('if action in ("settings_set"')]
        self.assertLess(seg.index("_rewrite_lines(USAGE_PATH, keep)"),
                        seg.index("_provider_counts_resync(keep)"))
        seg = src[src.index('if action == "factory_reset":'):]
        seg = seg[:seg.index('if action == "add":')]
        self.assertLess(seg.index('USAGE_PATH.write_text("")'),
                        seg.index("_provider_counts_resync([])"))


class Wave16ProviderBlockedUnitTests(unittest.TestCase):
    """Fixes 5-7 (image funding sum, None-slot age bound,
    substitution check+retag atomicity)."""

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

    # -- Fix 5: the image pair is judged summed -------------------
    def test_w16_image_funding_pair_summed(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"google": 1}
            server._SETTINGS["provider_disabled"] = []
            server._provider_counts_today = lambda: {"relay_gemini": 5}
            res = server._inflight_add("u16", "google")
            # Each single-name check reads the twin's spends as
            # zero (the pre-fix _img_blocked OR of the two)...
            self.assertFalse(
                server._provider_blocked("google", exclude=res))
            # ...the summed funding-lane form binds.
            self.assertTrue(server._provider_blocked(
                "google", exclude=res, also="relay_gemini"))
            src = (REPO / "app" / "server.py").read_text()
            seg = src[src.index("def _img_blocked(p):"):]
            seg = seg[:seg.index("# Wave 12 (C2): born-tagged")]
            self.assertIn('_provider_blocked("google", '
                          'exclude=self._cap_res, '
                          'also="relay_gemini")', seg)
            self.assertNotIn('or _provider_blocked("relay_gemini"',
                             seg)
        finally:
            self._restore(orig, saved_i, saved_c)

    # -- Fix 6: old None bases stop ranking; young ones still do --
    def test_w16_none_base_age_bound(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"huggingface": 1}
            server._SETTINGS["provider_disabled"] = []
            server._provider_counts_today = lambda: {}
            stale = server._inflight_add("peer16")
            stale["ts"] = time.time() - 300  # a post-parse text chat
            caller = server._inflight_add("u16", "huggingface")
            # Pre-fix the stale None base alone blocked at limit 1.
            self.assertFalse(server._provider_blocked(
                "huggingface", exclude=caller))
            # A YOUNG untagged base (body still arriving) still
            # occupies the slot — the wave-15 trickle fix stands.
            stale["ts"] = time.time()
            self.assertTrue(server._provider_blocked(
                "huggingface", exclude=caller))
        finally:
            self._restore(orig, saved_i, saved_c)

    # -- Fix 7: substitution check+retag is one lock hold ---------
    def test_w16_substitution_tag_atomic(self):
        orig, saved_i, saved_c = self._env()
        try:
            server._SETTINGS["provider_limits"] = {"pollinations": 1}
            server._SETTINGS["provider_disabled"] = []
            server._provider_counts_today = lambda: {}
            peer = server._inflight_add("peer16", "pollinations")
            self.assertFalse(server._provider_blocked(
                "pollinations", exclude=peer))
            q1 = server._inflight_add("u16", "google")
            # The substitute lane is full: no tag is earned.
            self.assertFalse(
                server._provider_blocked_and_tag("pollinations", q1))
            self.assertEqual(q1["provider"], "google")
            # Lane free: the tag lands with the passing check.
            server._inflight_drop(peer)
            self.assertTrue(
                server._provider_blocked_and_tag("pollinations", q1))
            self.assertEqual(q1["provider"], "pollinations")
            # Source: the handler's substitution gate goes through
            # the locked helper — no bare check-then-assign pair.
            src = (REPO / "app" / "server.py").read_text()
            seg = src[src.index("_may_substitute = (provider in ("):]
            seg = seg[:seg.index("_pollinations(model")]
            self.assertIn(
                "_provider_blocked_and_tag(_sub_p, self._cap_res)",
                seg)
            self.assertNotIn(
                'self._cap_res["provider"] = _sub_p', seg)
        finally:
            self._restore(orig, saved_i, saved_c)


class Wave16ClearUnitTests(unittest.TestCase):
    """Fix 8: the clear's fast path judges PERSISTED state."""

    def test_w16_clear_fast_path_checks_persisted(self):
        label = "w16ghost"
        saved_settings = dict(server._SETTINGS)
        saved_save = server._save_settings
        saved_persisted = server._persisted_settings
        state = {"persisted": None, "saves": 0}
        try:
            for k in ("roles", "user_caps", "vault_meta"):
                d = dict(server._SETTINGS.get(k) or {})
                d.pop(label, None)
                server._SETTINGS[k] = d
            for k in ("suspended", "terms_seen"):
                server._SETTINGS[k] = [
                    x for x in (server._SETTINGS.get(k) or [])
                    if x != label]
            server._SETTINGS["oauth_links"] = [
                e for e in (server._SETTINGS.get("oauth_links") or [])
                if not (isinstance(e, dict)
                        and e.get("label") == label)]
            # Memory is clean; the PERSISTED store still carries
            # the stranded entries (a faulted first clear left the
            # two diverged — D15-1's exact shape).
            stranded = {"roles": {label: "moderator"},
                        "user_caps": {label: 777},
                        "vault_meta": {label: []},
                        "suspended": [label], "terms_seen": [label],
                        "oauth_links": [{"email": "g@example.co",
                                         "label": label}]}
            state["persisted"] = stranded

            def fake_persisted():
                return state["persisted"]

            def fake_save():
                state["saves"] += 1
                # The save persists the current (cleared) memory.
                import copy
                state["persisted"] = copy.deepcopy(
                    {k: server._SETTINGS.get(k) for k in
                     ("roles", "user_caps", "vault_meta",
                      "suspended", "terms_seen", "oauth_links")})
                return True

            server._persisted_settings = fake_persisted
            server._save_settings = fake_save
            verdict = server._clear_stranded_label(label)
            self.assertEqual(verdict, "ok")
            # Pre-fix: the memory-only fast path returned "ok"
            # with NO save, leaving the stranded store in place.
            self.assertGreaterEqual(state["saves"], 1)
            self.assertTrue(
                server._label_settings_absent(state["persisted"],
                                              label))
            # Happy path: persisted clean too -> still "ok".
            self.assertEqual(
                server._clear_stranded_label(label), "ok")
        finally:
            server._save_settings = saved_save
            server._persisted_settings = saved_persisted
            server._SETTINGS.clear()
            server._SETTINGS.update(saved_settings)


class Wave16HttpTests(_FixtureServerBase):
    """Fixes 1/3/4 over HTTP: boot restore, friend usage reset and
    factory reset all resync the provider counter."""

    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def _access(self, payload, ck):
        return self._req("POST", "/api/access", payload, ck=ck)

    def _limits(self, admin, limits):
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"provider_limits": limits}}, admin)
        self.assertEqual(status, 200, body)

    def _transcribe(self, pw):
        _, _, cookie = self._login(pw)
        self.assertTrue(cookie)
        return self._req("POST", "/api/transcribe",
                         {"audio": "data:audio/webm;base64,AAAA"},
                         ck=cookie)

    def _seed_usage(self, rows):
        with open(self.tmp / "usage.jsonl", "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

    # -- Fix 4: friend_usage_reset refunds provider limits too ---
    def test_w16_1_friend_reset_resyncs_counter(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        rows = [_today_row("groq", FRIEND) for _ in range(3)]
        rows.append(_today_row("groq", "solo"))
        self._seed_usage(rows)
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        self._limits(admin, {"groq": 2})
        # At the limit: the friend's transcribe is refused.
        status, body, _ = self._transcribe(FRIEND_PW)
        self.assertEqual(status, 403, body)
        status, body, _ = self._access(
            {"action": "friend_usage_reset", "label": FRIEND,
             "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("removed"), 3)
        # The disk scan now says {groq: 1}; post-fix the counter
        # agrees, so governance passes and the request proceeds
        # upstream (502 on the fake key). Pre-fix the stale
        # counter ({groq: 4}) kept refusing with 403.
        status, body, _ = self._transcribe(FRIEND_PW)
        self.assertNotEqual(status, 403, body)
        self._limits(admin, {})

    # -- Fix 1: a telemetry-restore boot counts restored spends --
    def test_w16_2_boot_restore_counts_restored_spends(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        self._limits(admin, {"groq": 2})
        rows = "".join(json.dumps(_today_row("groq", "solo")) + "\n"
                       for _ in range(3))
        encrypt_keys({"v": 1, "saved": "x", "usage": rows,
                      "audit": ""}, RESTORE,
                     self.tmp / "telemetry.enc")
        usage = self.tmp / "usage.jsonl"
        if usage.exists():
            usage.unlink()
        audit = self.tmp / "audit.jsonl"
        if not audit.exists():
            audit.write_text("")
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        self.assertTrue((self.tmp / "usage.jsonl").exists())
        # Restored spends (3 >= limit 2) must block from the first
        # request after boot. Pre-fix the counter was seeded
        # before the restore and stayed {} — transcribe proceeded
        # upstream (502) instead of being refused.
        status, body, _ = self._transcribe(UNIQUE_PW)
        self.assertEqual(status, 403, body)
        self._limits(admin, {})

    # -- Fix 3: factory reset zeroes the counter ------------------
    def test_w16_3_factory_reset_resyncs_counter(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        self._seed_usage([_today_row("groq", "solo")
                          for _ in range(3)])
        _respawn_fixture(self.__class__)
        _, _, admin = self._login(MASTER)
        status, body, _ = self._access(
            {"action": "factory_reset", "confirm": "RESET",
             "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        # A provider limit created later the SAME day must judge
        # the truncated (empty) log, not the erased counts.
        self._limits(admin, {"groq": 2})
        status, body, _ = self._access(
            {"action": "add", "label": "fact16",
             "password": "fact16-pass-1", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._transcribe("fact16-pass-1")
        self.assertNotEqual(status, 403, body)
        self._limits(admin, {})


class Wave16FaultHarness(_FixtureServerBase):
    """Fixes 8-11 over the wave-15 fault shape (SAVE_FAULT):
    persisted-truthful clear, redeem clear relocation, creation
    file-store clearing, and the pre-clear / in-lock recheck."""

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

    def _settings(self, admin):
        status, body, _ = self._access(
            {"action": "settings_set", "master_pw": MASTER,
             "patch": {"global_cap": 0}}, admin)
        self.assertEqual(status, 200, body)
        return body.get("settings") or {}

    def _strand(self, admin, label):
        status, body, _ = self._access(
            {"action": "add", "label": label,
             "password": f"{label}-pw-1", "master_pw": MASTER,
             "role": "moderator", "cap": 777}, admin)
        self.assertEqual(status, 200, body)
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

    # -- Fix 8: a plain retry after a faulted clear stays clean ---
    def test_w16_add_retry_after_faulted_clear(self):
        _, _, admin = self._login(MASTER)
        admin = self._strand(admin, "ghost16")
        self.assertEqual(
            (self._settings(admin).get("roles") or {}).get(
                "ghost16"), "moderator")
        # First clear faults: honest 500, no account (wave-15
        # contract) — memory cleared, disk still stranded.
        self._fault(True)
        try:
            status, body, _ = self._access(
                {"action": "add", "label": "ghost16",
                 "password": "ghost16-new-pw",
                 "master_pw": MASTER}, admin)
            self.assertEqual(status, 500, body)
        finally:
            self._fault(False)
        # The plain retry: pre-fix the memory-only fast path
        # returned "ok" with no save, so the account was created
        # over the still-stranded persisted store.
        status, body, _ = self._access(
            {"action": "add", "label": "ghost16",
             "password": "ghost16-new-pw", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        # Read the PERSISTED store DIRECTLY (decrypt settings.enc;
        # any API settings read would itself save and heal the
        # divergence — the verifier's D15-1 read shape).
        from key_security import decrypt_keys
        persisted = decrypt_keys(self.tmp / "settings.enc",
                                 RESTORE)
        self.assertNotIn("ghost16", persisted.get("roles") or {})
        self.assertNotIn("ghost16",
                         persisted.get("user_caps") or {})
        self.assertNotIn("ghost16",
                         persisted.get("suspended") or [])
        self.assertFalse(any(
            isinstance(e, dict) and e.get("label") == "ghost16"
            for e in (persisted.get("oauth_links") or [])))
        _respawn_fixture(self.__class__)
        status, body, _ = self._login("ghost16-new-pw")
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "friend", body)

    # -- Fix 9: a bogus redeem may not wipe a stranded label -----
    def test_w16_bogus_redeem_keeps_stranded_settings(self):
        _, _, admin = self._login(MASTER)
        admin = self._strand(admin, "prelink16")
        # Source order: validation + budget precede the clear;
        # the clear precedes the claim.
        src = (REPO / "app" / "server.py").read_text()
        seg = src[src.index('if parsed.path == "/api/invite/redeem":'):]
        seg = seg[:seg.index('if parsed.path == "/api/login":')]
        self.assertLess(seg.index("an invite code is required"),
                        seg.index("_clear_stranded_label(label)"))
        self.assertLess(
            seg.index('_probe_ok = _rl_ok("redeemprobe"'),
            seg.index("_clear_stranded_label(label)"))
        self.assertLess(seg.index("_clear_stranded_label(label)"),
                        seg.index('invite["used_by"] = label'))
        # One unauthenticated bogus-code POST: 400, no account —
        # and the stranded entries SURVIVE (pre-fix the clear ran
        # before validation and wiped them).
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "prelink16", "password": "prelink16-new-pw",
             "code": "BOGUSW16"})
        self.assertEqual(status, 400, body)
        settings = self._settings(admin)
        self.assertEqual(
            (settings.get("roles") or {}).get("prelink16"),
            "moderator")
        self.assertIn("prelink16", settings.get("suspended") or [])
        # A valid redeem still clears and creates clean.
        status, body, _ = self._access(
            {"action": "invite_create", "role": "friend",
             "days": 1, "master_pw": MASTER}, admin)
        self.assertEqual(status, 200, body)
        status, body, _ = self._req(
            "POST", "/api/invite/redeem",
            {"label": "prelink16", "password": "prelink16-new-pw",
             "code": body["code"]})
        self.assertEqual(status, 200, body)
        status, body, _ = self._login("prelink16-new-pw")
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("role"), "friend", body)

    # -- Fix 11: creation clears the file stores ------------------
    def _strand_files(self, label, pw):
        for sub, payload in (
                ("chats", {"chats": [{"id": "x", "title": "old",
                                      "messages": []}]}),
                ("userkeys", {"groq": "sk-old-fake-key"}),
                ("userintegrations", {"linear": {"api_key": "old"}})):
            d = self.tmp / sub
            d.mkdir(exist_ok=True)
            encrypt_keys(payload, pw, d / f"{label}.enc")

    def _files_exist(self, label):
        return {sub: (self.tmp / sub / f"{label}.enc").exists()
                for sub in ("chats", "userkeys", "userintegrations")}

    def test_w16_creation_clears_file_stores(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        self._strand_files("file16", "file16-old-pw")
        status, body, _ = self._access(
            {"action": "add", "label": "file16",
             "password": "file16-new-pw", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        # Pre-fix all three stranded files survived creation —
        # bricking the new holder's saves (strict loaders 500).
        self.assertEqual(self._files_exist("file16"),
                         {"chats": False, "userkeys": False,
                          "userintegrations": False})
        status, body, ck = self._login("file16-new-pw")
        self.assertEqual(status, 200, body)
        status, body, _ = self._req("POST", "/api/mykeys",
                                    {"action": "view"}, ck=ck)
        self.assertEqual(status, 200, body)
        self.assertFalse(body.get("has_vault"), body)
        # Same-password re-registration must not revive either.
        self._strand_files("file17", "file17-old-pw")
        status, body, _ = self._access(
            {"action": "add", "label": "file17",
             "password": "file17-old-pw", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 200, body)
        self.assertEqual(self._files_exist("file17"),
                         {"chats": False, "userkeys": False,
                          "userintegrations": False})

    def test_w16_undeletable_file_aborts_creation(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        # A directory where the chats file belongs cannot be
        # unlinked: creation must abort, not brick the account.
        d = self.tmp / "chats" / "dir16.enc"
        d.mkdir(parents=True, exist_ok=True)
        status, body, _ = self._access(
            {"action": "add", "label": "dir16",
             "password": "dir16-new-pw", "master_pw": MASTER},
            admin)
        self.assertEqual(status, 500, body)
        self.assertIn("friend not added", body.get("error", ""),
                      body)
        status, _, _ = self._login("dir16-new-pw")
        self.assertEqual(status, 401)

    # -- Fix 10: clear runs BEFORE _ACCESS_LOCK; in-lock recheck --
    def test_w16_clear_outside_access_lock_source(self):
        src = (REPO / "app" / "server.py").read_text()
        for seg_start, seg_end in (
                ('if parsed.path == "/api/invite/redeem":',
                 'if parsed.path == "/api/login":'),
                ('if action == "add":', 'if action == "revoke":')):
            seg = src[src.index(seg_start):]
            seg = seg[:seg.index(seg_end)]
            self.assertLess(
                seg.index("_clear_stranded_label(label)"),
                seg.index("with _ACCESS_LOCK:"),
                seg_start)
            # The in-lock guard judges PERSISTED state.
            self.assertIn("_persisted_settings()", seg)
            self.assertIn("_label_settings_absent(", seg)


class Wave16LauncherTests(unittest.TestCase):
    """Fixes 12-13 (launcher): DQ pre-expansion passwordAlt and
    the *.node pre-filter's subtree/symlink traversal."""

    def _parse(self, env_text):
        return _a16.Wave14LauncherTests()._parse(env_text)

    @staticmethod
    def _codes(s):
        return [ord(c) for c in s]

    # -- Fix 12: DQ expansion earns a literal alternate -----------
    def test_w16_parse_dq_backslash_literal_alt(self):
        out = self._parse('ENGINE_ADMIN_PASSWORD="pa\\nss"\n')
        self.assertEqual(out["pw"], self._codes("pa\nss"))
        # Pre-fix: alt was null for every quoted line, so a legacy
        # record whose engine holds the LITERAL form got exactly
        # one POST, a definitive 401, and deleted credentials.
        self.assertEqual(out["alt"], self._codes("pa\\nss"))
        out = self._parse('ENGINE_ADMIN_PASSWORD="pa\\rss"\n')
        self.assertEqual(out["alt"], self._codes("pa\\rss"))
        # No expansion change -> no alternate.
        out = self._parse('ENGINE_ADMIN_PASSWORD="plainpw"\n')
        self.assertIsNone(out["alt"])
        # The REJECTED quoted-# leg stays rejected: no pre-# alt
        # is restored for quoted lines.
        out = self._parse('ENGINE_ADMIN_PASSWORD="abc#def"\n')
        self.assertEqual(out["pw"], self._codes("abc#def"))
        self.assertIsNone(out["alt"])
        # Single-quoted values are never expanded, never alted.
        out = self._parse("ENGINE_ADMIN_PASSWORD='pa\\nss'\n")
        self.assertEqual(out["pw"], self._codes("pa\\nss"))
        self.assertIsNone(out["alt"])
        # Unquoted shapes keep their genuine alternates.
        out = self._parse("ENGINE_ADMIN_PASSWORD=p@ss#w0rd!\n")
        self.assertEqual(out["alt"], self._codes("p@ss"))

    # -- Fix 12 E2E (netns): the literal form is retried ----------
    def test_w16_verify_dq_literal_retry_keeps_creds(self):
        node = shutil.which("node")
        if not node or not shutil.which("unshare"):
            self.skipTest("node/unshare not available")
        h = _a16.Wave12LauncherTests()
        h.ENGINE_PW = "pa\\nss"  # literal backslash-n (6 chars)
        tmp = h._fixture(
            f"ENGINE_ADMIN_EMAIL={h.ENGINE_EMAIL}\n"
            'ENGINE_ADMIN_PASSWORD="pa\\nss"\n')
        # The stub embeds the expected password in a JS string
        # literal, which would eat the backslash: double it so
        # the stub really holds the literal backslash form.
        dist = tmp / "app" / "engine" / "server" / "dist" / "index.js"
        stub = dist.read_text()
        assert "pa\\nss" in stub
        dist.write_text(stub.replace("pa\\nss", "pa\\\\nss"))
        pre = subprocess.run(
            ["unshare", "-rn", "bash", "-c",
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
        proc = subprocess.Popen(
            ["unshare", "-rn", "bash", "-c",
             "ip link set lo up 2>/dev/null; exec "
             f"{node} {tmp / 'bin' / 'nexuslocal.js'}"],
            cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            h._wait_for(proc, tmp,
                        lambda: len(h._logins(tmp)) >= 2,
                        timeout=60,
                        what="verify login + literal retry")
            time.sleep(1)
            logins = h._logins(tmp)
            # Primary (expanded) form refused, literal retried.
            self.assertEqual(logins[0]["password"], "pa\nss")
            self.assertEqual(logins[1]["password"], "pa\\nss")
            env_after = (tmp / "app" / ".env").read_text(
                encoding="utf-8")
            self.assertIn("ENGINE_ADMIN_PASSWORD", env_after)
            self.assertIn("ENGINE_ADMIN_EMAIL", env_after)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            shutil.rmtree(tmp, ignore_errors=True)

    # -- Fix 13: the *.node pre-filter traversal ------------------
    def _binding_present(self, node_modules, as_nobody=False):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        src = (REPO / "bin" / "nexuslocal.js").read_text()
        fn = src[src.index("const _bsqBindingPresent"):]
        fn = fn[:fn.index("const _bsqLoadable")]
        script = (
            "const fs=require('fs');const path=require('path');"
            f"const nodeModules={json.dumps(str(node_modules))};"
            + fn +
            "console.log(_bsqBindingPresent());")
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w16-gate-"))
        try:
            (tmp / "gate.js").write_text(script)
            cmd = [node, str(tmp / "gate.js")]
            if as_nobody:
                # The suite runs as root here, and root bypasses
                # mode-000; the readdir-error leg only fires for a
                # non-root uid (the verifier's bound). Run the
                # harness as nobody via setpriv.
                setpriv = shutil.which("setpriv")
                if not setpriv:
                    self.skipTest("setpriv not available")
                os.chmod(tmp, 0o755)
                os.chmod(tmp / "gate.js", 0o644)
                cmd = [setpriv, "--reuid=65534", "--regid=65534",
                       "--clear-groups", node, str(tmp / "gate.js")]
            # Pure-fs harness: no launcher boot, no network code —
            # it cannot reach an engine port.
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            return r.stdout.strip() == "true"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _bsq_tree(self):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w16-bsq-"))
        nm = tmp / "node_modules"
        pkg = nm / "better-sqlite3"
        pkg.mkdir(parents=True)
        return tmp, nm, pkg

    def test_w16_gate_unreadable_subdir_skipped(self):
        tmp, nm, pkg = self._bsq_tree()
        try:
            # World-traversable so the nobody harness can walk it.
            for d in (tmp, nm, pkg):
                os.chmod(d, 0o755)
            (pkg / "d1").mkdir()
            (pkg / "d2").mkdir()
            # The walk is a stack: the LAST entry in readdir order
            # is popped first. Assign roles by NODE's readdir
            # order (python's listdir order differs) so the
            # unreadable subtree is provably visited before the
            # binding subtree (the verifier's G2 shape).
            node = shutil.which("node")
            if not node:
                self.skipTest("node not available")
            r = subprocess.run(
                [node, "-e",
                 "console.log(JSON.stringify(require('fs')"
                 f".readdirSync({json.dumps(str(pkg))})));"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            order = json.loads(r.stdout)
            good = pkg / order[0]
            bad = pkg / order[-1]
            (good / "x.node").write_text("bin")
            os.chmod(good, 0o755)
            os.chmod(bad, 0o000)
            try:
                # Pre-fix the unreadable subtree's readdir error
                # returned false for the WHOLE search.
                self.assertTrue(
                    self._binding_present(nm, as_nobody=True))
            finally:
                os.chmod(bad, 0o755)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_w16_gate_symlinked_subdir_traversed(self):
        tmp, nm, pkg = self._bsq_tree()
        try:
            target = tmp / "elsewhere"
            target.mkdir()
            (target / "x.node").write_text("bin")
            os.symlink(target, pkg / "linked")
            self.assertTrue(self._binding_present(nm))
            # A symlink cycle with NO binding terminates false.
            pkg2 = tmp / "nm2" / "better-sqlite3"
            pkg2.mkdir(parents=True)
            os.symlink(pkg2, pkg2 / "loop")
            self.assertFalse(self._binding_present(tmp / "nm2"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_w16_gate_controls(self):
        tmp, nm, pkg = self._bsq_tree()
        try:
            # No binding anywhere: still false (the gate must
            # fail bindings-missing trees without executing).
            (pkg / "lib").mkdir()
            self.assertFalse(self._binding_present(nm))
            # The package dir itself missing: still false.
            self.assertFalse(
                self._binding_present(tmp / "no_such_dir"))
            # pnpm shape: the package itself is a symlink into a
            # store dir whose internal dirs are real.
            store = tmp / "store" / "better-sqlite3"
            rel = store / "build" / "Release"
            rel.mkdir(parents=True)
            (rel / "better_sqlite3.node").write_text("bin")
            nm2 = tmp / "nm3"
            nm2.mkdir()
            os.symlink(store, nm2 / "better-sqlite3")
            self.assertTrue(self._binding_present(nm2))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
