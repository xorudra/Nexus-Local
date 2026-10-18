#!/usr/bin/env python3
"""Regression tests for the wave-22 fixes (security audit run-21:
5 confirmed findings, all LOW).

Fix 1 (D21-DATA-1, merged with AUTH21-1; app/server.py):
  _read_diverged_sidecar swallowed absent / unreadable /
  malformed into the same None, so wave 21's clear
  verification and logical-clock max-read were blind exactly
  when a present sidecar could not be read: a heal save's
  clear early-returned a silent True (arm A) or stamped its
  tombstone below an unseen future raise (arm B). Fix:
  tri-state read — ("unknown", None) when the file exists
  but its read/parse failed; _clear_backup_diverged and
  _persist_diverged route that state to the existing loud
  access_backup_diverged_unpersisted path and return False
  (no ts is stamped from a blind max-read); the boot fold
  leaves a loud audit line and folds nothing.

Fix 2 (D21-DATA-2; app/server.py): a non-finite ts (NaN /
  Infinity) on the settings/memory channel poisoned the
  merged ranking permanently. Fix: ONE shared predicate
  (_diverged_ts_ok) at BOTH readers — a ts is valid only
  when int/float, not bool, and finite; anything else
  coerces to 0 like a non-numeric ts.

Fix 3 (L21-L1; bin/nexuslocal.js): the sentinel selection
  failed OPEN on candidate exhaustion (fell back to the
  known-present \\u0001, reviving L20-L1). Fix (verifier's
  smallest): exhaustion returns null and the parse fails
  CLOSED as absent; the candidate list is widened by U+0008
  and U+001B. No pair escalation, no naive-split fallback.

Fix 4 (L21-L2; bin/nexuslocal.js): the arming gate's key
  class [\\w.-]* armed quote mode for KEYLESS records
  (dotenv requires [\\w.-]+). Fix: one character, * -> +.

Fix 5 (L21-L3 + L21-L4 merged; bin/nexuslocal.js): the
  splitter treated a quote closing on a LATER line as a
  multiline close without checking that line's remainder;
  dotenv falls back to the unquoted parse unless the
  remainder is whitespace/comment. Fix: on close, peek at
  the closing line's remainder; if it is not
  /^\\s*(#.*)?$/ the record was never a valid multiline —
  re-split naively from recStart up to the closing line and
  resume quote-aware scanning AT the closing line as a
  fresh record start (same check at every later close).
  All three quote chars, one path; properly-closed
  multilines untouched.

Fix 6 (L21-L5; bin/nexuslocal.js): a quoted credential
  value starting on the line AFTER `=` read absent. Fix
  (verifier's narrower prescription): parse-local only —
  a credential record with an empty value adopts a
  following record consisting solely of a quoted string,
  fed through the existing quoted-value parse.

Run:  python3 -m unittest tests.test_wave22_fixes -v
   or python3 -m unittest discover -s tests
"""

import json
import os
import shutil
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

from key_security import decrypt_keys, encrypt_keys  # noqa: E402
import server  # noqa: E402

import test_security_audit_2026_10_16 as _a16  # noqa: E402
import test_wave18_fixes as _w18  # noqa: E402

MASTER = _a16.MASTER
RKEY = "restore-wave22-key"
NODE_HARNESS_JS = _w18.NODE_HARNESS_JS


# =====================================================================
# Fixes 1+2 — divergence-flag tri-state + ts predicate (server.py)
# =====================================================================
class Wave22DataTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w22-data-"))
        self._saved = (server.ACCESS_PATH, server.USERS_PATH,
                       server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
                       server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
                       server.AUDIT_PATH,
                       server.decrypt_keys, server.encrypt_keys)
        server.ACCESS_PATH = self.tmp / "access.json"
        server.USERS_PATH = self.tmp / "users.enc"
        server.ACCESS_ENC_PATH = self.tmp / "access.enc"
        server.SETTINGS_PATH = self.tmp / "settings.json"
        server.SETTINGS_ENC_PATH = self.tmp / "settings.enc"
        server.AUDIT_PATH = self.tmp / "audit.jsonl"
        server.RESTORE_KEY = RKEY
        self._settings_saved = dict(server._SETTINGS)
        server._SETTINGS.clear()
        server._SETTINGS.update(
            json.loads(json.dumps(server._SETTINGS_DEFAULTS)))
        server._BACKUP_DIVERGED_MEM[0] = None

    def tearDown(self):
        (server.ACCESS_PATH, server.USERS_PATH,
         server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
         server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
         server.AUDIT_PATH,
         server.decrypt_keys, server.encrypt_keys) = self._saved
        server._SETTINGS.clear()
        server._SETTINGS.update(self._settings_saved)
        server._BACKUP_DIVERGED_MEM[0] = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------
    def _sidecar_path(self):
        return self.tmp / "access_diverged.json"

    def _write_sidecar(self, rec):
        self._sidecar_path().write_text(json.dumps(rec))

    def _garbage_sidecar(self):
        # Present but unparseable: the record-preserving
        # read-fault episode's observable state at the reader.
        self._sidecar_path().write_bytes(b"\xff\xfe not json {{{")

    def _iofault_sidecar(self):
        # Wave 23: an IO-fault sidecar — a directory at the
        # sidecar path, whose read raises OSError — is the
        # "unknown" exemplar from wave 23 on. Garbage bytes
        # are the separate parse-fault ("corrupt") class,
        # which wave 23's persist stamps over and heals
        # (run-22 D22-DATA-1); the unknown-arm expectations
        # below are the IO-fault contract, preserved exactly.
        p = self._sidecar_path()
        try:
            p.unlink()
        except FileNotFoundError:
            pass
        p.mkdir()

    def _persisted_settings_flag(self):
        d = decrypt_keys(server.SETTINGS_ENC_PATH, RKEY)
        return d.get("access_backup_diverged")

    def _seed(self, d):
        server.ACCESS_PATH.write_text(json.dumps(d))
        encrypt_keys(d, MASTER, server.USERS_PATH)
        self.assertTrue(server._save_settings())

    def _sole_sidecar_raise(self, ts=None):
        """The raise [alpha] lives ONLY on the sidecar channel
        (its settings leg faulted in the process that wrote
        it — the standard D19/D20 fault family state)."""
        self._seed({"alpha": "h-a", "beta": "h-b"})
        self._write_sidecar(
            {"ts": ts if ts is not None else int(time.time()),
             "intended_labels": ["alpha"]})
        server._SETTINGS["access_backup_diverged"] = None
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        self.assertIsNone(self._persisted_settings_flag())

    def _audit_text(self):
        if server.AUDIT_PATH.exists():
            return server.AUDIT_PATH.read_text(errors="replace")
        return ""

    def _restart(self):
        server._BACKUP_DIVERGED_MEM[0] = None
        server._SETTINGS = dict(server._SETTINGS_DEFAULTS)
        server._boot_restore_settings()
        return server._backup_diverged()

    def _wipe(self):
        server.ACCESS_PATH.write_text("{}")
        try:
            server.ACCESS_ENC_PATH.unlink()
        except FileNotFoundError:
            pass

    def _live(self):
        return json.loads(server.ACCESS_PATH.read_text())

    # -- DATA-1 arm A: clear must not early-return silent True --
    def test_w22_data1_armA_clear_loud_false_unreadable_sidecar(self):
        self._sole_sidecar_raise()
        self._iofault_sidecar()
        log_events = []
        orig_log_event = server._log_event
        server._log_event = lambda *a, **k: log_events.append((a, k))
        try:
            ret = server._clear_backup_diverged()
        finally:
            server._log_event = orig_log_event
        # Pre-fix: the merged read is blind (None), the clear
        # early-returns True, no audit ever.
        self.assertIs(ret, False)
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        self.assertTrue(
            any(a and a[1] == "access_backup_diverged_unpersisted"
                for a, _k in log_events), log_events)

    # -- DATA-1 arm A (full): heal save under the fault is loud,
    #    and once the channel heals the loss never happens ------
    def test_w22_data1_armA_heal_loud_then_charlie_survives(self):
        raise_ts = int(time.time())
        self._sole_sidecar_raise(ts=raise_ts)
        self._garbage_sidecar()
        # The heal: add charlie while the sidecar is unreadable.
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a", "charlie": "h-c"},
                                MASTER)
        # users.enc was written correctly…
        self.assertEqual(sorted(decrypt_keys(server.USERS_PATH,
                                             MASTER)),
                         ["alpha", "charlie"])
        # …but the clear inside the heal was LOUD, not a silent
        # True (pre-fix: no audit at any point, ever).
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        # The channel heals; the durable record is intact.
        self._write_sidecar({"ts": raise_ts,
                             "intended_labels": ["alpha"]})
        # The next save's pre-note re-stamps the full intended
        # set above the stale raise, and its clear lands.
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a", "charlie": "h-c"},
                                MASTER)
        self.assertIsNone(server._backup_diverged())
        self.assertIsNone(self._restart())
        self._wipe()
        server._restore_access(MASTER)
        self.assertIn("charlie", self._live())
        self.assertIn("charlie",
                      decrypt_keys(server.USERS_PATH, MASTER))

    # -- DATA-1 arm B: no logical ts stamped from a blind
    #    max-read (no below-future tombstone can be minted) -----
    def test_w22_data1_armB_persist_loud_false_no_stamp(self):
        self._seed({"alpha": "h-a"})
        old = {"ts": int(time.time()) - 100,
               "intended_labels": ["alpha"]}
        server._SETTINGS["access_backup_diverged"] = old
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        self._iofault_sidecar()
        ret = server._persist_diverged(
            {"ts": int(time.time()), "intended_labels": None})
        # Pre-fix: reads the blind sidecar as empty, stamps and
        # returns True (a tombstone that an unseen future raise
        # on the sidecar would out-rank after recovery).
        self.assertIs(ret, False)
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        # Nothing was stamped anywhere: the in-memory record is
        # untouched and the sidecar was not overwritten.
        self.assertEqual(
            server._SETTINGS["access_backup_diverged"], old)
        self.assertTrue(self._sidecar_path().is_dir())

    # -- DATA-1 arm (b): boot fold on unreadable sidecar is loud
    #    and folds nothing over the RAM/settings record ---------
    def test_w22_data1_boot_fold_loud_and_non_destructive(self):
        self._seed({"alpha": "h-a"})
        rec = {"ts": int(time.time()), "intended_labels": ["alpha"]}
        server._SETTINGS["access_backup_diverged"] = rec
        server._BACKUP_DIVERGED_MEM[0] = rec
        self._garbage_sidecar()
        server._load_diverged_sidecar_boot()
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        self.assertEqual(server._BACKUP_DIVERGED_MEM[0], rec)
        self.assertEqual(
            server._SETTINGS["access_backup_diverged"], rec)

    # -- DATA-2: NaN / Infinity poison coerces to 0 at the
    #    merged reader — a newer finite tombstone wins ----------
    def test_w22_data2_nonfinite_ts_ranking_coerced(self):
        for bad in (float("nan"), float("inf")):
            self._seed({"alpha": "h-a"})
            now = int(time.time())
            server._SETTINGS["access_backup_diverged"] = \
                {"ts": bad, "intended_labels": ["alpha"]}
            server._BACKUP_DIVERGED_MEM[0] = None
            self._write_sidecar({"ts": now + 5000,
                                 "intended_labels": None})
            # Pre-fix: the poison raise rules the merged read
            # even against the newer finite sidecar tombstone.
            self.assertIsNone(server._backup_diverged(),
                              repr(bad))
            # A bool ts coerces the same way (pre-fix: ranked
            # as ts=1 — still loses here, so this leg pins the
            # predicate, ranked against a ts=0 tombstone it
            # must NOT beat by being True).
            server._SETTINGS["access_backup_diverged"] = \
                {"ts": True, "intended_labels": ["alpha"]}
            self._write_sidecar({"ts": 0,
                                 "intended_labels": None})
            merged = server._backup_diverged_record()
            self.assertTrue(
                merged is None
                or merged.get("intended_labels") is None,
                merged)

    # -- DATA-2: the persisted arm — poison saved through the
    #    real settings path loses after restart, and the
    #    _persist max-read skips it instead of throwing --------
    def test_w22_data2_persisted_poison_and_max_read(self):
        for bad in (float("nan"), float("inf")):
            self._seed({"alpha": "h-a"})
            server._SETTINGS["access_backup_diverged"] = \
                {"ts": bad, "intended_labels": ["alpha"]}
            server._BACKUP_DIVERGED_MEM[0] = None
            try:
                self._sidecar_path().unlink()
            except FileNotFoundError:
                pass
            self.assertTrue(server._save_settings())
            self.assertEqual(
                repr(self._persisted_settings_flag()["ts"]),
                repr(bad))
            self._write_sidecar(
                {"ts": int(time.time()) + 5000,
                 "intended_labels": None})
            # Pre-fix: merged = the poison raise again.
            self.assertIsNone(self._restart(), repr(bad))
        # Max-read leg: poison in SETTINGS (considered first)
        # must not abort the scan before a finite future ts in
        # MEMORY — pre-fix int(NaN)/int(inf) threw inside the
        # swallowed try and the new record stamped at wall-now,
        # BELOW the memory record it supersedes.
        self._seed({"alpha": "h-a"})
        fut = int(time.time()) + 3600
        server._SETTINGS["access_backup_diverged"] = \
            {"ts": float("inf"), "intended_labels": ["alpha"]}
        server._BACKUP_DIVERGED_MEM[0] = \
            {"ts": fut, "intended_labels": ["alpha"]}
        try:
            self._sidecar_path().unlink()
        except FileNotFoundError:
            pass
        self.assertTrue(server._persist_diverged(
            {"ts": int(time.time()),
             "intended_labels": ["alpha"]}))
        self.assertEqual(
            server._BACKUP_DIVERGED_MEM[0]["ts"], fut + 1)


# =====================================================================
# Fixes 3-6 — the launcher parser patch (bin/nexuslocal.js)
# =====================================================================
class Wave22LauncherTests(unittest.TestCase):

    def setUp(self):
        self.node = shutil.which("node")
        if not self.node:
            self.skipTest("node not available")
        self._tmps = []

    def tearDown(self):
        for tmp in self._tmps:
            shutil.rmtree(tmp, ignore_errors=True)

    def _fixture(self):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w22-launcher-"))
        self._tmps.append(tmp)
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        (tmp / "harness.js").write_text(NODE_HARNESS_JS)
        return tmp

    def _parse(self, tmp, label, text):
        f = tmp / (label + ".env")
        f.write_bytes(text.encode("utf-8"))
        r = subprocess.run(
            [self.node, str(tmp / "harness.js"),
             str(tmp / "bin" / "nexuslocal.js"), "parse", str(f)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip())

    EM = "ENGINE_ADMIN_EMAIL=e@x.io\n"
    PW = "ENGINE_ADMIN_PASSWORD="

    # -- L21-L1: exhaustion fails CLOSED as absent --------------
    def test_w22_l1_exhaustion_absent_and_controls(self):
        tmp = self._fixture()
        all28 = "".join(chr(c) for c in
                        list(range(0x01, 0x08)) + [0x08, 0x0B, 0x0C]
                        + list(range(0x0E, 0x1B)) + [0x1B]
                        + list(range(0x1C, 0x20)))
        self.assertEqual(len(all28), 28)
        text = ("# pad " + all28 + " end\n" + self.EM + self.PW
                + '"a\x01b"\n')
        out = self._parse(tmp, "l1exhausted", text)
        # Pre-fix: fell back to the present \u0001 and mangled
        # the password to 'a\nb' (hasPassword True).
        # Wave 23 (run-22 L22-L1): the exhaustion return also
        # carries the `exhausted` flag — claimStep must be
        # able to tell it apart from a genuinely unrecorded
        # file; the has* absent contract is unchanged.
        self.assertEqual(out, {"hasEmail": False,
                               "hasPassword": False,
                               "exhausted": True}, out)
        # Widening control: all 26 ORIGINAL candidates but not
        # U+0008 — the parse now succeeds on the widened list
        # and the literal \u0001 survives as data.
        orig26 = "".join(chr(c) for c in
                          list(range(0x01, 0x08)) + [0x0B, 0x0C]
                          + list(range(0x0E, 0x1B))
                          + list(range(0x1C, 0x20)))
        self.assertEqual(len(orig26), 26)
        text = ("# pad " + orig26 + " end\n" + self.EM + self.PW
                + '"a\x01b"\n')
        out = self._parse(tmp, "l1widened", text)
        self.assertEqual(out.get("password"), "a\x01b", out)
        self.assertEqual(out.get("email"), "e@x.io", out)
        # Non-exhausted control: byte-unchanged behaviour.
        out = self._parse(tmp, "l1control",
                          self.EM + self.PW + '"a\x01b"\n')
        self.assertEqual(out.get("password"), "a\x01b", out)
        self.assertEqual(out.get("email"), "e@x.io", out)

    # -- L21-L2: keyless records never arm quote mode -----------
    def test_w22_l2_empty_key_gate_all_quotes(self):
        tmp = self._fixture()
        prefixes = ['="oops', 'export ="oops', ' ="oops',
                    '\t="oops']
        n = 0
        for pre in prefixes:
            for q in ('"', "'", "`"):
                n += 1
                armer = pre.replace('"', q)
                text = (armer + "\n" + self.EM + self.PW
                        + '"Pw22x"\n')
                out = self._parse(tmp, f"l2_{n}", text)
                self.assertEqual(out.get("password"), "Pw22x",
                                 (pre, q, out))
                self.assertEqual(out.get("email"), "e@x.io",
                                 (pre, q, out))
        # Control: a VALID key with an unmatched quote is the
        # L3 span family, not this gate — covered below; a
        # closed keyless line stays inert on both trees.
        out = self._parse(tmp, "l2ctl",
                          '="closed"\n' + self.EM + self.PW
                          + '"Pw22x"\n')
        self.assertEqual(out.get("password"), "Pw22x", out)

    # -- L21-L3+L21-L4: splitter spans past a mid-line close ----
    def test_w22_l3_absent_arms_all_quotes(self):
        tmp = self._fixture()
        for i, q in enumerate(('"', "'", "`")):
            text = ("OTHER=" + q + "oops\n" + self.EM + self.PW
                    + q + "Pw22x" + q + "\n")
            out = self._parse(tmp, f"l3abs{i}", text)
            # Pre-fix: the credential record is glued into the
            # armer and reads absent.
            self.assertEqual(out.get("password"), "Pw22x",
                             (q, out))
            self.assertEqual(out.get("email"), "e@x.io", (q, out))

    def test_w22_l3_deletion_arms_all_quotes(self):
        tmp = self._fixture()
        for i, q in enumerate(('"', "'", "`")):
            text = (self.EM + self.PW + q + "a\n"
                    + "OTHER=" + q + "z" + q + "\n")
            out = self._parse(tmp, f"l3del{i}", text)
            # dotenv's fallback parse: the password is the
            # unquoted remainder of its own line. Pre-fix: the
            # fabricated 'a\nOTHER=<q>z' was POSTed instead.
            self.assertEqual(out.get("password"), q + "a",
                             (q, out))
            self.assertEqual(out.get("email"), "e@x.io", (q, out))
        # Closer lands on the quoted EMAIL line: both records
        # survive as their own lines.
        text = (self.PW + '"a\n'
                'ENGINE_ADMIN_EMAIL="e@x.io"\n')
        out = self._parse(tmp, "l3delemail", text)
        self.assertEqual(out.get("password"), '"a', out)
        self.assertEqual(out.get("email"), "e@x.io", out)

    def test_w22_l3_resume_precision_and_controls(self):
        tmp = self._fixture()
        # The verifier's precision: the credential line
        # swallowed INSIDE the span must be recovered (a fix
        # resuming AFTER the whole glued span would still
        # skip it) — here the span is three lines deep and the
        # closing line is the credential line itself, which
        # opens a legitimate multiline: resuming quote-aware
        # scanning AT the closing line parses it as one.
        # Pre-fix: the glued record absorbs the credential
        # line and the password reads absent.
        text = ('OTHER="oops\n'
                'MID=plain\n'
                + self.PW + '"a\nb"\n' + self.EM)
        out = self._parse(tmp, "l3precision", text)
        self.assertEqual(out.get("password"), "a\nb", out)
        self.assertEqual(out.get("email"), "e@x.io", out)
        # Properly-closed multiline controls: untouched.
        text = ('OTHER="a\nb" # note\n' + self.EM + self.PW
                + '"Pw22x"\n')
        out = self._parse(tmp, "l3ctl1", text)
        self.assertEqual(out.get("password"), "Pw22x", out)
        text = (self.EM + self.PW + '"a\nb"\nOTHER="z"\n')
        out = self._parse(tmp, "l3ctl2", text)
        self.assertEqual(out.get("password"), "a\nb", out)
        # Unterminated-at-EOF control: the naive fallback
        # already agreed with dotenv and still does.
        text = self.EM + self.PW + '"abc\nOTHER=1\n'
        out = self._parse(tmp, "l3ctl3", text)
        self.assertEqual(out.get("password"), '"abc', out)

    # -- L21-L5: quoted value on the line after `=` -------------
    def test_w22_l5_adoption_shapes(self):
        tmp = self._fixture()
        n = 0
        for eol in ("\n", "\r"):
            for q in ('"', "'", "`"):
                n += 1
                text = (self.EM.rstrip("\n") + eol + self.PW + eol
                        + q + "Pw22x" + q + eol)
                out = self._parse(tmp, f"l5_{n}", text)
                # Pre-fix: password absent on every shape.
                self.assertEqual(out.get("password"), "Pw22x",
                                 (repr(eol), q, out))
                self.assertEqual(out.get("email"), "e@x.io",
                                 (repr(eol), q, out))
        # Controls: same-line spaced value unchanged; an empty
        # value followed by a NON-quoted record stays absent;
        # a quoted record with junk after its close is not
        # "solely a quoted string" and is not adopted.
        out = self._parse(tmp, "l5ctl1",
                          self.EM + self.PW + ' "Pw22x"\n')
        self.assertEqual(out.get("password"), "Pw22x", out)
        out = self._parse(tmp, "l5ctl2",
                          self.EM + self.PW + "\nOTHER=1\n")
        self.assertFalse(out.get("password"), out)
        out = self._parse(tmp, "l5ctl3",
                          self.EM + self.PW + '\n"Pw22x" junk\n')
        self.assertFalse(out.get("password"), out)


if __name__ == "__main__":
    unittest.main()
