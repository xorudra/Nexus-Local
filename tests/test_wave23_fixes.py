#!/usr/bin/env python3
"""Regression tests for the wave-23 fixes (security audit run-22:
5 confirmed findings, all LOW).

Fix 1 (AUTH22-1, merged with D22-DATA-2; app/server.py):
  _restore_access never consulted the sidecar tri-state, so a
  wipe+restore decided while the sidecar was present but
  unreadable merged the stale backup UNCAPPED and resurrected
  a revoked label into the live store and users.enc. Fix:
  fail closed inside _restore_access (after the USERS_PATH
  existence decision) — when the sidecar read is ("unknown",
  None) (IO fault) or ("corrupt", None) (parse fault; at
  wave 22 both classified "unknown", and the garbage arm is
  the same defect), fire the loud
  access_backup_diverged_unpersisted audit and skip the merge.

Fix 2 (D22-DATA-1, a wave-22 REGRESSION; app/server.py):
  the tri-state lumped byte-acquisition failure (IO fault)
  with decode/parse failure of in-hand bytes (parse fault).
  _persist_diverged blocked on both, so a corrupt-but-
  replaceable sidecar could never heal and the healthy
  channels were abandoned with a stale raise. Fix (the
  verifier's validated split): stage the read (read_bytes,
  then decode+parse); OSError-family read failure keeps
  ("unknown", None) and wave 22's block exactly; ValueError-
  family parse failure returns ("corrupt", None), which
  persist treats as absent for stamping (one loud note, the
  atomic sidecar write then heals the file), clear treats as
  absent for clearing (falls through to its tombstone
  persist), and the boot fold treats as absent (folds the
  other channels' record, one loud note).

Fix 3 (D22-DATA-3 + the persist rider; app/server.py):
  _clear_backup_diverged's merged read and unknown check
  were two independent sidecar reads — a transient fault
  clearing between them early-returned a silent True while
  a readable raise still ruled. Fix (the verifier's
  preferred single-snapshot form): the merged read surfaces
  the sidecar state from its OWN single read
  (_backup_diverged_record_and_state /
  _backup_diverged_and_state) and the clear consumes that
  pair. Rider (same fix): _persist_diverged's entry read is
  reused for its logical-clock max computation instead of
  being discarded and re-read (a blind max-read plus a
  failed sidecar write in the same call used to mint a
  below-future stamp and return a silent True). The boot
  fold's two reads were verified SAFE — untouched beyond
  Fix 2's corrupt note.

Fix 4 (L22-L1; bin/nexuslocal.js): sentinel exhaustion
  failed closed as absent, but that absent shape was
  indistinguishable from a genuinely unrecorded file at the
  parse -> claimStep interface, and claimStep's absent
  branch WRITES: it claimed with the default email and
  appended a duplicate credential pair the still-exhausted
  file could never verify. Fix (verifier-validated):
  parseEngineAdminCreds flags the exhaustion outcome
  (exhausted: true — ONLY on the exhaustion return, never
  on readEngineAdminCreds' unreadable-file catch), and
  claimStep, on that flag, fails closed via the existing
  retry() mechanism with the distinct why string
  "env credentials unreadable (sentinel exhaustion)".
  verifyClaim is unchanged; genuinely unrecorded files and
  other false-absent shapes (colon separators) carry no
  flag and claim exactly as before.

Fix 5 (L22-L2, the surviving legs of L21-L5;
  bin/nexuslocal.js): the wave-22 next-line adoption was
  narrower than dotenv in three legs. Fix (verifier's three
  precisions): (a) whitespace-only records between `=` and
  the quoted line are skipped; (b) the remainder test
  (/^\\s*(#.*)?$/) is applied at the close wherever it
  lands, so a next-line value with a trailing comment
  adopts; (c) further records are consumed only when the
  opening record has no unescaped close (multiline
  next-line values adopt, joined with \\n), and no close
  anywhere means no adoption. No-steal controls preserved:
  no adoption across a comment record or an OTHER record,
  junk after the close stays unadopted, and adopted values
  keep feeding passwordAlt.

Note on tests/test_wave22_fixes.py: its two unknown-arm
tests used garbage bytes as the unknown exemplar; wave 23
reclassifies garbage as the parse-fault class, so those two
tests now use a true IO fault (a directory at the sidecar
path) — their wave-22 expectations (loud False, no stamp)
are the IO-fault contract, preserved exactly.

Run:  python3 -m unittest tests.test_wave23_fixes -v
   or python3 -m unittest discover -s tests
"""

import json
import os
import re
import shutil
import signal
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
RKEY = "restore-wave23-key"
ENGINE_CLAIM_JS = _w18.ENGINE_CLAIM_JS

NODE_HARNESS23_JS = r"""
const fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
const a=src.indexOf('function parseEngineAdminCreds');
const b=src.indexOf('// Wave 13 (run-12 launcher): the shutdown path');
eval(src.slice(a,b));
if(process.argv[3]==='parse'){
  console.log(JSON.stringify(
    parseEngineAdminCreds(fs.readFileSync(process.argv[4],'utf8'))));
} else if(process.argv[3]==='read'){
  console.log(JSON.stringify(readEngineAdminCreds(process.argv[4])));
} else if(process.argv[3]==='remove'){
  removeEngineAdminCreds(process.argv[4]);
}
"""


# =====================================================================
# Fixes 1-3 — the divergence sidecar (server.py)
# =====================================================================
class Wave23DataTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w23-data-"))
        self._saved = (server.ACCESS_PATH, server.USERS_PATH,
                       server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
                       server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
                       server.AUDIT_PATH,
                       server.decrypt_keys, server.encrypt_keys)
        self._saved_reader = server._read_diverged_sidecar
        self._saved_writer = server._write_diverged_sidecar
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
        server._read_diverged_sidecar = self._saved_reader
        server._write_diverged_sidecar = self._saved_writer
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
        self._sidecar_path().write_bytes(b"\xff\xfe not json {{{")

    def _iofault_sidecar(self):
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

    def _restore_setup(self):
        """Stale backup [alpha, solo]; the ONLY durable flag
        copy is the sidecar raise [alpha] (solo was revoked);
        live stores wiped (the redeploy shape)."""
        backup = {"alpha": "h-a", "solo": "h-s"}
        self._seed(backup)
        self._write_sidecar({"ts": int(time.time()),
                             "intended_labels": ["alpha"]})
        server._SETTINGS["access_backup_diverged"] = None
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        self.assertIsNone(self._persisted_settings_flag())
        self._wipe()
        return backup

    # -- Fix 1: restore skips + logs on unknown ----------------------
    def test_w23_restore_skips_and_logs_on_unknown(self):
        backup = self._restore_setup()
        server._read_diverged_sidecar = lambda: ("unknown", None)
        try:
            server._restore_access(MASTER)
        finally:
            server._read_diverged_sidecar = self._saved_reader
        # Pre-fix: the merge ran uncapped — solo was
        # resurrected into the live store AND users.enc.
        self.assertEqual(self._live(), {})
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha", "solo"])
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        self.assertIn("restore was skipped", self._audit_text())
        self.assertEqual(backup, {"alpha": "h-a", "solo": "h-s"})

    # -- Fix 1, garbage arm (D22-DATA-2): a parse-fault sidecar
    #    is the same blind channel for the restore --------------
    def test_w23_restore_skips_and_logs_on_corrupt_garbage(self):
        self._restore_setup()
        self._garbage_sidecar()
        self.assertEqual(server._read_diverged_sidecar(),
                         ("corrupt", None))
        server._restore_access(MASTER)
        self.assertEqual(self._live(), {})
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha", "solo"])
        self.assertIn("restore was skipped", self._audit_text())

    # -- Fix 1 controls: readable flag caps; absent sidecar
    #    restores ordinarily ------------------------------------
    def test_w23_restore_readable_flag_capped_control(self):
        self._restore_setup()
        server._restore_access(MASTER)
        self.assertEqual(self._live(), {"alpha": "h-a"})
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha"])

    def test_w23_restore_absent_sidecar_control(self):
        backup = self._restore_setup()
        self._sidecar_path().unlink()
        server._restore_access(MASTER)
        self.assertEqual(self._live(), backup)
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha", "solo"])

    # -- Fix 2: parse-fault persist stamps over + heals ------------
    def test_w23_persist_parsefault_stamps_over_and_heals(self):
        self._seed({"alpha": "h-a"})
        old = {"ts": int(time.time()) - 100,
               "intended_labels": ["alpha"]}
        server._SETTINGS["access_backup_diverged"] = old
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        self._garbage_sidecar()
        self.assertEqual(server._read_diverged_sidecar(),
                         ("corrupt", None))
        ret = server._persist_diverged(
            {"ts": int(time.time()),
             "intended_labels": ["alpha", "charlie"]})
        # Pre-fix (wave 22): the parse fault lumped into
        # "unknown" — ret False, nothing stamped, the garbage
        # sidecar byte-identical forever.
        self.assertIs(ret, True)
        self.assertIn("corrupt", self._audit_text())
        sc = json.loads(self._sidecar_path().read_text())
        self.assertEqual(sc["intended_labels"],
                         ["alpha", "charlie"])
        self.assertEqual(
            self._persisted_settings_flag()["intended_labels"],
            ["alpha", "charlie"])
        self.assertEqual(
            server._BACKUP_DIVERGED_MEM[0]["intended_labels"],
            ["alpha", "charlie"])

    # -- Fix 2: the full DATA-1 composition — charlie survives -----
    def test_w23_data1_full_composition_charlie_survives(self):
        self._seed({"alpha": "h-a"})
        old = {"ts": int(time.time()) - 100,
               "intended_labels": ["alpha"]}
        server._SETTINGS["access_backup_diverged"] = old
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        self._garbage_sidecar()
        # The heal save: users.enc lands [alpha, charlie]
        # while the sidecar is corrupt.
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a", "charlie": "h-c"},
                                MASTER)
        self.assertEqual(sorted(decrypt_keys(server.USERS_PATH,
                                             MASTER)),
                         ["alpha", "charlie"])
        # Pre-fix: the stale raise still ruled the merged read
        # here (every persist/clear blocked on the lumped
        # "unknown"), and a later wipe+restore deleted
        # charlie everywhere.
        self.assertIsNone(server._backup_diverged())
        sc = json.loads(self._sidecar_path().read_text())
        self.assertIsNone(sc["intended_labels"])  # tombstone
        self.assertIsNone(self._restart())
        self._wipe()
        server._restore_access(MASTER)
        self.assertIn("charlie", self._live())
        self.assertIn("charlie",
                      decrypt_keys(server.USERS_PATH, MASTER))

    # -- Fix 2 control: the IO-fault arm is EXACTLY wave 22's ------
    def test_w23_persist_iofault_arm_unchanged(self):
        self._seed({"alpha": "h-a"})
        old = {"ts": int(time.time()) - 100,
               "intended_labels": ["alpha"]}
        server._SETTINGS["access_backup_diverged"] = old
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        self._iofault_sidecar()
        self.assertEqual(server._read_diverged_sidecar(),
                         ("unknown", None))
        ret = server._persist_diverged(
            {"ts": int(time.time()), "intended_labels": None})
        self.assertIs(ret, False)
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        self.assertEqual(
            server._SETTINGS["access_backup_diverged"], old)
        self.assertTrue(self._sidecar_path().is_dir())

    # -- Fix 2, clear arm: corrupt is absent for clearing ----------
    def test_w23_clear_corrupt_falls_through_and_heals(self):
        self._seed({"alpha": "h-a"})
        self._garbage_sidecar()
        ret = server._clear_backup_diverged()
        # Pre-fix: merged None + lumped "unknown" -> loud
        # False, the garbage left in place. Post-fix: the
        # clear falls through to its tombstone persist, which
        # stamps over the corrupt file and is verified.
        self.assertIs(ret, True)
        self.assertIn("corrupt", self._audit_text())
        sc = json.loads(self._sidecar_path().read_text())
        self.assertIsNone(sc["intended_labels"])

    # -- Fix 2, boot arm: corrupt folds as absent, loudly ----------
    def test_w23_boot_corrupt_folds_and_logs(self):
        self._seed({"alpha": "h-a"})
        rec = {"ts": int(time.time()), "intended_labels": ["alpha"]}
        server._SETTINGS["access_backup_diverged"] = rec
        server._BACKUP_DIVERGED_MEM[0] = None
        self._garbage_sidecar()
        server._load_diverged_sidecar_boot()
        # Pre-fix: garbage classified "unknown" — the fold was
        # skipped entirely, MEM stayed None.
        self.assertEqual(server._BACKUP_DIVERGED_MEM[0], rec)
        self.assertIn("corrupt", self._audit_text())

    # -- Fix 3: clear judges ONE snapshot ---------------------------
    def test_w23_clear_single_snapshot_disagreeing_reads(self):
        self._seed({"alpha": "h-a", "charlie": "h-c"})
        self._write_sidecar({"ts": int(time.time()),
                             "intended_labels": ["alpha"]})
        server._SETTINGS["access_backup_diverged"] = None
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        real_reader = server._read_diverged_sidecar
        calls = {"n": 0}

        def plan():
            calls["n"] += 1
            if calls["n"] == 1:
                return ("unknown", None)
            return real_reader()

        server._read_diverged_sidecar = plan
        try:
            ret = server._clear_backup_diverged()
        finally:
            server._read_diverged_sidecar = real_reader
        # Pre-fix: read 1 (merged) blind, read 2 (the unknown
        # check) healthy -> early-returned a SILENT True while
        # the readable raise still ruled (2 reads consumed).
        self.assertIs(ret, False)
        self.assertEqual(calls["n"], 1)
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        # The readable raise is untouched and still rules.
        self.assertEqual(server._backup_diverged()
                         ["intended_labels"], ["alpha"])

    # -- Fix 3 rider: persist reuses its entry read for the max ----
    def test_w23_persist_rider_compound_fault(self):
        self._seed({"alpha": "h-a"})
        fut = int(time.time()) + 3600
        self._write_sidecar({"ts": fut,
                             "intended_labels": ["alpha"]})
        server._SETTINGS["access_backup_diverged"] = None
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        real_reader = server._read_diverged_sidecar
        calls = {"n": 0}

        def plan():
            calls["n"] += 1
            if calls["n"] == 1:
                return real_reader()
            return ("unknown", None)

        server._read_diverged_sidecar = plan
        server._write_diverged_sidecar = lambda rec: False
        try:
            ret = server._persist_diverged(
                {"ts": int(time.time()),
                 "intended_labels": ["alpha", "charlie"]})
        finally:
            server._read_diverged_sidecar = self._saved_reader
            server._write_diverged_sidecar = self._saved_writer
        # The settings channel landed, so True is the writer's
        # contract — but pre-fix the stamp was minted from the
        # BLIND second read (raw now, an hour below the future
        # raise) and the stale raise ruled after recovery: a
        # silent True. Post-fix the entry read's future ts is
        # the max, so the stamp is fut+1 on the landed channel.
        self.assertIs(ret, True)
        rec = self._persisted_settings_flag()
        self.assertEqual(rec["ts"], fut + 1)
        self.assertEqual(rec["intended_labels"],
                         ["alpha", "charlie"])
        self.assertEqual(server._backup_diverged()
                         ["intended_labels"], ["alpha", "charlie"])


# =====================================================================
# Fixes 4+5 — the launcher (bin/nexuslocal.js)
# =====================================================================
class Wave23LauncherTests(unittest.TestCase):

    def setUp(self):
        self.node = shutil.which("node")
        if not self.node or not shutil.which("unshare"):
            self.skipTest("node/unshare not available")
        self._procs = []
        self._tmps = []

    def tearDown(self):
        for proc in self._procs:
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=10)
                except Exception:
                    pass
        for tmp in self._tmps:
            for name in ("engine.pid", "dash.pid", "squatter.pid"):
                f = tmp / name
                if f.exists():
                    try:
                        os.kill(int(f.read_text().strip()),
                                signal.SIGKILL)
                    except Exception:
                        pass
            shutil.rmtree(tmp, ignore_errors=True)

    # -- fixture (wave-21 shape) ------------------------------------
    def _fixture(self, env_bytes, engine_js):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w23-launcher-"))
        self._tmps.append(tmp)
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        (tmp / "harness.js").write_text(NODE_HARNESS23_JS)
        app = tmp / "app"
        srv = app / "engine" / "server"
        (srv / "dist").mkdir(parents=True)
        (app / "engine-data").mkdir()
        (app / "server.py").write_text(
            "import os, time\n"
            "with open(os.environ['DASH_PID'], 'w') as f:\n"
            "    f.write(str(os.getpid()))\n"
            "time.sleep(120)\n")
        (app / ".env").write_bytes(env_bytes)
        (srv / "package.json").write_text(json.dumps(
            {"name": "stub",
             "dependencies": {"dotenv": "^17.0.0", "express": "^5.0.0"}}))
        (srv / "package-lock.json").write_text("{}")
        nm = srv / "node_modules"
        nm.mkdir()
        for dep in ("dotenv", "express"):
            (nm / dep).mkdir()
            (nm / dep / "package.json").write_text("{}")
            (nm / dep / "index.js").write_text("")
        (nm / ".package-lock.json").write_text("{}")
        (srv / "dist" / "index.js").write_text(engine_js)
        return tmp

    def _boot(self, tmp):
        env = dict(os.environ)
        env.update({
            "ENGINE_PID": str(tmp / "engine.pid"),
            "DASH_PID": str(tmp / "dash.pid"),
            "SETUP_FILE": str(tmp / "setup.jsonl"),
            "LOGIN_FILE": str(tmp / "logins.jsonl"),
            "DIED_FILE": str(tmp / "died.marker"),
            "SQUAT_FILE": str(tmp / "squat.jsonl"),
            "SQUAT_PID": str(tmp / "squatter.pid"),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        bash = (
            "ip link set lo up 2>/dev/null; "
            "curl -s -m 2 http://127.0.0.1:3001/api/auth/status "
            ">/dev/null 2>&1; "
            f"echo PRECHECK_OK curl_exit=$? >> {tmp / 'precheck.log'}; "
            f"exec {self.node} {tmp / 'bin' / 'nexuslocal.js'}")
        proc = subprocess.Popen(
            ["unshare", "-rn", "bash", "-c", bash],
            cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._procs.append(proc)
        return proc

    def _wait(self, proc, pred, timeout=30, tmp=None, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        log = ""
        if tmp is not None and (tmp / "startup.log").exists():
            log = (tmp / "startup.log").read_text(errors="replace")
        self.fail(f"launcher {what} not reached; log tail:\n"
                  + log[-1200:])

    def _precheck_ok(self, tmp):
        f = tmp / "precheck.log"
        deadline = time.time() + 15
        while time.time() < deadline and not f.exists():
            time.sleep(0.2)
        self.assertTrue(f.exists(), "no pre-check was logged")
        self.assertIn("PRECHECK_OK curl_exit=7", f.read_text())

    def _harness(self, tmp, *args):
        r = subprocess.run([self.node, str(tmp / "harness.js"),
                            str(tmp / "bin" / "nexuslocal.js"), *args],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def _parse(self, tmp, label, text):
        f = tmp / (label + ".env")
        f.write_bytes(text.encode("utf-8"))
        return json.loads(self._harness(tmp, "parse", str(f)))

    def _log(self, tmp):
        f = tmp / "startup.log"
        return f.read_text(errors="replace") if f.exists() else ""

    EM = "ENGINE_ADMIN_EMAIL=e@x.io\n"
    PW = "ENGINE_ADMIN_PASSWORD="

    # -- Fix 4: the exhaustion flag ---------------------------------
    def test_w23_l1_exhaustion_flag_parse_and_catch(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        all28 = "".join(chr(c) for c in
                        list(range(0x01, 0x08)) + [0x08, 0x0B, 0x0C]
                        + list(range(0x0E, 0x1B)) + [0x1B]
                        + list(range(0x1C, 0x20)))
        self.assertEqual(len(all28), 28)
        text = ("# pad " + all28 + " end\n" + self.EM + self.PW
                + '"a\x01b"\n')
        out = self._parse(tmp, "l1exhausted", text)
        # Pre-fix: the exhaustion return was the plain absent
        # shape — indistinguishable from unrecorded.
        self.assertEqual(out, {"hasEmail": False,
                               "hasPassword": False,
                               "exhausted": True}, out)
        # Control: a parse that finds a sentinel carries no flag.
        out = self._parse(tmp, "l1control",
                          self.EM + self.PW + '"a\x01b"\n')
        self.assertEqual(out.get("password"), "a\x01b", out)
        self.assertNotIn("exhausted", out)
        # Precision: the unreadable-file CATCH in
        # readEngineAdminCreds must NOT set the flag.
        out = json.loads(self._harness(
            tmp, "read", str(tmp / "no-such-file.env")))
        self.assertEqual(out, {"hasEmail": False,
                               "hasPassword": False}, out)

    # -- Fix 4: claimStep fails closed on the flag (real boots) -----
    def test_w23_l1_claimstep_exhaustion_and_controls(self):
        all28 = "".join(chr(c) for c in
                        list(range(0x01, 0x08)) + [0x08, 0x0B, 0x0C]
                        + list(range(0x0E, 0x1B)) + [0x1B]
                        + list(range(0x1C, 0x20)))
        # (1) Exhausted file + UNclaimed engine: no claim, no
        # append, no setup POST — a retry with the distinct why.
        env = ("# pad " + all28 + " end\n"
               "ENGINE_ADMIN_EMAIL=stale@x.io\n"
               'ENGINE_ADMIN_PASSWORD="StalePw23"\n').encode("utf-8")
        tmp = self._fixture(env, ENGINE_CLAIM_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        # Pre-fix: claimStep claimed fresh instead — a setup
        # POST with the default email, and the file grew a
        # duplicate pair (2 -> 4 credential lines).
        self._wait(proc,
                   lambda: "Engine claim pending (env credentials "
                           "unreadable (sentinel exhaustion))"
                           in self._log(tmp),
                   timeout=25, tmp=tmp,
                   what="exhaustion retry log")
        time.sleep(1)
        self.assertFalse((tmp / "setup.jsonl").exists())
        self.assertEqual((tmp / "app" / ".env").read_bytes(), env)
        self.assertNotIn("Engine admin claimed", self._log(tmp))

        # (2) Control: a genuinely unrecorded file first-claims
        # exactly as before (default email, pair appended).
        tmp = self._fixture(b"OTHER=1\n", ENGINE_CLAIM_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc, lambda: (tmp / "setup.jsonl").exists(),
                   tmp=tmp, what="unrecorded first claim")
        setup = json.loads((tmp / "setup.jsonl").read_text()
                           .splitlines()[0])
        self.assertEqual(setup["email"], "owner@example.com")
        self.assertTrue(
            re.fullmatch(r"[0-9a-f]{48}", setup["password"]),
            setup)
        env_after = (tmp / "app" / ".env").read_text()
        self.assertEqual(env_after.count("ENGINE_ADMIN_EMAIL="), 1)
        self.assertEqual(env_after.count("ENGINE_ADMIN_PASSWORD="), 1)

        # (3) Control: colon-separator creds carry no flag —
        # the self-healing first claim (append) is NOT blocked.
        env = (b"ENGINE_ADMIN_EMAIL: e@x.io\n"
               b"ENGINE_ADMIN_PASSWORD: ColonPw23\n")
        tmp = self._fixture(env, ENGINE_CLAIM_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc, lambda: (tmp / "setup.jsonl").exists(),
                   tmp=tmp, what="colon-separator first claim")
        setup = json.loads((tmp / "setup.jsonl").read_text()
                           .splitlines()[0])
        self.assertEqual(setup["email"], "owner@example.com")
        env_after = (tmp / "app" / ".env").read_bytes()
        self.assertEqual(env_after.count(b"ENGINE_ADMIN"), 4)

    # -- Fix 5: adoption widening legs -------------------------------
    def test_w23_l2_adoption_widening_shapes(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        n = 0
        for q in ('"', "'", "`"):
            n += 1
            # Multiline next-line value.
            out = self._parse(tmp, f"l2ml{n}",
                              self.EM + self.PW + "\n" + q
                              + "line1\nline2" + q + "\n")
            self.assertEqual(out.get("password"), "line1\nline2",
                             (q, out))
            # Trailing comment after the next-line value.
            out = self._parse(tmp, f"l2tc{n}",
                              self.EM + self.PW + "\n" + q
                              + "Pw22x" + q + " # note\n")
            self.assertEqual(out.get("password"), "Pw22x", (q, out))
            # Intervening blank lines (and a whitespace-only
            # record among them).
            out = self._parse(tmp, f"l2bl{n}",
                              self.EM + self.PW + "\n\n  \n" + q
                              + "Pw22x" + q + "\n")
            self.assertEqual(out.get("password"), "Pw22x", (q, out))
            # Multiline + trailing comment on the closing line.
            out = self._parse(tmp, f"l2mc{n}",
                              self.EM + self.PW + "\n" + q
                              + "line1\nline2" + q + " # note\n")
            self.assertEqual(out.get("password"), "line1\nline2",
                             (q, out))
        # Tab-comment form.
        out = self._parse(tmp, "l2tab",
                          self.EM + self.PW + '\n"Pw22x"\t# note\n')
        self.assertEqual(out.get("password"), "Pw22x", out)
        # Blank CR-only line between `=` and the value.
        out = self._parse(tmp, "l2crblank",
                          self.EM + self.PW + '\n\r\n"Pw22x"\n')
        self.assertEqual(out.get("password"), "Pw22x", out)
        # CRLF inside a multiline next-line value normalises.
        out = self._parse(tmp, "l2crlf",
                          self.EM + self.PW + '\n"line1\r\nline2"\n')
        self.assertEqual(out.get("password"), "line1\nline2", out)
        # Email form: multiline next-line value.
        out = self._parse(
            tmp, "l2email",
            'ENGINE_ADMIN_EMAIL=\n"e\n@x.io"\n' + self.PW + "Pw22x\n")
        self.assertEqual(out.get("email"), "e\n@x.io", out)
        self.assertEqual(out.get("password"), "Pw22x", out)
        # Spaced-= form of the multiline leg.
        out = self._parse(tmp, "l2spaced",
                          self.EM + 'ENGINE_ADMIN_PASSWORD =\n'
                          '"a\nb"\n')
        self.assertEqual(out.get("password"), "a\nb", out)
        # Adopted values keep feeding passwordAlt (a literal
        # backslash-n in an adopted double-quoted value).
        out = self._parse(tmp, "l2alt",
                          self.EM + self.PW + '\n"a\\nb"\n')
        self.assertEqual(out.get("password"), "a\nb", out)
        self.assertEqual(out.get("passwordAlt"), "a\\nb", out)

    # -- Fix 5 controls: no stealing, junk stays unadopted -----------
    def test_w23_l2_adoption_no_steal_controls(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        cases = [
            # No adoption across a comment record.
            self.PW + "\n# note\n\"Pw22x\"\n" + self.EM,
            # No adoption across an OTHER record (both forms).
            self.PW + "\nOTHER=1\n\"Pw22x\"\n" + self.EM,
            self.PW + "\nOTHER=\n\"Pw22x\"\n" + self.EM,
            # Junk after the close: single-line and multiline.
            self.PW + "\n\"Pw22x\" junk\n" + self.EM,
            self.PW + "\n\"line1\nline2\" junk\n" + self.EM,
            # No close anywhere: no adoption.
            self.PW + "\n\"abc\nOTHER=1\n" + self.EM,
        ]
        for i, text in enumerate(cases):
            out = self._parse(tmp, f"l2ctl{i}", text)
            self.assertFalse(out.get("password"), (i, out))
            self.assertEqual(out.get("email"), "e@x.io", (i, out))
        # Another assignment's wrapped value is not stolen:
        # the password keeps its OWN line's value.
        out = self._parse(tmp, "l2ctlown",
                          self.PW + '"own"\nOTHER=\n"wrapped"\n'
                          + self.EM)
        self.assertEqual(out.get("password"), "own", out)


if __name__ == "__main__":
    unittest.main()
