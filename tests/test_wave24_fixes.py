#!/usr/bin/env python3
"""Regression tests for the wave-24 fixes (security audit run-23:
3 confirmed residual findings, all LOW).

Fix 1 (AUTH23-1, merged AUTH23-1 + D23-DATA-1 + CAPS23-X1(b);
  app/server.py): wave 23's restore entry guard and _merge19's
  cap were two independent sidecar reads — a fault ONSET after
  the guard read and at/before the cap read (the window is one
  full PBKDF2 decrypt wide) made the merge run blind/uncapped
  and resurrect a revoked label, silently in the transient
  schedule (the post-merge clear even tombstoned the flag
  that would have proven it). Fix (the verifier's PICK, the
  merge-local re-judge — NOT the threaded snapshot, whose
  freshness test loses a legitimately-grown flag): at the top
  of _merge19, judge the sidecar state from
  _backup_diverged_and_state() — the SAME snapshot supplies
  both the state judgement and the cap's record — and on
  ("unknown", None) / ("corrupt", None) abort loudly via
  _audit_diverged_unpersisted and return the current live
  dict, without merging, without the trailing clear, and
  without touching the flag, the live store or users.enc.
  The _restore_access entry guard stays as-is.

Fix 2 (L23-L1 legs (a)+(b); bin/nexuslocal.js): the wave-23
  exhaustion flag fired on files with NO credential records
  at all (pad-only) or only commented-out ones, so claimStep
  never claimed a provably unrecorded file. Fix (the
  verifier's validated census gate): the flag is set ONLY
  when the file ALSO contains at least one credential
  record-start line matching the parser's own record-start
  grammar /^\\s*(?:export\\s+)?ENGINE_ADMIN_(?:EMAIL|PASSWORD)\\s*=/
  (the `=` is required — colon-separator lines do not count,
  preserving the colon+pad self-heal; \\s is the full class,
  so NBSP/VT/FF-led records count). Record-bearing exhausted
  files — including EMPTY credential lines (the verifier
  rejected the D2 leg: absence is unprovable there) — keep
  the flag and fail closed exactly as at 91736e2.

Fix 3 (L23-L2, L21-L5 residual leg; bin/nexuslocal.js): an
  adopted next-line value whose ONLY closing quote is
  backslash-escaped read absent. Fix (the verifier's
  REPLACEMENT prescription — the hunter's sketch misses the
  even-close-with-junk shape P11): when the existing
  even-close search yields no adoption, collect the span's
  odd-backslash quote candidates in order, STOPPING at the
  first even-backslash quote, and re-test them
  LAST-to-FIRST with the existing remainder test; the first
  candidate that passes adopts. Even-backslash closes and
  no-close-at-all behaviour are byte-unchanged.

Fix 4 (L23-L3; bin/nexuslocal.js): an on-line multiline
  credential whose closing line's only quote is
  backslash-escaped never closed in the splitter, so the
  EOF fallback fabricated the truncated first line as the
  value (verifyClaim POSTed it and the definitive 401
  deleted every credential line). Fix (the verifier's
  splitter fix, EOF-branch ONLY): at EOF, re-test the span's
  odd-backslash candidates LAST-to-FIRST with the
  closing-line remainder test; on a pass, emit the span as
  ONE record and resume splitting after the closing line.
  The even-backslash remainder machinery is untouched.
  Fixes 3 and 4 are two implementations at two sites — the
  verifier ruled they must not be unified.

Run:  python3 -m unittest tests.test_wave24_fixes -v
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
RKEY = "restore-wave24-key"
ENGINE_CLAIM_JS = _w18.ENGINE_CLAIM_JS

NODE_HARNESS24_JS = r"""
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

BS = "\\"
ALL28 = "".join(chr(c) for c in
                list(range(0x01, 0x08)) + [0x08, 0x0B, 0x0C]
                + list(range(0x0E, 0x1B)) + [0x1B]
                + list(range(0x1C, 0x20)))
PAD = "# pad " + ALL28 + " end\n"


# =====================================================================
# Fix 1 — the restore merge re-judge (server.py)
# =====================================================================
class Wave24ServerTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w24-data-"))
        self._saved = (server.ACCESS_PATH, server.USERS_PATH,
                       server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
                       server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
                       server.AUDIT_PATH)
        self._saved_reader = server._read_diverged_sidecar
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
         server.AUDIT_PATH) = self._saved
        server._read_diverged_sidecar = self._saved_reader
        server._SETTINGS.clear()
        server._SETTINGS.update(self._settings_saved)
        server._BACKUP_DIVERGED_MEM[0] = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------
    def _sidecar_path(self):
        return self.tmp / "access_diverged.json"

    def _seed(self, d):
        server.ACCESS_PATH.write_text(json.dumps(d))
        encrypt_keys(d, MASTER, server.USERS_PATH)
        self.assertTrue(server._save_settings())

    def _audit_text(self):
        if server.AUDIT_PATH.exists():
            return server.AUDIT_PATH.read_text(errors="replace")
        return ""

    def _live(self):
        return json.loads(server.ACCESS_PATH.read_text())

    def _restore_setup(self, backup=None):
        """Stale backup [alpha, solo]; the ONLY durable flag
        copy is the sidecar raise [alpha] (solo was revoked);
        live stores wiped (the redeploy shape)."""
        backup = {"alpha": "h-a", "solo": "h-s"} if backup is None \
            else backup
        self._seed(backup)
        self.flag = {"ts": int(time.time()) + 7200,
                     "intended_labels": ["alpha"]}
        self._sidecar_path().write_text(json.dumps(self.flag))
        server._SETTINGS["access_backup_diverged"] = None
        server._BACKUP_DIVERGED_MEM[0] = None
        self.assertTrue(server._save_settings())
        server.ACCESS_PATH.write_text("{}")
        try:
            server.ACCESS_ENC_PATH.unlink()
        except FileNotFoundError:
            pass
        return backup

    def _plan(self, plan, default="real"):
        """Plan-driven sidecar reader (the verifier's design):
        call N consults the plan — 'real' delegates to the
        genuine reader, 'unknown'/'corrupt' return the blind
        states, a tuple is returned verbatim."""
        real = self._saved_reader
        state = {"plan": dict(plan), "default": default, "n": 0}

        def reader():
            state["n"] += 1
            mode = state["plan"].get(state["n"], state["default"])
            if isinstance(mode, tuple):
                return mode
            if mode == "unknown":
                return ("unknown", None)
            if mode == "corrupt":
                return ("corrupt", None)
            return real()

        server._read_diverged_sidecar = reader
        return state

    def _assert_merge_aborted(self, state):
        # Pre-fix: the merge ran uncapped at the blind cap
        # read — solo was resurrected into BOTH stores, the
        # abort never fired, and (transient arm) the trailing
        # clear tombstoned the flag, erasing the evidence.
        self.assertEqual(self._live(), {})
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha", "solo"])
        self.assertIn("access_backup_diverged_unpersisted",
                      self._audit_text())
        self.assertIn("merge was aborted", self._audit_text())
        # The flag is preserved (no tombstone) for the
        # deferred restore, and the restore stopped AT the
        # merge snapshot: exactly 3 sidecar reads (needs-gate,
        # entry guard, merge re-judge) — no trailing clear ran.
        self.assertEqual(
            json.loads(self._sidecar_path().read_text()), self.flag)
        self.assertEqual(state["n"], 3)

    # -- onset arms ---------------------------------------------------
    def test_w24_restore_unknown_onset_persistent_aborts(self):
        self._restore_setup()
        state = self._plan({1: "real", 2: "real"}, default="unknown")
        server._restore_access(MASTER)
        self._assert_merge_aborted(state)

    def test_w24_restore_unknown_onset_transient_aborts(self):
        self._restore_setup()
        state = self._plan({1: "real", 2: "real", 3: "unknown"},
                           default="real")
        server._restore_access(MASTER)
        self._assert_merge_aborted(state)

    def test_w24_restore_corrupt_onset_transient_aborts(self):
        self._restore_setup()
        state = self._plan({1: "real", 2: "real", 3: "corrupt"},
                           default="real")
        server._restore_access(MASTER)
        self._assert_merge_aborted(state)

    # -- freshness: a flag that GROWS during decrypt is honoured -----
    def test_w24_restore_flag_grows_during_decrypt(self):
        backup = {"alpha": "h-a", "charlie": "h-c", "solo": "h-s"}
        self._restore_setup(backup=backup)
        fut = int(time.time()) + 7200
        flag1 = {"ts": fut, "intended_labels": ["alpha"]}
        flag2 = {"ts": fut + 10,
                 "intended_labels": ["alpha", "charlie"]}
        self._plan({1: ("rec", dict(flag1)), 2: ("rec", dict(flag1))},
                   default=("rec", dict(flag2)))
        server._restore_access(MASTER)
        # The merge-local re-judge honours the MERGE-TIME flag:
        # charlie is restored, solo (revoked under either
        # flag) stays out. (The threaded-snapshot alternative
        # applies the stale [alpha] cap and loses charlie.)
        self.assertEqual(sorted(self._live()), ["alpha", "charlie"])
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha", "charlie"])
        self.assertNotIn("merge was aborted", self._audit_text())

    # -- controls -----------------------------------------------------
    def test_w24_restore_healthy_capped_merge_control(self):
        self._restore_setup()
        server._restore_access(MASTER)
        self.assertEqual(self._live(), {"alpha": "h-a"})
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha"])
        self.assertNotIn("merge was aborted", self._audit_text())
        sc = json.loads(self._sidecar_path().read_text())
        self.assertIsNone(sc["intended_labels"])  # tombstone

    def test_w24_restore_unflagged_absent_sidecar_control(self):
        backup = self._restore_setup()
        self._sidecar_path().unlink()
        server._restore_access(MASTER)
        self.assertEqual(self._live(), backup)
        self.assertEqual(
            sorted(decrypt_keys(server.USERS_PATH, MASTER)),
            ["alpha", "solo"])
        self.assertNotIn("merge was aborted", self._audit_text())


# =====================================================================
# Fixes 2-4 — the launcher (bin/nexuslocal.js)
# =====================================================================
class Wave24LauncherTests(unittest.TestCase):

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

    # -- fixture (wave-21 shape, as wave 23) -------------------------
    def _fixture(self, env_bytes, engine_js):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w24-launcher-"))
        self._tmps.append(tmp)
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        (tmp / "harness.js").write_text(NODE_HARNESS24_JS)
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

    # -- Fix 2: the census gate (parse level) -------------------------
    def test_w24_l1_census_gate_parse(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        self.assertEqual(len(ALL28), 28)
        # (a) Pad-only: NO credential record lines — the flag
        # must CLEAR (pre-fix: exhausted:true, never claims).
        out = self._parse(tmp, "censuspad", PAD + "OTHER=1\n")
        self.assertEqual(out, {"hasEmail": False,
                               "hasPassword": False}, out)
        # (b) Commented-out creds only: not records in either
        # grammar — the flag must CLEAR.
        out = self._parse(
            tmp, "censuscomment",
            PAD + "# ENGINE_ADMIN_EMAIL=e@x.io\n"
                  "# ENGINE_ADMIN_PASSWORD=SomePw\n")
        self.assertEqual(out, {"hasEmail": False,
                               "hasPassword": False}, out)
        # Colon+pad self-heal control: colon lines carry no
        # `=`, so they must NOT count as records.
        out = self._parse(
            tmp, "censuscolon",
            PAD + "ENGINE_ADMIN_EMAIL: e@x.io\n"
                  "ENGINE_ADMIN_PASSWORD: ColonPw23\n")
        self.assertEqual(out, {"hasEmail": False,
                               "hasPassword": False}, out)
        # Record-bearing exhausted files keep the flag and
        # fail closed exactly as at 91736e2.
        out = self._parse(tmp, "censusreal",
                          PAD + self.EM + self.PW + "RealPw23\n")
        self.assertEqual(out, {"hasEmail": False,
                               "hasPassword": False,
                               "exhausted": True}, out)
        # D2 control: EMPTY credential lines are record lines
        # — absence is unprovable there, flag stays.
        out = self._parse(tmp, "censusd2",
                          PAD + "ENGINE_ADMIN_EMAIL=\n"
                                "ENGINE_ADMIN_PASSWORD=\n")
        self.assertEqual(out.get("exhausted"), True, out)
        # NBSP-led record lines count (full \s class).
        out = self._parse(
            tmp, "censusnbsp",
            PAD + "\u00a0ENGINE_ADMIN_EMAIL=e@x.io\n"
                  "\u00a0ENGINE_ADMIN_PASSWORD=RealPw23\n")
        self.assertEqual(out.get("exhausted"), True, out)
        # Export-led and spaced-key records count too.
        out = self._parse(
            tmp, "censusexport",
            PAD + "export ENGINE_ADMIN_EMAIL=e@x.io\n"
                  "ENGINE_ADMIN_PASSWORD =RealPw23\n")
        self.assertEqual(out.get("exhausted"), True, out)

    # -- Fix 2: claim behaviour over real boots -----------------------
    def test_w24_l1_census_claims_and_failclosed_boots(self):
        # (a) Pad-only file + unclaimed engine: first-claims
        # exactly as at 4993ca9 (setup POST happens).
        tmp = self._fixture((PAD + "OTHER=1\n").encode("utf-8"),
                            ENGINE_CLAIM_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        # Pre-fix: no setup POST ever — the exhaustion retry
        # loop ran for the life of the process.
        self._wait(proc, lambda: (tmp / "setup.jsonl").exists(),
                   tmp=tmp, what="pad-only first claim")
        setup = json.loads((tmp / "setup.jsonl").read_text()
                           .splitlines()[0])
        self.assertEqual(setup["email"], "owner@example.com")
        self.assertTrue(
            re.fullmatch(r"[0-9a-f]{48}", setup["password"]), setup)
        env_after = (tmp / "app" / ".env").read_text()
        self.assertEqual(env_after.count("ENGINE_ADMIN_EMAIL="), 1)
        self.assertEqual(env_after.count("ENGINE_ADMIN_PASSWORD="), 1)

        # (b) Commented-only file: first-claims too; the pair
        # is appended below the comments.
        env = (PAD + "# ENGINE_ADMIN_EMAIL=old@x.io\n"
                     "# ENGINE_ADMIN_PASSWORD=OldPw\n").encode("utf-8")
        tmp = self._fixture(env, ENGINE_CLAIM_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc, lambda: (tmp / "setup.jsonl").exists(),
                   tmp=tmp, what="commented-only first claim")
        setup = json.loads((tmp / "setup.jsonl").read_text()
                           .splitlines()[0])
        self.assertEqual(setup["email"], "owner@example.com")
        env_after = (tmp / "app" / ".env").read_text()
        # 1 commented + 1 appended real line for each key.
        self.assertEqual(env_after.count("ENGINE_ADMIN_EMAIL="), 2)
        self.assertEqual(env_after.count("ENGINE_ADMIN_PASSWORD="), 2)

        # Control: record-bearing exhausted file still fails
        # closed — retry with the distinct why, no setup POST,
        # env byte-identical.
        env = (PAD + "ENGINE_ADMIN_EMAIL=stale@x.io\n"
                     'ENGINE_ADMIN_PASSWORD="StalePw23"\n'
               ).encode("utf-8")
        tmp = self._fixture(env, ENGINE_CLAIM_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc,
                   lambda: "Engine claim pending (env credentials "
                           "unreadable (sentinel exhaustion))"
                           in self._log(tmp),
                   timeout=25, tmp=tmp,
                   what="exhaustion retry log")
        time.sleep(1)
        self.assertFalse((tmp / "setup.jsonl").exists())
        self.assertEqual((tmp / "app" / ".env").read_bytes(), env)

    # -- Fix 3: adoption terminal escaped close ------------------------
    def test_w24_l2_adoption_escaped_close_shapes(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        n = 0
        for q in ('"', "'", "`"):
            n += 1
            # Odd count 1, single-line adopted value.
            out = self._parse(tmp, f"l2o1s{n}",
                              self.EM + self.PW + "\n" + q + "w"
                              + BS + q + "\n")
            self.assertEqual(out.get("password"), "w" + BS, (q, out))
            # Odd count 1, multiline closing line.
            out = self._parse(tmp, f"l2o1m{n}",
                              self.EM + self.PW + "\n" + q + "wxyz\n"
                              + BS + q + "\n")
            self.assertEqual(out.get("password"), "wxyz\n" + BS,
                             (q, out))
            # Odd count 3, multiline closing line.
            out = self._parse(tmp, f"l2o3m{n}",
                              self.EM + self.PW + "\n" + q + "wxyz\n"
                              + BS * 3 + q + "\n")
            self.assertEqual(out.get("password"),
                             "wxyz\n" + BS * 3, (q, out))
        # Email leg (dq): the adopted escaped-close value is
        # the email; the password reads normally.
        out = self._parse(
            tmp, "l2email",
            "ENGINE_ADMIN_EMAIL=\n\"v\n" + BS + "\"\n"
            + self.PW + "VerPw23\n")
        self.assertEqual(out.get("email"), "v\n" + BS, out)
        self.assertEqual(out.get("password"), "VerPw23", out)
        # Escaped close + comment-only remainder adopts.
        out = self._parse(tmp, "l2comment",
                          self.EM + self.PW + "\n\"w" + BS
                          + "\" # note\n")
        self.assertEqual(out.get("password"), "w" + BS, out)

    def test_w24_l2_adoption_escaped_close_controls(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # Even count 2 close: byte-unchanged (adopts as before).
        out = self._parse(tmp, "l2even2",
                          self.EM + self.PW + "\n\"wxyz\n"
                          + BS * 2 + "\"\n")
        self.assertEqual(out.get("password"), "wxyz\n" + BS * 2, out)
        # Even count 4 close: byte-unchanged.
        out = self._parse(tmp, "l2even4",
                          self.EM + self.PW + "\n\"wxyz\n"
                          + BS * 4 + "\"\n")
        self.assertEqual(out.get("password"), "wxyz\n" + BS * 4, out)
        # P11: an odd candidate on the opening record, with an
        # even close carrying a JUNK remainder on a later
        # record — dotenv closes at the odd candidate. (The
        # hunter's sketch, gated on "no even close in span",
        # would NOT engage here.)
        out = self._parse(tmp, "l2p11",
                          self.EM + self.PW + "\n\"w" + BS + "\"\n"
                          "tail\" junk\n")
        self.assertEqual(out.get("password"), "w" + BS, out)
        # Two odd candidates: the LAST viable one closes (P13).
        out = self._parse(tmp, "l2p13",
                          self.EM + self.PW + "\n\"w" + BS + "\"\n"
                          + BS + "\"\n")
        self.assertEqual(out.get("password"),
                         "w" + BS + "\"\n" + BS, out)
        # No close at all: no adoption (byte-unchanged).
        out = self._parse(tmp, "l2noclose",
                          self.EM + self.PW + "\n\"wxyz\ntail\n")
        self.assertFalse(out.get("password"), out)
        self.assertEqual(out.get("email"), "e@x.io", out)
        # Odd candidate + junk remainder: no adoption.
        out = self._parse(tmp, "l2oddjunk",
                          self.EM + self.PW + "\n\"w" + BS
                          + "\" junk\n")
        self.assertFalse(out.get("password"), out)
        # Bound: a candidate AFTER an even close with junk
        # remainder is unreachable — no adoption (NS7).
        out = self._parse(tmp, "l2ns7",
                          self.EM + self.PW + "\n\"wxyz\" junk\n"
                          + BS + "\"\n")
        self.assertFalse(out.get("password"), out)
        # Plain adoption control: byte-unchanged.
        out = self._parse(tmp, "l2plain",
                          self.EM + self.PW + "\n\"VerPw23\"\n")
        self.assertEqual(out.get("password"), "VerPw23", out)

    # -- Fix 4: splitter terminal escaped close ------------------------
    def test_w24_l3_splitter_escaped_close_shapes(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        n = 0
        for q in ('"', "'", "`"):
            n += 1
            # On-line multiline, closing line's only quote is
            # escaped (odd 1): the value is the full span, NOT
            # the fabricated truncated first line.
            out = self._parse(tmp, f"l3o1{n}",
                              self.EM + self.PW + q + "wxyz\n"
                              + BS + q + "\n")
            self.assertEqual(out.get("password"), "wxyz\n" + BS,
                             (q, out))
            self.assertNotEqual(out.get("password"), q + "wxyz",
                                (q, out))
            # Odd count 3 on the closing line.
            out = self._parse(tmp, f"l3o3{n}",
                              self.EM + self.PW + q + "wxyz\n"
                              + BS * 3 + q + "\n")
            self.assertEqual(out.get("password"),
                             "wxyz\n" + BS * 3, (q, out))
        # Email leg (dq).
        out = self._parse(
            tmp, "l3email",
            "ENGINE_ADMIN_EMAIL=\"v\n" + BS + "\"\n"
            + self.PW + "VerPw23\n")
        self.assertEqual(out.get("email"), "v\n" + BS, out)
        self.assertEqual(out.get("password"), "VerPw23", out)
        # Closing line with x + escaped quote.
        out = self._parse(tmp, "l3x",
                          self.EM + self.PW + "\"wxyz\nx"
                          + BS + "\"\n")
        self.assertEqual(out.get("password"), "wxyz\nx" + BS, out)
        # Escaped close + comment remainder.
        out = self._parse(tmp, "l3comment",
                          self.EM + self.PW + "\"wxyz\n" + BS
                          + "\" # note\n")
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        # A record after the closing line still parses (Q10).
        out = self._parse(tmp, "l3other",
                          self.EM + self.PW + "\"wxyz\n" + BS
                          + "\"\nOTHER=1\n")
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        # CRLF variant.
        out = self._parse(
            tmp, "l3crlf",
            "ENGINE_ADMIN_EMAIL=e@x.io\r\n" + self.PW
            + "\"wxyz\r\n" + BS + "\"\r\n")
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        self.assertEqual(out.get("email"), "e@x.io", out)

    def test_w24_l3_splitter_controls_byte_unchanged(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # Junk remainder after the escaped close: BOTH parsers
        # hold the fabricated first line — byte-unchanged (QC3).
        out = self._parse(tmp, "l3qc3",
                          self.EM + self.PW + "\"wxyz\n" + BS
                          + "\" junk\n")
        self.assertEqual(out.get("password"), "\"wxyz", out)
        # No quote at all after the opening: the unterminated
        # fallback itself is dotenv-faithful (QC4).
        out = self._parse(tmp, "l3qc4",
                          self.EM + self.PW + "\"wxyz\ntail\n")
        self.assertEqual(out.get("password"), "\"wxyz", out)
        # Escaped close followed by a later REAL close: the
        # full span wins, in-scan (QC2) — the EOF fallback
        # must not engage.
        out = self._parse(tmp, "l3qc2",
                          self.EM + self.PW + "\"wxyz\ntail"
                          + BS + "\"\nend\"\n")
        self.assertEqual(out.get("password"),
                         "wxyz\ntail" + BS + "\"\nend", out)
        # Normal multiline even close (QC5).
        out = self._parse(tmp, "l3qc5",
                          self.EM + self.PW + "\"wxyz\ntail\"\n")
        self.assertEqual(out.get("password"), "wxyz\ntail", out)
        # Single-line terminal escaped close (QC1).
        out = self._parse(tmp, "l3qc1",
                          self.EM + self.PW + "\"w" + BS + "\"\n")
        self.assertEqual(out.get("password"), "w" + BS, out)


if __name__ == "__main__":
    unittest.main()
