#!/usr/bin/env python3
"""Regression tests for the wave-21 fixes (security audit run-20:
6 confirmed findings, all LOW).

Fix 1+2 (D20-DATA-1 merged with AUTH20-1, and D20-DATA-2 with
arm B = AUTH20-2; app/server.py — ONE combined patch in
_persist_diverged + _backup_diverged + _clear_backup_diverged,
prescribed by verify-data20):
  DATA-1: a clear used to be a ts'd tombstone ONLY in the
  sidecar; the settings/memory legs stored bare None, which
  the merged read does not rank — a heal save whose sidecar
  channel was faulted for the whole save left the stale
  sidecar raise as the ONLY record, _persist_diverged still
  returned True (no audit), and wipe+restore deleted the
  legitimate label from every store including users.enc.
  Fix: ONE shared ts'd tombstone dict stored on ALL channels;
  the merged read ranks settings/memory tombstone dicts as
  clear records; a clear VERIFIES it took (re-read merged
  state; a surviving raise fires the loud
  access_backup_diverged_unpersisted path and the clear
  returns False).
  DATA-2: the merged read ordered by int-second wall-clock
  ts — a future-stamped raise out-ranked a real-now tombstone
  after a clock step-back (arm A), and a same-second fresh
  raise in settings+memory lost its tie to a stale sidecar
  tombstone, dropping the raise so wipe+restore resurrected
  the revoked label (arm B). Fix: the single writer stamps
  EVERY record (raises AND tombstones, re-stamping
  caller-supplied records) with a logical ts =
  max(now, max_existing_ts_across_all_channels + 1), and
  passes it into the sidecar writer instead of letting it
  self-stamp.

Fix 3-6 (L20-L1..L4; bin/nexuslocal.js — ONE unified parser
patch to parseEngineAdminCreds/_splitQuoted20, prototype-
tested by verify-launcher20 at 49 shapes, 48/49 vs real
dotenv 17.4.2, the 1 being the deliberate wave-13 unquoted-#
divergence):
  L1: the splitter's \\x01 protection byte collided with a
  literal \\x01 in a credential value — the unconditional
  restore handed it back as a newline, the mangled value was
  POSTed, a definitive 401 deleted every ENGINE_ADMIN line.
  Fix: a per-parse sentinel VERIFIED ABSENT from the input.
  L2: quote mode armed on ANY record containing '=' —
  a comment / commented-out example / invalid-key line with
  an unmatched quote glued the credential records below into
  it; credentials read ABSENT, permanent false foreign-claim
  alarm. Fix: quote mode arms only when the text before the
  record's first '=' is an assignment prefix.
  L3: the pre-quote whitespace skip was space/tab only,
  while dotenv accepts all JS \\s — VT/FF/NBSP/U+2003/
  U+2028/U+2029/U+3000/U+FEFF-led quoted values never entered
  quote mode and truncated. Fix: skip /\\s/ minus \\r and \\n
  (U+2028/U+2029 INCLUDED — dotenv treats them as pre-quote
  whitespace in this position, never as separators).
  L4: backtick (dotenv's third quote char) was unknown to
  both splitter and record parser. Fix: backtick as a third
  quote in both, with single-quote semantics.
  (L20-L5 is a comment-only amendment to the exit-guard
  comment — no test, by prescription.)

Run:  python3 -m unittest tests.test_wave21_fixes -v
   or python3 -m unittest discover -s tests
"""

import json
import os
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
import test_wave20_fixes as _w20  # noqa: E402

MASTER = _a16.MASTER
RKEY = "restore-wave21-key"

ENGINE_CLAIM_JS = _w18.ENGINE_CLAIM_JS
NODE_HARNESS_JS = _w18.NODE_HARNESS_JS

# Stub engine for the L20-L1 end-to-end test: already claimed,
# holding the dotenv view of the password — the literal byte
# a<0x01>b, exactly as recorded in the .env's double quotes.
ENGINE_X01_JS = r"""
const http=require('http'),fs=require('fs');
fs.writeFileSync(process.env.ENGINE_PID,String(process.pid));
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{res.setHeader('Content-Type','application/json');
if(req.url==='/api/auth/status'){
  res.end(JSON.stringify({needsSetup:false}));}
else if(req.url==='/api/auth/login'){
  fs.appendFileSync(process.env.LOGIN_FILE,b+'\n');
  let ok=false;try{const j=JSON.parse(b);
  ok=j.email==='e@x.io'&&j.password==='a\u0001b';}catch(e){}
  if(ok){res.end(JSON.stringify({ok:true}));}
  else{res.statusCode=401;res.end('{}');}}
else{res.statusCode=404;res.end('{}');}});}).listen(3001,'127.0.0.1');
"""

# Stub engine for the L20-L2 end-to-end test: already claimed
# with the plain recorded password Pw20x.
ENGINE_GLUE_JS = r"""
const http=require('http'),fs=require('fs');
fs.writeFileSync(process.env.ENGINE_PID,String(process.pid));
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{res.setHeader('Content-Type','application/json');
if(req.url==='/api/auth/status'){
  res.end(JSON.stringify({needsSetup:false}));}
else if(req.url==='/api/auth/login'){
  fs.appendFileSync(process.env.LOGIN_FILE,b+'\n');
  let ok=false;try{const j=JSON.parse(b);
  ok=j.email==='e@x.io'&&j.password==='Pw20x';}catch(e){}
  if(ok){res.end(JSON.stringify({ok:true}));}
  else{res.statusCode=401;res.end('{}');}}
else{res.statusCode=404;res.end('{}');}});}).listen(3001,'127.0.0.1');
"""


# =====================================================================
# Fixes 1+2 — the combined divergence-flag patch (server.py)
# =====================================================================
class Wave21DataTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w21-data-"))
        self._saved = (server.ACCESS_PATH, server.USERS_PATH,
                       server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
                       server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
                       server.AUDIT_PATH,
                       server.decrypt_keys, server.encrypt_keys)
        self._saved_sc_write = server._write_diverged_sidecar
        server.ACCESS_PATH = self.tmp / "access.json"
        server.USERS_PATH = self.tmp / "users.enc"
        server.ACCESS_ENC_PATH = self.tmp / "access.enc"
        server.SETTINGS_PATH = self.tmp / "settings.json"
        server.SETTINGS_ENC_PATH = self.tmp / "settings.enc"
        server.AUDIT_PATH = self.tmp / "audit.jsonl"
        # Production-like enc mode (the verifier's shape).
        server.RESTORE_KEY = RKEY
        self._settings_saved = dict(server._SETTINGS)
        server._SETTINGS.clear()
        server._SETTINGS.update(
            json.loads(json.dumps(server._SETTINGS_DEFAULTS)))
        server._BACKUP_DIVERGED_MEM[0] = None
        self.fault = {"users": False, "settings": False,
                      "sidecar": False}
        orig_enc = self._saved[8]

        def enc_wrap(d, pw, path):
            if self.fault["users"] \
                    and Path(path) == server.USERS_PATH:
                raise OSError("injected users.enc fault (wave21)")
            if self.fault["settings"] \
                    and str(path).startswith(
                        str(server.SETTINGS_ENC_PATH)):
                raise OSError("injected settings.enc fault (wave21)")
            return orig_enc(d, pw, path)

        self._enc_wrap = enc_wrap
        server.encrypt_keys = enc_wrap
        real_sc = self._saved_sc_write

        def sc_wrap(rec):
            if self.fault["sidecar"]:
                return False
            return real_sc(rec)

        server._write_diverged_sidecar = sc_wrap

    def tearDown(self):
        (server.ACCESS_PATH, server.USERS_PATH,
         server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
         server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
         server.AUDIT_PATH,
         server.decrypt_keys, server.encrypt_keys) = self._saved
        server._write_diverged_sidecar = self._saved_sc_write
        server._SETTINGS.clear()
        server._SETTINGS.update(self._settings_saved)
        server._BACKUP_DIVERGED_MEM[0] = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------
    def _sidecar(self):
        p = self.tmp / "access_diverged.json"
        return json.loads(p.read_text()) if p.exists() else None

    def _write_sidecar(self, rec):
        (self.tmp / "access_diverged.json").write_text(
            json.dumps(rec))

    def _persisted_settings_flag(self):
        d = decrypt_keys(server.SETTINGS_ENC_PATH, RKEY)
        return d.get("access_backup_diverged")

    def _seed(self, d):
        server.ACCESS_PATH.write_text(json.dumps(d))
        encrypt_keys(d, MASTER, server.USERS_PATH)
        self.assertTrue(server._save_settings())

    def _raise_alpha(self):
        """Faulted revoke of beta: flag [alpha] on both channels,
        users.enc stale at [alpha, beta]."""
        self._seed({"alpha": "h-a", "beta": "h-b"})
        self.fault["users"] = True
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a"}, MASTER)
        self.fault["users"] = False
        flag = server._backup_diverged()
        self.assertEqual(flag["intended_labels"], ["alpha"])

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

    # -- DATA-1: heal save, sidecar faulted for the whole save ------
    def test_w21_data1_heal_sidecar_faulted_charlie_survives(self):
        self._raise_alpha()
        # The heal: add charlie; users.enc + settings healthy,
        # the SIDECAR channel faulted for the whole save
        # (pre-note + clear — the D20-DATA-1 composition).
        self.fault["sidecar"] = True
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a", "charlie": "h-c"},
                                MASTER)
        self.fault["sidecar"] = False
        # The backup really converged…
        self.assertEqual(sorted(decrypt_keys(server.USERS_PATH,
                                             MASTER)),
                         ["alpha", "charlie"])
        # …the sidecar still holds the STALE raise (its writes
        # faulted)…
        sc = self._sidecar()
        self.assertEqual(sc["intended_labels"], ["alpha"])
        # …but the clear is now a real record on the settings
        # channel too: ONE shared ts'd tombstone dict (pre-fix:
        # bare None, which the merged read cannot rank).
        pf = self._persisted_settings_flag()
        self.assertIsInstance(pf, dict)
        self.assertIsNone(pf["intended_labels"])
        self.assertGreater(pf["ts"], sc["ts"])
        # The merged read is clear IMMEDIATELY in-process
        # (pre-fix: the stale sidecar raise ruled unopposed)…
        self.assertIsNone(server._backup_diverged())
        # …and after a real restart…
        self.assertIsNone(self._restart())
        # …so wipe + restore keeps charlie everywhere (pre-fix:
        # capped to [alpha] and deleted from users.enc too).
        self._wipe()
        server._restore_access(MASTER)
        self.assertIn("charlie", self._live())
        self.assertEqual(self._live().get("alpha"), "h-a")
        self.assertIn("charlie",
                      decrypt_keys(server.USERS_PATH, MASTER))

    # -- DATA-1 / AUTH20-1: standalone clear, sidecar faulted -------
    def test_w21_data1_standalone_clear_sidecar_faulted(self):
        self._raise_alpha()
        # The backup legitimately reconverged elsewhere (live +
        # users.enc both hold charlie now); a standalone clear
        # runs with ONE transient sidecar fault, settings
        # healthy — AUTH20-1's arm, no timing window.
        both = {"alpha": "h-a", "charlie": "h-c"}
        server.ACCESS_PATH.write_text(json.dumps(both))
        encrypt_keys(both, MASTER, server.USERS_PATH)
        self.fault["sidecar"] = True
        ret = server._clear_backup_diverged()
        self.fault["sidecar"] = False
        self.assertIs(ret, True)
        # The settings tombstone out-ranks the stale sidecar
        # raise immediately (pre-fix: merged read = [alpha]).
        self.assertIsNone(server._backup_diverged())
        self.assertIsNone(self._restart())
        # Wipe + restore as the next master-bearing operation:
        # charlie survives (pre-fix: capped out and lost).
        self._wipe()
        server._restore_access(MASTER)
        self.assertIn("charlie", self._live())
        self.assertIn("charlie",
                      decrypt_keys(server.USERS_PATH, MASTER))

    # -- DATA-1: clear verification is LOUD, return is honest -------
    def test_w21_clear_verification_loud_and_returns_false(self):
        self._raise_alpha()
        # Control: a healthy clear reports success.
        self.assertIs(server._clear_backup_diverged(), True)
        self.assertIsNone(server._backup_diverged())
        # Re-raise [alpha] on both channels.
        self.fault["users"] = True
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a"}, MASTER)
        self.fault["users"] = False
        self.assertEqual(server._backup_diverged()
                         ["intended_labels"], ["alpha"])
        # A clear whose durable channels BOTH fault while the
        # raises survive persisted: the failure must be LOUD
        # (the access_backup_diverged_unpersisted audit/log
        # path) and the return must be an honest False
        # (pre-fix: the clear returned None and, in the
        # one-channel shape, a silent True).
        log_events = []
        orig_log_event = server._log_event
        server._log_event = lambda *a, **k: log_events.append((a, k))
        try:
            self.fault["sidecar"] = True
            self.fault["settings"] = True
            ret = server._clear_backup_diverged()
        finally:
            self.fault["sidecar"] = False
            self.fault["settings"] = False
            server._log_event = orig_log_event
        self.assertIs(ret, False)
        audit_text = ""
        if server.AUDIT_PATH.exists():
            audit_text = server.AUDIT_PATH.read_text()
        self.assertIn("access_backup_diverged_unpersisted",
                      audit_text)
        self.assertTrue(
            any(a and a[1] == "access_backup_diverged_unpersisted"
                for a, _k in log_events), log_events)

    # -- DATA-2 arm A: future-stamped raise vs the heal's tombstone --
    def test_w21_data2_future_raise_tombstone_bumped(self):
        self._raise_alpha()
        # Craft the state a raise written before a clock
        # step-back leaves: durable records stamped ahead of
        # the wall clock (direct writes, verified by decrypt).
        fut = int(time.time()) + 7200
        rec = {"ts": fut, "intended_labels": ["alpha"]}
        self._write_sidecar(rec)
        server._SETTINGS["access_backup_diverged"] = rec
        server._BACKUP_DIVERGED_MEM[0] = rec
        self.assertTrue(server._save_settings())
        self.assertEqual(self._persisted_settings_flag()["ts"],
                         fut)
        # Heal adding charlie, the SETTINGS channel faulted for
        # the whole save (sidecar healthy — its tombstone
        # LANDS, at a real-now ts pre-fix).
        self.fault["settings"] = True
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a", "charlie": "h-c"},
                                MASTER)
        self.fault["settings"] = False
        self.assertEqual(sorted(decrypt_keys(server.USERS_PATH,
                                             MASTER)),
                         ["alpha", "charlie"])
        # The tombstone's logical ts was BUMPED past the future
        # stamp (pre-fix: stamped with raw time.time(), ~7200s
        # BEHIND the raise it supersedes).
        sc = self._sidecar()
        self.assertIsNone(sc["intended_labels"])
        self.assertGreater(sc["ts"], fut)
        # The persisted settings copy is still the future raise…
        self.assertEqual(self._persisted_settings_flag()["ts"],
                         fut)
        # …but after a restart the bumped tombstone rules, not
        # the future raise (pre-fix: merged = future [alpha])…
        self.assertIsNone(self._restart())
        # …and wipe + restore keeps charlie (pre-fix: lost
        # everywhere, backup included).
        self._wipe()
        server._restore_access(MASTER)
        self.assertIn("charlie", self._live())
        self.assertIn("charlie",
                      decrypt_keys(server.USERS_PATH, MASTER))

    # -- DATA-2 arm B: a fresh raise must out-rank the tombstone ----
    def test_w21_data2_raise_after_tombstone_bumped_wins(self):
        self._raise_alpha()
        # Heal: the clear lands a tombstone on every channel.
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a"}, MASTER)
        self.assertIsNone(server._backup_diverged())
        # State a faulted revoke of charlie leaves: live +
        # backup still hold charlie, intended is [alpha].
        stale = {"alpha": "h-a", "charlie": "h-c"}
        server.ACCESS_PATH.write_text(json.dumps(stale))
        encrypt_keys(stale, MASTER, server.USERS_PATH)
        # Stamp the tombstone in the FUTURE on every channel —
        # the deterministic form of the same-second tie: a
        # writer stamping raw wall clock can NEVER beat it,
        # so only the logical-clock bump can win here.
        fut = int(time.time()) + 3600
        tomb = {"ts": fut, "intended_labels": None}
        self._write_sidecar(tomb)
        server._SETTINGS["access_backup_diverged"] = tomb
        server._BACKUP_DIVERGED_MEM[0] = tomb
        self.assertTrue(server._save_settings())
        # The re-raise, via the real writer, sidecar faulted
        # (lands in settings + memory only).
        self.fault["sidecar"] = True
        server._note_backup_diverged(["alpha"])
        self.fault["sidecar"] = False
        # The raise's ts was bumped strictly past the tombstone
        # it supersedes (pre-fix: raw now, an hour behind).
        pf = self._persisted_settings_flag()
        self.assertEqual(pf["intended_labels"], ["alpha"])
        self.assertEqual(pf["ts"], fut + 1)
        # The merged read SEES the raise, in-process and after
        # restart (pre-fix: the sidecar tombstone won the tie /
        # the future ts, the raise was invisible, both
        # consumers disengaged)…
        flag = server._backup_diverged()
        self.assertIsNotNone(flag)
        self.assertEqual(flag["intended_labels"], ["alpha"])
        flag = self._restart()
        self.assertIsNotNone(flag)
        self.assertEqual(flag["intended_labels"], ["alpha"])
        # …so wipe + restore runs CAPPED: the revoked charlie
        # is NOT resurrected (pre-fix: uncapped merge brought
        # charlie back into live AND users.enc — D18-2).
        self._wipe()
        server._restore_access(MASTER)
        self.assertNotIn("charlie", self._live())
        self.assertEqual(self._live().get("alpha"), "h-a")
        self.assertNotIn("charlie",
                         decrypt_keys(server.USERS_PATH, MASTER))


# =====================================================================
# Fixes 3-6 — the unified launcher parser patch (bin/nexuslocal.js)
# =====================================================================
class Wave21LauncherTests(unittest.TestCase):

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

    # -- fixture (wave-20 shape) ------------------------------------
    def _fixture(self, env_bytes, engine_js):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w21-launcher-"))
        self._tmps.append(tmp)
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        (tmp / "harness.js").write_text(NODE_HARNESS_JS)
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

    # -- The verifier's 49-shape corpus (verify-launcher20
    #    patch_sim.js), recorded here with the real dotenv
    #    17.4.2 expected values from patch_sim.log. ----------
    EM = "ENGINE_ADMIN_EMAIL=e@x.io\n"
    PW = "ENGINE_ADMIN_PASSWORD="
    CORPUS = [
        # L20-L1 — literal \x01 must survive as data
        ("L1-A1 dq x01", EM + PW + '"a\x01b"\n', "a\x01b", "e@x.io"),
        ("L1-A2 sq x01", EM + PW + "'a\x01b'\n", "a\x01b", "e@x.io"),
        ("L1-A3 unq x01", EM + PW + "a\x01b\n", "a\x01b", "e@x.io"),
        ("L1-A4 dq multi x01+LF", EM + PW + '"a\x01b\nc"\n',
         "a\x01b\nc", "e@x.io"),
        ("L1-A5 email dq x01",
         'ENGINE_ADMIN_EMAIL="e\x01@x.io"\n' + PW + "Pw20x\n",
         "Pw20x", "e\x01@x.io"),
        ("L1-A7 between = and dq x01", EM + PW + '\x01"a"\n',
         '\x01"a"', "e@x.io"),
        ("L1-A15 whole x01", EM + PW + '"\x01"\n', "\x01", "e@x.io"),
        ("L1-P10 unq start x01", EM + PW + "\x01abc\n",
         "\x01abc", "e@x.io"),
        ("L1-both x01 and x02 literal",
         EM + PW + '"a\x01b\x02c\nd"\n', "a\x01b\x02c\nd", "e@x.io"),
        # L20-L2 — non-assignment records must never arm quote mode
        ("L2-G1 comment dq unmatched",
         '# note="oops\n' + PW + '"Pw20x"\n' + EM, "Pw20x", "e@x.io"),
        ("L2-G2 comment, creds unquoted, quoted email closes",
         '# note="oops\n' + PW + 'Pw20x\n'
         'ENGINE_ADMIN_EMAIL="e@x.io"\n', "Pw20x", "e@x.io"),
        ("L2-G3 comment, later OTHER closes",
         '# note="oops\n' + PW + "Pw20x\n" + EM.rstrip("\n")
         + '\nOTHER="z"\n', "Pw20x", "e@x.io"),
        ("L2-SQ comment sq unmatched",
         "# guide: ENGINE_ADMIN_PASSWORD='fill later\n" + EM + PW
         + "'Pw20x'\n", "Pw20x", "e@x.io"),
        ("L2-G6 invalid-key line",
         'SOME KEY="oops\n' + PW + '"Pw20x"\n' + EM,
         "Pw20x", "e@x.io"),
        ("L2-DOC closed-quote comment control",
         '# ENGINE_ADMIN_PASSWORD="set below"\n' + EM + PW
         + '"Pw20x"\n', "Pw20x", "e@x.io"),
        ("L2-legit multiline OTHER above creds",
         'OTHER="a\nb"\n' + EM + PW + '"Pw20x"\n',
         "Pw20x", "e@x.io"),
        ("L2-legit multiline cred itself",
         EM + PW + '"a\nb"\nOTHER="z"\n', "a\nb", "e@x.io"),
        # L20-L3 — one representative here; the full sweep is below
        ("L3-NBSP sq LF", EM + PW + "\u00a0'a\nb'\n",
         "a\nb", "e@x.io"),
        # L20-L4 — backtick, dotenv's third quote char
        ("L4-K2 backtick single", EM + PW + "`Pw20x`\n",
         "Pw20x", "e@x.io"),
        ("L4-K1 backtick multi LF", EM + PW + "`a\nb`\nOTHER=1\n",
         "a\nb", "e@x.io"),
        ("L4-K3 backtick multi CR", EM + PW + "`a\rb`\nOTHER=1\n",
         "a\nb", "e@x.io"),
        ("L4-K4 backtick email",
         "ENGINE_ADMIN_EMAIL=`e@x.io`\n" + PW + "Pw20x\n",
         "Pw20x", "e@x.io"),
        ("L4-K5 backtick backslash-n literal",
         EM + PW + "`a\\nb`\n", "a\\nb", "e@x.io"),
        ("L4-K7 backtick trailing comment",
         EM + PW + "`Pw20x` # note\n", "Pw20x", "e@x.io"),
        ("L4-K8 backtick escaped backtick",
         EM + PW + "`a\\`b`\nOTHER=1\n", "a\\`b", "e@x.io"),
        ("L4-K6 backtick unterminated fallback",
         EM + PW + "`Pw20x\nOTHER=1\n", "`Pw20x", "e@x.io"),
        # Headline-fix controls (must not regress)
        ("CTRL space dq LF", EM + PW + ' "a\nb"\n',
         "a\nb", "e@x.io"),
        ("CTRL dq CRLF", EM + PW + '"a\r\nb"\n', "a\nb", "e@x.io"),
        ("CTRL dq escaped quote + CR", EM + PW + '"a\\"b\rc"\n',
         'a\\"b\nc', "e@x.io"),
        ("CTRL unterminated dq", EM + PW + '"abc\nOTHER=1\n',
         '"abc', "e@x.io"),
        ("CTRL export dq multi",
         "export " + PW + '"a\nb"\n' + EM, "a\nb", "e@x.io"),
        ("CTRL apostrophe unquoted above",
         "OTHER=don't\n" + EM + PW + "Pw20x\n", "Pw20x", "e@x.io"),
    ]

    def test_w21_parser_verifier_corpus(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        for i, (label, text, want_pw, want_em) in enumerate(
                self.CORPUS):
            out = self._parse(tmp, f"corpus{i}", text)
            self.assertEqual(out.get("password"), want_pw,
                             (label, out))
            self.assertEqual(out.get("email"), want_em,
                             (label, out))
            self.assertTrue(out.get("hasPassword"), (label, out))
        # L1-A17: with backslash-n expansion BOTH the primary
        # and the alternate must keep the literal \x01 as data
        # (pre-fix both were mangled to contain a newline).
        out = self._parse(tmp, "corpusA17",
                          self.EM + self.PW + '"a\\nb\x01c"\n')
        self.assertEqual(out.get("password"), "a\nb\x01c", out)
        self.assertEqual(out.get("passwordAlt"), "a\\nb\x01c", out)
        # The corpus's single deliberate divergence (wave-13
        # unquoted-# handling) stays EXACTLY as wave 20: the
        # primary keeps the '#' as data and the dotenv-truncated
        # form is the retry alternate. (Real dotenv parses "ab";
        # this is the prototype corpus's 48/49 row.)
        out = self._parse(tmp, "corpusHash",
                          self.EM + self.PW + "ab#cd\n")
        self.assertEqual(out.get("password"), "ab#cd", out)
        self.assertEqual(out.get("passwordAlt"), "ab", out)

    def test_w21_parser_entry_skip_whitespace_sweep(self):
        # L20-L3: the FULL pre-quote whitespace sweep — every
        # JS-\s char except \r/\n (which are separators), for
        # both quote chars and both in-value line endings, must
        # enter quote mode exactly as dotenv does. U+2028 and
        # U+2029 are INCLUDED (the verifier's empirical ruling:
        # dotenv consumes them as pre-quote whitespace here).
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        ws = {"VT": "\x0b", "FF": "\x0c", "NBSP": "\u00a0",
              "EMSP": "\u2003", "LS": "\u2028", "PS": "\u2029",
              "IDEO": "\u3000", "FEFF": "\ufeff"}
        n = 0
        for name, w in ws.items():
            for q in ('"', "'"):
                for eol in ("\n", "\r"):
                    n += 1
                    text = (self.EM + self.PW + w + q + "a" + eol
                            + "b" + q + "\n")
                    out = self._parse(tmp, f"sweep{n}", text)
                    self.assertEqual(out.get("password"), "a\nb",
                                     (name, q, repr(eol), out))
                    self.assertEqual(out.get("email"), "e@x.io",
                                     (name, q, repr(eol), out))
        self.assertEqual(n, 32)

    # -- L20-L1 E2E: \x01 password verifies byte-exact, no deletion --
    def test_w21_e2e_x01_password_verifies_no_deletion(self):
        env = (b"ENGINE_ADMIN_EMAIL=e@x.io\n"
               b'ENGINE_ADMIN_PASSWORD="a\x01b"\n')
        tmp = self._fixture(env, ENGINE_X01_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc,
                   lambda: (tmp / "logins.jsonl").exists()
                   and bool((tmp / "logins.jsonl").read_text()
                            .strip()),
                   tmp=tmp, what="verify login POST")
        time.sleep(1)
        logins = [json.loads(ln) for ln in
                  (tmp / "logins.jsonl").read_text().splitlines()
                  if ln.strip()]
        # The EXACT bytes were POSTed (pre-fix: the literal
        # \x01 was handed back as a newline — "a\nb" — the
        # stub answered a definitive 401 and every
        # ENGINE_ADMIN line was deleted).
        self.assertEqual(logins[0]["password"], "a\x01b", logins)
        self.assertEqual(logins[0]["email"], "e@x.io", logins)
        env_after = (tmp / "app" / ".env").read_bytes()
        self.assertIn(b"ENGINE_ADMIN_PASSWORD", env_after)
        self.assertIn(b"ENGINE_ADMIN_EMAIL", env_after)
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertNotIn("now removed", log)

    # -- L20-L2 E2E: comment glue — creds verify, no false alarm ----
    def test_w21_e2e_comment_glue_verifies_no_false_alarm(self):
        env = (b'# note="oops\n'
               b'ENGINE_ADMIN_PASSWORD="Pw20x"\n'
               b"ENGINE_ADMIN_EMAIL=e@x.io\n")
        tmp = self._fixture(env, ENGINE_GLUE_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        # Pre-fix: the comment's unmatched quote glued the
        # credential records into it — the capture contained
        # ONLY the status GET (zero login POSTs) and the false
        # 'holds no ENGINE_ADMIN credentials' alarm logged.
        self._wait(proc,
                   lambda: (tmp / "logins.jsonl").exists()
                   and bool((tmp / "logins.jsonl").read_text()
                            .strip()),
                   tmp=tmp, what="verify login POST")
        time.sleep(1)
        logins = [json.loads(ln) for ln in
                  (tmp / "logins.jsonl").read_text().splitlines()
                  if ln.strip()]
        self.assertEqual(logins[0]["password"], "Pw20x", logins)
        self.assertEqual(logins[0]["email"], "e@x.io", logins)
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertNotIn("holds no ENGINE_ADMIN", log)
        self.assertNotIn("now removed", log)
        # The closed-quote comment control is unchanged: a
        # documentation comment whose quote closes on its own
        # line parses exactly as before (unit-level, in the
        # corpus as L2-DOC; here the .env stayed byte-identical).
        self.assertEqual((tmp / "app" / ".env").read_bytes(), env)


if __name__ == "__main__":
    unittest.main()
