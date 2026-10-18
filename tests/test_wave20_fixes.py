#!/usr/bin/env python3
"""Regression tests for the wave-20 fixes (security audit run-19:
5 confirmed findings, all LOW).

Fixes 1+2 (D19-1 + D19-2, app/server.py — ONE unified patch,
prescribed by verify-data19): the users.enc divergence flag's
write side is a single writer, _persist_diverged, with TWO
durable channels — a PLAIN sidecar (access_diverged.json in
the app data dir, atomic tmp+replace) written FIRST, and the
_SETTINGS copy via _save_settings (the friend_blob sync mirror)
kept as the second channel. Reads merge the channels by ts
(newest wins, at boot and on every read); a clear writes a ts'd
tombstone to the sidecar; total failure of both channels fires
a loud _audit + _log_event instead of silence.
  D19-1 leg (pre-note ordering): wherever a users.enc write is
  about to happen while a flag exists (_save_access's backup
  write, _merge19's convergence refresh), the NEW dict's
  intended label set is persisted BEFORE the write executes —
  so a faulted clear-persist, or a kill inside the clear
  window, leaves a persisted cap that names the just-written
  set and excludes nothing.
  D19-2 leg (durable second channel): when the raising fault
  is a correlated IO fault, _save_settings fails too (its
  settings.enc encrypt aborts before the plain write), which
  used to leave the flag only in process memory, dead at
  restart. The plain sidecar lands in exactly that save.

Fix 3 (L19-L1, bin/nexuslocal.js): parseEngineAdminCreds uses
a quote-tracking splitter — line endings split only OUTSIDE
quotes; line-ending bytes inside a quoted value normalise to
\\n exactly as dotenv 17.4.2 does. The wave-19 split cut inside
quoted values, so the launcher read a truncated password,
POSTed it, and verifyClaim's definitive-401 leg DELETED every
recorded credential line.

Fix 4 (L19-L2, bin/nexuslocal.js): the stale-lock reclaim
re-reads the lock immediately before unlinking and deletes
only the instance it judged (content still naming the same
dead pid); the exit handler unlinks only while the content
still names its own pid.

Fix 5 (L19-L3, bin/nexuslocal.js): lock content is
"<pid> <start-epoch-ms>"; unparseable content with an mtime
older than 60s is reclaimable (younger stays fail-closed); on
Linux a live pid whose /proc start time is after the lock's
mtime is a recycled pid and the lock is reclaimable; the
already-running refusal names the lock file path.

Run:  python3 -m unittest tests.test_wave20_fixes -v
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
import test_wave19_fixes as _w19  # noqa: E402

MASTER = _a16.MASTER
RKEY = "restore-wave20-key"

ENGINE_CLAIM_JS = _w18.ENGINE_CLAIM_JS
NODE_HARNESS_JS = _w18.NODE_HARNESS_JS

# Stub engine for the L19-L1 end-to-end test: already claimed,
# holding the dotenv view of the quoted-CR password ("a\nb").
ENGINE_VERIFY_JS = r"""
const http=require('http'),fs=require('fs');
fs.writeFileSync(process.env.ENGINE_PID,String(process.pid));
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{res.setHeader('Content-Type','application/json');
if(req.url==='/api/auth/status'){
  res.end(JSON.stringify({needsSetup:false}));}
else if(req.url==='/api/auth/login'){
  fs.appendFileSync(process.env.LOGIN_FILE,b+'\n');
  let ok=false;try{const j=JSON.parse(b);
  ok=j.email==='e@x.io'&&j.password==='a\nb';}catch(e){}
  if(ok){res.end(JSON.stringify({ok:true}));}
  else{res.statusCode=401;res.end('{}');}}
else{res.statusCode=404;res.end('{}');}});}).listen(3001,'127.0.0.1');
"""

# Node harness for the lock block: extracts it verbatim from
# the launcher (same anchors the run-19 verifier used) and
# drives it with stub actors inside vm contexts — pure
# filesystem work in temp dirs, no engine port is reachable.
LOCK_HARNESS_JS = r"""
"use strict";
const fs=require("fs"),os=require("os"),path=require("path"),
      vm=require("vm");
const SRC=fs.readFileSync(process.argv[2],"utf8");
const start=SRC.indexOf("const _lockPath19");
const end=SRC.indexOf(
  'console.log("============================================");',
  start);
if(start<0||end<0){console.error("block markers missing");
  process.exit(2);}
const BLOCK=SRC.slice(start,end);
function makeActor(dir,pid,opts){
  opts=opts||{};
  const actor={pid:pid,exited:null,exitHandlers:[],logs:[],
               fd:undefined};
  let fsA=fs;
  if(opts.wrapFs){
    fsA=Object.create(fs);
    for(const k of ["openSync","readFileSync","unlinkSync",
                    "writeSync","closeSync","statSync",
                    "rmdirSync"]){
      fsA[k]=(...a)=>opts.wrapFs(k,fs,a,actor);
    }
  }
  const proc={pid:pid,platform:process.platform,
    kill:(p,s)=>process.kill(p,s),
    on:(ev,fn)=>{if(ev==="exit")actor.exitHandlers.push(fn);},
    exit:(code)=>{const e=new Error("EXIT_"+code);
      e.__exitCode=code;throw e;}};
  const ctx={require:require,console:console,process:proc,
    path:path,fs:fsA,Buffer:Buffer,PKG_ROOT:dir,
    log:(m)=>actor.logs.push(m)};
  vm.createContext(ctx);
  actor.run=()=>{
    try{
      vm.runInContext(BLOCK+"\n;globalThis.__fd=_lockFd19;",ctx);
      actor.fd=ctx.__fd;
      return {owner:actor.fd!==null&&actor.fd!==undefined};
    }catch(e){
      if(e&&e.__exitCode!==undefined){
        actor.exited=e.__exitCode;
        return {owner:false,exited:e.__exitCode};
      }
      throw e;
    }};
  actor.fireExit=()=>{for(const fn of actor.exitHandlers)fn();};
  return actor;
}
const DEAD=999999;
const mode=process.argv[3];
const out={};
function tmpdir(tag){
  return fs.mkdtempSync(path.join(os.tmpdir(),"w20lock_"+tag+"_"));
}
if(mode==="interleave"){
  const dir=tmpdir("race");const lock=path.join(dir,".nexuslocal.lock");
  fs.writeFileSync(lock,String(DEAD));
  let A=null,reads=0,preempted=false;
  const B=makeActor(dir,410009,{wrapFs:(name,realFs,args)=>{
    if(name==="readFileSync"&&args[0]===lock){
      reads++;
      if(reads===2&&!preempted){
        preempted=true;
        A=makeActor(dir,410010);
        out.aResult=A.run();
        out.contentDuringB=fs.readFileSync(lock,"utf8");
      }
    }
    return realFs[name](...args);
  }});
  out.bResult=B.run();out.bExited=B.exited;
  out.lockAfter=fs.existsSync(lock)
    ?fs.readFileSync(lock,"utf8"):"(absent)";
  // Exit leg: a successor's lock must survive A's exit.
  fs.writeFileSync(lock,"410011 "+Date.now());
  A.fireExit();
  out.lockAfterAExit=fs.existsSync(lock)
    ?fs.readFileSync(lock,"utf8"):"(absent)";
  fs.rmSync(dir,{recursive:true,force:true});
}else if(mode==="fresh"){
  const dir=tmpdir("fresh");const lock=path.join(dir,".nexuslocal.lock");
  const A=makeActor(dir,process.pid);
  out.result=A.run();
  out.content=fs.readFileSync(lock,"utf8");
  A.fireExit();
  out.existsAfterExit=fs.existsSync(lock);
  fs.rmSync(dir,{recursive:true,force:true});
}else if(mode==="wedge"){
  const kind=process.argv[4];
  const dir=tmpdir(kind);const lock=path.join(dir,".nexuslocal.lock");
  const old=new Date(Date.now()-3600e3);
  if(kind==="empty_old"){fs.writeFileSync(lock,"");
    fs.utimesSync(lock,old,old);}
  else if(kind==="empty_young"){fs.writeFileSync(lock,"");}
  else if(kind==="garbage_old"){fs.writeFileSync(lock,"hello");
    fs.utimesSync(lock,old,old);}
  else if(kind==="garbage_young"){fs.writeFileSync(lock,"hello");}
  else if(kind==="dir_old"){fs.mkdirSync(lock);
    fs.utimesSync(lock,old,old);}
  else if(kind==="recycled"){
    fs.writeFileSync(lock,String(process.pid)+" "
      +(Date.now()-3600e3));
    fs.utimesSync(lock,old,old);}
  else if(kind==="genuine"){
    fs.writeFileSync(lock,String(process.pid)+" "+Date.now());}
  else{console.error("unknown wedge "+kind);process.exit(2);}
  const A=makeActor(dir,410100);
  out.result=A.run();out.exited=A.exited;out.logs=A.logs;
  out.lockPath=lock;
  out.contentAfter=fs.existsSync(lock)&&fs.statSync(lock).isFile()
    ?fs.readFileSync(lock,"utf8"):"(n/a)";
  fs.rmSync(dir,{recursive:true,force:true});
}else{console.error("unknown mode "+mode);process.exit(2);}
console.log(JSON.stringify(out));
"""


# =====================================================================
# Fixes 1+2 — the unified divergence-flag patch (server.py)
# =====================================================================
class Wave20DataTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w20-data-"))
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
        # Production-like enc mode (the verifier's shape):
        # settings.enc is the encrypted boot source of truth.
        server.RESTORE_KEY = RKEY
        self._settings_saved = dict(server._SETTINGS)
        server._SETTINGS.clear()
        server._SETTINGS.update(
            json.loads(json.dumps(server._SETTINGS_DEFAULTS)))
        server._BACKUP_DIVERGED_MEM[0] = None
        self.fault = {"users": False, "settings": False}
        orig_enc = self._saved[8]

        def enc_wrap(d, pw, path):
            if self.fault["users"] \
                    and Path(path) == server.USERS_PATH:
                raise OSError("injected users.enc fault (wave20)")
            if self.fault["settings"] \
                    and str(path).startswith(
                        str(server.SETTINGS_ENC_PATH)):
                raise OSError("injected settings.enc fault (wave20)")
            return orig_enc(d, pw, path)

        self._enc_wrap = enc_wrap
        server.encrypt_keys = enc_wrap

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
    def _sidecar(self):
        p = self.tmp / "access_diverged.json"
        return json.loads(p.read_text()) if p.exists() else None

    def _sidecar_path(self):
        return self.tmp / "access_diverged.json"

    def _persisted_settings_flag(self):
        d = decrypt_keys(server.SETTINGS_ENC_PATH, RKEY)
        return d.get("access_backup_diverged")

    def _seed(self, d):
        server.ACCESS_PATH.write_text(json.dumps(d))
        encrypt_keys(d, MASTER, server.USERS_PATH)
        self.assertTrue(server._save_settings())

    def _restart(self):
        """The verifier's real restart: the in-memory copies
        die; _SETTINGS is rebuilt ONLY by _boot_restore_settings
        from the persisted files (plus the sidecar fold-in)."""
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

    # -- D19-1: pre-note ordering at the _save_access write site ----
    def test_w20_d19_1_prenote_ordering_charlie_survives(self):
        self._seed({"alpha": "h-a", "beta": "h-b"})
        # Fault 1: revoke beta; the users.enc write faults and
        # the flag raises + persists with intended [alpha].
        self.fault["users"] = True
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a"}, MASTER)
        self.fault["users"] = False
        flag = server._backup_diverged()
        self.assertEqual(flag["intended_labels"], ["alpha"])
        self.assertEqual(
            self._persisted_settings_flag()["intended_labels"],
            ["alpha"])
        # Save 2 (the heal): add charlie. users.enc write
        # SUCCEEDS; only the flag-clear's settings persist is
        # faulted. Instrument the users.enc write: at the
        # moment it executes, the persisted flag must ALREADY
        # name the new set (the pre-note) — the D19-1 ordering.
        seen_at_write = []
        orig_wrap = self._enc_wrap

        def observing_wrap(d, pw, path):
            if Path(path) == server.USERS_PATH:
                seen_at_write.append(self._sidecar())
            return orig_wrap(d, pw, path)

        server.encrypt_keys = observing_wrap
        self.fault["settings"] = True
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a", "charlie": "h-c"},
                                MASTER)
        self.fault["settings"] = False
        server.encrypt_keys = self._enc_wrap
        self.assertTrue(seen_at_write)
        self.assertEqual(
            seen_at_write[-1]["intended_labels"],
            ["alpha", "charlie"],
            "the persisted flag did not name the new set "
            "BEFORE the heal write landed")
        # The backup really converged…
        self.assertEqual(sorted(decrypt_keys(server.USERS_PATH,
                                             MASTER)),
                         ["alpha", "charlie"])
        # …while the settings channel still holds the STALE
        # pre-heal flag (its persist faulted) — the exact state
        # that used to manufacture the loss after a restart.
        self.assertEqual(
            self._persisted_settings_flag()["intended_labels"],
            ["alpha"])
        # Real restart, full wipe, recovery login restore:
        # charlie SURVIVES (pre-fix: capped to [alpha] and
        # deleted from every store, backup included).
        self.assertIsNone(self._restart())
        self._wipe()
        server._restore_access(MASTER)
        self.assertIn("charlie", self._live())
        self.assertEqual(self._live().get("alpha"), "h-a")
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertIn("charlie", backup)

    # -- D19-1: pre-note ordering at the _merge19 write site -------
    def test_w20_d19_1_merge_path_prenote(self):
        self._seed({"friendone": "h-f1", "beta": "h-b"})
        # A revoke whose backup write faults: flag [friendone]
        # persists; users.enc stays stale.
        self.fault["users"] = True
        with server._ACCESS_LOCK:
            server._save_access({"friendone": "h-f1"}, MASTER)
        self.fault["users"] = False
        self.assertEqual(server._backup_diverged()
                         ["intended_labels"], ["friendone"])
        # Healing restore: a creation lands in the live store
        # during the restore's decrypt window; the merge's
        # convergence write SUCCEEDS but its clear's settings
        # persist is faulted (the AUTH19-1 composition — the
        # clear is the restore flow's last settings save, so
        # no trailing save heals it).
        orig_decrypt = self._saved[7]
        state = {"fired": False}

        def wrap_decrypt(path, pw):
            result = orig_decrypt(path, pw)
            if not state["fired"]:
                state["fired"] = True
                with server._ACCESS_LOCK:
                    server._save_access(
                        {"friendone": "h-f1", "newbie": "h-n"})
            return result

        server.decrypt_keys = wrap_decrypt
        self.fault["settings"] = True
        server._restore_access(MASTER)
        self.fault["settings"] = False
        server.decrypt_keys = self._saved[7]
        # The merge converged the backup onto the merged set…
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertEqual(sorted(backup), ["friendone", "newbie"])
        # …and the persisted settings flag is STILL the stale
        # [friendone] (the clear never landed there)…
        self.assertEqual(
            self._persisted_settings_flag()["intended_labels"],
            ["friendone"])
        # …but after a real restart the merged record is clear
        # (the pre-note + tombstone in the sidecar out-rank the
        # stale settings copy), so wipe + restore keeps newbie.
        self.assertIsNone(self._restart())
        self._wipe()
        server._restore_access(MASTER)
        self.assertIn("newbie", self._live())
        self.assertIn("friendone", self._live())

    # -- D19-2: the sidecar survives a correlated fault + restart --
    def test_w20_d19_2_sidecar_survives_correlated_fault(self):
        self._seed({"alpha": "h-a", "solo": "h-s"})
        # Correlated IO fault: BOTH encrypt paths fail inside
        # one master-bearing revoke — the flag's own settings
        # save fails with the _save_settings_impl shape (False
        # before the plain settings.json write is attempted).
        self.fault["users"] = self.fault["settings"] = True
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a"}, MASTER)
        self.fault["users"] = self.fault["settings"] = False
        # Both settings channels are flag-free by direct read…
        self.assertIsNone(self._persisted_settings_flag())
        plain = json.loads(server.SETTINGS_PATH.read_text())
        self.assertIsNone(plain.get("access_backup_diverged"))
        # …but the PLAIN sidecar holds the record (direct file
        # read — the durable second channel landed where both
        # encrypt paths failed).
        sc = self._sidecar()
        self.assertIsNotNone(sc)
        self.assertEqual(sc["intended_labels"], ["alpha"])
        # Real restart: the record survives (pre-fix: the flag
        # existed only in process memory and died here).
        flag = self._restart()
        self.assertIsNotNone(flag)
        self.assertEqual(flag["intended_labels"], ["alpha"])
        # Wipe both live stores + restore: the revoked label
        # stays excluded (pre-fix: resurrected, exactly D18-2).
        self._wipe()
        server._restore_access(MASTER)
        self.assertNotIn("solo", self._live())
        self.assertEqual(self._live().get("alpha"), "h-a")

    # -- D19-2: total failure of both channels is LOUD -------------
    def test_w20_d19_2_total_failure_is_loud(self):
        self._seed({"alpha": "h-a", "solo": "h-s"})
        log_events = []
        orig_log_event = server._log_event
        server._log_event = lambda *a, **k: log_events.append((a, k))
        real_settings_path = server.SETTINGS_PATH
        try:
            # Break the sidecar channel too: its directory does
            # not exist, so the plain write cannot land; the
            # settings channel is encrypt-faulted as above.
            server.SETTINGS_PATH = self.tmp / "gone" / "settings.json"
            self.fault["users"] = self.fault["settings"] = True
            with server._ACCESS_LOCK:
                server._save_access({"alpha": "h-a"}, MASTER)
            self.fault["users"] = self.fault["settings"] = False
        finally:
            server.SETTINGS_PATH = real_settings_path
            server._log_event = orig_log_event
        # The in-memory record is kept…
        flag = server._backup_diverged()
        self.assertIsNotNone(flag)
        self.assertEqual(flag["intended_labels"], ["alpha"])
        # …and the total failure is VISIBLE, not silent: the
        # audit log carries the unpersisted event…
        audit_text = ""
        if server.AUDIT_PATH.exists():
            audit_text = server.AUDIT_PATH.read_text()
        self.assertIn("access_backup_diverged_unpersisted",
                      audit_text)
        # …and _log_event fired with the same event name.
        self.assertTrue(
            any(a and a[1] == "access_backup_diverged_unpersisted"
                for a, _k in log_events), log_events)

    # -- guard: a no-flag clear stays a true no-op -------------------
    def test_w20_no_flag_clear_writes_no_sidecar(self):
        self._seed({"alpha": "h-a"})
        with server._ACCESS_LOCK:
            server._save_access({"alpha": "h-a"}, MASTER)
        self.assertIsNone(server._backup_diverged())
        self.assertFalse(self._sidecar_path().exists(),
                         "a healthy save must not create the "
                         "sidecar or bump the flag machinery")


# =====================================================================
# Fixes 3+4+5 — the launcher (bin/nexuslocal.js)
# =====================================================================
class Wave20LauncherTests(unittest.TestCase):

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

    # -- fixture (wave-19 shape) ------------------------------------
    def _fixture(self, env_bytes, engine_js):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w20-launcher-"))
        self._tmps.append(tmp)
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        (tmp / "harness.js").write_text(NODE_HARNESS_JS)
        (tmp / "lockharness.js").write_text(LOCK_HARNESS_JS)
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

    def _lockharness(self, tmp, *args):
        r = subprocess.run([self.node, str(tmp / "lockharness.js"),
                            str(tmp / "bin" / "nexuslocal.js"), *args],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    # -- Fix 3: quoted-multiline corpus at dotenv parity (unit) -----
    # Expected values recorded from the REAL dotenv 17.4.2 (the
    # engine's pinned version; the run-19 verifier's byte probe
    # agrees) — and cross-checked live below when that dotenv
    # is importable in this environment.
    PARITY_CASES = [
        # (label, env bytes, expected password, expected email)
        ("quoted lone CR dq",
         b'ENGINE_ADMIN_EMAIL=e@x.io\n'
         b'ENGINE_ADMIN_PASSWORD="a\rb"\n', "a\nb", "e@x.io"),
        ("quoted lone CR sq",
         b"ENGINE_ADMIN_PASSWORD='a\rb'\n"
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a\nb", "e@x.io"),
        ("quoted CR at end dq",
         b'ENGINE_ADMIN_PASSWORD="abc\r"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "abc\n", "e@x.io"),
        ("quoted CRLF dq",
         b'ENGINE_ADMIN_PASSWORD="a\r\nb"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a\nb", "e@x.io"),
        ("quoted LF dq",
         b'ENGINE_ADMIN_PASSWORD="a\nb"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a\nb", "e@x.io"),
        ("quoted LF sq",
         b"ENGINE_ADMIN_PASSWORD='a\nb'\n"
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a\nb", "e@x.io"),
        ("plain CR-only",
         b"ENGINE_ADMIN_EMAIL=e@x.io\r"
         b"ENGINE_ADMIN_PASSWORD=plainpw\r", "plainpw", "e@x.io"),
        ("plain CRCRLF",
         b"ENGINE_ADMIN_EMAIL=e@x.io\r\r\n"
         b"ENGINE_ADMIN_PASSWORD=plainpw\r\r\n", "plainpw", "e@x.io"),
        ("plain CRLF",
         b"ENGINE_ADMIN_EMAIL=e@x.io\r\n"
         b"ENGINE_ADMIN_PASSWORD=plainpw\r\n", "plainpw", "e@x.io"),
        ("plain LF",
         b"ENGINE_ADMIN_EMAIL=e@x.io\n"
         b"ENGINE_ADMIN_PASSWORD=plainpw\n", "plainpw", "e@x.io"),
        ("escaped quote then CR line end",
         b'ENGINE_ADMIN_PASSWORD="a\\"b"\r'
         b"ENGINE_ADMIN_EMAIL=e@x.io\r", 'a\\"b', "e@x.io"),
        ("escaped backslash-r dq",
         b'ENGINE_ADMIN_PASSWORD="a\\rb"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a\rb", "e@x.io"),
        ("unquoted CR value",
         b"ENGINE_ADMIN_PASSWORD=abc\r"
         b"ENGINE_ADMIN_EMAIL=e@x.io\r", "abc", "e@x.io"),
        ("apostrophe in unquoted OTHER value",
         b"OTHER=don't\nENGINE_ADMIN_PASSWORD=plainpw\n"
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "plainpw", "e@x.io"),
        ("quote in trailing comment",
         b'ENGINE_ADMIN_PASSWORD=plainpw # say "hi"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "plainpw", "e@x.io"),
        ("unterminated quote then email line",
         b'ENGINE_ADMIN_PASSWORD="abc\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", '"abc', "e@x.io"),
        ("unterminated quote at EOF",
         b"ENGINE_ADMIN_EMAIL=e@x.io\n"
         b'ENGINE_ADMIN_PASSWORD="abc', '"abc', "e@x.io"),
        ("hash inside double quotes",
         b'ENGINE_ADMIN_PASSWORD="a#b"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a#b", "e@x.io"),
        ("spaced quoted CR value",
         b'ENGINE_ADMIN_PASSWORD = "a\rb"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a\nb", "e@x.io"),
        ("export quoted CR value",
         b'export ENGINE_ADMIN_PASSWORD="a\rb"\n'
         b"ENGINE_ADMIN_EMAIL=e@x.io\n", "a\nb", "e@x.io"),
    ]

    def test_w20_parser_quoted_multiline_dotenv_parity(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        for i, (label, given, want_pw, want_em) in enumerate(
                self.PARITY_CASES):
            f = tmp / f"parity{i}.env"
            f.write_bytes(given)
            out = json.loads(self._harness(tmp, "parse", str(f)))
            self.assertEqual(out.get("password"), want_pw,
                             (label, out))
            self.assertEqual(out.get("email"), want_em,
                             (label, out))
            self.assertTrue(out.get("hasPassword"), (label, out))
        # The one alternate the corpus pins: a double-quoted
        # backslash-r value offers its pre-expansion literal.
        f = tmp / "parity_alt.env"
        f.write_bytes(b'ENGINE_ADMIN_PASSWORD="a\\rb"\n')
        out = json.loads(self._harness(tmp, "parse", str(f)))
        self.assertEqual(out.get("password"), "a\rb")
        self.assertEqual(out.get("passwordAlt"), "a\\rb")
        # Live cross-check against the real dotenv 17.4.2 when
        # it is importable here (the recorded values above are
        # the fallback and stay authoritative when it is not).
        dotenv_dir = (Path.home() / "workspace" / "freellmapi"
                      / "node_modules" / "dotenv")
        if (dotenv_dir / "package.json").exists():
            script = (
                "const fs=require('fs');"
                f"const dotenv=require({json.dumps(str(dotenv_dir))});"
                "const cases=JSON.parse(fs.readFileSync("
                "process.argv[1],'utf8'));"
                "const out=cases.map(b=>{const d=dotenv.parse("
                "Buffer.from(b,'base64'));"
                "return {pw:d.ENGINE_ADMIN_PASSWORD,"
                "em:d.ENGINE_ADMIN_EMAIL};});"
                "console.log(JSON.stringify(out));")
            cases_file = tmp / "parity_cases.json"
            cases_file.write_text(json.dumps(
                [__import__("base64").b64encode(g).decode()
                 for _l, g, _p, _e in self.PARITY_CASES]))
            r = subprocess.run(
                [self.node, "-e", script, str(cases_file)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            live = json.loads(r.stdout.strip())
            for (label, _g, want_pw, want_em), got in zip(
                    self.PARITY_CASES, live):
                self.assertEqual(got["pw"], want_pw,
                                 ("dotenv live", label))
                self.assertEqual(got["em"], want_em,
                                 ("dotenv live", label))

    def test_w20_parser_nonquoted_shapes_unchanged(self):
        # The 37-shape corpus's non-quoted core (wave 12-19
        # semantics): every shape must parse byte-identically
        # to the wave-19 parser — the quote-aware splitter only
        # changes behaviour inside quoted values.
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        em, pw = "boss20@example.com", "recorded-pw-20"
        cases = [
            f"ENGINE_ADMIN_EMAIL={em}\n"
            f"ENGINE_ADMIN_PASSWORD={pw}\n".encode(),
            f"ENGINE_ADMIN_EMAIL={em}\r\n"
            f"ENGINE_ADMIN_PASSWORD={pw}\r\n".encode(),
            f"ENGINE_ADMIN_EMAIL={em}\r"
            f"ENGINE_ADMIN_PASSWORD={pw}\r".encode(),
            f"ENGINE_ADMIN_EMAIL={em}\r\r\n"
            f"ENGINE_ADMIN_PASSWORD={pw}\r\r\n".encode(),
            f"export ENGINE_ADMIN_EMAIL={em}\n"
            f"export ENGINE_ADMIN_PASSWORD={pw}\n".encode(),
            f"ENGINE_ADMIN_EMAIL = {em} \n"
            f"ENGINE_ADMIN_PASSWORD = {pw} \n".encode(),
            f"ENGINE_ADMIN_PASSWORD={pw} # a comment\n"
            f"ENGINE_ADMIN_EMAIL={em}\n".encode(),
            b"\xef\xbb\xbf"
            + f"ENGINE_ADMIN_EMAIL={em}\n"
              f"ENGINE_ADMIN_PASSWORD={pw}\n".encode(),
        ]
        for i, given in enumerate(cases):
            f = tmp / f"plain{i}.env"
            f.write_bytes(given)
            out = json.loads(self._harness(tmp, "parse", str(f)))
            self.assertEqual(out.get("email"), em, (i, out))
            self.assertEqual(out.get("password"), pw, (i, out))

    # -- Fix 3 E2E: quoted-CR password verifies, creds kept ---------
    def test_w20_e2e_quoted_cr_password_verifies_creds_kept(self):
        env = (b"ENGINE_ADMIN_EMAIL=e@x.io\n"
               b'ENGINE_ADMIN_PASSWORD="a\rb"\n')
        tmp = self._fixture(env, ENGINE_VERIFY_JS)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc,
                   lambda: (tmp / "logins.jsonl").exists(),
                   tmp=tmp, what="verify login POST")
        self._wait(
            proc,
            lambda: bool((tmp / "logins.jsonl").read_text()
                         .strip()),
            tmp=tmp, what="verify login body")
        time.sleep(1)
        logins = [json.loads(ln) for ln in
                  (tmp / "logins.jsonl").read_text().splitlines()
                  if ln.strip()]
        # The launcher verified with the FULL dotenv-view
        # value — not the wave-19 truncated '"a'.
        self.assertEqual(logins[0]["password"], "a\nb", logins)
        self.assertEqual(logins[0]["email"], "e@x.io", logins)
        # The stub accepted (200), so nothing was deleted:
        # the credential lines survive byte-present and no
        # foreign-claim removal was logged. (Pre-fix: 401 on
        # the truncated value -> removeEngineAdminCreds
        # gutted the .env to the 3-byte residue.)
        env_after = (tmp / "app" / ".env").read_bytes()
        self.assertIn(b"ENGINE_ADMIN_PASSWORD", env_after)
        self.assertIn(b"ENGINE_ADMIN_EMAIL", env_after)
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertNotIn("now removed", log)

    # -- Fix 4: lock interleave + exit guard (algorithm level) ------
    def test_w20_lock_interleave_and_exit_guard(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        out = self._lockharness(tmp, "interleave")
        # B decided the stale pid dead and was preempted at
        # its guard re-read; A completed its reclaim. B's
        # re-read sees A's fresh lock, so B must NOT unlink
        # it and must exit already-running: exactly one owner.
        self.assertTrue(out["aResult"]["owner"], out)
        self.assertFalse(out["bResult"]["owner"], out)
        self.assertEqual(out["bExited"], 0, out)
        self.assertTrue(out["lockAfter"].startswith("410010"),
                        out)
        # Exit leg: A's exit handler leaves a successor's
        # lock intact (content still names the successor).
        self.assertTrue(
            out["lockAfterAExit"].startswith("410011"), out)
        # Fresh acquisition writes the corroborated content
        # "<pid> <start-epoch-ms>" and a clean exit removes
        # only its own lock.
        out = self._lockharness(tmp, "fresh")
        self.assertTrue(out["result"]["owner"], out)
        parts = out["content"].strip().split()
        self.assertEqual(len(parts), 2, out)
        self.assertTrue(parts[0].isdigit(), out)
        self.assertTrue(parts[1].isdigit(), out)
        self.assertGreater(int(parts[1]), 10**12, out)
        self.assertFalse(out["existsAfterExit"], out)

    # -- Fix 5: unprovable stale locks (algorithm level) -------------
    def test_w20_lock_wedges(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # Backdated unparseable locks are corpses: reclaimed.
        for kind in ("empty_old", "garbage_old", "dir_old",
                     "recycled"):
            out = self._lockharness(tmp, "wedge", kind)
            self.assertTrue(out["result"]["owner"], (kind, out))
        # Young unparseable locks stay fail-closed (a holder
        # may be mid-write), and the refusal names the file.
        for kind in ("empty_young", "garbage_young"):
            out = self._lockharness(tmp, "wedge", kind)
            self.assertFalse(out["result"]["owner"], (kind, out))
            self.assertEqual(out["exited"], 0, (kind, out))
            joined = " ".join(out["logs"])
            self.assertIn("already running", joined, (kind, out))
            self.assertIn(out["lockPath"], joined, (kind, out))
        # A genuine live holder (lock mtime ~ its process
        # start) is refused — the recycled-pid check must
        # never refuse the genuine writer.
        out = self._lockharness(tmp, "wedge", "genuine")
        self.assertFalse(out["result"]["owner"], out)
        self.assertEqual(out["exited"], 0, out)

    # -- Fix 5: wedges over real boots (netns) ------------------------
    def test_w20_lock_real_boot_wedges(self):
        # Empty lock backdated past 60s: boot proceeds.
        tmp = self._fixture(b"ENCRYPTION_KEY=abc\n",
                            ENGINE_CLAIM_JS)
        lock = tmp / ".nexuslocal.lock"
        lock.write_bytes(b"")
        old = time.time() - 3600
        os.utime(lock, (old, old))
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc, lambda: (tmp / "setup.jsonl").exists(),
                   tmp=tmp, what="boot past backdated empty lock")
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertNotIn("already running", log)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        # Fresh empty lock: this launch refuses, naming the
        # lock path, and sends no engine traffic.
        tmp = self._fixture(b"ENCRYPTION_KEY=abc\n",
                            ENGINE_CLAIM_JS)
        lock = tmp / ".nexuslocal.lock"
        lock.write_bytes(b"")
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc, lambda: proc.poll() is not None,
                   timeout=20, tmp=tmp, what="young-lock refusal")
        self.assertEqual(proc.returncode, 0)
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertIn("already running", log)
        self.assertIn(str(lock), log)
        self.assertFalse((tmp / "setup.jsonl").exists())

    def test_w20_lock_real_boot_recycled_pid(self):
        # A lock naming a live UNRELATED pid (a sleeper that
        # started long after the lock was written) is a
        # recycled pid: on Linux the /proc start-time check
        # proves it is not the writer and the boot proceeds.
        if sys.platform != "linux":
            self.skipTest("recycled-pid check is Linux-only")
        tmp = self._fixture(b"ENCRYPTION_KEY=abc\n",
                            ENGINE_CLAIM_JS)
        sleeper = subprocess.Popen(["sleep", "300"])
        try:
            lock = tmp / ".nexuslocal.lock"
            lock.write_text(f"{sleeper.pid} {int(time.time()*1000)}")
            old = time.time() - 3600
            os.utime(lock, (old, old))
            proc = self._boot(tmp)
            self._precheck_ok(tmp)
            self._wait(proc,
                       lambda: (tmp / "setup.jsonl").exists(),
                       tmp=tmp, what="boot past recycled-pid lock")
            log = (tmp / "startup.log").read_text(
                errors="replace")
            self.assertNotIn("already running", log)
        finally:
            sleeper.kill()
            sleeper.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
