#!/usr/bin/env python3
"""Regression tests for the wave-25 fix (security audit run-24:
1 confirmed residual finding, LOW).

Fix (L24-L1, fix-incompleteness of L23-L3; bin/nexuslocal.js):
  the wave-24 splitter escaped-close retest lived ONLY in the
  EOF branch of _splitQuoted20, so it engaged only when the
  span survived the main scan unterminated. The wave-22
  in-scan even-close/junk-remainder machinery consumes the
  span one branch earlier whenever a same-char even quote
  appears later — most realistically the NEXT credential
  record's own opening quote (C15) — and the fabricated
  truncated first line survives, with its verify-deletion
  arm. Fix (the verifier's prototype, patch-inscan-retest):
  hoist the retest into the in-scan junk branch — in the
  junk-remainder branch, before the naive re-split, collect
  the span's odd-backslash candidates over [recStart, i),
  re-test them LAST-to-FIRST with the SAME remainder test;
  on a pass, emit the span up to the candidate as ONE record
  (line endings protected as SENT) and resume scanning AFTER
  the candidate's closing line. No pass: fall through to the
  existing re-split, byte-unchanged. The even-backslash
  remainder machinery and the EOF branch are untouched.

Run:  python3 -m unittest tests.test_wave25_fixes -v
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
sys.path.insert(0, str(REPO / "tests"))

import test_wave18_fixes as _w18  # noqa: E402

ENGINE_CLAIM_JS = _w18.ENGINE_CLAIM_JS

# Stub engine holding the DOTENV view of the fixture file:
# status needsSetup:false; login answers 200 ONLY for the
# held pair (passed via HELD_JSON) and logs every attempt.
ENGINE_VERIFY_JS = r"""
const http=require('http'),fs=require('fs');
fs.writeFileSync(process.env.ENGINE_PID,String(process.pid));
const HELD=JSON.parse(process.env.HELD_JSON);
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{res.setHeader('Content-Type','application/json');
if(req.url==='/api/auth/status'){res.end(JSON.stringify({needsSetup:false}));}
else if(req.url==='/api/auth/login'){fs.appendFileSync(process.env.LOGIN_FILE,b+'\n');
  let ok=false; try{const j=JSON.parse(b); ok=(j.email===HELD.email&&j.password===HELD.password);}catch(e){}
  res.statusCode=ok?200:401; res.end('{}');}
else{res.statusCode=404;res.end('{}');}});}).listen(3001,'127.0.0.1');
"""

NODE_HARNESS25_JS = r"""
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


class Wave25LauncherTests(unittest.TestCase):

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

    # -- fixture (wave-24 shape) ------------------------------------
    def _fixture(self, env_bytes, engine_js, held=None):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w25-launcher-"))
        self._tmps.append(tmp)
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        (tmp / "harness.js").write_text(NODE_HARNESS25_JS)
        (tmp / "held.json").write_text(json.dumps(held or {}))
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
            "HELD_JSON": (tmp / "held.json").read_text(),
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

    # -- L24-L1: pre-empted spans now close at the candidate ---------
    def test_w25_l1_preempted_span_shapes(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # C15 (primary): PW span's escaped close, then the EMAIL
        # record's own opening quote pre-empts (junk remainder).
        out = self._parse(tmp, "c15",
                          self.PW + '"abc\n' + BS + '"\n'
                          'ENGINE_ADMIN_EMAIL="e@x.io"\n')
        self.assertEqual(out.get("password"), "abc\n" + BS, out)
        self.assertEqual(out.get("email"), "e@x.io", out)
        self.assertNotEqual(out.get("password"), '"abc', out)
        # C8: BOTH spans escaped-close — the first span is fixed
        # too now (pre-fix only the second, via the EOF retest).
        out = self._parse(tmp, "c8",
                          self.PW + '"wxyz\n' + BS + '"\n'
                          'ENGINE_ADMIN_EMAIL="em\n' + BS + '"\n')
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        self.assertEqual(out.get("email"), "em\n" + BS, out)
        # C9: a NORMAL dq multiline follows the escaped close.
        out = self._parse(tmp, "c9",
                          self.PW + '"wxyz\n' + BS + '"\n'
                          'ENGINE_ADMIN_EMAIL="e1\ne2"\n')
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        self.assertEqual(out.get("email"), "e1\ne2", out)
        # C16: plain tail line with an even quote + junk.
        out = self._parse(tmp, "c16",
                          self.EM + self.PW + '"wxyz\n' + BS + '"\n'
                          'tail" junk\n')
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        # C18: comment line containing an even quote.
        out = self._parse(tmp, "c18",
                          self.EM + self.PW + '"wxyz\n' + BS + '"\n'
                          '# note "x\n')
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        # V5: candidate line carries a clean comment remainder,
        # still pre-empted pre-fix by a later quoted record.
        out = self._parse(tmp, "v5",
                          self.EM + self.PW + '"wxyz\n' + BS
                          + '" # note\nOTHER="x"\n')
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        # S11: pre-empting quote is a non-cred record's opening
        # quote with junk after its own close.
        out = self._parse(tmp, "s11",
                          self.PW + '"abc\n' + BS + '"\n'
                          'OTHER="zz" tail\n')
        self.assertEqual(out.get("password"), "abc\n" + BS, out)
        # S12: pre-empting quote is the CLOSING quote of a later
        # span (clean remainder there does not rescue pre-fix,
        # because the naive re-split consumed the span first).
        out = self._parse(tmp, "s12",
                          self.PW + '"abc\n' + BS + '"\n'
                          'OTHER="x\ny"\n')
        self.assertEqual(out.get("password"), "abc\n" + BS, out)

    def test_w25_l1_same_line_and_multi_candidate(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # S7: candidate and pre-empting quote on the SAME closing
        # line — the candidate's remainder is a comment that
        # itself contains the even quote.
        out = self._parse(tmp, "s7",
                          self.EM + self.PW + '"wxyz\n' + BS
                          + '" # "x" tail\n')
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)
        # S8: two odd candidates before the even-junk quote; the
        # LAST fails its remainder test, an EARLIER one passes —
        # the retest must iterate last-to-first SKIPPING failures.
        out = self._parse(tmp, "s8",
                          self.EM + self.PW + '"wxyz\n' + BS + '"\n'
                          + BS + '" junk\ntail" junk\n')
        self.assertEqual(out.get("password"), "wxyz\n" + BS, out)

    def test_w25_l1_quote_classes_and_crlf(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # V1: single-quote analogue of C15.
        out = self._parse(tmp, "v1sq",
                          self.PW + "'abc\n" + BS + "'\n"
                          "ENGINE_ADMIN_EMAIL='e@x.io'\n")
        self.assertEqual(out.get("password"), "abc\n" + BS, out)
        self.assertEqual(out.get("email"), "e@x.io", out)
        # V2: backtick analogue of C15.
        out = self._parse(tmp, "v2bt",
                          self.PW + "`abc\n" + BS + "`\n"
                          "ENGINE_ADMIN_EMAIL=`e@x.io`\n")
        self.assertEqual(out.get("password"), "abc\n" + BS, out)
        self.assertEqual(out.get("email"), "e@x.io", out)
        # V3: CRLF form of C15.
        out = self._parse(tmp, "v3crlf",
                          self.PW + '"abc\r\n' + BS + '"\r\n'
                          'ENGINE_ADMIN_EMAIL="e@x.io"\r\n')
        self.assertEqual(out.get("password"), "abc\n" + BS, out)
        self.assertEqual(out.get("email"), "e@x.io", out)

    def test_w25_l1_email_leg(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # V4: the EMAIL span is the escaped-close one; the quoted
        # PASSWORD record after it pre-empts pre-fix.
        out = self._parse(
            tmp, "v4email",
            'ENGINE_ADMIN_EMAIL="em\n' + BS + '"\n'
            + self.PW + '"VerPw24"\n')
        self.assertEqual(out.get("email"), "em\n" + BS, out)
        self.assertEqual(out.get("password"), "VerPw24", out)
        self.assertNotEqual(out.get("email"), '"em', out)

    # -- Controls: byte-identical pre/post fix ------------------------
    def test_w25_l1_controls_byte_unchanged(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        # C17: later even quote with a CLEAN remainder — the
        # longest close still wins over the earlier candidate.
        out = self._parse(tmp, "c17",
                          self.EM + self.PW + '"wxyz\n' + BS + '"\n'
                          'tail"\n')
        self.assertEqual(out.get("password"),
                         "wxyz\n" + BS + '"\ntail', out)
        # C19: even-junk quote BEFORE any odd candidate — no
        # rescue; the fabricated value is dotenv's own answer.
        out = self._parse(tmp, "c19",
                          self.EM + self.PW + '"wxyz\ntail" junk\n'
                          + BS + '"\n')
        self.assertEqual(out.get("password"), '"wxyz', out)
        # C26: adoption-side analogue (even-junk line then
        # escaped close) — absent in both parsers.
        out = self._parse(tmp, "c26",
                          self.EM + self.PW + '\n"wxyz\ntail" junk\n'
                          + BS + '"\n')
        self.assertFalse(out.get("password"), out)
        self.assertEqual(out.get("email"), "e@x.io", out)
        # QC1: single-line terminal escaped close.
        out = self._parse(tmp, "qc1",
                          self.EM + self.PW + '"w' + BS + '"\n')
        self.assertEqual(out.get("password"), "w" + BS, out)
        # QC2: escaped close then a later REAL clean close —
        # the full span wins in-scan; no retest engages.
        out = self._parse(tmp, "qc2",
                          self.EM + self.PW + '"wxyz\n' + BS + '"\n'
                          'more"\n')
        self.assertEqual(out.get("password"),
                         "wxyz\n" + BS + '"\nmore', out)
        # QC3: junk remainder after the escaped close, no later
        # quote — the fabrication IS dotenv's answer.
        out = self._parse(tmp, "qc3",
                          self.EM + self.PW + '"wxyz\n' + BS
                          + '" junk\n')
        self.assertEqual(out.get("password"), '"wxyz', out)
        # QC4: no quote after the opening at all.
        out = self._parse(tmp, "qc4",
                          self.EM + self.PW + '"wxyz\nOTHER=1\n')
        self.assertEqual(out.get("password"), '"wxyz', out)
        # QC5: normal multiline even close.
        out = self._parse(tmp, "qc5",
                          self.EM + self.PW + '"a\nb"\n')
        self.assertEqual(out.get("password"), "a\nb", out)
        # QC6: two normal multilines.
        out = self._parse(tmp, "qc6",
                          'ENGINE_ADMIN_EMAIL="e1\ne2"\n'
                          + self.PW + '"p1\np2"\n')
        self.assertEqual(out.get("email"), "e1\ne2", out)
        self.assertEqual(out.get("password"), "p1\np2", out)
        # S6 bound: odd candidate with JUNK remainder + later
        # even-junk quote — no candidate passes, no rescue.
        out = self._parse(tmp, "s6",
                          self.EM + self.PW + '"wxyz\n' + BS
                          + '" junk\ntail" junk\n')
        self.assertEqual(out.get("password"), '"wxyz', out)
        # S10 bound: even-junk quote on the candidate's own line
        # after the odd quote makes its remainder fail.
        out = self._parse(tmp, "s10",
                          self.EM + self.PW + '"wxyz\n' + BS
                          + '" tail" junk\nOTHER=1\n')
        self.assertEqual(out.get("password"), '"wxyz', out)

    # -- E2E: the C15 deletion arm is closed --------------------------
    def test_w25_l1_e2e_c15_boot(self):
        held = {"email": "vx@x.io", "password": "vx9\n" + BS}
        env = ('ENGINE_ADMIN_PASSWORD="vx9\n' + BS + '"\n'
               'ENGINE_ADMIN_EMAIL="vx@x.io"\n').encode("utf-8")
        tmp = self._fixture(env, ENGINE_VERIFY_JS, held=held)
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        # Post-fix: exactly ONE login POST with the exact
        # dotenv-view password; the engine answers 200, the
        # .env stays byte-intact and no foreign-claim warning
        # is logged. Pre-fix: the fabricated '"vx9' was POSTed,
        # the 401 deleted both credential lines.
        self._wait(proc, lambda: (tmp / "logins.jsonl").exists(),
                   tmp=tmp, what="C15 verify login")
        time.sleep(2)
        logins = [json.loads(x) for x in
                  (tmp / "logins.jsonl").read_text().splitlines()
                  if x.strip()]
        self.assertEqual(logins, [held], logins)
        self.assertEqual((tmp / "app" / ".env").read_bytes(), env)
        self.assertNotIn("claimed by credentials that are NOT",
                         self._log(tmp))


if __name__ == "__main__":
    unittest.main()
