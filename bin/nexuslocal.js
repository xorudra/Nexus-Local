#!/usr/bin/env node
/**
 * nexuslocal - Global CLI launcher for Nexus-Local
 *
 * Install: npm install -g nexuslocal
 * Run:     nexuslocal (from any directory)
 *
 * This script locates the installed package and launches the
 * dashboard + engine, reusing the same setup logic as start.bat.
 */
"use strict";

const { spawn, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

// Package root = parent of bin/
const PKG_ROOT = path.join(__dirname, "..");
const APP_DIR = path.join(PKG_ROOT, "app");
const LOG_FILE = path.join(PKG_ROOT, "startup.log");

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try { fs.appendFileSync(LOG_FILE, line); } catch (e) {}
  console.log(msg);
}

function findPython() {
  // Check system Python first
  for (const cmd of ["python", "python3", "py"]) {
    try {
      execSync(`"${cmd}" --version`, { stdio: "ignore", windowsHide: true });
      return cmd;
    } catch (e) {}
  }
  // Check portable Python in tools/
  const toolsPython = path.join(PKG_ROOT, "tools", "python", "python.exe");
  if (fs.existsSync(toolsPython)) return `"${toolsPython}"`;
  return null;
}

// Wave 12 (L1/L2/L3): ONE shared .env reader for the ENGINE_ADMIN
// credentials, used by the claim path, the verify path and the
// credential-removal path. dotenv grammar for these keys: a leading
// BOM is stripped, whitespace around `=` is tolerated, one layer of
// surrounding single/double quotes is stripped, an EMPTY value
// counts as ABSENT (a later line for the same key wins over an
// empty earlier one), and the first non-empty match wins. The old
// private regex readers disagreed with all of that: an empty first
// line shadowed valid credentials in verifyClaim, quoted/spaced
// values were read literally (a quoted password was POSTed with its
// quotes on, and the 401 that earned deleted every credential
// line), and a BOM made the first line invisible.
function parseEngineAdminCreds(envTxt) {
  let txt = envTxt || "";
  if (txt.charCodeAt(0) === 0xFEFF) txt = txt.slice(1);
  // Wave 21 (run-20 launcher L20-L1): the splitter's in-quote
  // line-ending protection byte is a PER-PARSE sentinel
  // VERIFIED ABSENT from this input (the first absent
  // candidate wins). Wave 22 (run-21 L21-L1): on candidate
  // EXHAUSTION there is no fallback byte — a byte known
  // present would revive the L20-L1 mangling verbatim, and a
  // naive split would re-open the L19-L1 truncation — so the
  // selection returns null and this parse fails CLOSED as
  // absent (the designed no-credentials path). The restores
  // below
  // therefore only ever convert bytes the splitter itself
  // inserted: with an absent-verified sentinel, no literal
  // byte in the file can collide, so a literal control byte
  // inside a credential value survives as data, exactly as
  // dotenv reads it.
  const SENT = (() => {
    for (const cand of ["\u0001", "\u0002", "\u0003", "\u0004",
                        "\u0005", "\u0006", "\u0007", "\u0008",
                        "\u000B", "\u000C", "\u000E", "\u000F",
                        "\u0010", "\u0011", "\u0012", "\u0013",
                        "\u0014", "\u0015", "\u0016", "\u0017",
                        "\u0018", "\u0019", "\u001A", "\u001B",
                        "\u001C", "\u001D", "\u001E", "\u001F"]) {
      if (!txt.includes(cand)) return cand;
    }
    return null;
  })();
  if (SENT === null) return { hasEmail: false,
                              hasPassword: false };
  const out = { hasEmail: false, hasPassword: false };
  // Wave 19 (run-18 launcher L18-L1): split on every line
  // ending dotenv accepts — /\r\n|\r|\n/ — not just /\r?\n/:
  // a piece ending in a lone \r failed the per-line $ anchor
  // below, so CRCRLF / CR-only / trailing-CR-at-EOF records
  // read as ABSENT to the launcher while the engine's dotenv
  // recovered them (a permanent false foreign-claim alarm,
  // and the claim was never verified).
  // Wave 20 (run-19 launcher L19-L1): that split cut INSIDE
  // quoted values — dotenv 17.4.2 treats a quoted value as
  // multiline and normalises a literal CR/LF/CRLF inside
  // quotes to \n, while the launcher read the truncated
  // first piece, POSTed it, and the definitive 401 deleted
  // every recorded credential line. The splitter below
  // splits only OUTSIDE quotes (prototype-verified against
  // real dotenv 17.4.2 on 13/13 shapes): quote mode opens
  // ONLY when the quote char is the first char after the
  // record's `=` (after optional whitespace — wave 21:
  // the full /\s/ set minus \r and \n) and closes at
  // the matching quote preceded by an EVEN number of
  // backslashes (an odd count makes it data — dotenv's own
  // rule, the same one the closing-quote scan below uses).
  // Line-ending bytes inside quotes are protected as SENT
  // (the per-parse absent-verified sentinel above) during
  // the scan and restored to \n after the per-record parse
  // (dotenv's normalisation).
  // Wave 21 (run-20 launcher L20-L2/L3/L4): quote mode arms
  // ONLY on a record whose text before its first `=` is an
  // assignment prefix (/^\s*(?:export\s+)?[\w.-]+\s*$/ —
  // wave 22, run-21 L21-L2: the key class is + not * — a
  // keyless record is not an assignment (dotenv requires
  // [\w.-]+) and must never arm quote mode —
  // comments, commented-out/truncated example lines and
  // invalid-key lines never arm, mirroring dotenv, which
  // discards them before any value parsing); and the
  // backtick is a third value-start quote, exactly as
  // dotenv 17.4.2 has it, treated as single-quote downstream.
  // Stated limits: a quote appearing mid-value is not
  // tracked (dotenv keys its multiline handling on the
  // value-start quote too — this is what saves an apostrophe
  // in an unquoted value and a quote in a trailing comment);
  // an unterminated quote is NOT glued — the tail record
  // falls back to the naive split, matching dotenv's
  // fallback parse.
  const _splitQuoted20 = (s) => {
    const out = [];
    let cur = "", q = null, seenEq = false, valBegun = false;
    let recStart = 0, i = 0;
    const bsBefore = (pos) => {
      let n = 0;
      for (let j = pos - 1; j >= 0 && s[j] === "\\"; j--) n++;
      return n;
    };
    while (i < s.length) {
      const c = s[i];
      if (q) {
        if (c === q && bsBefore(i) % 2 === 0) {
          // Wave 22 (run-21 L21-L3+L21-L4, merged): dotenv's
          // quoted alternative counts as a multiline ONLY when
          // the rest of the CLOSING physical line is whitespace
          // or a comment; anything else throws the record back
          // to the unquoted per-line parse. Mirror that: peek
          // at the closing line's remainder — if it is not
          // /^\s*(#.*)?$/, the record was never a valid
          // multiline (see the re-split below). Properly
          // closed multilines are untouched. One path for all
          // three quote chars — no backtick-specific code.
          let _eol22 = i + 1;
          while (_eol22 < s.length && s[_eol22] !== "\r"
                 && s[_eol22] !== "\n") _eol22++;
          if (/^\s*(#.*)?$/.test(s.slice(i + 1, _eol22))) {
            q = null; cur += c; i++; continue;
          }
          // The span was never a valid multiline. Re-split
          // naively from recStart up to the closing line, then
          // resume quote-aware scanning AT the closing line as
          // a fresh record start — the credential record
          // swallowed inside the span becomes its own record
          // again, and if the closing line itself opens a
          // legitimate multiline it still parses as one (this
          // same check applies at its close). A close on the
          // record's OWN line is the degenerate case: the
          // whole line is the span, re-split it and move on.
          const _ls22 = Math.max(
            s.lastIndexOf("\n", i - 1),
            s.lastIndexOf("\r", i - 1)) + 1;
          if (_ls22 > recStart) {
            const _pre22 = s.slice(recStart, _ls22)
              .split(/\r\n|\r|\n/);
            if (_pre22[_pre22.length - 1] === "") _pre22.pop();
            for (const piece of _pre22) out.push(piece);
            i = _ls22; recStart = i; cur = ""; q = null;
            seenEq = false; valBegun = false;
            continue;
          }
          for (const piece of s.slice(recStart, _eol22)
                 .split(/\r\n|\r|\n/)) {
            out.push(piece);
          }
          if (_eol22 >= s.length) return out;
          i = _eol22 + (s[_eol22] === "\r"
                        && s[_eol22 + 1] === "\n" ? 2 : 1);
          recStart = i; cur = ""; q = null;
          seenEq = false; valBegun = false;
          continue;
        }
        if (c === "\r" || c === "\n") {
          if (c === "\r" && s[i + 1] === "\n") i++;
          cur += SENT; i++; continue;
        }
        cur += c; i++; continue;
      }
      if (c === "\r" || c === "\n") {
        if (c === "\r" && s[i + 1] === "\n") i++;
        out.push(cur); cur = "";
        seenEq = false; valBegun = false;
        i++; recStart = i; continue;
      }
      if (!seenEq && c === "="
          && /^\s*(?:export\s+)?[\w.-]+\s*$/.test(cur)) {
        seenEq = true; cur += c; i++; continue;
      }
      if (seenEq && !valBegun && /\s/.test(c)
          && c !== "\r" && c !== "\n") {
        cur += c; i++; continue;
      }
      if (seenEq && !valBegun && (c === '"' || c === "'" || c === "`")) {
        q = c; valBegun = true; cur += c; i++; continue;
      }
      if (seenEq) valBegun = true;
      cur += c; i++;
    }
    if (q) {
      // Unterminated quote: dotenv fails the multiline
      // match and falls back to per-line parsing — the
      // tail record re-splits naively, exactly as before.
      for (const piece of s.slice(recStart)
             .split(/\r\n|\r|\n/)) {
        out.push(piece);
      }
    } else {
      out.push(cur);
    }
    return out;
  };
  const _lines22 = _splitQuoted20(txt);
  for (let _li22 = 0; _li22 < _lines22.length; _li22++) {
    const line = _lines22[_li22];
    const m = line.match(/^\s*(?:export\s+)?(ENGINE_ADMIN_EMAIL|ENGINE_ADMIN_PASSWORD)\s*=\s*(.*)$/);
    if (!m) continue;
    const isEmail = m[1] === "ENGINE_ADMIN_EMAIL";
    if (isEmail) out.hasEmail = true; else out.hasPassword = true;
    let v = m[2].trim();
    // Wave 22 (run-21 L21-L5, the verifier's narrower fix):
    // a credential record with an EMPTY value adopts a
    // following record consisting SOLELY of a quoted string
    // — dotenv reads KEY=<EOL>"v" as KEY="v". The adoption
    // is parse-local (a splitter-level join would leave the
    // sentinel byte leading the value and mangle it); the
    // adopted text flows through the quoted-value parse
    // below exactly as an on-line quoted value does.
    if (v === "" && _li22 + 1 < _lines22.length) {
      const _nx22 = _lines22[_li22 + 1].trim();
      if (_nx22.length >= 2
          && (_nx22[0] === '"' || _nx22[0] === "'"
              || _nx22[0] === "`")) {
        const _nq22 = _nx22[0];
        let _end22 = -1;
        for (let _k22 = 1; _k22 < _nx22.length; _k22++) {
          if (_nx22[_k22] !== _nq22) continue;
          let _bs22 = 0;
          for (let _j22 = _k22 - 1; _j22 >= 0
               && _nx22[_j22] === "\\"; _j22--) _bs22++;
          if (_bs22 % 2 === 0) { _end22 = _k22; break; }
        }
        if (_end22 === _nx22.length - 1) {
          v = _nx22;
          _li22++;
        }
      }
    }
    // The value with NO comment handling at all (quote-strip only):
    // the alternate form verifyClaim retries with before it may
    // declare a foreign claim (wave 14, run-13 launcher L13-2).
    let raw = v;
    if (raw.length >= 2
        && ((raw[0] === '"' && raw[raw.length - 1] === '"')
            || (raw[0] === "'" && raw[raw.length - 1] === "'")
            || (raw[0] === "`" && raw[raw.length - 1] === "`"))) {
      raw = raw.slice(1, -1);
    }
    // Wave 13 (run-12 launcher): dotenv's inline-comment rule —
    // an unquoted value truncates at the first '#' (even with no
    // preceding space, so `= # none yet` is EMPTY, i.e. absent);
    // a quoted value ends at its closing quote and the rest is a
    // comment. The existing quote-strip below then applies.
    // Wave 14 (run-13 launcher): (L13-1) the closing-quote scan is
    // escape-aware — a quote preceded by an ODD number of
    // backslashes is data, not the terminator, exactly as dotenv
    // treats it; the old indexOf truncated `"a\"b#c"` to `a\` and
    // verify then DELETED valid credentials. (L13-2) the unquoted
    // branch treats '#' as a comment starter only at value start
    // or when preceded by whitespace (/^#/ or /\s+#/): this
    // record's authoritative value is the engine password itself
    // (an arbitrary API-set / pre-seeded string that never passed
    // through dotenv grammar), so a '#' inside it is data — while
    // `abc123 # comment` and `= # none yet` keep their run-12
    // behaviour.
    const _quoted15 = v.startsWith('"') || v.startsWith("'") || v.startsWith("`");
    if (_quoted15) {
      const q = v[0];
      let end = -1;
      for (let i = 1; i < v.length; i++) {
        if (v[i] !== q) continue;
        let bs = 0;
        for (let j = i - 1; j >= 0 && v[j] === "\\"; j--) bs++;
        if (bs % 2 === 0) { end = i; break; }
      }
      if (end > 0) {
        // Truncate only when what follows the closing quote is
        // empty or a comment; otherwise the quotes are data
        // throughout (dotenv: `"abc""def"` -> `abc""def`) and the
        // whole-value quote-strip below applies instead.
        const rest = v.slice(end + 1);
        if (/^\s*(#.*)?$/.test(rest)) v = v.slice(0, end + 1);
      }
    } else {
      const hm = v.match(/\s+#|^#/);
      if (hm) v = v.slice(0, hm.index).trim();
    }
    let _dqPre16 = null;
    if (v.length >= 2
        && ((v[0] === '"' && v[v.length - 1] === '"')
            || (v[0] === "'" && v[v.length - 1] === "'")
            || (v[0] === "`" && v[v.length - 1] === "`"))) {
      const _dq15 = v[0] === '"';
      v = v.slice(1, -1);
      // Wave 15 (run-14 launcher L14-1): dotenv 17 expands exactly
      // \n and \r in DOUBLE-quoted values, in this order, with
      // these regexes — \t, \\ and \" stay literal, and
      // single-quoted values are never expanded.
      if (_dq15) {
        // Wave 16 (run-15 launcher L15-1): remember the
        // pre-expansion literal — when the expansion changed the
        // value it becomes the password alternate below (the
        // primary in every pre-wave-15 release, and the form a
        // legacy engine may still hold).
        _dqPre16 = v;
        v = v.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
        if (v === _dqPre16) _dqPre16 = null;
      }
    }
    // Wave 20 (L19-L1): hand back the real line-ending byte
    // the quote-aware splitter protected inside quoted
    // values (dotenv normalises those bytes to \n). Wave 21
    // (L20-L1): the protection byte is SENT, the per-parse
    // absent-verified sentinel — these restores only ever
    // convert bytes the splitter itself inserted.
    v = v.split(SENT).join("\n");
    raw = raw.split(SENT).join("\n");
    if (_dqPre16) _dqPre16 = _dqPre16.split(SENT).join("\n");
    if (!v) continue;  // empty = absent: fall through to a later line
    if (isEmail && out.email === undefined) out.email = v;
    if (!isEmail && out.password === undefined) {
      out.password = v;
      // The alternate form for verifyClaim's one retry: the raw
      // value when comment handling shortened the primary, else
      // (symmetrically) the dotenv-truncated value when the
      // primary kept a '#' the engine may not hold.
      let alt = null;
      // Wave 15 (run-14 launcher L14-2, leg (a) only): the
      // alternate is built ONLY from unquoted lines, where the
      // raw and truncated forms are both genuine alternate
      // parses. For a quoted line the raw tail still carries the
      // quotes and the comment text — a candidate that can never
      // be the engine password — and the primary parse is
      // authoritative, so no alternate is offered.
      if (!_quoted15) {
        if (raw && raw !== v) alt = raw;
        else {
          const h = v.indexOf("#");
          if (h > 0) alt = v.slice(0, h).trim() || null;
        }
      } else if (_dqPre16) {
        // Wave 16 (run-15 launcher L15-1, backslash leg only):
        // a DOUBLE-quoted line whose expansion changed the value
        // offers the pre-expansion literal as its one alternate —
        // a genuine alternate parse, NOT the raw-tail junk alt
        // L14-2(a) killed (that still carried quotes and comment
        // text), and NOT a pre-'#' alternate (that leg was
        // rejected in run-15: no reader ever parsed a quoted
        // value truncated at '#').
        alt = _dqPre16;
      }
      if (alt && alt !== v) out.passwordAlt = alt;
    }
  }
  return out;
}

function readEngineAdminCreds(envFile) {
  try {
    return parseEngineAdminCreds(fs.readFileSync(envFile, "utf8"));
  } catch (e) {
    return { hasEmail: false, hasPassword: false };
  }
}

function removeEngineAdminCreds(envFile) {
  // The credential-removal path uses the same grammar: drop EVERY
  // ENGINE_ADMIN line, whatever its spacing, quoting or BOM.
  // Wave 18 (run-17 launcher L17-1): the write-back regexes (here
  // and claimStep's two in-place rewrites) anchor with HORIZONTAL
  // whitespace only ([ \t], never \s) — in multiline mode ^ also
  // matches between a \r and its \n and \s* then eats the LF, so
  // on a CRLF .env a rewrite glued the cred line onto its
  // neighbour and the launcher's own parser read it back as
  // absent (a permanent false foreign-claim alarm).
  // Wave 19 (run-18 launcher L18-L2): the class is now
  // [^\S\r\n] — every whitespace the PARSER accepts (its ^\s*
  // covers VT/FF/NBSP leads, which the horizontal-only
  // narrowing silently no-oped on: a claim password recorded
  // nowhere, a removal that removed nothing) — while still
  // never crossing a line boundary (CR/LF excluded), so
  // wave 18's CRLF safety holds.
  const envTxt = fs.readFileSync(envFile, "utf8");
  fs.writeFileSync(envFile,
    envTxt.replace(/^\uFEFF?[^\S\r\n]*(?:export[^\S\r\n]+)?ENGINE_ADMIN_(EMAIL|PASSWORD)[^\S\r\n]*=.*\r?\n?/gm, ""));
  try { fs.chmodSync(envFile, 0o600); } catch (e) {}
}

// Wave 18 (run-17 launcher L17-2): pre-spawn port probe. A bare
// TCP connect — it sends no HTTP and no credentials: ANY listener
// on 127.0.0.1:3001 before our child starts is a foreign
// responder (a squatter, or the owner's own standalone gateway),
// and claim/verify must never engage it. Only a clean refusal
// (ECONNREFUSED) means the port is free; any other outcome is
// treated as occupied (fail closed).
function probePort3001() {
  return new Promise((resolve) => {
    const sock = require("net").connect(
      { host: "127.0.0.1", port: 3001 });
    let done = false;
    const fin = (v) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (e) {}
      resolve(v);
    };
    sock.setTimeout(1500, () => fin(true));
    sock.on("connect", () => fin(true));
    sock.on("error", (e) => fin(
      !(e && e.code === "ECONNREFUSED")));
  });
}

// Wave 13 (run-12 launcher): the shutdown path and the child
// registry live at module scope so the signal handlers can be
// registered at the TOP of main() — before the dependency gates.
// A pid-targeted SIGTERM during the (possibly minutes-long) first
// install used to orphan the npm child, which kept rewriting
// node_modules invisibly; the handlers now exist from the start
// and shutdown() can kill the in-flight install child too.
let engine = null;
let dashboard = null;
let installChild = null;
let shuttingDown = false;
let _shutdownCode = 0;

function _killTree(child, sig) {
  if (!child) return;
  // Install children are spawned detached on POSIX so the whole
  // process GROUP (sh -> npm -> its children) gets the signal.
  if (child === installChild && process.platform !== "win32"
      && child.pid) {
    try { process.kill(-child.pid, sig); return; } catch (e) {}
  }
  try { child.kill(sig); } catch (e) {}
}

function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;  // F15: the engine exit this causes is ours
  _shutdownCode = code || 0;
  log("Shutting down...");
  // Wave 14 (run-13 launcher L13-3): capture the install child (and
  // its process group) NOW. The direct child's own close handler
  // nulls the global installChild as soon as the shell dies on the
  // group SIGTERM — well before the 1500ms escalation — so an
  // escalation that re-read the global had no target and a
  // TERM-ignoring install grandchild survived launcher exit.
  const _install14 = installChild;
  const _ipgid14 = _install14 && _install14.pid;
  _killTree(_install14, "SIGTERM");
  _killTree(engine, "SIGTERM");
  _killTree(dashboard, "SIGTERM");
  setTimeout(() => {
    if (_ipgid14 && process.platform !== "win32") {
      try { process.kill(-_ipgid14, "SIGKILL"); } catch (e) {}
    }
    _killTree(_install14, "SIGKILL");
    _killTree(engine, "SIGKILL");
    _killTree(dashboard, "SIGKILL");
  }, 1500);
  setTimeout(() => process.exit(_shutdownCode), 2000);
}

function runInstall(cmd, cwd) {
  // Spawn (tracked) rather than execSync: the JS thread stays free
  // so a signal during the install reaches shutdown(), which kills
  // the install child's whole group. Resolves false on a non-zero
  // exit (the caller keeps the old error path), true on success;
  // during shutdown it never resolves (shutdown exits the process).
  return new Promise((resolve) => {
    installChild = spawn(cmd, {
      cwd, stdio: "inherit", windowsHide: false, shell: true,
      detached: process.platform !== "win32",
    });
    installChild.on("error", () => { installChild = null; resolve(false); });
    installChild.on("close", (code) => {
      installChild = null;
      resolve(code === 0);
    });
  });
}

async function main() {
  // Wave 13: signal handlers FIRST, before any install phase.
  process.on("SIGINT", () => shutdown(0));
  process.on("SIGTERM", () => shutdown(0));
  process.on("SIGHUP", () => shutdown(0));
  // Wave 19 (run-18 launcher L18-L3): single-instance lock,
  // taken before the port probe / any spawn / any engine
  // traffic — the probe cannot see a sibling whose engine
  // child has spawned but is not LISTENING yet, and a second
  // launcher used to claim that sibling's engine. The lock
  // file lives beside the launcher's other state (PKG_ROOT,
  // like startup.log), names its holder's pid, and is held
  // for the process lifetime. A stale lock (holder provably
  // dead) is reclaimed once; a live holder — or a pid that
  // cannot be read, which cannot be proven dead — means
  // another launcher owns this install and this one exits.
  const _lockPath19 = path.join(PKG_ROOT, ".nexuslocal.lock");
  let _lockFd19 = null;
  for (let _att19 = 0; _att19 < 2 && _lockFd19 === null;
       _att19++) {
    try {
      _lockFd19 = fs.openSync(_lockPath19, "wx");
    } catch (e) {
      if (!e || e.code !== "EEXIST") {
        log("ERROR: could not take the single-instance lock ("
            + ((e && e.message) || e) + ") — exiting.");
        process.exit(1);
      }
      // Wave 20 (run-19 launcher L19-L3): the lock content
      // is "<pid> <start-epoch-ms>" (written at acquisition
      // below); the pid is the first token, so bare-pid locks
      // from older launchers still parse.
      let _raw19 = "";
      try {
        _raw19 = fs.readFileSync(_lockPath19, "utf8");
      } catch (e2) {}
      const _pid19 = parseInt(
        (_raw19 || "").trim().split(/\s+/)[0], 10);
      const _provable19 = Number.isFinite(_pid19) && _pid19 > 0;
      let _alive19 = true;
      let _mtime19 = null;
      try {
        _mtime19 = fs.statSync(_lockPath19).mtimeMs;
      } catch (e5) {}
      if (_provable19) {
        try { process.kill(_pid19, 0); }
        catch (e3) { _alive19 = !!(e3 && e3.code === "EPERM"); }
        // Wave 20 (L19-L3, Linux): a RECYCLED pid is provably
        // not the writer — a genuine holder's process starts
        // BEFORE its lock write; a recycled pid's process
        // necessarily started AFTER it. /proc/<pid> start
        // time (stat field 22, clock ticks since boot, via
        // btime in /proc/stat at USER_HZ 100) against the
        // lock's mtime decides. Every read is guarded: any
        // error, or a non-Linux host, falls back to the
        // liveness-only verdict above. Windows residual,
        // stated honestly: no equivalent check is made
        // there, so a recycled pid can wedge the install
        // until the lock file — named in the refusal below —
        // is deleted by hand.
        if (_alive19 && _mtime19 !== null
            && process.platform === "linux") {
          try {
            const _stat20 = fs.readFileSync(
              "/proc/" + _pid19 + "/stat", "utf8");
            const _bt20 = /btime (\d+)/.exec(
              fs.readFileSync("/proc/stat", "utf8"));
            if (_bt20) {
              const _after20 = _stat20.slice(
                _stat20.lastIndexOf(")") + 2).split(" ");
              const _startMs20 =
                (parseInt(_bt20[1], 10)
                 + parseInt(_after20[19], 10) / 100) * 1000;
              if (_startMs20 > _mtime19 + 2000) {
                _alive19 = false;
              }
            }
          } catch (e6) {}
        }
      } else if (_mtime19 !== null
                 && Date.now() - _mtime19 > 60000) {
        // Wave 20 (L19-L3): UNPARSEABLE content (empty or
        // garbage — a crash in the create->write window,
        // foreign matter, a directory) older than 60s is a
        // corpse, never a holder being born: a genuine
        // holder writes its pid within milliseconds of
        // creating the file. 60s or younger stays
        // fail-closed, exactly as wave 19 left it.
        _alive19 = false;
      }
      if (_alive19 || _att19 === 1) {
        // Wave 20 (L19-L3): the refusal NAMES the lock
        // file — hand-deleting it is the trivial recovery,
        // and it must be discoverable from what the
        // product itself says.
        if (_provable19) {
          log("nexuslocal is already running — exiting. "
              + "(lock file " + _lockPath19 + ")");
        } else {
          log("nexuslocal is already running — exiting. "
              + "(lock file " + _lockPath19 + " has no "
              + "readable pid; if no launcher is running, "
              + "delete it and retry)");
        }
        process.exit(0);
      }
      // Wave 20 (run-19 launcher L19-L2): re-read the lock
      // immediately before unlinking and delete ONLY the
      // instance just judged — if the content changed (a
      // successor's fresh lock), do not unlink; treat it as
      // held and exit already-running. This SHRINKS the
      // reclaim race to the re-read->unlink gap; it cannot
      // eliminate that sub-syscall window (the fully atomic
      // fix is fd-based locking — a larger cross-platform
      // change, not prescribed).
      let _still19 = false;
      try {
        const _againRaw20 = fs.readFileSync(
          _lockPath19, "utf8");
        const _againPid20 = parseInt(
          (_againRaw20 || "").trim().split(/\s+/)[0], 10);
        if (_provable19) {
          _still19 = _againPid20 === _pid19;
        } else {
          const _againMt20 = fs.statSync(
            _lockPath19).mtimeMs;
          _still19 = !(Number.isFinite(_againPid20)
                       && _againPid20 > 0)
                     && Date.now() - _againMt20 > 60000;
        }
      } catch (e7) {
        // A throwing re-read (the lock path is a
        // directory) cannot resurrect content: in the
        // unparseable case the stat verdict that judged
        // the lock stale stands on its own.
        if (!_provable19) {
          try {
            _still19 = Date.now()
              - fs.statSync(_lockPath19).mtimeMs > 60000;
          } catch (e9) {}
        }
      }
      if (!_still19) {
        log("nexuslocal is already running — exiting. "
            + "(lock file " + _lockPath19 + ")");
        process.exit(0);
      }
      try { fs.unlinkSync(_lockPath19); } catch (e4) {
        // A directory at the lock path cannot be unlinked:
        // remove it only if it is an (empty) directory;
        // otherwise the next attempt refuses, naming the
        // path (L19-L3).
        try { fs.rmdirSync(_lockPath19); } catch (e8) {}
      }
    }
  }
  if (_lockFd19 !== null) {
    // Wave 20 (L19-L3): corroborated content — the pid plus
    // the writer's start epoch (Date.now() at acquisition),
    // the corroborator the recycled-pid check above reads.
    try {
      fs.writeSync(_lockFd19,
                   String(process.pid) + " " + Date.now());
    } catch (e) {}
    process.on("exit", () => {
      try { fs.closeSync(_lockFd19); } catch (e) {}
      // Wave 20 (L19-L2): unlink ONLY while the file's
      // content still names THIS pid — a successor's live
      // lock is never deleted by our exit. Unlike the
      // shrunken reclaim race, this leg IS eliminated by
      // the guard for holders running wave-20+ code (it
      // also covers the manual-deletion composition: a
      // user deleting a running launcher's lock, a
      // successor acquiring, the old holder then exiting
      // over the successor's lock). Wave 21 (run-20
      // L20-L5, comment-only): a PRE-wave-20 holder still
      // running across an in-place upgrade unlinks the
      // lock path unconditionally on exit, so during an
      // upgrade the old launcher must be STOPPED, not
      // lock-deleted, before its lock is removed; the
      // mixed-version composition self-eliminates once no
      // pre-wave-20 launcher process survives.
      try {
        const _own20 = fs.readFileSync(_lockPath19, "utf8")
          .trim().split(/\s+/)[0];
        if (_own20 === String(process.pid)) {
          fs.unlinkSync(_lockPath19);
        }
      } catch (e) {}
    });
  }
  console.log("============================================");
  console.log(" Nexus-Local - Your Personal AI Dashboard");
  console.log("============================================\n");
  log("Starting via nexuslocal CLI");

  // Verify app directory exists
  if (!fs.existsSync(path.join(APP_DIR, "server.py"))) {
    console.error("ERROR: app/server.py not found in " + PKG_ROOT);
    console.error("The installation may be corrupted. Try: npm install -g nexuslocal");
    process.exit(1);
  }

  const python = findPython();
  if (!python) {
    console.error("ERROR: Python 3.10+ not found.");
    console.error("Install from https://www.python.org/downloads/ (tick 'Add to PATH')");
    console.error("Then run 'nexuslocal' again.");
    process.exit(1);
  }
  log("Using Python: " + python);

  // Check Node.js (needed for engine)
  try {
    execSync("node --version", { stdio: "ignore", windowsHide: true });
  } catch (e) {
    console.error("ERROR: Node.js 18+ not found.");
    console.error("Install from https://nodejs.org/ then run 'nexuslocal' again.");
    process.exit(1);
  }

  // Ensure engine dependencies
  const engineServer = path.join(APP_DIR, "engine", "server");
  const nodeModules = path.join(engineServer, "node_modules");
  // Audit run-9 (L4): the gate used to be a sole dotenv sentinel —
  // a node_modules containing ONLY dotenv (an interrupted install)
  // skipped npm ci and the engine then died on a missing module in
  // total silence (stdio ignored). npm ci also writes
  // node_modules/.package-lock.json, so require both: a partial
  // tree now triggers the install.
  // Wave 11 (F14): the two sentinels alone are not enough — a
  // partial tree can keep dotenv + the hidden lockfile while losing
  // another direct dependency (express is the engine's entry point),
  // and the engine then died on every boot with the install never
  // re-attempted. Probe every direct runtime dependency named in
  // the engine's own package.json (still a cheap existence check).
  let _depsMissing = !fs.existsSync(path.join(nodeModules, "dotenv"))
      || !fs.existsSync(path.join(nodeModules, ".package-lock.json"));
  try {
    const _epkg = JSON.parse(fs.readFileSync(
      path.join(engineServer, "package.json"), "utf8"));
    // Wave 12 (L4/L5/L6): probe each direct dependency's
    // package.json (an empty directory left by an interrupted copy
    // or an antivirus quarantine is NOT an installed dependency),
    // cover `dependencies` ONLY (npm legitimately omits
    // optionalDependencies, so gating on them never converged and
    // any npm ci failure then failed the whole boot), and treat an
    // unreadable or unparseable manifest as a gate FAILURE said
    // loudly — the old silent catch{} fell back to the two
    // sentinels and hid exactly the damage this gate exists for.
    const _edeps = Object.keys(_epkg.dependencies || {});
    // Wave 13 (run-12 launcher): probe LOADABILITY, not existence —
    // require.resolve parses the dep's package.json AND resolves
    // its entry point, exactly what the engine's loader will do. A
    // manifest-only tree (or a dep whose package.json is invalid
    // JSON) used to pass the existsSync gate while the engine died
    // on every boot.
    const _unloadable = (d) => {
      try { require.resolve(d, { paths: [engineServer] }); return false; }
      catch (e) { return true; }
    };
    if (_edeps.some(_unloadable)) {
      _depsMissing = true;
    }
    // Wave 13: better-sqlite3 sits in optionalDependencies (npm may
    // omit it silently, exit 0, when its native build fails), but
    // the engine hard-requires it on every non-Android platform —
    // gate on it there. Android/Termux keeps the wave-12 exemption
    // (its node:sqlite fallback), so the gate still converges there.
    // Wave 14 (run-13 launcher L13-4): require.resolve is NOT
    // loadability for a native dep — a better-sqlite3 whose .node
    // binding is absent (npm ci --ignore-scripts tree, exit 0)
    // RESOLVES while require() fails "Could not locate the bindings
    // file", so the resolve probe certified a tree the engine dies
    // on every boot. Probe a real require in a throwaway child
    // process (a broken addon can never crash the launcher).
    // Wave 15 (run-14 launcher gate cluster — the surviving
    // run-13 gate item + L14-3 + L14-4, in verify-launcher14's
    // rank-1 shape): (i) a recursive *.node presence pre-filter —
    // a tree with NO native binding file fails the gate and is
    // reinstalled WITHOUT executing anything from it; (ii) only
    // when a binding file IS present, and only when no other
    // signal already condemns the tree, a hardened child probe
    // require()s AND instantiates the addon (better-sqlite3@12
    // loads its binding lazily, so require alone certifies
    // corrupt/wrong-arch trees), with killSignal SIGKILL so the
    // timeout is a real bound (SIGTERM can be ignored), a
    // scrubbed environment (no launcher secrets inherited) and
    // the same 15s timeout; (iii) a corrupt/wrong-arch binding
    // fails the instantiate and triggers the reinstall.
    const _bsqBindingPresent = () => {
      // Wave 16 (run-15 launcher L15-2): an unreadable SUBtree is
      // "unknown", never proof the binding is absent — skip it and
      // keep searching (only a failure at the package directory
      // itself returns false); and traverse symlinked
      // subdirectories, guarded by a visited-realpath set so a
      // symlink cycle cannot loop (the old code never traversed
      // links at all: Dirent.isDirectory() is false for them).
      const stack = [path.join(nodeModules, "better-sqlite3")];
      const seen = new Set();
      let first = true;
      while (stack.length) {
        const d = stack.pop();
        const isRoot = first;
        first = false;
        let real;
        try { real = fs.realpathSync(d); }
        catch (e) { if (isRoot) return false; continue; }
        if (seen.has(real)) continue;
        seen.add(real);
        let ents;
        try { ents = fs.readdirSync(d, { withFileTypes: true }); }
        catch (e) { if (isRoot) return false; continue; }
        for (const ent of ents) {
          const p = path.join(d, ent.name);
          if (ent.isDirectory()) { stack.push(p); continue; }
          if (ent.name.endsWith(".node")) return true;
          if (ent.isSymbolicLink()) {
            let st = null;
            try { st = fs.statSync(p); } catch (e) {}
            if (st && st.isDirectory()) stack.push(p);
          }
        }
      }
      return false;
    };
    const _bsqLoadable = () => {
      if (_unloadable("better-sqlite3")) return false;
      try {
        const { spawnSync } = require("child_process");
        const r = spawnSync(process.execPath,
          ["-e", "const DB = require('module').createRequire(process.argv[1])"
                 + "('better-sqlite3'); const db = new DB(':memory:');"
                 + " db.close();",
           path.join(engineServer, "package.json")],
          { timeout: 15000, stdio: "ignore", killSignal: "SIGKILL",
            env: { PATH: process.env.PATH || "" } });
        return !r.error && r.status === 0;
      } catch (e) { return false; }
    };
    if (process.platform !== "android"
        && (_epkg.optionalDependencies || {})["better-sqlite3"]) {
      if (!_bsqBindingPresent()) {
        log("Engine dependency better-sqlite3 has no native binding (.node) file — treating engine dependencies as missing and reinstalling.");
        _depsMissing = true;
      } else if (!_depsMissing && !_bsqLoadable()) {
        log("Engine dependency better-sqlite3 failed its load probe — treating engine dependencies as missing and reinstalling.");
        _depsMissing = true;
      }
    }
  } catch (e) {
    log(`WARNING: could not read the engine package.json (${e.message}) — treating engine dependencies as missing and reinstalling.`);
    _depsMissing = true;
  }
  if (_depsMissing) {
    log("Installing engine dependencies (first run)...");
    console.log("Installing engine (first run)...");
    // Audit run-7: install EXACTLY the pinned tree from the shipped
    // package-lock.json (npm ci verifies integrity hashes). The old
    // bare `npm install` resolved hundreds of unpinned packages on
    // first run — a supply-chain hole into processes that hold keys.
    const _lock = path.join(engineServer, "package-lock.json");
    const _npmCmd = fs.existsSync(_lock)
      ? "npm ci --no-audit --no-fund"
      : "npm install --no-audit --no-fund";
    const _npmOk = await runInstall(_npmCmd, engineServer);
    if (shuttingDown) return;
    if (!_npmOk) {
      console.error("npm install failed. Check your internet connection and try again.");
      process.exit(1);
    }
  }

  // Python dependencies
  try {
    // Audit run-9 (L5): probe EVERY module the pinned requirements
    // provide, not just cryptography — a venv with only cryptography
    // passed the old probe, the pinned install never ran, and TOTP
    // QR enrollment (qrcode/PIL) 500'd forever.
    execSync(`${python} -c "import cryptography, qrcode, PIL"`, { stdio: "ignore", windowsHide: true, cwd: APP_DIR });
  } catch (e) {
    log("Installing Python dependencies (pinned)...");
    console.log("Installing Python components...");
    // Audit run-7: install the repo's pinned requirements.txt —
    // a bare `pip install cryptography` took whatever PyPI served
    // that day (and never installed qrcode/pillow at all).
    const _pipOk = await runInstall(
      `${python} -m pip install -r "${path.join(APP_DIR, "requirements.txt")}" --quiet`,
      APP_DIR);
    if (shuttingDown) return;
    if (!_pipOk) {
      console.error("Python dependency install failed. Check your internet connection and try again.");
      process.exit(1);
    }
  }

  // Setup .env if missing
  const envFile = path.join(APP_DIR, ".env");
  if (!fs.existsSync(envFile)) {
    const example = path.join(APP_DIR, ".env.example");
    if (fs.existsSync(example)) {
      let content = fs.readFileSync(example, "utf8");
      const key = require("crypto").randomBytes(32).toString("hex");
      content = content.replace("PASTE_64_CHAR_HEX_HERE", key);
      // The .env carries the generated ENCRYPTION_KEY: owner-only
      // (audit run-7 — it used to land with default 0644).
      fs.writeFileSync(envFile, content, { mode: 0o600 });
      log("Generated .env with encryption key");
    }
  }

  // Start engine (if dist exists)
  const engineDist = path.join(engineServer, "dist", "index.js");
  engine = null;
  // Wave 18 (L17-2): if 3001 is already bound BEFORE our child
  // starts, do not spawn into the collision and do not POST any
  // credentials anywhere — every claim/verify answer would come
  // from a responder we did not spawn. Surface it loudly and
  // skip the engine for this boot (the dashboard still starts).
  let portPreOccupied = false;
  if (fs.existsSync(engineDist)) {
    portPreOccupied = await probePort3001();
    if (portPreOccupied) {
      log("WARNING: port 3001 already in use — something is listening on 127.0.0.1:3001 before the engine started, so the engine was NOT started and no engine credentials were sent anywhere. Stop the other process on port 3001 (for example a separately running FreeLLMAPI gateway) and run nexuslocal again.");
      console.error("Port 3001 already in use: the engine was not started and no credentials were sent. Stop the process using port 3001 and run nexuslocal again.");
    }
  }
  // Wave 11 (F15): shuttingDown is set by the shutdown path BEFORE
  // it kills the engine, so the exit handler can tell a deliberate
  // stop from a genuine crash (which must still warn). It lives at
  // module scope now (wave 13: the handlers register pre-install).
  if (fs.existsSync(engineDist) && !portPreOccupied) {
    log("Starting engine on 127.0.0.1:3001");
    console.log("Starting engine...");
    const engineEnv = {
      ...process.env,
      PORT: "3001",
      HOST: "127.0.0.1",
      FREEAPI_DB_PATH: path.join(APP_DIR, "engine-data", "freeapi.db"),
      FREEAPI_CONFIG_PATH: path.join(APP_DIR, "engine", "freellmapi.config.json"),
      FREEAPI_ENV_PATH: envFile,
    };
    engine = spawn("node", [engineDist], {
      cwd: engineServer,
      env: engineEnv,
      stdio: "ignore",
      windowsHide: true,
    });
    // Audit run-7: the engine's first-run design lets any loopback
    // caller claim its admin with NO setup code, and this launcher
    // never creates a user — so the claim window never closed and a
    // claimant could export the engine's stored provider keys. Claim
    // it ourselves with a generated password (kept in the 0600 .env)
    // as soon as the engine answers.
    // Audit run-8: the run-7 claim retried only TRANSPORT errors
    // (30 x 1s), set no request timeouts, and stayed silent on
    // every other failure — a slow first boot (>~30s, e.g. AV
    // scanning on Windows) left the unauthenticated setup window
    // open for the whole session, and an active loopback claimant
    // could win the 1s poll race without leaving a trace. The
    // claim now retries ANY failure until the engine is claimed
    // or gone, verifies the claim is OURS via a login check, and
    // shouts (and drops the unregistered credentials) when a
    // foreign process won the race.
    let engineExited = false;
    engine.on("exit", (code, signal) => {
      engineExited = true;
      if (shuttingDown) {
        // Wave 11 (F15): our own SIGINT handler killed the engine —
        // an intentional stop is not a gateway failure.
        log(`Engine stopped (code ${code}, signal ${signal}) — launcher shutdown.`);
        return;
      }
      // Audit run-9 (L4): a dead engine was silent (stdio ignored,
      // exit unlogged) — the dashboard kept running with no gateway
      // behind it. Name the exit in startup.log.
      log(`WARNING: engine process exited (code ${code}, signal ${signal}) — the AI gateway is down; restart nexuslocal to bring it back.`);
    });
    const claimState = { tries: 0, lastWhy: "no attempt yet" };
    // Wave 18 (run-17 launcher L17-2): the liveness re-check the
    // claim/verify flow was missing — engineExited used to be
    // consulted ONCE at claimStep entry, so verifyClaim's retry
    // loop kept POSTing the recorded admin credentials to
    // whatever answered on 3001 after the child died (a squatter
    // bound after the death captured them, and its forged 200
    // was silently accepted). Every credential-bearing or
    // verdict-forming request now re-checks first; on failure
    // the claim state is UNKNOWN and credentials are KEPT.
    const credGuard = (where) => {
      if (engineExited || shuttingDown || portPreOccupied) {
        log(`WARNING: the spawned engine is gone — NOT sending the recorded engine admin credentials to whatever now answers on 127.0.0.1:3001 (${where}). Claim state UNKNOWN (credentials kept).`);
        return false;
      }
      return true;
    };
    const verifyClaim = (http) => {
      if (engineExited || shuttingDown || portPreOccupied) return;
      // Wave 12 (L1/L2/L3): the shared dotenv-style reader — an
      // empty first line no longer shadows valid credentials, and
      // quoted/spaced/BOM values parse the way dotenv parses them.
      const _creds = readEngineAdminCreds(envFile);
      let email = _creds.email || null, pw = _creds.password || null;
      // Wave 14 (run-13 launcher L13-2): the alternate parse of the
      // recorded password (no comment truncation). A definitive
      // refusal of the primary form retries ONCE with this form
      // before anything may be deleted — a credential the engine
      // itself accepts must never be destroyed on a parse
      // technicality.
      const pwAlt = _creds.passwordAlt || null;
      let emailDefaulted = false;
      if (!pw) {
        log("WARNING: the engine admin was already claimed but app/.env holds no ENGINE_ADMIN credentials — on a fresh install, another local process claimed it first.");
        return;
      }
      // Audit run-9 (L2): a password-only .env used to leave email
      // null here — the claim had used the default owner@example.com
      // but never recorded it, so this POSTed {"email":null}, the
      // engine answered 400, and the outcome was swallowed below.
      // Fall back to the same default the claim path uses, and say
      // so loudly instead of verifying against a null identity.
      if (!email) {
        email = "owner@example.com";
        emailDefaulted = true;
        log("WARNING: app/.env holds an ENGINE_ADMIN_PASSWORD but no ENGINE_ADMIN_EMAIL — verifying the claim against the default owner@example.com.");
      }
      // Audit run-9 (L1): the old verify made ONE login POST and
      // silently swallowed every outcome other than 200/401/403 —
      // including the REAL 429 case (the engine locks the email for
      // 15 minutes after 5 failed logins, so a correct password can
      // legitimately answer 429). Inconclusive outcomes now retry a
      // bounded number of times and end in a WARNING naming the
      // outcome — never silence, and credentials are only removed
      // on a DEFINITIVE 401/403.
      let attempts = 0, triedAlt = false;
      const tryLogin = () => {
        // Wave 18 (L17-2): re-check before EVERY credential POST,
        // including every scheduled retry and the alt-form retry.
        if (!credGuard("verify login")) return;
        attempts += 1;
        const payload = JSON.stringify({ email, password: pw });
        const post = http.request({
          host: "127.0.0.1", port: 3001, path: "/api/auth/login",
          method: "POST",
          headers: { "Content-Type": "application/json",
                     "Content-Length": Buffer.byteLength(payload) },
        }, (r2) => {
          r2.resume();
          r2.on("end", () => {
            if (r2.statusCode === 200) return; // ours — done
            if (r2.statusCode === 401 || r2.statusCode === 403) {
              if (pwAlt && !triedAlt) {
                // Wave 14: retry ONCE with the alternate form —
                // only a refusal of BOTH forms is a foreign claim.
                triedAlt = true;
                pw = pwAlt;
                attempts = 0;
                setTimeout(tryLogin, 300);
                return;
              }
              if (emailDefaulted) {
                // Wave 12 (L1): a login attempted with the DEFAULT
                // email (the .env recorded none) is not a
                // definitive verdict on the recorded password —
                // credentials are never deleted on it.
                log("WARNING: the engine admin login with the recorded password and the default email was refused — credentials KEPT, because app/.env records no email to verify against. Check the engine and app/.env.");
                return;
              }
              try { removeEngineAdminCreds(envFile); } catch (e) {}
              log("WARNING: the engine admin is claimed by credentials that are NOT the ones from app/.env (now removed) — another local process won the first-run claim, and the engine's stored provider keys may be exposed to it.");
              return;
            }
            if (attempts < 5) { setTimeout(tryLogin, 3000); return; }
            log(`WARNING: could not verify the engine admin claim — login answered ${r2.statusCode} on all ${attempts} attempts; whether the claim is ours is UNKNOWN (credentials kept). Check the engine and app/.env.`);
          });
        });
        post.setTimeout(3000, () => post.destroy(new Error("timeout")));
        post.on("error", () => {
          if (attempts < 5) { setTimeout(tryLogin, 3000); return; }
          log(`WARNING: could not verify the engine admin claim — the login request failed on all ${attempts} attempts; whether the claim is ours is UNKNOWN (credentials kept). Check the engine and app/.env.`);
        });
        post.write(payload);
        post.end();
      };
      tryLogin();
    };
    const claimStep = () => {
      if (engineExited || shuttingDown || portPreOccupied) return;
      claimState.tries += 1;
      if (claimState.tries === 301) {
        // Audit run-9 (L3): the old cap stopped the loop FOREVER
        // with one cause-less WARNING while the unauthenticated
        // setup window stayed open. The warning now names the
        // last failure cause, and the claim keeps retrying at a
        // slow cadence (see retry) for the life of the process.
        log(`WARNING: engine admin still unclaimed after 300 attempts (last failure: ${claimState.lastWhy}) — its setup window may be open; the claim keeps retrying every 5 minutes. Check the engine.`);
      }
      const http = require("http");
      const retry = (why) => {
        claimState.lastWhy = why;
        if (claimState.tries === 1 || claimState.tries % 30 === 0) {
          log(`Engine claim pending (${why}), retrying...`);
        }
        setTimeout(claimStep, claimState.tries > 300 ? 5 * 60 * 1000 : 1000);
      };
      const req = http.get("http://127.0.0.1:3001/api/auth/status", (res) => {
        let body = "";
        res.on("data", (c) => { body += c; });
        res.on("end", () => {
          let st = null;
          try { st = JSON.parse(body); } catch (e) {}
          if (!st || typeof st.needsSetup !== "boolean") {
            return retry("bad status reply");
          }
          // Wave 18 (L17-2): the status reply is verdict-forming
          // — if the child died while it was in flight, do not
          // branch to verify/setup against a foreign responder.
          if (!credGuard("claim/verify")) return;
          if (!st.needsSetup) return verifyClaim(http);
          let email = "owner@example.com", pw = null;
          try {
            // Credentials land in .env: tighten a pre-existing
            // loose file (the .env.example copy path used to stay
            // 0644 with the admin password inside — run-8) BEFORE
            // appending, and never duplicate the email line.
            try { fs.chmodSync(envFile, 0o600); } catch (e) {}
            const envTxt = fs.readFileSync(envFile, "utf8");
            // Wave 12 (L1/L2/L3): the shared dotenv-style reader
            // (claimStep keeps no private reader any more). Wave 11
            // (F12/F13) semantics ride on top of it: an EMPTY-valued
            // line counts as ABSENT — readers used to be
            // first-match, so an empty line left in place shadowed
            // any appended credential forever. Empty lines are
            // therefore REWRITTEN IN PLACE with the value being
            // recorded, never duplicated by an append.
            const _creds = parseEngineAdminCreds(envTxt);
            if (_creds.email) email = _creds.email;
            if (_creds.password) pw = _creds.password;
            const emEmpty = _creds.hasEmail && !_creds.email;
            const pmEmpty = _creds.hasPassword && !_creds.password;
            if (!pw) {
              pw = require("crypto").randomBytes(24).toString("hex");
              let txt = envTxt, add = "";
              if (pmEmpty) {
                txt = txt.replace(/^\uFEFF?[^\S\r\n]*(?:export[^\S\r\n]+)?ENGINE_ADMIN_PASSWORD[^\S\r\n]*=.*$/m,
                                  `ENGINE_ADMIN_PASSWORD=${pw}`);
              } else {
                add += `\nENGINE_ADMIN_PASSWORD=${pw}\n`;
              }
              if (emEmpty) {
                txt = txt.replace(/^\uFEFF?[^\S\r\n]*(?:export[^\S\r\n]+)?ENGINE_ADMIN_EMAIL[^\S\r\n]*=.*$/m,
                                  `ENGINE_ADMIN_EMAIL=${email}`);
              } else if (!_creds.hasEmail) {
                add += `\nENGINE_ADMIN_EMAIL=${email}`;
              }
              if (txt !== envTxt) fs.writeFileSync(envFile, txt);
              if (add) fs.appendFileSync(envFile, add);
            } else if (!_creds.hasEmail || emEmpty) {
              // Audit run-9 (L2): a pre-existing password with NO
              // email line — record the email actually being used
              // (the default above) so verifyClaim never has to
              // guess it (it used to POST {"email":null}). Wave 11:
              // an EMPTY email line gets the same recording, by
              // rewriting it in place instead of appending a
              // shadowed duplicate.
              if (emEmpty) {
                fs.writeFileSync(envFile, envTxt.replace(
                  /^\uFEFF?[^\S\r\n]*(?:export[^\S\r\n]+)?ENGINE_ADMIN_EMAIL[^\S\r\n]*=.*$/m,
                  `ENGINE_ADMIN_EMAIL=${email}`));
              } else {
                fs.appendFileSync(envFile, `\nENGINE_ADMIN_EMAIL=${email}\n`);
              }
            }
          } catch (e) { return retry("env write failed"); }
          // Wave 18 (L17-2): re-check immediately before the
          // setup POST that carries the claim credentials.
          if (!credGuard("engine setup")) return;
          const payload = JSON.stringify({ email, password: pw });
          const post = http.request({
            host: "127.0.0.1", port: 3001, path: "/api/auth/setup",
            method: "POST",
            headers: { "Content-Type": "application/json",
                       "Content-Length": Buffer.byteLength(payload) },
          }, (r2) => {
            r2.resume();
            r2.on("end", () => {
              if (r2.statusCode === 201) {
                log("Engine admin claimed (credentials in app/.env)");
              } else {
                retry("setup answered " + r2.statusCode);
              }
            });
          });
          post.setTimeout(3000, () => post.destroy(new Error("timeout")));
          post.on("error", () => retry("setup post failed"));
          post.write(payload);
          post.end();
        });
      });
      req.setTimeout(3000, () => req.destroy(new Error("timeout")));
      req.on("error", () => retry("engine not answering yet"));
    };
    setTimeout(claimStep, 500);
    // Don't detach — we need to kill it on shutdown
  } else {
    log(portPreOccupied
      ? "Skipping engine: port 3001 already in use (see the warning above)."
      : "Engine dist not found, skipping engine");
  }

  // Start dashboard (foreground - keeps the terminal alive)
  log("Starting dashboard on 127.0.0.1:8080");
  console.log("\nOpen http://127.0.0.1:8080 in your browser\n");
  console.log("Press Ctrl+C to stop.\n");

  // Auto-open browser on Windows
  if (os.platform() === "win32") {
    setTimeout(() => {
      try {
        execSync('start http://127.0.0.1:8080', { windowsHide: true });
      } catch (e) {}
    }, 2000);
  }

  dashboard = spawn(python.replace(/"/g, ""), ["server.py"], {
    cwd: APP_DIR,
    stdio: "inherit",
    windowsHide: false,
    shell: python.startsWith('"'),
  });

  // Wave 12 (L7/L8): ONE shutdown path for every exit route —
  // SIGINT, SIGTERM, SIGHUP, and the dashboard dying on its own.
  // The shared path (module scope since wave 13, so it can be
  // registered before the install phase and can kill the install
  // child) sets the flag, stops ALL children (SIGTERM, a short
  // grace, then SIGKILL), then exits.
  dashboard.on("close", (code) => {
    log(`Dashboard exited with code ${code}`);
    if (!shuttingDown) {
      // L8: the dashboard died on its own — stop the engine via
      // the same shutdown path instead of orphaning it.
      shutdown(code || 0);
    }
  });
}

main();
