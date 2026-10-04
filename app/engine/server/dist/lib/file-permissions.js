import fs from 'fs';
import path from 'path';
import { execFileSync as nodeExecFileSync } from 'node:child_process';
const EXEC_TIMEOUT_MS = 5_000;
/** SYSTEM and the local Administrators group, as well-known SIDs. Referenced by
 *  SID rather than by name because the display names are localized — a German
 *  Windows reports `VORDEFINIERT\Administratoren`. */
const SID_SYSTEM = 'S-1-5-18';
const SID_ADMINISTRATORS = 'S-1-5-32-544';
const defaultExecFileSync = (file, args, options) => nodeExecFileSync(file, args, options);
/** Absolute path into System32. Never resolve these off PATH: a Git Bash or
 *  MSYS `whoami` shadows the Windows one and fails outright, and letting PATH
 *  decide which binary hardens a file is itself a hijack vector. */
function system32(binary) {
    return path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', binary);
}
let cachedOwnerSid;
/**
 * The current user's SID, via `whoami /user /fo csv /nh`, which prints
 * `"DOMAIN\\user","S-1-5-21-..."`. Returns null if it cannot be determined.
 * Memoized only for the real binary — a process's own SID cannot change — so an
 * injected fake in tests is never cached and never reads another test's value.
 */
function resolveOwnerSid(exec, useCache) {
    if (useCache && cachedOwnerSid !== undefined)
        return cachedOwnerSid;
    let sid = null;
    try {
        // No existsSync guard: a missing binary throws ENOENT out of exec, which
        // this catch already handles, and probing the filesystem first would make
        // the Windows branch untestable anywhere but Windows.
        const out = exec(system32('whoami.exe'), ['/user', '/fo', 'csv', '/nh'], {
            encoding: 'utf8',
            timeout: EXEC_TIMEOUT_MS,
            windowsHide: true,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        sid = /"(S-1-[0-9-]+)"/.exec(out)?.[1] ?? null;
    }
    catch {
        sid = null;
    }
    if (useCache)
        cachedOwnerSid = sid;
    return sid;
}
/**
 * The icacls arguments that restrict `target` to `ownerSid` + SYSTEM +
 * Administrators. Split out from the spawn so the command shape is testable
 * without a Windows box.
 *
 * `/inheritance:r` removes the inherited ACEs (the whole point — that is where
 * the extra principals come from), and `/grant:r` replaces rather than adds, so
 * running it twice is idempotent. The `*` prefix makes icacls read each
 * principal as a SID literal instead of an account name.
 *
 * `inheritable` adds `(OI)(CI)` so children created later are born restricted.
 * It is only ever set for a directory: the flags describe what a container
 * hands down, and on a leaf file they protect nothing.
 */
export function windowsRestrictArgs(target, ownerSid, opts) {
    const rights = opts?.inheritable ? '(OI)(CI)(F)' : '(F)';
    return [
        target,
        '/inheritance:r',
        '/grant:r', `*${ownerSid}:${rights}`,
        '/grant:r', `*${SID_SYSTEM}:${rights}`,
        '/grant:r', `*${SID_ADMINISTRATORS}:${rights}`,
    ];
}
/** A directory needs its search bit kept, or the owning process locks itself
 *  out of its own data directory; 0600 on a directory is not a stricter 0700,
 *  it is a broken one. */
const POSIX_MODE = { file: 0o600, directory: 0o700 };
function restrict(target, kind, opts) {
    const platform = opts?.platform ?? process.platform;
    const exec = opts?.execFileSync ?? defaultExecFileSync;
    try {
        if (!fs.existsSync(target))
            return true;
    }
    catch {
        return false;
    }
    if (platform !== 'win32') {
        try {
            fs.chmodSync(target, POSIX_MODE[kind]);
            return true;
        }
        catch {
            return false;
        }
    }
    const ownerSid = opts?.ownerSid !== undefined
        ? opts.ownerSid
        : resolveOwnerSid(exec, opts?.execFileSync === undefined);
    if (!ownerSid)
        return false;
    try {
        exec(system32('icacls.exe'), windowsRestrictArgs(target, ownerSid, { inheritable: kind === 'directory' }), {
            encoding: 'utf8',
            timeout: EXEC_TIMEOUT_MS,
            windowsHide: true,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Restrict `target` to its owner. Never throws: permissions are a hardening
 * measure, not a correctness one, and startup must survive a filesystem that
 * cannot express them.
 *
 * @returns true when the restriction was applied, false when it could not be.
 *          Callers are expected to surface a false — the failure mode that made
 *          this function necessary was a guard everyone believed was running.
 */
export function restrictToOwner(target, opts) {
    return restrict(target, 'file', opts);
}
/**
 * Restrict a directory to its owner, so files created inside it later are
 * protected without anyone having to remember to harden them. See the header
 * for why this is the only thing that can cover SQLite's WAL sidecars.
 *
 * Callers must be sure the directory is theirs. This is deliberately not
 * something to do to any path handed in by configuration: locking down a shared
 * directory — a temp dir, a working copy, someone else's data directory — is a
 * worse outage than the leak it prevents.
 *
 * @returns true when the restriction was applied, false when it could not be.
 */
export function restrictDirToOwner(target, opts) {
    return restrict(target, 'directory', opts);
}
/**
 * Restrict several files that share an owner, resolving the SID at most once.
 * Missing files are skipped, not failed — SQLite's `-wal`/`-shm` sidecars do not
 * exist until the first write.
 *
 * @returns the targets that could not be restricted.
 */
export function restrictAllToOwner(targets, opts) {
    const platform = opts?.platform ?? process.platform;
    const exec = opts?.execFileSync ?? defaultExecFileSync;
    const ownerSid = platform === 'win32' && opts?.ownerSid === undefined
        ? resolveOwnerSid(exec, opts?.execFileSync === undefined)
        : opts?.ownerSid ?? null;
    const failed = [];
    for (const target of targets) {
        if (!restrictToOwner(target, { ...opts, platform, ownerSid }))
            failed.push(target);
    }
    return failed;
}
//# sourceMappingURL=file-permissions.js.map