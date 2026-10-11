# Scale notes — Nexus Local (Launch Safety Standard G35)

Recorded 2026-10-11 as part of the G/H audit. This is an honest
description of the current architecture, not an aspiration.

## State architecture (deliberately NOT stateless)

Nexus is a personal, single-instance app and its state design is a
known, accepted trade-off (frozen by owner order 2026-10-09):

- **Sessions** live in an in-memory dict on the one server process.
  A restart ends all sessions; users simply sign in again.
- **Durable data** lives in encrypted files next to the code
  (`keys.enc`, `access.enc`, `users.enc`, `settings.enc`,
  `telemetry.enc`, `v1key.enc`, per-user vaults in `userkeys/`).
- The host's disk is **ephemeral**, so the encrypted stores are
  mirrored off-host (friend-blob sync) and restored at boot
  (`_boot_restore_access`, `_boot_restore_settings`,
  `_boot_restore_telemetry`). The mirror — not the disk — is the
  source of truth across redeploys.
- There is **no SQL database**, so there are no indexes to audit
  (G32 N/A) and no connection pooler to configure (this clause of
  G35 N/A). Data volumes are tiny (a handful of accounts), lookups
  are in-memory dict/file reads.

## Host plan limits (Render free tier, as recorded 2026-10-11)

- 1 web service instance, ~512 MB RAM, shared fractional CPU.
- Service sleeps after inactivity; an external uptime monitor
  pings `/health` every 5 minutes to keep it warm.
- Ephemeral filesystem (see mirrors above); monthly instance-hour
  cap on the free plan.
- Health check: `GET /health` → `{"ok": true}` (deploy/render.yaml).

## What breaks first at 10x traffic

1. **Provider free-tier rate limits** — the real ceiling. Chat and
   /v1 lanes run on free provider quotas; 10x users exhaust those
   long before the host notices. Circuit breakers + failover lanes
   already spread this, but quota is quota.
2. **Single-process Python** — one `ThreadingHTTPServer` process;
   concurrent streaming chats contend on the GIL and threads.
3. **Whole-file store rewrites** — access/settings mutations rewrite
   an entire encrypted file per change; write contention grows with
   admin/friend activity (negligible at current scale).
4. **Host ceiling** — free-tier RAM/CPU cap and cold starts after
   sleep.
5. **Loopback relay** — a second single process on the same host.

If scale ever becomes real, the named path is: externalize sessions
and the encrypted stores to a hosted datastore, then run >1
instance. Not built — no current need.

## Load testing

`tests/load/k6-smoke.js` — run ONLY against a locally booted
instance or staging, never production (G34).
