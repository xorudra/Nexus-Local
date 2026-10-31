# Hyperframes Composition Brief: Nexus

## Objective
Create a short launch-style brag video for Nexus.

## Output
- Composition directory: `brag-output-2026-10-24-085716/composition/`
- Rendered video: `brag-output-2026-10-24-085716/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20 seconds

## Source Material
- Project root: `~/workspace/local-dashboard`
- Primary files read: `app/landing.html` (hero, feature sections, demo failover lines), `app/dashboard.html` (chat UI: composer pill "Type a message...", chat rows, failover trace)
- Product name: Nexus
- Tagline / strongest claim: "Chat with every AI, from one Nexus."
- Key UI or visual moment to recreate: the chat window with the failover trace — a lane fails, Nexus switches automatically, the answer still arrives
- Copy that must appear verbatim:
  - "Chat with every AI, from one Nexus."
  - "Explain failover like I'm five"
  - "One shared memory"
  - "Automatic failover"
  - "Your keys, your vault"
  - "Get the app — or don't."
  - "Type a message..."

## Creative Direction
- Tone preset: polished
- Creative direction: quiet premium product film — one chat, one switch, no noise
- Interpretation: slow reveals, long holds, generous letter-spacing, soft crossfades; restraint is the confidence
- Angle: The video shows the one moment that makes Nexus different — a provider dies mid-conversation and the user never has to care. One chat, one switch, no noise.
- Hook: the hero line full-screen, no chrome, first 3 seconds
- Outro / punchline: Nexus wordmark, hero line again, public address, and the landing page's shrug "Get the app — or don't."
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign
  - Real provider names, real user names, emails, keys, tokens, internal hostnames (use neutral "lane" labels; the landing demo's provider names are replaced with stand-ins)

## Visual Identity
- Background: #050505 (panels #0d0d10)
- Text: #fafafa (primary), #a7a7b0 (muted)
- Accent: #38bdf8 (sky blue); trace-fail red #ff9d97 (from the dashboard's danger color)
- Display font: Space Grotesk (vendored locally as woff2: 400/500/700)
- Body font: Space Grotesk; JetBrains Mono (vendored) for the failover trace lines
- Visual references from the project: dark chat window with sky-blue glow (landing hero-chip glow rgba(56,189,248,.5)), composer pill, mono trace lines

## Storyboard
Use the storyboard in `brag-output-2026-10-24-085716/brag-plan.md` as the creative contract.

Scene summary:
1. Hook — 3.0s — hero line full-screen, two lines, both hold settled to 3.0s
2. The flow — 7.0s — recreated chat window: prompt types itself, send tap, lane fails, switches automatically, answer key line settles and holds to 10.0s
3. Three truths — 6.0s — three verbatim feature lines arrive on beats and hold as a set to 16.0s
4. Outro — 4.0s — Nexus wordmark, hero line, public address nexusos.dpdns.org, "Get the app — or don't.", fade to black

Timing corrections vs the plan (reading-time floors govern): the scene-2 answer line settles at 6.6s (not 8.74s) so its 10 words get a full 3.4s hold; beat-locked majors are the scene-3 third line (13.11s) and the scene-4 address line (17.47s). Beat accents (non-text glows) land at 8.74s and 9.29s.

## Audio
- Audio role: warm bed with sparse professional accents
- Audio arc: steady bed throughout; five quiet motion-matched cue groups (key ticks, send click, switch, answer drop, line drops, logo bell); fade-out over the final 1.5s
- Music: happy-beats-business-moves-vol-12-by-ende-dot-app.mp3 (bundled, CC BY 4.0 ende.app), copied to `composition/assets/music/`
- Music treatment: start 0, volume 0.35, fade-out 1.5s at the end
- Music cue guidance: bundled preset `assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.md` (tempo 109.96 BPM). Strong-cue locks: scene-3 third line at 13.11s; scene-4 address line at 17.47s. Beat-grid: scene-3 lines at 10.93, 12.02, 13.11s. Non-text glow accents at 8.74s and 9.29s.
- Audio-reactive treatment: none — the hyperframes-creative extraction helper is not installed in this environment, so per-frame audio-reactive wiring is skipped rather than faked (per step-3-compose.md, this is documented, not a blocker).
- Audio-coupled moments:
  - Scene 2 typing — soft key ticks
  - Scene 2 send — click
  - Scene 2 failover switch — quiet switch cue
  - Scene 2 answer arrival — soft drop
  - Scene 3 lines — one soft drop per line
  - Scene 4 wordmark — one low bell
- SFX selection guidance: low-HF-risk picks per the skill's sfx-analysis.md (click_003, switch_001, drop_001/002, bong_001, keypress-001/007/014); one cue per beat at most, volumes 0.5–0.7, music never above 0.35
- SFX analysis guidance: `~/workspace/custom-skills/brag/assets/sfx/sfx-analysis.md` (read; low-risk picks chosen)
- Exact SFX choice: Hyperframes chose filenames, timestamps, density, and volume based on the implemented animation (listed above).
- Audio files: music + selected SFX copied into `composition/assets/` before render

## Hyperframes Instructions
Load the composition-building Hyperframes conventions from the scaffolded project's AGENTS.md and the `hyperframes docs` CLI reference (no hyperframes domain skills are installed in this environment, so the CLI docs + scaffold contract are the authority). /brag is its own workflow: do not enter the hyperframes entry-point intent interview and do not route into its generic promo / launch-video workflow. Prefer native Hyperframes conventions over anything in /brag.

Requirements:
- Show at least one real UI, copy, or visual element from the source project.
- Keep all text readable in the final render.
- Keep the video within 15-25 seconds (20s).
- Include the planned music/SFX layer.
- Treat /brag audio notes as guidance, not a fixed cue sheet.
- Treat music cue metadata as optional timing hints; ignore cues that hurt readability, scene pacing, or the product story.
- Major reveals may move toward nearby strong cues within about 0.15s. Smaller entrances may align to nearby beat points within about 0.10s. Use only 1-3 strong cue locks in a 15-25s video.
- Use SFX to support motion and interaction; restraint when the edit is already busy.
- Honor planned music treatment (fade-out under the outro) using the best Hyperframes-supported implementation.
- Use local assets for audio and runtime/media dependencies (GSAP + fonts vendored into composition/assets/; no CDN, no network fetches, no Date.now(), no Math.random()).
- Run `hyperframes check` before render — it is brag's single gate.
- Keep creation and rendering local. No publishing.
