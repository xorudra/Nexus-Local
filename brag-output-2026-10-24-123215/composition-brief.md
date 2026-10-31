# Hyperframes Composition Brief: Nexus — v4 (animated beam + real pictures)

## v4 changes (only these; everything else identical to v3)
- ANIMATED BORDER BEAM (user: "not just stucked on one place"). V3's beam
  was a static gradient streak. V4's beam travels:
  - Scenes 1 and 2: the picture frame is a 4px conic-gradient ring
    (`transparent 0–280deg, #38bdf8 310deg, #ffffff 340deg, #38bdf8 355deg,
    transparent 360deg`) — a ~75° bright segment with a white-hot core,
    hard-edged, NO blur, NO shadow. GSAP tweens the `--ba` custom property
    0→360deg, 3s per revolution, `repeat: -1`, so the segment travels
    continuously around the border for the whole scene. At the chat-scene
    proof timestamps the segment sits at 0° (6s), 240° (8s), 120° (10s) —
    a different border position every time.
  - Scene 4: the under-wordmark streak keeps its linear gradient but its
    bright core now sweeps continuously along it (GSAP `backgroundPosition`
    100%→0%, 2.5s, `repeat: -1`), instead of sitting still.
- REAL PICTURES (user: "use real picture"). The recreated mock chat window
  is deleted entirely.
  - Scene 2 shows `assets/img/dashboard.png` — the real Nexus dashboard
    app screenshot — at 1560px wide (81% of frame width), ringed by the
    traveling beam.
  - Scene 1 reveals `assets/img/landing.png` — the real landing-page hero
    screenshot — at 1500px wide beneath the hook line, ringed by the same
    traveling beam.
  - The failover story is now caption text BELOW the real picture (mono
    trace lines + answer line), never fake UI inside a mock app.
  - Typing/send interaction and its key-tick + send-click SFX are removed
    from the root index; switch (6.2s) and answer (6.6s) cues stay, timed to
    the caption reveals. The v3 music-envelope opacity steps are dropped:
    the beams now move instead of breathing.
- Blur audit: `grep -ri "blur|radial|box-shadow"` over the v4 composition
  returns only comments stating NO blur. The only gradients: the hook first
  line's vertical linear-gradient text fill (glyph coloring, as in v3),
  the conic ring beams, and the scene-4 linear streak — none blurred, none
  shadowed.

## v3 brief (base, unchanged below except as noted above)

## Objective
Create a short launch-style brag video for Nexus (v4 rework of v3).

## Output
- Composition directory: `brag-output-2026-10-24-123215/composition/`
- Rendered video: `brag-output-2026-10-24-123215/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20 seconds

## Source Material
- Project root: `~/workspace/local-dashboard`
- Real pictures (copied, not moved, into `composition/assets/img/`):
  - `landing.png` — real public Nexus landing-page hero screenshot
    (1920×937, inspected: no personal data)
  - `dashboard.png` — real Nexus dashboard app screenshot, test account
    (1920×937, inspected: no keys, emails, or user names)
- Product name: Nexus
- Tagline / strongest claim: "Chat with every AI, from one Nexus."
- Copy that must appear verbatim:
  - "Chat with every AI, from one Nexus."
  - "✕ Claude · limit reached" (Claude struck through, danger red)
  - "✓ Gemini continues — same memory" (highlighted, sky-blue)
  - "If one lane goes quiet, Nexus asks the next."
  - "One shared memory"
  - "Automatic failover"
  - "Your keys, your vault"
  - "Get the app — or don't."

## Creative Direction
- Tone preset: polished
- Creative direction: quiet premium product film — one chat, one switch, no noise
- Interpretation: slow reveals, long holds, generous letter-spacing, soft
  crossfades; restraint is the confidence. The one loud thing is the beam,
  and it moves.
- Angle: The video shows the one moment that makes Nexus different — a
  provider dies mid-conversation and the user never has to care. One chat,
  one switch, no noise.
- Hook: the hero line full-screen, first 3 seconds, then the real landing
  picture reveals beneath it
- Outro / punchline: Nexus wordmark, hero line again, public address, and
  the landing page's shrug "Get the app — or don't."
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Mock UI presented as the app
  - Secrets, keys, tokens, internal hostnames, real user names, emails
  - Static beams, pulsing-in-place beams, blur anywhere

## Visual Identity
- Background: #050505 (panels #0d0d10)
- Text: #fafafa (primary), #a7a7b0 (muted)
- Accent: #38bdf8 (sky blue), beam core white; trace-fail red #ff9d97
- Display font: Space Grotesk (vendored locally as woff2: 400/500/700)
- Body font: Space Grotesk; JetBrains Mono (vendored) for the failover
  caption lines
- Visual references: the real dashboard screenshot at 81% frame width with
  a gradient beam traveling around its border; the real landing screenshot
  under the hero line

## Storyboard
Use the storyboard in `brag-output-2026-10-24-123215/brag-plan.md` as the
creative contract.

Scene summary:
1. Hook + real landing reveal — 3.0s — hero line, then landing.png fades
   in below at 1500px, traveling beam ring, one revolution
2. The real app + failover captions — 7.0s — dashboard.png at 1560px with
   traveling beam ring (3s/rev loop); captions below: Claude fails (5.5s),
   Gemini continues (6.2s), answer line (6.6s), hold to 10.0s
3. Three truths — 6.0s — three verbatim feature lines at 92px with 120×6
   rules, arriving on beats 10.37/10.93/11.46 and held as a set to 16.0s
4. Outro — 4.0s — Nexus wordmark, hero line, public address
   nexusos.dpdns.org, "Get the app — or don't.", sweeping beam, fade out

Structure: each scene is its own sub-composition file under
`composition/compositions/` (scene1–scene4.html), mounted from the root with
`data-composition-src` + `data-composition-id` + `data-start`/`data-duration`.
Scene timelines are relative to their mount (scene 1 at 0s, scene 2 at 3s,
scene 3 at 10s, scene 4 at 16s).

## Audio
- Audio role: warm bed with sparse professional accents
- Audio arc: steady bed throughout; quiet motion-matched cues (switch,
  answer drop, line drops, logo bell); fade-out over the final 1.5s
- Music: happy-beats-business-moves-vol-12-by-ende-dot-app.mp3 (bundled, CC
  BY 4.0 ende.app), in `composition/assets/music/`
- Music treatment: start 0, volume 0.35, fade-out 1.5s at the end
- Music cue guidance: bundled preset (tempo 109.96 BPM). Beat-grid: scene-3
  lines at 10.37, 10.93, 11.46s. Strong-cue locks: scene-4 address line at
  17.47s.
- SFX selection: low-HF-risk picks (switch_001, drop_001/002, bong_001); one
  cue per beat at most, volumes 0.6–0.7, music never above 0.35
- Audio files: music + selected SFX in `composition/assets/` before render

## Hyperframes Instructions
Load the composition-building Hyperframes conventions from the scaffolded
project's AGENTS.md and the `hyperframes docs` CLI reference (no hyperframes
domain skills are installed in this environment, so the CLI docs + scaffold
contract are the authority). /brag is its own workflow: do not enter the
hyperframes entry-point intent interview and do not route into its generic
promo / launch-video workflow. Prefer native Hyperframes conventions over
anything in /brag.

Requirements:
- Show real product pictures, large — not mock UI.
- Keep all text readable in the final render.
- Keep the video within 15-25 seconds (20s).
- Include the planned music/SFX layer.
- Treat /brag audio notes as guidance, not a fixed cue sheet.
- Use SFX to support motion and interaction; restraint when the edit is
  already busy.
- Honor planned music treatment (fade-out under the outro) using the best
  Hyperframes-supported implementation.
- Use local assets for audio and runtime/media dependencies (GSAP + fonts
  vendored into composition/assets/; no CDN, no network fetches, no
  Date.now(), no Math.random()).
- Run `hyperframes check` before render — it is brag's single gate.
- Keep creation and rendering local. No publishing.

## Environment notes (same workarounds as v1–v3)
- Browser: Hyperframes resolves its own Chrome-for-Testing headless shell
  152.0.7977.30 (`hyperframes browser path`); the VM's managed Chromium
  hard-blocks loopback navigation and is not used.
- /tmp is a 512 MB tmpfs: the render runs with TMPDIR set into the run dir,
  cleaned up afterward.
