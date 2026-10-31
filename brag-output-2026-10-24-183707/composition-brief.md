# Hyperframes Composition Brief: Nexus — v7 (cursor zoom + text zoom)

## v7 changes (only the chat scene; everything else identical to v6)
- CURSOR ZOOM, professional screen-recording style (user: "cursor zoom
  text zoom like in professional videos"). The raw clip was driven
  programmatically and contains no cursor, so a cursor is added IN POST
  — this is standard professional practice (Camtasia/ScreenFlow cursor
  effects are post overlays too), stated honestly here and in the plan;
  no fake typing and no fake UI is added. A crisp white SVG arrow
  (dark 1.2px stroke, tip at 0,0 of its box so GSAP x/y place the hot
  spot exactly; NO blur, NO shadow) is overlaid inside a new #cam
  wrapper that also holds the video, so camera and cursor move as one.
  Path, synced to the clip's MEASURED timeline (frames of the raw clip:
  typing ~0.7-3.0s, send ~3.4s, answer ~5.8s; scene-local = clip time):
  glides from the thread area (700,400) to the composer (320,722) over
  0.0-0.7s as typing starts; nudges right (520,722) at 1.6s and
  (680,722) at 2.5s following the growing text; glides to the send
  button (1484,722) over 2.9-3.4s; CLICKS at 3.4s (scale 0.82 press +
  expanding hard-edged #38bdf8 ripple ring, NO blur) exactly when the
  clip's message sends; parks top-right (1450,150) over 3.5-4.2s, out
  of the answer's way. All positions are #cam display coords
  (1560 x 877.5 = clip coords x 0.8125), grounded from the clip frames
  (send button center clip (1827,889); composer line y ~890 clip).
- CURSOR-TRACKING CAMERA (replaces v6's fixed push-in). #cam's scale +
  transformOrigin are tweened by GSAP so the zoom focal point glides
  with the cursor: 1.0 at origin 50% 50% → 1.10 at 35% 82% (composer)
  over 0.0-0.7s → 1.15 at 42% 82% over 0.7-2.9s (following the text) →
  1.20 at 95% 82% (send button) over 2.9-3.4s → 1.20 at 50% 45%
  (thread center) over 3.5-4.6s while waiting. The traveling beam
  still rings the same fixed outer frame; the zoom happens beneath it.
- TEXT ZOOM (magnified answer, professional emphasis style). When the
  real answer arrives (clip ~5.8s), the camera pushes FURTHER to 1.55x
  centered on the answer bubble + trace (origin 46% 46%, measured from
  the clip frame: answer+trace region display x 262-1222, y 371-435)
  over 5.8-6.1s, holds to 6.45s, then eases back to 1.20x at 50% 50%
  over 6.45-6.7s before the scene fade. The 48% origin first tried
  clipped the bubble's left edge by ~4px at 1.55x (visible window
  starts at 265.7 vs bubble left 262); 46% gives window [254.6, 1261.1]
  and the full bubble + trace verified in the 9.3s snapshot. The v6
  frame scale accent at 5.5s is removed (subsumed by the text zoom).
- Everything else unchanged from v6: captions slide+fade at 2.5s/3.2s,
  beam tween, dashframe entrance, scene fade at 6.7s, 20s, music bed,
  share copy.
- Blur audit: grep for blur/radial/box-shadow over the v7 composition
  returns only comments stating NO blur. The only gradients: the hook
  first line's vertical linear-gradient text fill, the conic ring
  beams, the scene-4 linear streak — none blurred, none shadowed.

## v6 changes (only the chat scene; everything else identical to v5)
- ANIMATED ZOOM-IN (user: "Zoom in"). Scene 2's footage now pushes in
  continuously: `#chat-video` scales 1.0 → 1.20 over the 7s scene
  (linear, transformOrigin '88% 55%'), inside a new fixed
  `.zoomstage` wrapper (100% width, aspect-ratio 16/9, overflow hidden,
  border-radius 20px) nested in the unchanged `.picframe` beam frame.
  The beam therefore rings the same fixed frame throughout while the
  footage crops inward beneath it. The video element carries
  `data-layout-allow-overflow` (the zoom overflow is intentional; the
  check's layout info note clears with it).
- WHY NOT 1.35 AT 62%: measured first. Conversation bounds in the raw
  clip (visual grounding, 1920x1080 coords): answer left 325, composer
  right 1859, trace top ~410, composer bottom 971 — a 1536px span.
  At 1.35x the visible window is 1422px wide, so 1.35 crops the
  conversation at ANY origin (first snapshot attempt cut the sent
  bubble to "Explain failover in one s"). At 1.20x with origin 88% x
  the visible window is [285, 1885] x [99, 999] — every bound holds
  with >=26px margin. 62% x was also tried and failed (right bound
  1780 < 1859). The sidebar still falls away; the conversation glides
  to frame center as it grows.
- ANIMATED CAPTIONS (user: "add animation"). `#tracefail` / `#traceok`
  tweens changed from opacity-only pops to slide+fade: fromTo
  {opacity: 0, y: 18} → {opacity: 1, y: 0, duration: 0.45,
  ease: 'power3.out'} at scene 2.5s / 3.2s (global 5.5s / 6.2s).
- ANSWER-ARRIVAL ACCENT. At scene 5.5s (the clip's real answer
  arrival; answer-drop SFX sits at global 8.6s) `#dashframe` does one
  restrained scale accent: 1 → 1.015 over 0.18s, back to 1 over 0.35s.
  No blur, no shake, no flash, no filter.
- NO new text, scenes, or claims. Blur audit: no blur, radial, or
  box-shadow anywhere (same as v5); the only gradients are the
  pre-existing text fill, conic ring beams, and scene-4 streak.
- Check: 0 errors, 0 warnings, 9/9 contrast. Render: 20.0s, 600
  frames, 1920x1080. Poster: 18.5s outro frame, baked as frame 0
  (frame count and duration unchanged after the bake).

## v5 brief (base, unchanged below except as noted above)

# Hyperframes Composition Brief: Nexus — v5 (real chat video)

## v5 change (only this; everything else identical to v4)
- REAL CHAT VIDEO (user: "Not just use picture use video, where you are
  doing chat"). V4's chat scene showed a static dashboard screenshot. V5
  embeds the REAL screen recording `assets/vid/chat-clip-raw.mp4` (7.5s,
  1920×1080, 6fps, h264, video-only — no audio track, so the element is
  muted) as a native Hyperframes timed `<video>` element:
  `<video id="chat-video" data-start="0" data-duration="7"
  data-media-start="0" muted playsinline preload="auto">`. The `id` is
  REQUIRED — `hyperframes check` fails with `media_missing_id` without it
  and warns the video would render FROZEN. The 7s scene shows the clip's
  first 7s (0.5s of tail trimmed); typing AND the arrived answer both
  survive (answer fully visible by clip 6s).
- The video sits in the SAME traveling-beam frame v4 used for the picture:
  `.picframe` conic-gradient ring (transparent 0–280deg, #38bdf8 310deg,
  #ffffff 340deg, #38bdf8 355deg, transparent 360deg), `--ba` tweened
  0→360deg at 3.5s per revolution, repeat 1 = the full 7s scene, hard-edged,
  NO blur, NO shadow. CSS rule changed from `.picframe img` to
  `.picframe video` (same sizing, border-radius 20px, black background).
- CAPTIONS: the two failover trace lines stay below the video at their v4
  beats (global 5.5s fail, 6.2s continue; switch SFX stays at 6.2s). The
  `#answerline` element, its CSS rule, and its tween are DELETED: the
  clip's own real answer carries that beat, and the full set would overflow
  the frame under the 877px-tall 16:9 video (877 + 8 padding + 26 gap +
  trace ≈ 1014 fits in 1080; + answerline ≈ 1120 does not).
- SFX: `sfx-answer` retimed 6.6s → 8.6s in the root index, matching the
  clip's real answer arrival (clip ~5.5s in = global ~8.5s). All other
  audio unchanged.
- Blur audit: no blur, radial, or box-shadow anywhere in the v5 composition
  (same as v4). The only gradients: the hook first line's vertical
  linear-gradient text fill, the conic ring beams, the scene-4 linear
  streak — none blurred, none shadowed.

## v4 brief (base, unchanged below except as noted above)

## Objective
Create a short launch-style brag video for Nexus (v5 rework of v4).

## Output
- Composition directory: `brag-output-2026-10-24-181349/composition/`
- Rendered video: `brag-output-2026-10-24-181349/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20 seconds

## Source Material
- Project root: `~/workspace/local-dashboard`
- Real media (copied, not moved, into `composition/assets/`):
  - `vid/chat-clip-raw.mp4` — REAL screen recording of a genuine Nexus
    chat on the live app, test account (7.5s, 1920×1080, 6fps, inspected:
    no personal data; trace names public lane/provider names only)
  - `img/landing.png` — real public Nexus landing-page hero screenshot
    (scene 1, unchanged from v4)
- Product name: Nexus
- Tagline / strongest claim: "Chat with every AI, from one Nexus."
- Copy that must appear verbatim:
  - "Chat with every AI, from one Nexus."
  - "✕ Claude · limit reached" (Claude struck through, danger red)
  - "✓ Gemini continues — same memory" (highlighted, sky-blue)
  - "One shared memory"
  - "Automatic failover"
  - "Your keys, your vault"
  - "Get the app — or don't."
  - (Dropped vs v4: "If one lane goes quiet, Nexus asks the next." —
    the clip's own real answer carries this beat now.)

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
  - Fake typing or fake motion overlaid on real footage

## Visual Identity
- Background: #050505 (panels #0d0d10)
- Text: #fafafa (primary), #a7a7b0 (muted)
- Accent: #38bdf8 (sky blue), beam core white; trace-fail red #ff9d97
- Display font: Space Grotesk (vendored locally as woff2: 400/500/700)
- Body font: Space Grotesk; JetBrains Mono (vendored) for the failover
  caption lines
- Visual references: the real chat video at 81% frame width with a
  gradient beam traveling around its border; the real landing screenshot
  under the hero line

## Storyboard
Use the storyboard in `brag-output-2026-10-24-181349/brag-plan.md` as the
creative contract.

Scene summary:
1. Hook + real landing reveal — 3.0s — hero line, then landing.png fades
   in below at 1500px, traveling beam ring, one revolution
2. The real chat, on video + failover captions — 7.0s — chat-clip-raw.mp4
   (first 7s) at 1560px with traveling beam ring (3.5s/rev loop); captions
   below: Claude fails (5.5s), Gemini continues (6.2s), hold to 10.0s
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
- Audio arc: steady bed throughout; quiet motion-matched cues (switch at
  6.2s, answer drop at 8.6s, line drops, logo bell); fade-out over the
  final 1.5s
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
- Show the real chat video, large — not a picture, not mock UI.
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

## Environment notes (same workarounds as v1–v4)
- Browser: Hyperframes resolves its own Chrome-for-Testing headless shell
  152.0.7977.30 (`hyperframes browser path`); the VM's managed Chromium
  hard-blocks loopback navigation and is not used.
- /tmp is a 512 MB tmpfs: the render runs with TMPDIR set into the run dir,
  cleaned up afterward.
- Render uses `--video-frame-format png`: the source clip is a UI screen
  recording and PNG extraction preserves its saturated UI colors.
