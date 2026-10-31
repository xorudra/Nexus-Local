# Brag Plan: Nexus — v2

A rework of v1 (`brag-output-2026-10-24-085716`), not a restart. Everything that
worked in v1 stays: the angle (a lane dies mid-chat, the user never cares),
the hook line "Chat with every AI, from one Nexus.", polished tone, landscape
1920×1080, 20 seconds, the same vol-12 music bed, and the outro (wordmark +
public address + "Get the app — or don't."). What changes is exactly the five
weaknesses found by watching v1's frames, each fixed below and verified against
the v2 frames at 1s / 4s / 8s / 12s / 16s / 19s.

## What is this app?
Nexus is one chat window for every AI — type once, and it answers through the
strongest available lane, switching providers automatically when one fails.

## The angle (unchanged)
The video shows the one moment that makes Nexus different: a provider dies
mid-conversation and the user never has to care — the answer just arrives
anyway. One chat, one switch, no noise.

## Hook (first 2-3 seconds, unchanged)
The landing page's own hero line, full-screen, no chrome: "Chat with every AI,
from one Nexus."

## What changed vs v1 — and why

### 1. Chat scene: bigger, denser, streaming (v1: small window, dead gap)
The chat window now fills ~85% of frame width (1632px, up from 1120px) with
larger type throughout (bubbles 38px, trace 32px, composer 32px), and its
height fits its content — no more `margin-top: auto` void between the answer
and the composer. The answer no longer sits as one settled line: it streams
in word by word (9 words, 0.11s stagger from 6.6s), so the window reads as a
live app, not a slide. Proof frame: 8s — the window dominates the frame and
the answer is settled with the trace directly above it.

### 2. Failover beat: real public lane names (v1: generic "lane" labels)
v1's caution is lifted for exactly the names Nexus itself publishes on its
public landing page. The trace now mirrors the landing page's own demo chain
("Claude answers → limit reached → Gemini continues, same memory"):
`✕ Claude · limit reached` — the name struck through, in the dashboard's
danger red — then `✓ Gemini continues — same memory`, highlighted in
sky-blue. This is what makes the brag believable: a named provider fails and
a named provider finishes the job. Still banned, as in v1: secrets, keys,
tokens, internal hostnames, real user names, email addresses — none appear.
Proof frame: 8s — both trace lines visible, Claude struck, Gemini highlighted.

### 3. Feature scene: no more void (v1: one small line in darkness at 12s)
Type grows from 64px to 92px, the sky-blue rules grow from 72×4 to 120×6 so
they actually read, and the three lines now arrive on consecutive beats
(10.37 / 10.93 / 11.46s) instead of spread to 13.11s — so the full set is
composed and settled well before 12s, and holds as a set to 16.0s. A subtle
scale pulse on the set's glow lands on the 13.11s strong cue instead of the
third line. Proof frame: 12s — all three lines, large, with visible rules.

### 4. Check warnings resolved (v1: 4 nested-structure + 1 SFX slot note)
The four `nested_structure_needs_subcomposition` warnings are fixed properly:
each scene is now its own sub-composition file under `composition/compositions/`,
mounted from the root with `data-composition-src`, with scene timelines
relative to their mount (scene 1 at 0s, scene 2 at 3s, scene 3 at 10s, scene 4
at 16s). The SFX slot note is fixed by setting `sfx-send`'s `data-duration`
to its real media length (0.01s). Target: `check` with zero errors and zero
warnings. Any warning that survives is documented in the brief with a reason.

### 5. Audio-reactive glow (v1: skipped — helper not installed)
The `hyperframes-creative` skill install fails here (GitHub manifest
unreachable), but the equivalent Hyperframes route works: `hyperframes audio
--only envelope` produces a real per-hop dB envelope of the music track
(signal provenance, 59ms hop). The first 20 seconds are normalized into a
glow-opacity lookup, baked into the scene timelines as 0.25s opacity steps
(pure timeline data — seek-safe, no callbacks, no randomness), so the hero
glow and chat glow breathe with the bed. Verified by comparing glow-region
pixels between a loud and a quiet moment in the final render. No waveform or
equalizer visuals — opacity only, subtle by design (0.65–1.00).

## Key moments (the middle, v2)
- A real chat flow at 85% frame width: the example prompt types itself,
  sends, and the answer streams back word by word.
- The failover beat, named: Claude fails (struck, red), Gemini continues
  (highlighted, sky-blue), same memory — the landing page's own demo.
- Three verbatim feature lines, large, arriving on beats and held as a set:
  "One shared memory" / "Automatic failover" / "Your keys, your vault".

## Outro / punchline (unchanged)
The Nexus wordmark, the hero line once more, and the public address — plus
the landing page's own shrug: "Get the app — or don't."

## User flow worth showing
Type a message → answer starts streaming → Claude fails → Gemini continues
automatically, same memory → the answer completes.

## Tone
- Preset: polished
- Creative direction: quiet premium product film — one chat, one switch, no noise
- Interpretation: slow reveals, long holds, generous letter-spacing, soft
  crossfades; restraint is the confidence. Nothing shouts; the failover beat
  does the talking.

## Format: landscape — 1920x1080
## Duration: 20 seconds

## Visual identity (from the project)
- Background: #050505 (landing page body; panels #0d0d10)
- Accent: #38bdf8 (sky blue, landing hero glow + links)
- Danger: #ff9d97 (dashboard danger color, for the failed lane)
- Text: #fafafa (primary), #a7a7b0 (muted)
- Display font: Space Grotesk
- Body font: Space Grotesk (JetBrains Mono for the failover trace lines,
  matching the dashboard's mono trace)
- Strongest visual element: the dark chat window at 85% width with the
  sky-blue glow, and the named failover trace — Claude struck through,
  Gemini answering

## Share copy (unchanged from v1 — v2's changes are visual, the line still fits)
Nexus: chat with every AI, from one Nexus. When a lane fails, it switches automatically — you never notice. Get the app, or don't.

## Audio direction
- Role: warm bed with sparse professional accents
- Music: happy-beats-business-moves-vol-12-by-ende-dot-app.mp3 (steady and
  clean, ~110 BPM) — the polished pick, unchanged from v1
- Music treatment: starts at 0, steady 0.35 bed, fades out over the final
  1.5s under the outro
- Music cue guidance: bundled preset read (assets/music/cues/
  happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.md, tempo
  109.96 BPM). Beat-grid for the three feature reveals: 10.37, 10.93, 11.46s
  (10.93 is also a strong cue). Strong-cue locks: set-glow pulse at 13.11s;
  outro address line at 17.47s. Non-text glow accents at 8.74s and 9.29s
  (scene-2 relative 5.74s and 6.29s).
- Audio-reactive treatment: subtle; the scene glows' opacity follows the
  music bed's envelope in 0.25s steps (0.65–1.00), baked as timeline data.
  No waveform/equalizer visuals.
- SFX posture: sparse, motion-matched, professional restraint
- Audio-coupled moments: typed prompt (soft key ticks), send tap (click),
  failover switch (quiet switch cue), answer stream (soft drop on arrival),
  feature lines (one soft drop per line), outro wordmark (one low bell)
- Restraint rule: no SFX on every word; at most one cue per beat, and
  silence under the hook line's hold

## Storyboard

### Scene 1 — Hook — 3.0s (0.0–3.0)
On screen: near-black background with a soft sky-blue glow that breathes
with the music bed. "Chat with every AI," fades up, then "from one Nexus."
beneath it. No chrome, no logo yet — the line is the whole frame.
Sequential/interaction: none — two lines, second line follows the first by
0.5s, both hold settled to 3.0s (8 words ≈ 2.4s floor, met).
Audio intent: music bed only, low; the line lands in near-silence.
Audio-coupled idea: glow breathes with the bed envelope.
Music: vol-12 bed, 0.35.
Transition mood: soft crossfade → Scene 2

### Scene 2 — The flow: type, fail, switch, answered — 7.0s (3.0–10.0)
On screen: a recreated Nexus chat window at 1632px wide (85% of frame),
dense: header, the typed prompt, the named trace, the streaming answer, the
composer pill — no dead gap. The example prompt types itself: "Explain
failover like I'm five". A cursor taps send. The trace appears: "✕ Claude ·
limit reached" (name struck, red), then "✓ Gemini continues — same memory"
(highlighted, sky-blue). The answer streams in word by word: "If one lane
goes quiet, Nexus asks the next."
Sequential/interaction: yes — typing (3.4–4.8), send tap (4.8), failover
flash (5.5 fail, 6.2 switched), answer streams 6.6–7.6s and holds to 10.0s
(progressive reading during the stream plus a 2.4s settled hold).
Audio intent: key ticks under typing, a soft click on send, one quiet
switch cue at the failover, a soft drop as the answer arrives.
Audio-coupled idea: typed text with key ticks; simulated tap on send;
failover switch cue; word-by-word answer stream.
Music: vol-12 bed continues.
Transition mood: soft crossfade → Scene 3

### Scene 3 — Three truths — 6.0s (10.0–16.0)
On screen: three feature lines, verbatim from the landing page, at 92px with
120×6 sky-blue rules, arriving one by one on beats and then held as a set:
"One shared memory" / "Automatic failover" / "Your keys, your vault".
Sequential/interaction: yes — lines arrive at 10.37, 10.93, and 11.46s
(beat-grid); the full set holds settled from ~11.9s to 16.0s, so the 12s
frame already shows the complete set, large.
Audio intent: one soft drop per line, quiet and even; set-glow pulse on the
13.11s strong cue.
Audio-coupled idea: card-by-card sequence (drop per line).
Music: vol-12 bed continues.
Transition mood: soft crossfade → Scene 4

### Scene 4 — Outro — 4.0s (16.0–20.0)
On screen: "Nexus" wordmark large, landing at 16.3s. Beneath it, the hero
line once more, small: "Chat with every AI, from one Nexus." Then the public
address "nexusos.dpdns.org" and the landing page's shrug: "Get the app — or
don't." — the address line lands at 17.47s (beat-locked to the strong cue).
Sequential/interaction: none — wordmark lands at 16.3s, tagline settles at
17.0s and holds to 20.0s (3.0s for 8 words — floor met), address line holds
17.47s to 20.0s (2.53s for a short label — floor met).
Audio intent: music fades out over 18.5–20.0s; one low bell as the wordmark
lands.
Audio-coupled idea: final logo bell.
Music: vol-12 bed, fade-out.
Transition mood: fade to black at 20.0s.

**Music mood for this video:** steady, clean, warm corporate bed
**Audio summary:** A steady low bed throughout with five quiet motion-matched
cues (key ticks, send click, switch, answer drop, logo bell) and a fade-out
under the outro — plus glows that breathe with the bed's own envelope.

## Stand-ins (privacy note)
No secrets, keys, tokens, internal hostnames, real user names, or email
addresses appear anywhere in this plan or the video. The provider names shown
(Claude, Gemini) are the product's own public landing-page marketing, not
private data; the chat example uses the landing page's own public example
prompt; no real user content is shown.
