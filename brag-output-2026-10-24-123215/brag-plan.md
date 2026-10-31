# Brag Plan: Nexus — v4

A rework of v3 (`brag-output-2026-10-24-122146`), not a restart. Everything
that worked in v3 stays: the angle (a lane dies mid-chat, the user never
cares), the hook line "Chat with every AI, from one Nexus.", polished tone,
landscape 1920×1080, 20 seconds, the same vol-12 music bed, the named
failover story (Claude fails, Gemini continues, same memory), the three
verbatim feature lines, and the outro (wordmark + public address + "Get the
app — or don't."). What changes is exactly the two new user complaints,
each fixed below and verified against the v4 frames.

## What is this app?
Nexus is one chat window for every AI — type once, and it answers through the
strongest available lane, switching providers automatically when one fails.

## The angle (unchanged)
The video shows the one moment that makes Nexus different: a provider dies
mid-conversation and the user never has to care — the answer just arrives
anyway. One chat, one switch, no noise.

## Hook (first 2-3 seconds, now with the real picture)
The landing page's own hero line, full-screen: "Chat with every AI, from one
Nexus." — then, at 1.4s, the REAL landing-page screenshot reveals beneath
it, large (1500px wide), framed by the traveling border beam. The viewer
meets the line first, then sees the real product it describes.

## What changed vs v3 — and why

### 1. The border beam ANIMATES — it travels, it is not stuck (v3: static streak)
V3's beam was a static gradient streak sitting under the card. V4's beam is
a crisp conic-gradient ring around the picture frame whose bright segment
travels continuously around the border — 3 seconds per revolution, looping
for the whole scene. The segment is a ~75° arc (sky-blue ramp to a white-hot
core and back), hard-edged, no blur, no shadow. Motion comes from position,
not softness. Proof frames: the chat scene at global 6s / 8s / 10s shows the
segment at 0° / 240° / 120° around the border — a different position every
time. The outro beam travels too: its bright core sweeps continuously along
the streak (background-position loop), instead of sitting still.

### 2. Real pictures, not a mock window (v3: recreated chat window)
V3 showed a recreated mock chat window as "the app". V4 shows the real
product, large:
- Scene 2 (the app scene, 3–10s) is the REAL dashboard screenshot
  (`dashboard.png`, real Nexus dashboard app), 1560px wide — 81% of frame
  width — framed by the traveling border beam.
- Scene 1 (the hook/reveal) shows the REAL landing screenshot
  (`landing.png`), 1500px wide, under the hero line.
- The failover story is no longer fake UI inside a mock app: it is video
  caption text clearly BELOW the real picture — "✕ Claude · limit reached"
  (struck, red), "✓ Gemini continues — same memory" (highlighted,
  sky-blue), then "If one lane goes quiet, Nexus asks the next."
- The typing/send interaction is gone with the mock window (and its key-tick
  and send-click SFX with it); the switch cue and answer drop stay, timed to
  the caption reveals.
- Both pictures were verified clean before use: no secrets, keys, tokens,
  internal hostnames, real user names, or emails visible. Still banned, as
  in every version: nothing of that kind is added anywhere.

## Key moments (the middle, v4)
- The real dashboard, large, ringed by a beam that travels around its
  border while the failover caption story lands beneath it.
- Three verbatim feature lines, large, arriving on beats and held as a set:
  "One shared memory" / "Automatic failover" / "Your keys, your vault".

## Outro / punchline (unchanged, beam now travels)
The Nexus wordmark, the hero line once more, and the public address — plus
the landing page's own shrug: "Get the app — or don't." The beam under the
wordmark sweeps continuously instead of sitting still.

## User flow worth showing
Real dashboard → a lane fails (caption) → Gemini continues automatically,
same memory → the answer line lands. The product is shown, not simulated.

## Tone
- Preset: polished
- Creative direction: quiet premium product film — one chat, one switch, no noise
- Interpretation: slow reveals, long holds, generous letter-spacing, soft
  crossfades; restraint is the confidence. Nothing shouts; the failover beat
  does the talking. The one loud thing is the beam, and it moves.

## Format: landscape — 1920x1080
## Duration: 20 seconds

## Visual identity (from the project)
- Background: #050505 (panels #0d0d10)
- Accent: #38bdf8 (sky blue); beam core white
- Danger: #ff9d97 (dashboard danger color, for the failed lane)
- Text: #fafafa (primary), #a7a7b0 (muted)
- Display font: Space Grotesk
- Body font: Space Grotesk (JetBrains Mono for the failover caption lines)
- Strongest visual element: the real dashboard screenshot, large, with a
  gradient beam traveling around its border

## Share copy (unchanged from v3 — v4's changes are visual, the line still fits)
Nexus: chat with every AI, from one Nexus. When a lane fails, it switches automatically — you never notice. Get the app, or don't.

## Audio direction
- Role: warm bed with sparse professional accents
- Music: happy-beats-business-moves-vol-12-by-ende-dot-app.mp3 (steady and
  clean, ~110 BPM) — unchanged
- Music treatment: starts at 0, steady 0.35 bed, fades out over the final
  1.5s under the outro
- SFX posture: sparse, motion-matched, professional restraint
- Audio-coupled moments: failover switch cue (6.2s, timed to the "Gemini
  continues" caption), answer drop (6.6s, timed to the answer line),
  feature lines (one soft drop per line), outro wordmark (one low bell)
- Dropped vs v3: key ticks and the send click — the typing/send interaction
  they belonged to is gone with the mock window. The v3 music-envelope
  opacity steps are dropped too: the beams now move instead of breathing,
  and motion is the life.
- Restraint rule: no SFX on every word; at most one cue per beat, and
  silence under the hook line's hold

## Storyboard

### Scene 1 — Hook + real landing reveal — 3.0s (0.0–3.0)
On screen: near-black #050505, no glow, no blur. "Chat with every AI,"
fades up, then "from one Nexus." beneath it. At 1.4s the real landing
screenshot fades in below the line, 1500px wide, ringed by the traveling
border beam (one full revolution across the scene).
Sequential/interaction: none — two lines, second line follows the first by
0.5s; picture reveals at 1.4s and holds to 3.0s.
Audio intent: music bed only, low; the line lands in near-silence.
Transition mood: soft crossfade → Scene 2

### Scene 2 — The real app + failover captions — 7.0s (3.0–10.0)
On screen: the real dashboard screenshot, 1560px wide, ringed by the
traveling border beam (3s per revolution, looping). Beneath it, as caption
text clearly outside the picture: "✕ Claude · limit reached" (struck, red)
at 5.5s, "✓ Gemini continues — same memory" (highlighted, sky-blue) at
6.2s, then "If one lane goes quiet, Nexus asks the next." at 6.6s, holding
to 10.0s.
Sequential/interaction: yes — picture fades in at 3.0s; captions arrive on
the v3 beats; the beam is at a different border position at 6s, 8s, 10s.
Audio intent: switch cue at 6.2s, answer drop at 6.6s.
Transition mood: soft crossfade → Scene 3

### Scene 3 — Three truths — 6.0s (10.0–16.0)
Unchanged from v3: three feature lines, verbatim from the landing page, at
92px with 120×6 sky-blue rules, arriving one by one on beats and then held
as a set: "One shared memory" / "Automatic failover" / "Your keys, your
vault".
Audio intent: one soft drop per line, quiet and even.
Transition mood: soft crossfade → Scene 4

### Scene 4 — Outro — 4.0s (16.0–20.0)
On screen: "Nexus" wordmark large, landing at 16.3s. Beneath it, the hero
line once more, small: "Chat with every AI, from one Nexus." Then the
public address "nexusos.dpdns.org" and the landing page's shrug: "Get the
app — or don't." The beam under the wordmark is a gradient streak whose
bright core sweeps continuously along it.
Audio intent: music fades out over 18.5–20.0s; one low bell as the wordmark
lands.
Transition mood: fade to black at 20.0s.

**Music mood for this video:** steady, clean, warm corporate bed
**Audio summary:** A steady low bed throughout with quiet motion-matched
cues (switch, answer drop, line drops, logo bell) and a fade-out under the
outro — plus a beam that never sits still.

## Stand-ins (privacy note)
No secrets, keys, tokens, internal hostnames, real user names, or email
addresses appear anywhere in this plan or the video. The provider names
shown (Claude, Gemini) are the product's own public landing-page marketing;
both real pictures were inspected before use and contain no private data.
