# Brag Plan: Nexus — v5

A rework of v4 (`brag-output-2026-10-24-123215`), not a restart. Everything
that worked in v4 stays: the angle (a lane dies mid-chat, the user never
cares), the hook line "Chat with every AI, from one Nexus.", polished tone,
landscape 1920×1080, 20 seconds, the same vol-12 music bed, the traveling
gradient border beam, the real landing picture in the hook, the three
verbatim feature lines, and the outro (wordmark + public address + "Get the
app — or don't."). What changes is exactly the one new user complaint.

## What is this app?
Nexus is one chat window for every AI — type once, and it answers through the
strongest available lane, switching providers automatically when one fails.

## The angle (unchanged)
The video shows the one moment that makes Nexus different: a provider dies
mid-conversation and the user never has to care — the answer just arrives
anyway. One chat, one switch, no noise.

## What changed vs v4 — and why

### Real chat VIDEO, not just a picture (user: "Not just use picture use video, where you are doing chat")
V4 showed a static screenshot of the dashboard in the chat scene. V5 shows
a REAL screen recording of a genuine Nexus chat on the live app:
`assets/vid/chat-clip-raw.mp4` — 7.5s, 1920×1080, 6fps, test account, no
secrets or personal data. In the clip the message "Explain failover in one
sentence" types itself into the real composer, sends, and a real AI answer
arrives with its real trace line ("Answered by Relay: Openrouter ·
nvidia/nemotron-3-ultra-550b-a55b:free · 1.2s"). The 6fps capture cadence is
slightly steppy; that is honest screen footage and is kept as-is — no
smoothing into fake motion, no fake typing overlaid on top of it.

The clip is embedded natively as a Hyperframes timed `<video>` element
(`id="chat-video"`, muted — the clip has no audio track), framed at the
same 1560px width (81% of frame) inside the same traveling conic-gradient
border beam. The 7s scene shows the clip's first 7s (the last 0.5s of tail
is trimmed); typing AND the arrived answer both survive — the answer is
fully visible by clip 6s and holds into the scene's end.

### Captions: trace lines stay, answerline dropped (deliberate, not an oversight)
The v4 failover captions ("✕ Claude · limit reached" / "✓ Gemini continues
— same memory") stay below the video at their v4 beats (global 5.5s/6.2s,
switch SFX still at 6.2s) — they tell the failover story the clip alone
does not show, and they are clearly caption text outside the video, never
fake UI. The "If one lane goes quiet, Nexus asks the next." answerline is
DROPPED: the clip's own real answer now carries that beat, and keeping the
full set under the 877px-tall 16:9 video would overflow the 1080px frame
(877 + 8 + 26 + trace ≈ 1014 fits; + answerline ≈ 1120 does not). The
answer-drop SFX moves with the real answer: 6.6s → 8.6s, when the clip's
answer is arriving on screen.

## Key moments (the middle, v5)
- A real chat, on video, large: typing, sending, a real answer arriving —
  ringed by a beam that travels around its border, with the failover
  captions landing beneath it.
- Three verbatim feature lines, large, arriving on beats and held as a set:
  "One shared memory" / "Automatic failover" / "Your keys, your vault".

## Outro / punchline (unchanged)
The Nexus wordmark, the hero line once more, and the public address — plus
the landing page's own shrug: "Get the app — or don't." The beam under the
wordmark sweeps continuously.

## User flow worth showing
Real chat on video → message types and sends → a real answer arrives with
its real trace → failover captions land beneath → the answer line's job is
done by the footage itself. The product is shown happening, not pictured.

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
- Strongest visual element: the real chat video, large, with a gradient
  beam traveling around its border

## Share copy (unchanged — v5's change is visual, the line still fits)
Nexus: chat with every AI, from one Nexus. When a lane fails, it switches automatically — you never notice. Get the app, or don't.

## Audio direction
- Role: warm bed with sparse professional accents
- Music: happy-beats-business-moves-vol-12-by-ende-dot-app.mp3 (steady and
  clean, ~110 BPM) — unchanged
- Music treatment: starts at 0, steady 0.35 bed, fades out over the final
  1.5s under the outro
- SFX posture: sparse, motion-matched, professional restraint
- Audio-coupled moments: failover switch cue (6.2s, timed to the "Gemini
  continues" caption), answer drop (8.6s, retimed from 6.6s to the clip's
  real answer arrival), feature lines (one soft drop per line), outro
  wordmark (one low bell)
- Restraint rule: no SFX on every word; at most one cue per beat, and
  silence under the hook line's hold

## Storyboard

### Scene 1 — Hook + real landing reveal — 3.0s (0.0–3.0)
Unchanged from v4: hero line, then the real landing screenshot fades in
below at 1.4s, 1500px wide, ringed by the traveling border beam.
Audio intent: music bed only, low; the line lands in near-silence.
Transition mood: soft crossfade → Scene 2

### Scene 2 — The real chat, on video + failover captions — 7.0s (3.0–10.0)
On screen: the REAL chat video clip, 1560px wide, ringed by the traveling
border beam (3.5s per revolution, looping). Inside the footage: the message
types itself, sends, "Request sent via Auto routing", "Waiting for a
provider to answer", then the real answer arrives with its real trace line.
Beneath the video, as caption text clearly outside the footage: "✕ Claude
· limit reached" (struck, red) at 5.5s, "✓ Gemini continues — same memory"
(highlighted, sky-blue) at 6.2s, holding to 10.0s.
Sequential/interaction: yes — the footage itself is the interaction;
captions arrive on the v4 beats; the beam is at a different border position
at 6s, 8s, 9s.
Audio intent: switch cue at 6.2s, answer drop at 8.6s (the clip's real
answer arrival).
Transition mood: soft crossfade → Scene 3

### Scene 3 — Three truths — 6.0s (10.0–16.0)
Unchanged from v4: three feature lines, verbatim from the landing page, at
92px with 120×6 sky-blue rules, arriving one by one on beats and then held
as a set: "One shared memory" / "Automatic failover" / "Your keys, your
vault".
Audio intent: one soft drop per line, quiet and even.
Transition mood: soft crossfade → Scene 4

### Scene 4 — Outro — 4.0s (16.0–20.0)
Unchanged from v4: "Nexus" wordmark, hero line once more, public address
"nexusos.dpdns.org", "Get the app — or don't.", sweeping beam, fade out.
Audio intent: music fades out over 18.5–20.0s; one low bell as the wordmark
lands.
Transition mood: fade to black at 20.0s.

**Music mood for this video:** steady, clean, warm corporate bed
**Audio summary:** A steady low bed throughout with quiet motion-matched
cues (switch, answer drop, line drops, logo bell) and a fade-out under the
outro — plus a beam that never sits still, and a chat that really happens.

## Stand-ins (privacy note)
No secrets, keys, tokens, internal hostnames, real user names, or email
addresses appear anywhere in this plan or the video. The clip is a test
account's real chat; its trace names only public lane/provider names. The
provider names in the captions (Claude, Gemini) are the product's own public
landing-page marketing.
