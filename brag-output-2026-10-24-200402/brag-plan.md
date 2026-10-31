# Brag Plan: Nexus — v9 (true native smoothness: new natively-captured clip)

Everything from v8 stands except the chat scene, which is rebuilt on a
NEW natively-captured clip. No new text, no new scenes, no new claims.

## What changed vs v8 (only the chat scene, now 3.0–11.0s)

**User complaint (verbatim intent):** "Improve more it's not smooth."

**Root cause (verified, not guessed):** v8's footage was still synthetic
motion — a 6fps capture motion-interpolated up to 30fps, so 5 of every
6 frames were invented and typing arrived as faint fades. v9 replaces
it with `brag-assets-real/chat-clip-30fps-real.mp4`: a REAL X-display
capture (real Chrome window, real cursor glides, real clicks, real
typing, real AI answer with trace) — 1920×1080, 14.9s, 313 frames,
nominal 30fps / ~21fps average (x11grab under load).

**Measured timing of the new clip (from its own frames + frame-diff
analysis, never reused from v8):** 0–1.1s static pre-roll (trimmed);
cursor glides to the composer ~1.1–1.8s; composer click ~2.3–2.5s;
typing ~2.5–7.0s (slow, real human typing: "Ex" at 2.5s, "Explain
failover in one se" at 5.0s, full sentence by ~7.0s); send click
~7.4s ("Request sent via Auto routing", "Waiting… 0.2s" at 7.5s);
waiting ~7.4–11.4s; answer arrives ~11.43s (trace: "Answered by Relay:
Openrouter · nvidia/nemotron-3-ultra-550b-a55b:free · 3.1s"); hold to
14.9s. The framing shows the dashboard hero on top with the composer
card below — that is the real product, kept as-is. Usage/chats counts
and the reply wording differ slightly from older clips — they are
real, so they stay.

**Fitting the full arc into 20s (honest edit, stated here):** the arc
after trimming pre-roll is ~11.4s, but the scene may grow only ~1s.
The edit time-compresses ONLY the slow parts, never the action beats:
typing 1.5x, waiting 2.1x; glide, send click, and answer arrival stay
at 1x. Edited clip = 8.0s exactly (scene 7→8s, +1.0s). The second is
taken from the feature scene's hold (6→5s); the outro keeps its full
4s. Scene map: hook 0–3, chat 3–11, features 11–16, outro 16–20.
SFX retimed to the new beats: answer drop 8.6→10.0s (global answer
arrival 3+7.0), feature drops 10.37/10.93/11.46→11.37/11.93/12.46,
logo bell 16.5 (unchanged: outro mount back at 16). Switch SFX stays
6.2s (captions keep their v8 beats).

**NO overlay cursor (v9's key correctness fix).** The new footage has
a REAL moving cursor — the v7/v8 post arrow would show TWO cursors,
so it is deleted entirely. Only a ripple-only accent remains: a
hard-edged #38bdf8 ring (NO blur) on the real send click. First render
caught the ripple ~75px above the button (my composer-line measurement
was wrong); it was re-grounded on the installed clip's 4.9s frame
(visual grounding: send button center clip (1837, 932), composer line
y ~933) and re-rendered — the final render shows the ring exactly on
the send button at 7.9s.

**Frame-rate normalization — minterpolate picked over CFR duplication
(after eyeballing BOTH at 0.1s steps during typing):** CFR duplication
kept typing perfectly crisp but held frames for 0.2–0.3s during the
typist's pauses — the same frame-cutting feel. Minterpolate
(mci/aobmc/bidir/vsbmc=1) moves every frame; its only artifact is a
single faint next-letter fade (e.g. "er" ghosting for one frame at
2.6s) that reads as a letter materializing, not a double word. From
a ~21fps native source only ~1 in 3 frames is invented, unlike v8's
5 in 6 — so MCI is genuinely smooth here, not synthetic-looking.
Final clip: 240 frames, 8.0s, constant 30fps.

**Camera (re-synced to the new clip, smooth eases only):** 1.0→1.05
toward the composer during the glide (35% 86%) → 1.12 drifting right
with the typing (45% 86%) → 1.12 at the send button for the click
(96% 86%) → 1.0 full thread view while waiting (50% 45%) → TEXT ZOOM
1.22 onto the answer bubble + trace on arrival (50% 44%), hold, ease
back to 1.0 before the fade. 1.22x is the largest push that keeps the
FULL bubble in frame (bubble span clip x 200–1710 = 1510px; visible
window at 1.22x is 1574px, [173, 1747], margins 27/37px). Beam: 4.0s
per revolution × 2 = the 8s scene. Captions unchanged (fail 2.5s,
continue 3.2s, slide + fade).

## Audio / share copy
Unchanged from v8.

## Honest post-production note
Only three things in the chat scene are not in the raw recording: the
speed-ramp of the slow parts (typing 1.5x, waiting 2.1x — all moments
present, in order, nothing added or removed), the click ripple accent,
and the camera moves. The glide, typing, send, waiting trace, and
answer are the real recording. No fake typing, no fake UI, no blur
anywhere.
