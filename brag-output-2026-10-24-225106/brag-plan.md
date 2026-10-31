# Brag Plan: Nexus — v10 (brag pipeline: smoother + no sidebar)

Everything from v9 stands except the chat scene, which is rebuilt on the
smooth 60fps take, cropped to the main pane. No new text, no new scenes,
no new claims. Share copy unchanged.

## What changed vs v9 (only the chat scene, still 3.0–11.0s)

**User complaint (verbatim intent):** "There is less smoothness, make
smooth more and animation should be smooth and remove side bar and
focus on main content in the video" — asked to be done through brag.

**Root causes (verified, not guessed):**
- v9's footage was a ~21fps native capture motion-interpolated to
  30fps — 1 in 3 frames invented. v10's footage is the 60fps smooth
  take (`onetake-smooth-raw.mp4`: real X-display capture, finer cursor
  glides at 30 steps x 16ms, finer scroll at 40px steps), downsampled
  to the 30fps timeline — every timeline frame is a real captured
  frame, nothing invented, nothing held. That is why it reads smooth.
- v9's chat scene showed the dashboard sidebar. v10's footage is
  cropped to the main pane before it ever reaches the composition
  (scale 2246:1264 + crop 1920:1080:322:91 from 14s onward in the
  take; the chat cut inherits it). NO sidebar appears anywhere in
  the chat scene — verified on the render at typing, send, and
  answer moments.

**Measured timing of the v10 clip (probed on the CFR clip itself,
never from VFR frame numbers — that mistake cost one render round):**
glide 0.0–0.7; typing 0.7–2.37 at 1.5x; send click 2.85 ("Request
sent" by 2.97); waiting segment 2.97–5.07 at 2.1x; answer segment
5.07–8.0 at 1x, with the answer visibly painting at 6.6 (thread
clears at 6.5, answer painted by 6.7); hold to 8.0. Edit (ffmpeg
segments):
raw 19.8–20.5 at 1x + 20.5–23.0 at 1.5x + 23.0–23.6 at 1x +
23.6–28.0 at 2.1x + 28.0–30.93 at 1x = 8.00s exactly, 240 frames,
constant 30fps. The first render round mistimed the answer at 5.47
(from VFR frame-number math); the CFR probe corrected it to 6.6,
and the answer SFX + text zoom + continue caption moved with it.

**Camera (gentler than v9 — footage is pre-cropped, so smaller
pushes; smooth eases only):** 1.0 → 1.03 toward the composer over
0.0–0.7 → 1.08 drifting with typing over 0.7–2.37 → 1.08 at the send
button (94% 94%) over 2.37–2.85 → 1.0 full thread view over
2.97–4.5 → TEXT ZOOM 1.12 onto the answer bubble + trace at
25% 51% over 6.6–6.9, hold to 7.7, ease back to 1.0 before the fade.
1.12x is the largest push keeping the FULL bubble in frame (bubble
span clip x 70–1110; window at 1.12x with origin 25% 51% is x
[51, 1765], left margin 19px — verified by math and on the render
at 9.6s global). Beam: 4.0s per revolution x 2 = the 8s scene.
Captions retimed: fail 3.2s, continue 6.6s (answer arrival).

**NO overlay cursor (unchanged from v9).** The footage has a REAL
moving cursor; only the ripple-only accent remains: a hard-edged
#38bdf8 ring (NO blur) on the real send click at scene 2.85s.
Grounded on the installed clip's 5.1s frame (send button center
clip (1820, 1024)); first render round put the ring ~16px high, so
its y was corrected +15 local and the re-render's expanding ring
was verified surrounding the send button at global 6.1s.

**SFX retiming (total stays 20s):** answer drop 10.0 → 9.6
(global = scene2 start 3 + answer 6.6). Switch 6.2 (fail caption),
feature drops 11.37/11.93/12.46, logo bell 16.5, music bed all
unchanged. Scenes 1/3/4 byte-identical to v9.

## Audio / share copy
Unchanged from v9.

## Honest post-production note
Only four things in the chat scene are not in the raw recording: the
speed-ramp of the slow parts (typing 1.5x, waiting 2.1x — all moments
present, in order, nothing added or removed), the main-pane crop
(sidebar removed, no content altered), the click ripple accent, and
the camera moves. The glide, typing, send, waiting trace, and answer
are the real recording. No fake typing, no fake UI, no blur anywhere.
