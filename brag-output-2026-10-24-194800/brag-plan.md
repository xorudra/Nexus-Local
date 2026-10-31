# Brag Plan: Nexus — v8 (smoothness: true 30fps chat footage)

Everything from v7 stands except ONE thing: the chat scene's footage is
now true 30fps. No new text, no new scenes, no new claims, no new
choreography — the cursor path, zoom focal points, text-zoom beat, beam,
captions, music, and share copy are all unchanged.

## What changed vs v7 (only the chat scene's footage, 3–10s)

**User complaint (verbatim intent):** "It's not smooth like it's feeling
like you are cutting frame."

**Root cause (verified, not guessed):** the real chat clip was 6fps
(45 frames, 7.5s) inside a 30fps timeline, so each captured frame held
~5 timeline frames while the cursor overlay and zoom tweens moved at
full 30fps. That mismatch is exactly what reads as frame-cutting.

**Fix (option A, motion interpolation — chosen after eyeballing both
modes on real frames):** the raw clip was interpolated to a true 30fps
with ffmpeg minterpolate, `fps=30:mi_mode=mci:mc_mode=aobmc:
me_mode=bidir:vsbmc=1` (motion-compensated). Result: 216 frames,
30fps, 7.2s (the 0.3s shortfall is minterpolate dropping the final
partial interval; the 7s scene only needs the first 7s, and every real
moment keeps its original timestamp, so cursor/zoom/text-zoom sync is
unchanged). Blend mode was also rendered and compared at 0.1s steps
during typing: both show only the next letter fading in faintly at
intermediate steps — no doubled words, no smeared letters in either
mode. MCI was picked because it handles motion (scrolls, timer ticks)
better than plain cross-dissolve, and its typing frames read identically
clean. Interpolation here is frame generation, NOT a blur filter: text
stays sharp in every checked frame.
**Option B (re-record) was not needed** — interpolation passed the
frame test, so no new capture was made and no new sync work was needed.

## Audio / share copy
Unchanged from v7.

---

# Brag Plan: Nexus — v7 (cursor zoom + text zoom on the chat scene)

Everything from v6 stands except the chat scene, which gains a
professional-style cursor zoom and a magnified text zoom. No new text,
no new scenes, no new claims.

## What changed vs v6 (only the chat scene, 3–10s)

1. **Cursor zoom (camera follows a cursor).** The raw clip has no cursor
   (it was driven programmatically), so a cursor is added in post —
   standard professional practice, same as Camtasia/ScreenFlow cursor
   effects; the footage itself stays real, no fake typing is added. A
   crisp white arrow glides to the composer as typing starts, rests
   near the text with small rightward nudges as it grows, glides to
   the send button and clicks (press-down + expanding ripple ring)
   exactly when the real message sends, then parks top-right out of
   the way. The CAMERA tracks it: the zoom focal point glides from
   the composer to the send button to the thread center, following
   the cursor's path.
2. **Text zoom (magnified answer).** When the real answer arrives, the
   camera pushes further to 1.55x centered on the answer bubble +
   trace line — clearly larger and more readable than v6's end state
   — holds for a beat, then eases back to the full conversation view
   before the scene fades. The full bubble + trace stay in view
   throughout (origin measured from the clip frame, not guessed).
3. **Sync measured from the real clip.** Cursor path, click, zoom
   focal points, and the text-zoom beat are synced to the clip's own
   measured moments (typing ~0.7–3.0s, send ~3.4s, answer ~5.8s of
   clip time), verified in render frames — never before the action
   they accompany.

## Honest post-production note

Only two things in the chat scene are not in the raw recording: the
cursor overlay (+ click ripple) and the camera moves. Both are
standard post-production for professional screen videos. The typing,
the send, the waiting trace, and the answer are the real recording,
untouched.

## What changed vs v5 (only the chat scene, 3–10s)

1. **Animated zoom-in (Ken Burns push-in, not a static crop).** The real
   chat footage now scales smoothly from 1.0 at scene start to 1.20 at
   scene end (linear, 7s), inside a fixed overflow-hidden stage, so the
   traveling border beam keeps ringing the same fixed outer frame
   unchanged. The sidebar falls away as the scene progresses and the
   typing + answer text grows large and readable.
2. **Animated caption reveals.** The two failover captions below the
   video ("✕ Claude · limit reached" at global 5.5s, "✓ Gemini
   continues — same memory" at global 6.2s) now slide up 18px while
   fading in over 0.45s (power3.out) instead of popping into existence.
3. **Answer-arrival emphasis.** When the real answer arrives in the
   footage (scene 5.5s, matching the answer-drop SFX at global 8.6s),
   the video frame does one brief restrained scale accent (1 → 1.015
   over 0.18s, back to 1 over 0.35s). No blur, no shake, no flash.

## One honest deviation, measured, not guessed

The brief suggested ~1.35 scale at ~62% x / 55% y. I measured the real
conversation bounds in the clip first (visual grounding on the raw clip
frame): answer bubble left x=325, composer right x=1859, trace top
y≈410, composer bottom y=971 (1920×1080 clip coords). At 1.35× the
visible window is only 1422px wide — narrower than the 1536px
conversation span — so 1.35 crops either the answer's left edge or the
sent bubble's right edge no matter the origin (proven in snapshots:
the first attempt cut the bubble to "Explain failover in one s").
1.20 is the largest push-in that keeps the full measured conversation in
frame, and the origin had to move to 88% x (not 62%): because the
zoom stage is not centered on the origin, the visible window at 1.20×
is [285, 1885] only when centered near the right — 62% put the right
bound at 1780 and cut the bubble. At 88% x / 55% y every bound holds
with ≥26px margin (left 285 vs 323 needed, right 1885 vs 1859,
bottom 999 vs 971), and the conversation glides to frame center as it
grows, which reads as a deliberate push-in, not a slide.

## What stayed from v5

Real chat video (typing → send → real AI answer with real trace),
traveling conic-gradient border beam, hook with real landing picture,
three feature lines, outro, 20s landscape, polished tone, same music
bed, same share copy, zero blur anywhere.

## Storyboard — scene 2 only (rest unchanged from v5)

### Scene 2 — The real chat, zooming in — 7.0s (3.0–10.0)
Footage scales 1.0 → 1.20 (origin 88% / 55%) inside the fixed beam
frame; captions slide+fade in at 5.5s / 6.2s; a 1.015 scale accent
lands on the frame as the real answer arrives (scene 5.5s). The typed
message, sent bubble, answer + trace, and composer stay fully visible
at every zoom level — verified in frames at 4s, 6s, and 9.5s.

**Music mood for this video:** steady, clean, warm corporate bed
**Audio summary:** unchanged from v5.
