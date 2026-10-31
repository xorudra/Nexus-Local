# Hyperframes Composition Brief: Nexus — v10 (smoother + no sidebar, via brag)

## v10 changes (only the chat scene + its knock-on retiming; everything else identical to v9)
- NEW FOOTAGE. Scene 2 embeds `assets/vid/chat-clip-10.mp4` (8.0s,
  1920×1080, constant 30fps, h264, video-only, muted) — cut from the
  60fps smooth take, cropped to the main pane (NO sidebar), then
  downsampled 60→30fps so every timeline frame is a real captured
  frame (no interpolation, no held frames). Edit (ffmpeg, segments
  concatenated): raw 19.8–20.5 at 1x (glide) + 20.5–23.0 at 1.5x
  (typing) + 23.0–23.6 at 1x (send) + 23.6–28.0 at 2.1x (waiting) +
  28.0–30.93 at 1x (answer + hold) = 8.00s, 240 frames. The `id="chat-video"`
  is REQUIRED (media_missing_id without it); the element keeps
  `data-start="0" data-duration="8" data-media-start="0" muted
  playsinline preload="auto"`.
- NO OVERLAY CURSOR (unchanged from v9). Only `#ripple` remains
  (72px hard-edged #38bdf8 ring, NO blur, NO shadow), positioned from
  VISUAL GROUNDING on the installed clip's 5.1s frame (send button
  center clip (1820, 1024) -> display (1471, 827)); first render
  round put the ring ~16px high, corrected +15 local y, and the
  re-render's expanding ring was verified surrounding the send
  button at global 6.1s. Ripple fires at scene 2.85s, exactly when
  the real message sends.
- CAMERA (gentler than v9 — footage is pre-cropped; same #cam
  wrapper, scale + transformOrigin tweened by GSAP, smooth eases
  only): 1.0 at 50% 50% -> 1.03 at 50% 88% over 0.0–0.7 (glide) ->
  1.08 at 55% 88% over 0.7–2.37 (typing drift) -> 1.08 at 94% 94%
  over 2.37–2.85 (send button) -> 1.0 at 50% 50% over 2.97–4.5
  (waiting, full view) -> TEXT ZOOM 1.12 at 25% 51% over 6.6–6.9
  (answer bubble + trace), hold to 7.7, ease back to 1.0 at 50% 50%
  over 7.7–7.95, scene fade 7.7–8.0. 1.12x is the max push keeping
  the FULL bubble in frame (bubble clip x 70–1110; window at 1.12x
  with origin 25% 51% is x [51, 1765], left margin 19px — verified
  by math and on the render at 9.6s global). Beam: `--ba` 0→360deg
  at 4.0s/rev, repeat 1 (2 revs = 8s). Captions retimed: fail 3.2s,
  continue 6.6s (answer arrival), slide + fade.
- RETIMING (total stays 20s): scene2 mount 3s/8s UNCHANGED; scene3
  mount 11s/5s UNCHANGED; scene4 mount 16s/4s UNCHANGED. Root SFX:
  answer 10.0 -> 9.6 (scene2 start 3 + answer 6.6); switch 6.2,
  feature drops 11.37/11.93/12.46, logo 16.5 all UNCHANGED. Music bed
  unchanged (0–20, fade-out 1.5s).
- TIMING CORRECTION (one render round): the first v10 render put
  the text zoom + answer SFX at 5.47, from VFR frame-number math on
  the raw take. Probing the CFR clip itself showed the thread
  clearing at 6.5 and the answer painted by 6.7, so arrival is 6.6
  and everything answer-linked moved there. Lesson: never map VFR
  frame numbers to time; probe the CFR clip.
- Blur audit: no blur, no radial gradients, no box-shadow anywhere
  in scene2 (same as v9). Only gradients: the pre-existing hook
  text fill, conic ring beams, scene-4 streak.
- Check: 0 errors, 0 warnings (lint, runtime, layout, motion,
  craft), 10/10 contrast. Render: 20.0s, 600 frames, 1920×1080,
  constant 30fps (r_frame_rate AND avg_frame_rate 30/1). Poster:
  18.5s outro frame, baked as frame 0 (frame count and duration
  unchanged after the bake; frame 0 eyeballed = outro wordmark +
  tagline + address + shrug).
