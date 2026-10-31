# Brag Plan: Nexus — v6 (zoom in + animation on the chat scene)

Everything from v5 stands except the chat scene, which gains an animated
push-in and real motion on its captions and answer beat. No new text, no
new scenes, no new claims.

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
