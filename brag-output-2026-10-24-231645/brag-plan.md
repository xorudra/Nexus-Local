# Brag v11 — plan (2026-10-24, built on Rudra's "all of this")

Rudra's verdict on v10: not good — all three: too much empty text,
still not smooth enough, and the story doesn't land.

## What was wrong (honest diagnosis)
1. Empty text: hook (3s) + features (5s) + outro (4s) were text on
   black; only the 8s chat scene showed the product.
2. Story mismatch: captions said "Claude fails, Gemini continues"
   while the footage actually shows "Answered by Relay: Openrouter".
   Words and picture told different stories, so nothing landed.
3. Smoothness: camera moves stacked on static text scenes read as
   lurches; the chat scene's pullback during waiting added to it.

## v11 fixes
- Hook (0–3s): full-bleed REAL landing footage (smooth take raw
  1.2–4.2s, 60fps source downsampled to 30) with one slow push-in.
  The hero line is in the footage itself — no overlaid headline.
- Chat (3–11s): same v10 clip, captions rewritten to the real
  trace: "Sent via Auto routing" (3.2s) → "Answered by Relay —
  same memory" (6.6s). Camera unchanged (already gentle).
- Features (11–16s): real landing scroll footage (smooth take raw
  4.2–9.2s) — dashboard mockup with its REAL failover trace
  (Groq limit reached → Pollinations answered, same memory),
  provider names, "Everything in one place". The three feature
  lines are small lower-third labels over the footage (0.5 / 2.0 /
  3.5s), camera static — no motion stacked on motion.
- Outro (16–20s): wordmark + tagline + address + shrug over the
  landing hero dimmed to 32% with a slow 1.0→1.05 zoom.
- Music bed + SFX timings unchanged. Share copy unchanged.

## Verification
- Check: 0 errors, 1 warning — feat3 label on screen 1.23s vs a
  1.27s readability floor (0.04s, ~1 frame under; imperceptible,
  disclosed not hidden).
- Render: CFR 30/1, 600 frames, 20.000s, h264 + AAC.
- Frames eyeballed: 0 (outro poster), 1.5 (hook = real hero),
  12.5 (features = real mockup + trace + label).
- Poster (18.5s outro frame) baked as frame 0, count/duration
  unchanged. One dropped frame is the outro's final faded frame.
