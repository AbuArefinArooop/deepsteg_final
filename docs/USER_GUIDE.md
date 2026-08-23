# DeepSteg v4 — User Guide

Version: 4.0.2
© 2026 Abu Arefin Aroop & Arslan Institute of Technology (AiT). All Rights Reserved.

This guide walks through using the DeepSteg v4 desktop app to hide and
recover an encrypted message inside a video. For installation, see
[`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md).

---

## Overview of the workflow

```
 1. Keystore tab / Embed tab   →  Generate Keys
 2. Embed tab                  →  Load or generate a cover video
 3. Embed tab                  →  Type a message (or pick a file) → Embed
 4. VAPT+ tab                  →  Verify the result is undetectable
 5. Extract tab                →  Recover and decrypt the message
```

The app has eight tabs across the top: **Embed, Extract, Results, VAPT+,
Audit, Keystore, Policy, About.**

---

## 1. Generate keys

Before anything else, you need a keypair. You can do this from either
the **Embed** tab's "Keys" panel or the dedicated **Keystore** tab.

1. Click **Generate Keys**.
2. The app generates, in order: an RSA-4096 keypair (classical
   fallback), an X25519 sender keypair, an X25519 receiver keypair, and
   derives a **pixel seed** from an ECDH exchange between the two. This
   pixel seed is what determines which pixels carry the hidden bits — it
   is as sensitive as a password.
3. Watch the **Live Operation Log** for confirmation and timing. RSA-4096
   generation is the slowest step (roughly under a second on a modern
   CPU).
4. The status badge in the top-right changes from **"No Keys"** to
   **"Keys Ready."**

Keys generated this way live only in memory for the current session. To
reuse them later, save them to an encrypted keystore (§2).

## 2. Save / load a keystore

Go to the **Keystore** tab (or use the **Save** / **Load** buttons on
the Embed tab).

- **Save Current Keys**: prompts for a password (minimum 8 characters,
  confirmed twice), then encrypts your RSA/X25519/pixel-seed key
  material with Scrypt (N=2¹⁷) and writes it to the path shown in
  **Keystore path**. This password is not recoverable if lost — there is
  no backdoor.
- **Load Keystore**: prompts for the password, decrypts, and populates
  your session with the stored keys.

**Keep this password safe and keep the keystore file backed up.** If you
lose either, any messages embedded with that pixel seed become
permanently unrecoverable.

## 3. Prepare a cover video

On the **Embed** tab:

- **Browse** next to *Cover video* to pick an existing `.mp4`, `.avi`,
  `.mov`, or `.mkv` file, **or**
- Click **⚙ Generate Test Video** to synthesize a short synthetic test
  clip (640×480, 40 frames) with visible on-screen labels — useful for
  trying the app without a real video on hand. This also auto-fills the
  *Output folder* field.

Once a video is loaded, the capacity line below **Settings** updates
automatically to show frames available, bytes per frame, and total
capacity at your current frame count and fill ratio.

## 4. Choose embedding settings

- **Frames**: how many consecutive frames to spread the encrypted
  bundle across (default 4). More frames = more capacity, but also more
  frames that visibly differ from the original if inspected side by
  side (though changes are imperceptible to the eye at normal fill
  ratios).
- **Start frame**: which frame index to begin embedding at.
- **Fill ratio**: what fraction of each frame's total bit capacity to
  use (5%–100%). Lower fill ratios are more resistant to statistical
  steganalysis; the accompanying research paper's evaluation used 5–10%
  for its headline PSNR/SSIM numbers. Higher fill ratios let you embed
  larger payloads in fewer frames but reduce image quality and
  steganalysis resistance.
- **Replay TTL**: `Demo (1h)` bundles remain valid for extraction for
  3600 seconds after embedding; `Prod (60s)` bundles expire after 60
  seconds — useful for testing replay-attack rejection, but easy to
  accidentally let a real bundle expire during testing. Use `Demo` while
  learning the app.

## 5. Choose a payload

Under **Payload**, pick:
- **Text**: type directly into the message box.
- **Binary File**: browse to any file on disk; its raw bytes become the
  payload (works for images, documents, archives — anything).

## 6. Embed

Click **▶ Embed (Hybrid-KEM v4)**. The pipeline runs in four visible
steps in the log:
1. Hybrid-KEM encryption of your payload into a signed, authenticated
   bundle.
2. A capacity check against your video/settings.
3. The actual pseudorandom LSB embed across your chosen frames,
   reporting PSNR/SSIM/MSE/NCC per frame as it goes.
4. A summary, including the exact **bundle length in bytes** and **frame
   count** — write these down (or leave the app open), since you need
   both, plus the pixel seed, to extract later.

Stego frames are written as lossless PNGs into your output folder
(`stego_frame_0000.png`, etc.) plus a lossless AVI reassembly of the
full video. **Only the PNGs (or a lossless re-encoding) preserve the
hidden payload** — do not convert to JPEG or any lossy format, and do
not upload to a platform that re-encodes video (most social/video
platforms do).

You can click **Stop** at any point to abort a running embed.

## 7. Check the results dashboard

The **Results** tab shows summary cards (PSNR, SSIM, MSE, NCC, frame
count, bits, method) after an embed. Click **Refresh Chart** for a full
visual dashboard: cover vs. stego frame side by side, an exaggerated
diff view (×30), a metrics-vs-target bar chart, and per-frame PSNR/SSIM/
MSE/embed-ratio plots. **Export JSON** saves all numeric results;
**Save Chart** saves the dashboard as a PNG.

## 8. Verify with VAPT+ (steganalysis self-check)

Go to **VAPT+** to run the app's own four steganalysis tests against
your stego output:
- **Chi-squared** — classic LSB pair-imbalance detector.
- **RS Analysis** — regular/singular block statistics (documented to
  need natural photographic covers for reliable results; on synthetic
  test covers it may report low statistical power rather than a clean
  pass/fail — this is expected and documented, not an error).
- **Sample Pair Analysis (SPA)** — similar caveat to RS Analysis.
- **Spatial Boundary (DeepSteg's own contribution)** — specifically
  detects the sequential-embedding artifact that pseudorandom embedding
  is designed to eliminate.

Click **Run VAPT** to check a single PNG you browse to, or **Analyse All
Session PNGs** to check every frame from your most recent embed at once.
The **OWASP STRIDE Threat Model** panel below is static reference
documentation of how each threat category is mitigated in the codebase.

## 9. Extract and decrypt

On the **Extract** tab:

1. **Folder**: browse to the folder containing the `stego_frame_*.png`
   files (or leave it — if you're extracting in the same session you
   just embedded in, the app can use the in-memory PNG paths directly).
2. **Keys / Keystore**: either use your current session's keys
   (**Extract (Session Keys)**) or load a saved keystore file with its
   password (**Extract (Load Keystore)**).
3. **Bundle length**: the exact byte count reported at the end of the
   Embed step. This is required — extraction cannot guess it.
4. **Frames**: the same frame count used during embedding.
5. Click the matching extract button.

On success, the **Decrypted Message / File** panel shows the recovered
plaintext (or a hex preview if it's binary), the original embed
timestamp, the bundle's age at extraction time, and confirmation that
both the HMAC integrity check and the GCM authentication tag verified.

If extraction fails, the panel shows the error along with a checklist —
double-check the folder, bundle length, frame count, and that you're
using the correct matching keys/pixel seed.

## 10. Audit log

The **Audit** tab shows a running, tamper-evident log of every
significant action taken in the app this session and in prior sessions
(key generation, keystore save/load, embed, extract, VAPT runs). Click
**Verify Chain** at any time to confirm no entry has been deleted or
altered — each entry is HMAC-chained to the previous one, so any
tampering anywhere in the file is detectable.

## 11. Policy and About

**Policy** contains the full software license, copyright/IP notices,
watermark policy, and disclaimer. **About** shows version info, the
developer/institution credit, and a summary of the cryptographic and
steganographic techniques in use.

---

## Practical tips

- **Always test round-trip on a copy first.** Embed, then immediately
  extract in the same session, before you rely on a real message going
  somewhere else.
- **Lower fill ratios are safer against detection, but need more frames
  or a longer video** for the same payload size — there's a genuine
  trade-off, not a free lunch.
- **The pixel seed is effectively your steganographic password.**
  Anyone with it (and the RSA/X25519 keys) can extract your hidden data
  from the stego video even without knowing anything else. Treat a saved
  keystore file and its password with the same care as any other secret
  key material.
- **Lossless transport only.** Copy the PNGs or the AVI as-is; don't
  re-encode, don't paste into a lossy converter, don't upload to a
  platform that transcodes video server-side.
