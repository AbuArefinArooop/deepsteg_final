# DeepSteg v4 — Deployment Guide

Version: 4.0.2
© 2026 Abu Arefin Aroop & Arslan Institute of Technology (AiT). All Rights Reserved.

This guide covers installing, configuring, verifying, and troubleshooting
DeepSteg v4 on Windows 11 and Linux. For how to *use* the app once it's
running, see [`USER_GUIDE.md`](USER_GUIDE.md).

---

## 1. System requirements

| Requirement | Minimum |
|---|---|
| OS | Windows 11, or Linux (Kali, Parrot, Ubuntu 22.04+, Debian 12+, Fedora, Arch) |
| Python | 3.10 – 3.12 (3.13 is untested; some pinned wheels may not yet exist) |
| RAM | 2 GB free (Scrypt keystore derivation uses ~128 MB per unlock) |
| Disk | ~500 MB for the venv + dependencies |
| Display | A GUI session (Tkinter). Headless/server installs are not supported for the GUI. |

No GPU is required or used.

---

## 2. Installation

### 2.1 Linux (recommended path)

```bash
chmod +x installer/linux/install.sh
./installer/linux/install.sh
```

This will:
1. Detect your distro (Kali/Parrot/Ubuntu/Debian/Fedora/Arch).
2. Verify or install Python 3.10+.
3. Install system packages needed by Tkinter/OpenCV (`python3-tk`,
   `libgl1-mesa-glx`, `libglib2.0-0`, or distro equivalents).
4. Copy the app into `~/.local/share/deepsteg`.
5. Create an isolated virtual environment and install
   `requirements.txt` into it (never touches your system Python).
6. Attempt to install the optional `kyber-py` package (safe to fail;
   the app falls back automatically — see §5).
7. Create a `deepsteg` command on your `PATH` (via `/usr/local/bin`,
   requires `sudo`) and a `.desktop` entry so it appears in your
   application menu.
8. Run the 56-test security suite and print the result.

Launch afterwards with:
```bash
deepsteg
# or directly:
~/.local/share/deepsteg/run.sh
```

To uninstall:
```bash
./installer/linux/install.sh --uninstall
```

### 2.2 Windows 11

Open **PowerShell as Administrator**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\installer\windows\install.ps1
```

This will:
1. Locate a Python 3.10+ interpreter (tries `python`, `python3`, `py`).
2. Create `%LOCALAPPDATA%\DeepSteg\venv` and install
   `requirements.txt` into it.
3. Attempt the optional `kyber-py` install.
4. Create `DeepSteg.cmd` (console launcher) and `DeepSteg.vbs`
   (silent launcher, no console flash).
5. Create a Desktop shortcut and Start Menu entry.
6. Register the app in **Add/Remove Programs**.
7. Run the security test suite.

Launch afterwards from the Desktop shortcut, Start Menu, or:
```powershell
& "$env:LOCALAPPDATA\DeepSteg\DeepSteg.cmd"
```

To uninstall:
```powershell
.\installer\windows\install.ps1 -Uninstall
```
or use **Add/Remove Programs → DeepSteg v4 → Uninstall**.

### 2.3 Manual installation (any platform, including macOS for development)

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 deepsteg_app.py
```

macOS is not an officially supported target (the installers and platform
detection cover Windows/Linux only), but the core cryptography and
steganography modules are pure-Python/OpenCV/NumPy and should run on any
platform with Tkinter available.

---

## 3. Post-install verification

Always confirm the security suite passes before relying on the
installation:

```bash
python3 tests/test_security.py
# or
python3 -m pytest tests/test_security.py -q
```

Expect: **56/56 passed**. If any test fails, do not use the installation
for anything beyond debugging — see §6.

A quick functional smoke test (no GUI needed) that exercises the full
encrypt → embed → steganalyze → extract → decrypt pipeline is included
below; run it from the project root with the venv active:

```bash
python3 - <<'PY'
import sys; sys.path.insert(0, ".")
import numpy as np, cv2
from core.crypto_engine import generate_rsa_keypair, generate_x25519_keypair, build_bundle_v4, parse_bundle_v4, hkdf_derive
from core.steg_engine import embed_multiframe, extract_multiframe, split_into_chunks

W,H,FPS,NF = 320,240,25.0,10
wr = cv2.VideoWriter("/tmp/_dstest.avi", cv2.VideoWriter_fourcc(*'HFYU'), FPS, (W,H))
rng = np.random.default_rng(0)
for _ in range(NF):
    wr.write(cv2.GaussianBlur(rng.integers(0,256,(H,W,3),dtype=np.uint8), (7,7), 0))
wr.release()

rsa_priv, rsa_pub = generate_rsa_keypair(2048)
s_priv, s_pub = generate_x25519_keypair()
r_priv, r_pub = generate_x25519_keypair()
pixel_seed = hkdf_derive(s_priv.exchange(r_pub), info=b"deepsteg-pixel-seed-v4")

bundle = build_bundle_v4(b"deployment smoke test", rsa_pub, s_priv, r_pub, ttl_mode='demo')
avg, _ = embed_multiframe("/tmp/_dstest.avi", "/tmp/_dsstego", bundle, pixel_seed, n_frames=4)
dummy = split_into_chunks(b'\x00'*len(bundle), len(avg['stego_pngs']))
sizes = [len(c) for c in dummy]
extracted = extract_multiframe(avg['stego_pngs'], sizes, pixel_seed)
plaintext, ts, age = parse_bundle_v4(extracted, rsa_priv, r_priv)
assert plaintext == b"deployment smoke test"
print(f"OK — PSNR={avg['PSNR']}dB, round-trip verified.")
PY
```

---

## 4. Configuration

DeepSteg v4 has no external config file; behaviour is controlled from
the GUI per-session, plus these on-disk locations:

| Data | Linux path | Windows path |
|---|---|---|
| Keystore (default) | `~/.config/deepsteg/keystore.bin` | `%APPDATA%\DeepSteg\deepsteg_keystore.bin` |
| Audit log | `~/.local/share/deepsteg/logs/audit.jsonl` | `%APPDATA%\DeepSteg\logs\audit.jsonl` |
| Default output folder | `~/DeepSteg/` | `Documents\DeepSteg\` |

The audit log secret key defaults to a fixed development value
(`deepsteg-audit-dev-key`) unless you set the environment variable
`DEEPSTEG_AUDIT_SECRET` before launching:

```bash
export DEEPSTEG_AUDIT_SECRET="a long random production secret"
deepsteg
```

**For any production or non-classroom deployment, set this variable.**
Without it, anyone with access to `core/audit_log.py` knows the HMAC key
and can forge a self-consistent (but still detectably different) chain.

---

## 5. Post-quantum KEM (Kyber-1024) — current status

The installers attempt `pip install kyber-py` as an optional step. If it
succeeds, note the following **known limitation in v4.0.2**: the code
path that would activate a real Kyber-1024 key exchange checks for a
`_kyber_pub` attribute on the receiver's X25519 public key object
(`core/crypto_engine.py`, `hybrid_kem_encapsulate`). A real
`X25519PublicKey` object from the `cryptography` library never has this
attribute, so **this path never actually triggers** — the hybrid KEM
always uses its documented fallback (a second independent X25519
exchange) regardless of whether `kyber-py` is installed.

This does not weaken the *classical* security of the scheme (X25519 +
X25519 via HKDF is still IND-CPA secure under the KEM combiner argument),
but it means the system is **not currently post-quantum secure** despite
the "Kyber-1024 ready" language in the UI and paper. If post-quantum
resistance is a hard requirement for your deployment, this needs a code
change (wiring a real Kyber keypair into the receiver's identity and
threading it through `hybrid_kem_encapsulate`/`hybrid_kem_decapsulate`)
before go-live. Treat "PQ-ready" as *architecturally prepared for*, not
*currently providing*.

---

## 6. Troubleshooting

**App won't start / `ImportError` on launch**
Confirm you're running the fixed `deepsteg_app.py` (v4.0.2 or later) —
earlier v4.0.1 builds had a startup-crashing import. Check with:
```bash
grep "APP_VERSION" core/policy.py
```

**`_tkinter.TclError: couldn't connect to display`**
You're running in a headless/SSH session without X forwarding or a
virtual framebuffer. Either run on a machine with a real display, use
`ssh -X`, or set up Xvfb for automated testing only (not for real usage
— steganography and key handling should be done on a trusted local
machine, not a remote headless server).

**`_tkinter.TclError: Layout Vertical.D.TScrollbar not found`**
This was a bug in versions prior to 4.0.2. Update to the current
release.

**Video won't embed — "Chunk too large" or capacity error**
Your message/file is larger than `n_frames × frame_capacity × fill_ratio`
allows. Either increase `Frames`, raise the `Fill ratio` slider, or
shorten the payload. The capacity label under Settings updates live once
a video is loaded.

**Extraction fails with "HMAC integrity check FAILED"**
The stego PNGs, the bundle length, the frame count, or the pixel seed
don't match what was used at embed time exactly. All four must match:
the bundle length shown in the Embed log, the same number of frames, the
unmodified PNG files (any re-encoding/re-compression breaks LSB data),
and the correct keys/pixel seed (matching keystore or same session).

**Extraction fails with "Bundle expired"**
The bundle's replay TTL (60s in `prod` mode, 3600s in `demo` mode) has
elapsed since embedding. Re-embed with `demo` mode for longer-lived test
bundles, or extract sooner.

**`pip install` fails on a dependency**
The pinned versions in `requirements.txt` target Python 3.10–3.12. If
you're on a newer Python without prebuilt wheels yet, either install a
supported Python version, or relax the pins (`pip install
opencv-python numpy Pillow scikit-image matplotlib cryptography`
without exact versions) — verify with the security test suite afterwards
since untested newer library versions could behave differently.

**Windows: shortcut icon doesn't show the AiT logo**
This is cosmetic; the installer falls back to a generic shell32 icon if
it cannot embed the PNG logo into a `.lnk`. The app itself still shows
the correct logo once launched.

---

## 7. Uninstalling / cleaning up

Linux: `./installer/linux/install.sh --uninstall` removes the install
directory, the `deepsteg` symlink, and the desktop entry, but **does
not** delete `~/.config/deepsteg` (keystore) or
`~/.local/share/deepsteg/logs` (audit log) — remove those manually if
you want a full wipe, understanding this destroys your saved keys and
tamper-evident history irreversibly.

Windows: `.\installer\windows\install.ps1 -Uninstall` or Add/Remove
Programs removes the install directory and shortcuts, but likewise
leaves `%APPDATA%\DeepSteg` (keystore/logs) in place by design.
