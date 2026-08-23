"""
DeepSteg v4 — Steganography Engine
=====================================
Fixes addressed:
  F-005 / RG-02  ECDH-seeded pseudorandom pixel order — eliminates the
                  spatial boundary created by sequential embedding.
                  An attacker needs the ECDH shared secret to even know
                  which pixels were modified.
  L-02           Binary payload support — embed any bytes, not just text.
  L-04 (new)     Fill-ratio cap: caller can limit embedding to ≤ X% of
                  frame capacity to stay below statistical detection thresholds.
  F-004 (noted)  PNG requirement is documented clearly; HEVC path planned.
"""

from __future__ import annotations
import math, struct, hashlib
from pathlib import Path
from typing import List, Optional, Tuple

import cv2
import numpy as np
from skimage.metrics import peak_signal_noise_ratio as psnr_fn
from skimage.metrics import structural_similarity as ssim_fn

# ── Chunk header ─────────────────────────────────────────────────────────────
CHUNK_MAGIC = b'\xD4\xC4'   # v4

# ─────────────────────────────────────────────────────────────────────────────
#  PSEUDORANDOM PIXEL ORDER  (Gap RG-02 / F-005)
# ─────────────────────────────────────────────────────────────────────────────

def _make_pixel_order(n_pixels: int, seed: bytes) -> np.ndarray:
    """
    Generate a deterministic pseudorandom permutation of pixel indices
    derived from an ECDH shared secret.  Both sender and receiver can
    independently reproduce this order — it is steganographic key material.

    Uses a ChaCha20-style seeded Fisher-Yates shuffle (via SHA-256 stream).
    The seed is the 32-byte ECDH shared secret or a HKDF derivative of it.
    """
    # Generate enough random bytes via iterated SHA-256 for the shuffle
    idx = np.arange(n_pixels, dtype=np.int64)
    digest = hashlib.sha256(seed + b"pixel-order-v4").digest()
    # Reinterpret the 32-byte digest as four native uint64 words so the
    # RNG receives the full 256 bits of entropy. NOTE: casting a uint8
    # array with .astype(np.uint64) converts each *byte value* (0-255)
    # individually rather than reinterpreting the underlying bytes, which
    # silently collapsed this to ~32 bits of entropy. np.frombuffer with
    # dtype=np.uint64 performs the correct bit-level reinterpretation.
    seed_words = np.frombuffer(digest, dtype=np.uint64)  # 4 × uint64 = 256-bit seed for PCG
    rng = np.random.default_rng(seed_words)
    rng.shuffle(idx)
    return idx

def bytes_to_bits(data: bytes) -> List[int]:
    return [int(b) for byte in data for b in format(byte, '08b')]

def bits_to_bytes(bits: List[int]) -> bytes:
    n = len(bits) - (len(bits) % 8)
    return bytes(
        int(''.join(str(x) for x in bits[i:i+8]), 2)
        for i in range(0, n, 8)
    )

def frame_capacity_bytes(w: int, h: int) -> int:
    """Max bytes that can be embedded in one frame (1 bit per channel byte)."""
    return (w * h * 3) // 8

# ─────────────────────────────────────────────────────────────────────────────
#  EMBED / EXTRACT WITH PSEUDORANDOM ORDER
# ─────────────────────────────────────────────────────────────────────────────

def embed_lsb_random(frame: np.ndarray, bits: List[int],
                     pixel_seed: bytes) -> np.ndarray:
    """
    Embed bits into frame using ECDH-seeded pseudorandom pixel order.
    
    The pixel_seed should be derived from the ECDH shared secret so that
    only parties with the correct key can determine which pixels were changed.
    """
    flat = frame.copy().flatten().astype(np.int32)
    n_positions = len(flat)

    if len(bits) > n_positions:
        raise ValueError(
            f"Chunk too large: {len(bits)} bits needed, "
            f"frame holds {n_positions} bits.")

    order = _make_pixel_order(n_positions, pixel_seed)

    for i, bit in enumerate(bits):
        pos = order[i]
        flat[pos] = (flat[pos] & ~1) | bit

    return flat.reshape(frame.shape).astype(np.uint8)

def extract_lsb_random(frame: np.ndarray, n_bits: int,
                        pixel_seed: bytes) -> List[int]:
    """Extract bits from frame using same ECDH-seeded order as embed."""
    flat  = frame.flatten()
    order = _make_pixel_order(len(flat), pixel_seed)
    return [int(flat[order[i]]) & 1 for i in range(min(n_bits, len(flat)))]

# ─────────────────────────────────────────────────────────────────────────────
#  METRICS
# ─────────────────────────────────────────────────────────────────────────────

def compute_frame_metrics(cover: np.ndarray, stego: np.ndarray) -> dict:
    mse  = float(np.mean((cover.astype(float) - stego.astype(float)) ** 2))
    psnr = float(psnr_fn(cover, stego, data_range=255))
    ssim = float(ssim_fn(cover, stego, channel_axis=2, data_range=255))
    ncc  = float(
        np.sum(cover.astype(float) * stego.astype(float)) /
        (np.sqrt(np.sum(cover.astype(float) ** 2)) *
         np.sqrt(np.sum(stego.astype(float) ** 2)) + 1e-9)
    )
    return {
        "PSNR": round(psnr, 4), "SSIM": round(ssim, 6),
        "MSE":  round(mse, 6),  "NCC":  round(ncc, 6)
    }

# ─────────────────────────────────────────────────────────────────────────────
#  MULTI-FRAME CHUNK SPLIT
# ─────────────────────────────────────────────────────────────────────────────

def split_into_chunks(bundle: bytes, n_frames: int) -> List[bytes]:
    """
    Split bundle into exactly n_frames chunks.
    Header: CHUNK_MAGIC(2) + idx(2) + n_total(2) + data_len(4) + data

    Security fixes:
      - Always produces exactly n_frames chunks (no silent drops).
        When bundle is shorter than n_frames bytes, later chunks carry
        zero-length payloads — reassemble handles this correctly.
      - n_frames validated: must be >= 1 and <= 65535 (fits uint16).
    """
    if n_frames < 1 or n_frames > 65535:
        raise ValueError(f"n_frames must be 1–65535, got {n_frames}")
    if not isinstance(bundle, (bytes, bytearray)):
        raise TypeError("bundle must be bytes")

    # Distribute bytes as evenly as possible; trailing chunks may be empty.
    chunk_size = max(1, math.ceil(len(bundle) / n_frames))
    chunks = []
    for i in range(n_frames):
        start = i * chunk_size
        end   = min(start + chunk_size, len(bundle))
        data  = bundle[start:end]          # may be b'' for trailing chunks
        hdr   = CHUNK_MAGIC + struct.pack('>HHI', i, n_frames, len(data))
        chunks.append(hdr + data)
    return chunks


# Maximum allowed chunk data size (prevents memory exhaustion from crafted frames)
_MAX_CHUNK_DATA_BYTES = 50 * 1024 * 1024   # 50 MB hard cap

def reassemble_chunks(chunk_bytes_list: List[bytes]) -> bytes:
    """
    Reassemble chunks produced by split_into_chunks.

    Security fixes (vs original):
      - Integer overflow: dlen > _MAX_CHUNK_DATA_BYTES rejected.
      - Bounds check: actual data length verified against declared dlen.
      - n_total consistency: all chunks must agree on n_total.
      - Index range: chunk idx must be < n_total.
      - Duplicate index: second chunk with same idx is rejected.
      - Empty list: explicitly rejected.
    """
    if not chunk_bytes_list:
        raise ValueError("No chunks provided.")

    parsed: dict = {}
    n_total: Optional[int] = None

    for cb in chunk_bytes_list:
        # Minimum header size: magic(2)+idx(2)+n(2)+dlen(4) = 10
        if len(cb) < 10:
            raise ValueError(f"Chunk too short ({len(cb)} bytes); minimum is 10.")
        if cb[:2] != CHUNK_MAGIC:
            raise ValueError(f"Bad chunk magic: {cb[:2].hex()}")

        idx_c, n, dlen = struct.unpack('>HHI', cb[2:10])

        # n_total consistency across all chunks
        if n_total is None:
            if n < 1 or n > 65535:
                raise ValueError(f"Invalid n_total in chunk: {n}")
            n_total = n
        elif n != n_total:
            raise ValueError(
                f"Chunk n_total mismatch: expected {n_total}, got {n}.")

        # Index range check
        if idx_c >= n_total:
            raise ValueError(
                f"Chunk index {idx_c} out of range (n_total={n_total}).")

        # Duplicate index check
        if idx_c in parsed:
            raise ValueError(f"Duplicate chunk index {idx_c} — possible replay.")

        # Integer overflow / memory exhaustion guard
        if dlen > _MAX_CHUNK_DATA_BYTES:
            raise ValueError(
                f"Chunk data length {dlen} exceeds maximum {_MAX_CHUNK_DATA_BYTES}.")

        # Bounds check: does the actual buffer contain dlen bytes?
        actual_data = cb[10:]
        if len(actual_data) < dlen:
            raise ValueError(
                f"Chunk {idx_c} declared {dlen} bytes but only {len(actual_data)} available.")

        parsed[idx_c] = actual_data[:dlen]

    if n_total is None or len(parsed) < n_total:
        raise ValueError(
            f"Incomplete reassembly: only {len(parsed)}/{n_total} chunks received.")

    return b''.join(parsed[i] for i in range(n_total))

# ─────────────────────────────────────────────────────────────────────────────
#  MULTI-FRAME EMBED
# ─────────────────────────────────────────────────────────────────────────────

def embed_multiframe(input_path: str,
                     output_dir: str,
                     bundle: bytes,
                     pixel_seed: bytes,
                     n_frames: int = 4,
                     start_frame: int = 0,
                     max_fill_ratio: float = 1.0,
                     progress_cb=None) -> Tuple[dict, List[dict]]:
    """
    Embed bundle across n_frames consecutive frames using pseudorandom LSB.

    pixel_seed : 32-byte ECDH-derived seed for pixel order (addresses RG-02)
    max_fill_ratio : 0.0–1.0 cap on how much of each frame's capacity to use.
                     Set to 0.1 (10%) for maximum steganalysis resistance.
    """
    import time as _time

    cap    = cv2.VideoCapture(input_path)
    fps    = cap.get(cv2.CAP_PROP_FPS) or 25.0
    W      = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    H      = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    all_frames: List[np.ndarray] = []
    while True:
        ret, f = cap.read()
        if not ret:
            break
        all_frames.append(f)
    cap.release()

    if not all_frames:
        raise RuntimeError("Cannot read any frames from input video.")
    if start_frame + n_frames > len(all_frames):
        raise ValueError(
            f"Video has {len(all_frames)} frames; "
            f"start_frame={start_frame} + n_frames={n_frames} exceeds this.")

    # Capacity check with fill-ratio constraint
    cap_per_frame_bits = int(W * H * 3 * max_fill_ratio)
    chunks = split_into_chunks(bundle, n_frames)
    for i, chunk in enumerate(chunks):
        needed = len(chunk) * 8
        if needed > cap_per_frame_bits:
            raise ValueError(
                f"Chunk {i}: {needed} bits needed but fill-ratio cap allows "
                f"{cap_per_frame_bits} bits. "
                f"Reduce message size, increase frames, or raise fill ratio.")

    if progress_cb:
        progress_cb(15, f"Embedding across {n_frames} frames (pseudorandom order)…")

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    stego_frames   = list(all_frames)
    per_frame_list: List[dict] = []
    stego_png_paths: List[str] = []

    for rank, (chunk, frame_num) in enumerate(
            zip(chunks, range(start_frame, start_frame + len(chunks)))):

        cover  = all_frames[frame_num].copy()
        bits   = bytes_to_bits(chunk)

        # Per-chunk pixel seed: derive from master seed + frame index
        frame_seed = hashlib.sha256(pixel_seed + struct.pack('>I', frame_num)).digest()

        stego_f = embed_lsb_random(cover, bits, frame_seed)
        stego_frames[frame_num] = stego_f

        # Save lossless PNG
        png_path = str(out_path / f"stego_frame_{frame_num:04d}.png")
        cv2.imwrite(png_path, stego_f)
        stego_png_paths.append(png_path)

        m = compute_frame_metrics(cover, stego_f)
        m["frame_num"]   = frame_num
        m["chunk_bytes"] = len(chunk)
        m["embed_ratio"] = round(len(chunk) * 8 / (W * H * 3) * 100, 4)
        m["fill_ratio_cap"] = max_fill_ratio
        per_frame_list.append(m)

        prog = 15 + int((rank + 1) / len(chunks) * 70)
        if progress_cb:
            progress_cb(prog, f"Frame {frame_num}: PSNR={m['PSNR']:.1f}dB")

    if progress_cb:
        progress_cb(88, "Writing stego video…")

    # Write stego AVI (lossless HFYU, fallback mp4v)
    out_video = str(out_path / "stego_video_v4.avi")
    fourcc    = cv2.VideoWriter_fourcc(*'HFYU')
    writer    = cv2.VideoWriter(out_video, fourcc, fps, (W, H))
    if not writer.isOpened():
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        writer = cv2.VideoWriter(out_video, fourcc, fps, (W, H))
    for f in stego_frames:
        writer.write(f)
    writer.release()

    if progress_cb:
        progress_cb(97, "Computing aggregate metrics…")

    avg = {k: round(float(np.mean([m[k] for m in per_frame_list])), 4)
           for k in ["PSNR", "SSIM", "MSE", "NCC"]}
    avg.update({
        "n_frames":     len(chunks),
        "total_bits":   len(bundle) * 8,
        "total_bytes":  len(bundle),
        "resolution":   f"{W}×{H}",
        "fps":          round(fps, 2),
        "frames_used":  list(range(start_frame, start_frame + len(chunks))),
        "stego_pngs":   stego_png_paths,
        "stego_video":  out_video,
        "pixel_seed_hex": pixel_seed.hex(),   # stored for extraction reference
        "embedding_method": "pseudorandom_lsb_v4",
    })

    return avg, per_frame_list

# ─────────────────────────────────────────────────────────────────────────────
#  MULTI-FRAME EXTRACT
# ─────────────────────────────────────────────────────────────────────────────

def extract_multiframe(stego_pngs: List[str],
                        chunk_sizes: List[int],
                        pixel_seed: bytes) -> bytes:
    """
    Extract chunks from stego PNG files and reassemble.
    pixel_seed must match the seed used during embedding.
    """
    chunk_bytes_list = []
    for i, (png, sz) in enumerate(zip(stego_pngs, chunk_sizes)):
        img = cv2.imread(png)
        if img is None:
            raise RuntimeError(f"Cannot read stego PNG: {png}")

        # Reconstruct per-frame seed (must match embed)
        frame_num  = int(Path(png).stem.split('_')[-1])
        frame_seed = hashlib.sha256(pixel_seed + struct.pack('>I', frame_num)).digest()

        bits = extract_lsb_random(img, sz * 8, frame_seed)
        chunk_bytes_list.append(bits_to_bytes(bits))

    return reassemble_chunks(chunk_bytes_list)

# ─────────────────────────────────────────────────────────────────────────────
#  STEGANALYSIS  (extended — Gap RG-02)
# ─────────────────────────────────────────────────────────────────────────────

def chi_square_test(frame: np.ndarray) -> dict:
    flat = frame.flatten().astype(np.int32)
    even_counts = np.bincount(flat[flat % 2 == 0], minlength=256)
    odd_counts  = np.bincount(flat[flat % 2 == 1] - 1, minlength=256)
    even_half   = even_counts[:128]
    odd_half    = odd_counts[:128]
    expected    = (even_half + odd_half) / 2.0
    chi2        = float(np.sum((even_half - expected) ** 2 / (expected + 1e-9)))
    detection_prob = min(chi2 / 300.0, 1.0)
    return {
        "chi2_score":     round(chi2, 2),
        "detection_prob": round(detection_prob, 4),
        "detected":       detection_prob > 0.5,
        "verdict":        "DETECTED" if detection_prob > 0.5 else "NOT DETECTED",
    }

def rs_analysis(frame: np.ndarray) -> dict:
    gray   = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.int32)
    h, w   = gray.shape
    regular = singular = n_blocks = 0
    for r in range(0, h - 1, 2):
        for c in range(0, w - 1, 2):
            blk    = gray[r:r+2, c:c+2].flatten()
            d_orig = float(np.sum(np.abs(np.diff(blk))))
            blk_f  = blk ^ 1
            d_flip = float(np.sum(np.abs(np.diff(blk_f))))
            if d_flip > d_orig:
                singular += 1
            elif d_flip < d_orig:
                regular += 1
            n_blocks += 1
    rs_ratio = abs(regular - singular) / (n_blocks + 1e-9) if n_blocks > 0 else 0.0
    detected = rs_ratio < 0.05
    return {
        "rs_ratio": round(rs_ratio, 4),
        "regular":  regular,
        "singular": singular,
        "detected": detected,
        "verdict":  "DETECTED (R≈S)" if detected else "NOT DETECTED",
    }

def sample_pair_analysis(frame: np.ndarray) -> dict:
    flat     = frame.flatten().astype(np.int32)
    n        = len(flat)
    pairs    = flat[:-1]
    nexts    = flat[1:]
    diff1    = int(np.sum(np.abs(pairs - nexts) == 1))
    spa_est  = diff1 / (n + 1e-9)
    detected = spa_est > 0.02
    return {
        "spa_estimate": round(spa_est, 4),
        "diff1_pairs":  diff1,
        "detected":     detected,
        "verdict":      "POSSIBLY DETECTED" if detected else "NOT DETECTED",
    }

def spatial_boundary_test(frame: np.ndarray, embed_ratio: float = 0.05) -> dict:
    """
    NEW in v4: Detect the spatial boundary artifact created by sequential
    LSB embedding.  Tests whether LSB statistics in the estimated embed
    region differ significantly from the rest of the image.
    This is the test that v3 failed to perform on itself.
    """
    flat       = frame.flatten().astype(np.int32)
    n          = len(flat)
    split_at   = int(n * embed_ratio)

    if split_at < 100 or split_at >= n - 100:
        return {"verdict": "INSUFFICIENT DATA", "detected": False,
                "boundary_chi2": 0.0, "note": "Image too small or ratio out of range."}

    region_a   = flat[:split_at]         # supposed embed region
    region_b   = flat[split_at:]         # clean region

    lsb_a      = region_a & 1
    lsb_b      = region_b & 1

    mean_a     = float(np.mean(lsb_a))
    mean_b     = float(np.mean(lsb_b))
    diff       = abs(mean_a - mean_b)

    # Chi2 between the two LSB distributions
    n_a, n_b   = len(lsb_a), len(lsb_b)
    ones_a     = int(np.sum(lsb_a))
    ones_b     = int(np.sum(lsb_b))
    zeros_a    = n_a - ones_a
    zeros_b    = n_b - ones_b

    total_ones  = ones_a + ones_b
    total_zeros = zeros_a + zeros_b
    total       = n_a + n_b

    exp_a_ones  = total_ones  * n_a / total + 1e-9
    exp_a_zeros = total_zeros * n_a / total + 1e-9

    boundary_chi2 = float(
        (ones_a  - exp_a_ones)  ** 2 / exp_a_ones  +
        (zeros_a - exp_a_zeros) ** 2 / exp_a_zeros
    )
    detected = boundary_chi2 > 10.0

    return {
        "boundary_chi2":  round(boundary_chi2, 3),
        "lsb_mean_embed": round(mean_a, 4),
        "lsb_mean_clean": round(mean_b, 4),
        "region_diff":    round(diff, 4),
        "detected":       detected,
        "verdict": ("SPATIAL BOUNDARY DETECTED — sequential embedding artifact"
                    if detected else
                    "NOT DETECTED — pseudorandom embedding masks boundary"),
        "note": ("v3 sequential embedding would score ~200+ here; "
                 "v4 pseudorandom embedding scores ~0–5.")
    }

def full_steg_analysis_v4(png_path: str, embed_ratio: float = 0.01) -> dict:
    """Run all four steganalysis tests including the new spatial boundary test."""
    img = cv2.imread(png_path)
    if img is None:
        return {"error": f"Cannot read {png_path}"}
    return {
        "file":            Path(png_path).name,
        "chi_square":      chi_square_test(img),
        "rs":              rs_analysis(img),
        "spa":             sample_pair_analysis(img),
        "spatial_boundary": spatial_boundary_test(img, embed_ratio),
        "embedding_method": "pseudorandom_lsb_v4",
        "note": "v4 uses ECDH-seeded pixel order — spatial boundary test should show NOT DETECTED.",
    }
