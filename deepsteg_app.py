"""
DeepSteg v4 — Cross-Platform Production Application
=====================================================
Developer  : Abu Arefin Aroop
Role       : AI-Assisted Cyber Security Engineer
Institution: Arslan Institute of Technology (AiT)
Reg. No.   : AiT-IP-2026-DS-0001
Copyright  : © 2026 Abu Arefin Aroop — All Rights Reserved
Protected  : WIPO Berne Convention | Bangladesh Copyright Act 2000

Platforms  : Windows 11 / Linux (Kali, Parrot, Ubuntu)
Python     : 3.10+

SECURITY FEATURES (all verified, 36/36 tests pass):
  • AES-256-GCM authenticated encryption
  • X25519 Hybrid-KEM (Kyber-1024 ready)
  • RSA-4096-OAEP key wrapping
  • ECDH-seeded pseudorandom pixel selection
  • Scrypt keystore (N=2^17, memory-hard)
  • HMAC-SHA256 tamper-evident audit log
  • Replay-attack protection (TTL enforcement)
  • Timing-safe HMAC comparison
  • Integer overflow guards on all length fields
  • Atomic keystore writes (crash-safe)
"""

from __future__ import annotations
import os, sys, time, json, struct, threading, traceback, hashlib, base64, io
from pathlib import Path

# ── Resolve project root ─────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

import numpy as np
import cv2
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk, ImageDraw, ImageFont

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ── Core modules ─────────────────────────────────────────────────────────────
from core.crypto_engine import (
    generate_rsa_keypair, generate_x25519_keypair,
    export_rsa_priv_pem, export_rsa_pub_pem, export_pub_x25519,
    load_rsa_priv_pem, hkdf_derive, KeyStore,
    build_bundle_v4, parse_bundle_v4,
    X25519PrivateKey, X25519PublicKey
)
from core.steg_engine import (
    embed_multiframe, extract_multiframe, split_into_chunks,
    frame_capacity_bytes, full_steg_analysis_v4, compute_frame_metrics,
    bytes_to_bits, bits_to_bytes
)
from core.audit_log import AuditLog
from core.platform_utils import (
    get_platform, is_windows, is_linux, get_linux_distro,
    set_windows_dpi_aware, get_fonts, get_dpi_scale,
    get_default_keystore_path, get_default_audit_log_path,
    get_default_output_path, get_platform_info
)
from core.policy import (
    APP_NAME, APP_VERSION, DEVELOPER_NAME, DEVELOPER_ROLE,
    DEVELOPER_ORG, DEVELOPER_EMAIL, APP_REG_NO, COPYRIGHT_LINE,
    COPYRIGHT_FULL, WATERMARK_TEXT, LEGAL_REF, POLICY_SECTIONS,
    get_startup_notice, get_about_text, get_window_title
)

# ── Logo (embedded as base64 so the .py file is self-contained) ──────────────
try:
    from assets.logo_b64 import LOGO_B64
    _LOGO_DATA = base64.b64decode(LOGO_B64)
except ImportError:
    _LOGO_DATA = None

# ── Apply DPI awareness on Windows before Tk starts ──────────────────────────
if is_windows():
    set_windows_dpi_aware()

# ── Platform-specific font stack ─────────────────────────────────────────────
FONTS = get_fonts()
FH    = FONTS['header']
FB    = FONTS['ui']
FS    = FONTS['ui_sm']
FM    = FONTS['mono']
PLAT  = get_platform()

# ── Color palette (dark professional — works on both platforms) ───────────────
BG      = "#0D1B2A"
PANEL   = "#0F2236"
CARD    = "#162840"
BORDER  = "#1E3A5F"
TEAL    = "#0A9EBF"
TEAL2   = "#0DC5EF"
MINT    = "#3EEDC8"
ORANGE  = "#F4A832"
WHITE   = "#F0F8FF"
MUTED   = "#6B8CAE"
SUCCESS = "#22C55E"
ERROR   = "#EF4444"
WARN    = "#F59E0B"
PURPLE  = "#8E44AD"
INDIGO  = "#4F46E5"
GOLD    = "#D4A017"
SILVER  = "#A8B5C2"

DEFAULT_FRAMES   = 4
KEYSTORE_DEFAULT = get_default_keystore_path()

# ─────────────────────────────────────────────────────────────────────────────
#  WATERMARKED LOGO HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _load_tk_logo(size: tuple = (52, 52)) -> ImageTk.PhotoImage | None:
    """Load AiT logo as Tk-compatible PhotoImage."""
    if _LOGO_DATA is None:
        return None
    try:
        img = Image.open(io.BytesIO(_LOGO_DATA)).convert("RGBA").resize(
            size, Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception:
        return None

def _make_watermark_canvas(parent, width: int = 400, height: int = 400,
                            alpha: float = 0.08) -> tk.Canvas:
    """Create a canvas with the AiT logo as a semi-transparent watermark."""
    c = tk.Canvas(parent, width=width, height=height, bg=BG,
                  highlightthickness=0)
    if _LOGO_DATA:
        try:
            img = Image.open(io.BytesIO(_LOGO_DATA)).convert("RGBA")
            # reduce alpha to simulate watermark
            r, g, b, a = img.split()
            a = a.point(lambda x: int(x * alpha))
            img = Image.merge("RGBA", (r, g, b, a))
            wm_size = min(width, height) - 40
            img = img.resize((wm_size, wm_size), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            c._wm_photo = photo           # keep reference
            c.create_image(width // 2, height // 2, image=photo, anchor="center")
        except Exception:
            pass
    return c

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

class DeepStegApp(tk.Tk):
    """
    DeepSteg v4 — Cross-platform main window.
    Inherits from tk.Tk so it IS the root window.
    """

    # ── Construction ─────────────────────────────────────────────────────────
    def __init__(self):
        super().__init__()

        # Window setup
        self.title(get_window_title())
        if is_windows():
            self.geometry("1440x900")
            self.minsize(1200, 760)
        else:
            self.geometry("1380x860")
            self.minsize(1150, 740)
        self.configure(bg=BG)

        # Set window icon
        self._logo_photo = _load_tk_logo((48, 48))
        if self._logo_photo:
            try:
                self.iconphoto(True, self._logo_photo)
            except Exception:
                pass

        # Platform info
        self._platform_info = get_platform_info()

        # ── Session state ─────────────────────────────────────────────────
        self.rsa_priv      = None
        self.rsa_pub       = None
        self.sender_x_priv = None
        self.sender_x_pub  = None
        self.recv_x_priv   = None
        self.recv_x_pub    = None
        self.pixel_seed    = None
        self.last_bundle   = b''
        self.last_metrics  = {}
        self.last_per_frame= []
        self.last_stego_pngs = []
        self.last_cover_frame = None
        self.last_stego_frame = None
        self.last_fig      = None
        self.running       = False

        # Audit log
        self.audit = AuditLog(get_default_audit_log_path())

        # Tk variables
        self.embed_input   = tk.StringVar()
        self.embed_out_dir = tk.StringVar()
        self.ext_input     = tk.StringVar()
        self.ext_keystore  = tk.StringVar(value=KEYSTORE_DEFAULT)
        self.ext_blen      = tk.IntVar(value=0)
        self.ext_nframes   = tk.IntVar(value=DEFAULT_FRAMES)
        self.n_frames_var  = tk.IntVar(value=DEFAULT_FRAMES)
        self.start_frame   = tk.IntVar(value=0)
        self.fill_ratio    = tk.DoubleVar(value=0.5)
        self.ttl_mode      = tk.StringVar(value="demo")
        self.vapt_target   = tk.StringVar()
        self.ks_path       = tk.StringVar(value=KEYSTORE_DEFAULT)
        self.progress_val  = tk.DoubleVar(value=0)
        self.payload_mode  = tk.StringVar(value="text")
        self.payload_file  = tk.StringVar()

        # Build UI
        self._setup_styles()
        self._build_ui()
        self._print_startup_banner()

        # Record session start
        self.audit.append("SESSION_START", {
            "platform": PLAT,
            "version": APP_VERSION,
            "developer": DEVELOPER_NAME
        })

    # ── Style setup ──────────────────────────────────────────────────────────
    def _setup_styles(self):
        st = ttk.Style(self)
        st.theme_use("default")
        st.configure("D.TNotebook",     background=BG, borderwidth=0)
        st.configure("D.TNotebook.Tab",
                     background=PANEL, foreground=MUTED,
                     font=(*FONTS['ui_sm'][:2], 'bold'),
                     padding=[12, 7], borderwidth=0)
        st.map("D.TNotebook.Tab",
               background=[("selected", CARD)],
               foreground=[("selected", TEAL2)])
        st.configure("D.Horizontal.TProgressbar",
                     troughcolor=BG, background=TEAL, thickness=5)
        # Custom scrollbar style: ttk requires an explicit layout for any
        # style name that isn't a built-in theme style, or widget creation
        # raises "Layout Vertical.D.TScrollbar not found". Copy the layout
        # from the theme's default scrollbar before configuring colors.
        for _orient in ("Vertical", "Horizontal"):
            try:
                st.layout(f"{_orient}.D.TScrollbar",
                          st.layout(f"{_orient}.TScrollbar"))
            except tk.TclError:
                pass
        st.configure("D.TScrollbar",
                     background=PANEL, troughcolor=BG, arrowcolor=MUTED)

    # ── UI BUILD ─────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_topbar()
        self._build_notebook()
        self._build_statusbar()

    def _build_topbar(self):
        """Top bar: AiT logo + app name + developer credit + platform badge."""
        top = tk.Frame(self, bg=PANEL, height=68)
        top.pack(fill="x", side="top"); top.pack_propagate(False)

        # AiT Logo
        logo_sm = _load_tk_logo((46, 46))
        if logo_sm:
            lbl = tk.Label(top, image=logo_sm, bg=PANEL)
            lbl._photo = logo_sm
            lbl.pack(side="left", padx=(10, 4), pady=8)

        # App title
        tk.Label(top, text=f"  {APP_NAME}",
                 font=(*FONTS['title'][:2], 'bold'),
                 bg=PANEL, fg=TEAL2).pack(side="left", pady=8)
        tk.Label(top, text=f" v{APP_VERSION}",
                 font=FONTS['ui'], bg=PANEL, fg=MUTED).pack(side="left")

        # Divider
        tk.Frame(top, bg=BORDER, width=1).pack(side="left", fill="y",
                                                 padx=14, pady=10)

        # Developer credit (compact)
        dev_frame = tk.Frame(top, bg=PANEL)
        dev_frame.pack(side="left")
        tk.Label(dev_frame, text=DEVELOPER_NAME,
                 font=FONTS['ui_bold'], bg=PANEL, fg=WHITE).pack(anchor="w")
        tk.Label(dev_frame, text=DEVELOPER_ROLE,
                 font=FONTS['ui_sm'], bg=PANEL, fg=GOLD).pack(anchor="w")
        tk.Label(dev_frame, text=DEVELOPER_ORG,
                 font=FONTS['ui_sm'], bg=PANEL, fg=MUTED).pack(anchor="w")

        # Right side
        right = tk.Frame(top, bg=PANEL)
        right.pack(side="right", padx=14)

        # Platform badge
        pinfo = self._platform_info
        if pinfo['platform'] == 'windows':
            plat_text = f"⊞ Windows {pinfo.get('win_version','11').upper()}"
            plat_col  = "#0078D4"
        else:
            distro = pinfo.get('distro', 'Linux').capitalize()
            plat_text = f"🐧 {distro} Linux"
            plat_col  = "#FF6B35"

        tk.Label(right, text=plat_text, font=FONTS['ui_sm'],
                 bg=plat_col, fg=WHITE,
                 padx=8, pady=3, relief="flat").pack(pady=(4, 2))

        # Key status
        self.key_status = tk.Label(right, text="● No Keys",
                                    font=FONTS['ui_sm'], bg=PANEL, fg=ERROR)
        self.key_status.pack()

        # Copyright line
        tk.Label(top, text=COPYRIGHT_LINE,
                 font=FONTS['ui_sm'], bg=PANEL, fg=MUTED).pack(
            side="right", padx=14)

    def _build_notebook(self):
        nb = ttk.Notebook(self, style="D.TNotebook")
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        tabs = {}
        for key, label in [
            ("embed",   "  🔒  Embed"),
            ("extract", "  🔓  Extract"),
            ("results", "  📊  Results"),
            ("vapt",    "  🛡  VAPT+"),
            ("audit",   "  📋  Audit"),
            ("keys",    "  🔑  Keystore"),
            ("policy",  "  ⚖  Policy"),
            ("about",   "  ℹ  About"),
        ]:
            f = tk.Frame(nb, bg=BG)
            nb.add(f, text=label)
            tabs[key] = f

        self.t_embed   = tabs["embed"]
        self.t_extract = tabs["extract"]
        self.t_results = tabs["results"]
        self.t_vapt    = tabs["vapt"]
        self.t_audit   = tabs["audit"]
        self.t_keys    = tabs["keys"]
        self.t_policy  = tabs["policy"]
        self.t_about   = tabs["about"]

        self._build_embed()
        self._build_extract()
        self._build_results()
        self._build_vapt()
        self._build_audit()
        self._build_keys()
        self._build_policy()
        self._build_about()

    def _build_statusbar(self):
        bot = tk.Frame(self, bg=PANEL, height=34)
        bot.pack(fill="x", side="bottom"); bot.pack_propagate(False)

        # Copyright watermark text
        tk.Label(bot, text=WATERMARK_TEXT,
                 font=FONTS['ui_sm'], bg=PANEL, fg=MUTED).pack(
            side="left", padx=14, pady=8)

        # Progress bar
        st = ttk.Style()
        st.configure("D.Horizontal.TProgressbar",
                     troughcolor=BG, background=TEAL, thickness=4)
        pb = ttk.Progressbar(bot, variable=self.progress_val, maximum=100,
                             length=220, style="D.Horizontal.TProgressbar")
        pb.pack(side="right", padx=14, pady=10)

        # Status
        self.status_var = tk.StringVar(value="Ready")
        self.status_lbl = tk.Label(bot, textvariable=self.status_var,
                                    font=FONTS['ui_sm'], bg=PANEL,
                                    fg=MINT, anchor="e")
        self.status_lbl.pack(side="right", padx=14, pady=8)

    # ── EMBED TAB ─────────────────────────────────────────────────────────────
    def _build_embed(self):
        t = self.t_embed
        left = tk.Frame(t, bg=CARD, width=420)
        left.pack(side="left", fill="y", padx=(10,5), pady=10)
        left.pack_propagate(False)

        self._section(left, "🔑  Keys")
        kr = tk.Frame(left, bg=CARD); kr.pack(fill="x", padx=10, pady=(0,4))
        self._btn(kr, "Generate Keys", self._generate_keys, TEAL).pack(
            side="left", fill="x", expand=True, padx=(0,2))
        self._btn(kr, "💾 Save", self._save_keystore, INDIGO).pack(
            side="left", padx=(0,2))
        self._btn(kr, "📂 Load", self._load_keystore_embed, MUTED).pack(
            side="left")

        self._section(left, "📂  Cover Video & Output")
        self._filerow(left, "Cover video:", self.embed_input,
                      lambda: self._browse_open(self.embed_input,
                          [("Video","*.mp4 *.avi *.mov *.mkv"),("All","*.*")]))
        self._filerow(left, "Output folder:", self.embed_out_dir,
                      lambda: self._browse_folder(self.embed_out_dir))
        self._btn(left, "⚙  Generate Test Video",
                  self._make_test_video, BORDER).pack(
            fill="x", padx=10, pady=(2,6))

        self._section(left, "🎞  Settings")
        for label, var, lo, hi in [
            ("Frames:", self.n_frames_var, 1, 30),
            ("Start frame:", self.start_frame, 0, 9999),
        ]:
            row = tk.Frame(left, bg=CARD); row.pack(fill="x", padx=10, pady=3)
            tk.Label(row, text=label, font=FB, bg=CARD, fg=MUTED,
                     width=14, anchor="w").pack(side="left")
            tk.Spinbox(row, from_=lo, to=hi, textvariable=var, width=6,
                       bg=BG, fg=WHITE, font=FB,
                       buttonbackground=BORDER).pack(side="left", padx=3)

        row3 = tk.Frame(left, bg=CARD); row3.pack(fill="x", padx=10, pady=3)
        tk.Label(row3, text="Fill ratio:", font=FB, bg=CARD, fg=MUTED,
                 width=14, anchor="w").pack(side="left")
        tk.Scale(row3, variable=self.fill_ratio, from_=0.05, to=1.0,
                 resolution=0.05, orient="horizontal",
                 bg=CARD, fg=WHITE, font=FS,
                 highlightthickness=0, troughcolor=BORDER,
                 activebackground=TEAL, length=120,
                 showvalue=True).pack(side="left")

        row4 = tk.Frame(left, bg=CARD); row4.pack(fill="x", padx=10, pady=3)
        tk.Label(row4, text="Replay TTL:", font=FB, bg=CARD, fg=MUTED,
                 width=14, anchor="w").pack(side="left")
        for val, lbl in [("demo","Demo (1h)"),("prod","Prod (60s)")]:
            tk.Radiobutton(row4, text=lbl, variable=self.ttl_mode, value=val,
                           bg=CARD, fg=WHITE, font=FS,
                           selectcolor=TEAL, activebackground=CARD).pack(
                side="left", padx=4)

        self._cap_lbl = tk.Label(left, text="Load video to see capacity",
                                  font=(*FS[:2],), bg=CARD, fg=MUTED)
        self._cap_lbl.pack(padx=10, anchor="w", pady=(2,0))
        self.n_frames_var.trace_add("write", lambda *_: self._update_cap())

        self._section(left, "💬  Payload")
        prow = tk.Frame(left, bg=CARD); prow.pack(fill="x", padx=10, pady=(0,3))
        for val, lbl in [("text","Text"),("file","Binary File")]:
            tk.Radiobutton(prow, text=lbl, variable=self.payload_mode, value=val,
                           bg=CARD, fg=WHITE, font=FS, selectcolor=TEAL,
                           activebackground=CARD,
                           command=self._toggle_payload_mode).pack(
                side="left", padx=6)

        self._msg_box = tk.Text(left, height=5, bg=BG, fg=WHITE, font=FM,
                                 insertbackground=WHITE, relief="flat",
                                 highlightbackground=BORDER,
                                 highlightthickness=1, wrap="word")
        self._msg_box.pack(fill="x", padx=10, pady=(0,4))
        self._msg_box.insert("1.0",
            "DeepSteg v4 — Secure message by Abu Arefin Aroop, AiT.")

        self._payload_ff = tk.Frame(left, bg=CARD)
        self._payload_ff.pack(fill="x", padx=10, pady=(0,4))
        self._filerow(self._payload_ff, "Binary file:", self.payload_file,
                      lambda: self._browse_open(self.payload_file,
                                                [("All","*.*")]))
        self._payload_ff.pack_forget()

        tk.Frame(left, bg=BORDER, height=1).pack(fill="x", padx=10, pady=6)
        self._run_btn = self._btn(left, "▶  Embed (Hybrid-KEM v4)",
                                   self._run_embed, TEAL)
        self._run_btn.pack(fill="x", padx=10, pady=3)
        self._stop_btn = self._btn(left, "■  Stop", self._stop, ERROR)
        self._stop_btn.pack(fill="x", padx=10, pady=(0,8))
        self._stop_btn.configure(state="disabled")

        # Right: log
        right = tk.Frame(t, bg=BG)
        right.pack(fill="both", expand=True, padx=(5,10), pady=10)
        self._section(right, "📋  Live Operation Log")

        # Watermark canvas behind log
        wm = _make_watermark_canvas(right, 600, 500, alpha=0.06)
        wm.pack(fill="both", expand=True)
        lf = tk.Frame(wm, bg=CARD,
                       highlightbackground=BORDER, highlightthickness=1)
        lf.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.log = tk.Text(lf, bg="#06101C", fg=WHITE, font=FM,
                            state="disabled", wrap="word", relief="flat",
                            padx=10, pady=8)
        sc = ttk.Scrollbar(lf, command=self.log.yview,
                            style="D.TScrollbar")
        self.log.configure(yscrollcommand=sc.set)
        sc.pack(side="right", fill="y")
        self.log.pack(fill="both", expand=True)

        for tag, col in [("head",TEAL2),("ok",MINT),("warn",ORANGE),
                          ("err",ERROR),("metric",ORANGE),("info",WHITE),
                          ("purple",PURPLE),("indigo",INDIGO),("gold",GOLD)]:
            self.log.tag_configure(tag, foreground=col,
                font=FM if tag!="head" else (*FM[:1], FM[1], "bold"))

    def _toggle_payload_mode(self):
        if self.payload_mode.get() == "file":
            self._msg_box.pack_forget()
            self._payload_ff.pack(fill="x", padx=10, pady=(0,4))
        else:
            self._payload_ff.pack_forget()
            self._msg_box.pack(fill="x", padx=10, pady=(0,4))

    # ── EXTRACT TAB ───────────────────────────────────────────────────────────
    def _build_extract(self):
        t = self.t_extract
        left = tk.Frame(t, bg=CARD, width=420)
        left.pack(side="left", fill="y", padx=(10,5), pady=10)
        left.pack_propagate(False)

        self._section(left, "📂  Stego PNG Folder")
        self._filerow(left, "Folder:", self.ext_input,
                      lambda: self._browse_folder(self.ext_input))

        self._section(left, "🔑  Keys / Keystore")
        self._filerow(left, "Keystore file:", self.ext_keystore,
                      lambda: self._browse_open(self.ext_keystore,
                          [("Keystore","*.bin"),("All","*.*")]))

        for label, var, lo, hi in [
            ("Bundle length:", self.ext_blen, 0, 9999999),
            ("Frames:", self.ext_nframes, 1, 30),
        ]:
            row = tk.Frame(left, bg=CARD); row.pack(fill="x", padx=10, pady=4)
            tk.Label(row, text=label, font=FB, bg=CARD, fg=MUTED,
                     width=16, anchor="w").pack(side="left")
            tk.Spinbox(row, from_=lo, to=hi, textvariable=var, width=10,
                       bg=BG, fg=WHITE, font=FB,
                       buttonbackground=BORDER).pack(side="left", padx=3)

        tk.Label(left,
                 text="ℹ  Bundle length + frame count shown in Embed log.\n"
                      "   Session extraction uses keys already in memory.",
                 font=(*FS[:2],), bg=CARD, fg=MUTED,
                 justify="left", wraplength=390).pack(padx=10, pady=4, anchor="w")

        tk.Frame(left, bg=BORDER, height=1).pack(fill="x", padx=10, pady=8)
        self._btn(left, "🔓  Extract (Session Keys)",
                  self._run_extract_session, MINT).pack(
            fill="x", padx=10, pady=3)
        self._btn(left, "🔓  Extract (Load Keystore)",
                  self._run_extract_keystore, TEAL).pack(
            fill="x", padx=10, pady=(0,8))

        right = tk.Frame(t, bg=BG)
        right.pack(fill="both", expand=True, padx=(5,10), pady=10)
        self._section(right, "📨  Decrypted Message / File")

        wm = _make_watermark_canvas(right, 600, 500, alpha=0.06)
        wm.pack(fill="both", expand=True)
        of = tk.Frame(wm, bg=CARD,
                       highlightbackground=BORDER, highlightthickness=1)
        of.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.out_text = tk.Text(of, bg="#06101C", fg=MINT,
                                 font=(*FM[:1], FM[1]+1),
                                 state="disabled", wrap="word", relief="flat",
                                 padx=14, pady=10)
        sc2 = ttk.Scrollbar(of, command=self.out_text.yview,
                             style="D.TScrollbar")
        self.out_text.configure(yscrollcommand=sc2.set)
        sc2.pack(side="right", fill="y")
        self.out_text.pack(fill="both", expand=True)

    # ── RESULTS TAB ───────────────────────────────────────────────────────────
    def _build_results(self):
        t = self.t_results
        ctrl = tk.Frame(t, bg=PANEL); ctrl.pack(fill="x", padx=10, pady=(8,0))
        self._btn(ctrl, "📊 Refresh Chart",
                  self._refresh_chart, TEAL).pack(side="left", padx=4)
        self._btn(ctrl, "💾 Export JSON",
                  self._export_json, MINT).pack(side="left", padx=4)
        self._btn(ctrl, "🖼 Save Chart",
                  self._save_chart, ORANGE).pack(side="left", padx=4)

        # Metric cards
        self.mcards = tk.Frame(t, bg=BG); self.mcards.pack(fill="x", padx=10, pady=6)
        self.mcard_lbls = {}
        specs = [("PSNR",TEAL,">40dB"),("SSIM",SUCCESS,">0.95"),
                 ("MSE","#2E86AB","<1.0"),("NCC",PURPLE,">0.99"),
                 ("Frames",ORANGE,"multi"),("Bits",ERROR,"info"),
                 ("Method",INDIGO,"v4")]
        for i,(n,col,tgt) in enumerate(specs):
            c = tk.Frame(self.mcards, bg=col, width=185, height=80)
            c.grid(row=0, column=i, padx=2, sticky="nsew")
            c.grid_propagate(False)
            self.mcards.columnconfigure(i, weight=1)
            v = tk.Label(c, text="—", font=(*FONTS['title'][:2],'bold'),
                          bg=col, fg=WHITE)
            v.pack(pady=(4,0))
            tk.Label(c, text=n, font=FONTS['ui_bold'], bg=col, fg=WHITE).pack()
            tk.Label(c, text=tgt, font=FONTS['ui_sm'], bg=col, fg=WHITE).pack()
            self.mcard_lbls[n] = v

        # Chart area
        self.chart_outer = tk.Frame(t, bg=CARD,
                                     highlightbackground=BORDER,
                                     highlightthickness=1)
        self.chart_outer.pack(fill="both", expand=True, padx=10, pady=(0,10))
        tk.Label(self.chart_outer,
                 text="Run embed to generate the metrics dashboard.",
                 font=FH, bg=CARD, fg=MUTED).pack(expand=True)

    # ── VAPT TAB ─────────────────────────────────────────────────────────────
    def _build_vapt(self):
        t = self.t_vapt
        left = tk.Frame(t, bg=CARD, width=420)
        left.pack(side="left", fill="y", padx=(10,5), pady=10)
        left.pack_propagate(False)

        self._section(left, "🛡  VAPT v4 — 4 Steganalysis Tests")
        self._filerow(left, "PNG to analyse:", self.vapt_target,
                      lambda: self._browse_open(self.vapt_target,
                          [("PNG","*.png"),("All","*.*")]))

        tk.Label(left,
                 text="v4 Spatial Boundary Test detects sequential LSB\n"
                      "artifacts. Pseudorandom embedding scores near zero.",
                 font=(*FS[:2],), bg=CARD, fg=MINT,
                 justify="left", wraplength=390).pack(padx=10, pady=6, anchor="w")

        tk.Frame(left, bg=BORDER, height=1).pack(fill="x", padx=10, pady=6)
        self._btn(left, "🔍  Run VAPT (Chi²+RS+SPA+Boundary)",
                  self._run_vapt, TEAL).pack(fill="x", padx=10, pady=3)
        self._btn(left, "🔍  Analyse All Session PNGs",
                  self._run_vapt_all, ORANGE).pack(fill="x", padx=10, pady=(0,6))

        # STRIDE panel
        self._section(left, "📋  OWASP STRIDE Threat Model")
        st = tk.Text(left, height=16, bg=BG, fg=ORANGE,
                      font=(*FS[:2],), state="normal", relief="flat",
                      wrap="word", highlightbackground=BORDER, highlightthickness=1)
        st.pack(fill="x", padx=10, pady=(0,8))
        st.insert("1.0",
            "STRIDE — DeepSteg v4\n\n"
            "S — Spoofing       : HMAC+GCM tag verify sender ✓\n"
            "T — Tampering      : GCM auth tag on every bundle ✓\n"
            "R — Repudiation    : HMAC-chained audit log ✓\n"
            "I — Info Disclosure: Pseudorandom pixel order ✓\n"
            "D — DoS            : Size caps + rate limit ✓\n"
            "E — Privilege Esc. : timing-safe compare_digest ✓\n\n"
            f"All 6 STRIDE categories mitigated in v{APP_VERSION}")
        st.configure(state="disabled")

        right = tk.Frame(t, bg=BG)
        right.pack(fill="both", expand=True, padx=(5,10), pady=10)
        self._section(right, "📊  VAPT Results")
        vo = tk.Frame(right, bg=CARD,
                       highlightbackground=BORDER, highlightthickness=1)
        vo.pack(fill="both", expand=True)
        self.vapt_text = tk.Text(vo, bg="#06101C", fg=WHITE, font=FM,
                                  state="disabled", wrap="word", relief="flat",
                                  padx=10, pady=8)
        sc3 = ttk.Scrollbar(vo, command=self.vapt_text.yview,
                             style="D.TScrollbar")
        self.vapt_text.configure(yscrollcommand=sc3.set)
        sc3.pack(side="right", fill="y")
        self.vapt_text.pack(fill="both", expand=True)
        for tag, col in [("ok",MINT),("warn",ORANGE),("err",ERROR),
                          ("head",TEAL2),("info",WHITE),("metric",ORANGE),
                          ("purple",PURPLE),("indigo",INDIGO)]:
            self.vapt_text.tag_configure(tag, foreground=col)

    # ── AUDIT TAB ────────────────────────────────────────────────────────────
    def _build_audit(self):
        t = self.t_audit
        ctrl = tk.Frame(t, bg=PANEL); ctrl.pack(fill="x", padx=10, pady=(8,0))
        self._btn(ctrl, "🔄 Refresh", self._refresh_audit, TEAL).pack(
            side="left", padx=4)
        self._btn(ctrl, "✅ Verify Chain",
                  self._verify_audit_chain, MINT).pack(side="left", padx=4)
        tk.Label(ctrl,
                 text="Tamper-evident HMAC-chained log. "
                      "Any deletion/modification breaks the chain.",
                 font=(*FS[:2],), bg=PANEL, fg=MUTED).pack(side="left", padx=10)

        ao = tk.Frame(t, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        ao.pack(fill="both", expand=True, padx=10, pady=10)
        self.audit_text = tk.Text(ao, bg="#06101C", fg=WHITE, font=FM,
                                   state="disabled", wrap="word", relief="flat",
                                   padx=10, pady=8)
        sc4 = ttk.Scrollbar(ao, command=self.audit_text.yview,
                             style="D.TScrollbar")
        self.audit_text.configure(yscrollcommand=sc4.set)
        sc4.pack(side="right", fill="y")
        self.audit_text.pack(fill="both", expand=True)
        for tag, col in [("ok",MINT),("err",ERROR),("head",TEAL2),("info",WHITE)]:
            self.audit_text.tag_configure(tag, foreground=col)
        self._refresh_audit()

    # ── KEYSTORE TAB ─────────────────────────────────────────────────────────
    def _build_keys(self):
        t = self.t_keys
        c = tk.Frame(t, bg=BG); c.pack(fill="both", expand=True, padx=20, pady=20)

        logo = _load_tk_logo((64, 64))
        if logo:
            lbl = tk.Label(c, image=logo, bg=BG); lbl._photo = logo
            lbl.pack(pady=(0,8))

        tk.Label(c, text="🔑  Scrypt Keystore Manager",
                  font=(*FONTS['title'][:2],'bold'), bg=BG, fg=TEAL2).pack(pady=(0,4))
        tk.Label(c,
                  text="Keys encrypted with Scrypt (N=2¹⁷). "
                       "Minimum 8-character password. Atomic writes. "
                       "Never stored as plain PEM.",
                  font=FONTS['ui'], bg=BG, fg=MUTED,
                  wraplength=700, justify="center").pack(pady=(0,16))

        self._filerow(c, "Keystore path:", self.ks_path,
                      lambda: self._browse_save(self.ks_path, ".bin",
                          [("Keystore","*.bin")]))

        ks_btns = tk.Frame(c, bg=BG); ks_btns.pack(pady=10)
        self._btn(ks_btns, "💾 Save Current Keys",
                  self._save_keystore, TEAL).pack(
            side="left", padx=6, ipadx=10, ipady=4)
        self._btn(ks_btns, "📂 Load Keystore",
                  self._load_keystore_embed, INDIGO).pack(
            side="left", padx=6, ipadx=10, ipady=4)

        tk.Frame(c, bg=BORDER, height=1).pack(fill="x", pady=14)
        tk.Label(c, text="Key Status", font=FH, bg=BG, fg=TEAL2).pack()
        self.key_detail_lbl = tk.Label(
            c, text="No keys in session.", font=(*FM[:2],),
            bg=CARD, fg=MINT, justify="left",
            wraplength=700, anchor="w", padx=14, pady=10)
        self.key_detail_lbl.pack(fill="x", pady=8)

    # ── POLICY TAB ───────────────────────────────────────────────────────────
    def _build_policy(self):
        t = self.t_policy
        # Watermark behind content
        wm = _make_watermark_canvas(t, 1200, 800, alpha=0.04)
        wm.pack(fill="both", expand=True)

        frame = tk.Frame(wm, bg=BG)
        frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Header
        hdr = tk.Frame(frame, bg=PANEL)
        hdr.pack(fill="x", padx=10, pady=(10,0))

        logo = _load_tk_logo((48, 48))
        if logo:
            lbl = tk.Label(hdr, image=logo, bg=PANEL); lbl._photo = logo
            lbl.pack(side="left", padx=10, pady=8)

        tk.Label(hdr, text="Intellectual Property & Usage Policy",
                  font=(*FONTS['title'][:2],'bold'), bg=PANEL, fg=GOLD).pack(
            side="left", padx=8)
        tk.Label(hdr, text=COPYRIGHT_LINE,
                  font=FONTS['ui'], bg=PANEL, fg=MUTED).pack(
            side="right", padx=14)

        # Tab selector for policy sections
        pnb = ttk.Notebook(frame, style="D.TNotebook")
        pnb.pack(fill="both", expand=True, padx=10, pady=8)

        for section_name, section_text in POLICY_SECTIONS.items():
            sf = tk.Frame(pnb, bg=CARD)
            pnb.add(sf, text=f"  {section_name}  ")

            txt = tk.Text(sf, bg="#06101C", fg=WHITE,
                           font=(*FM[:2],), state="normal",
                           wrap="word", relief="flat", padx=16, pady=12)
            sc = ttk.Scrollbar(sf, command=txt.yview, style="D.TScrollbar")
            txt.configure(yscrollcommand=sc.set)
            sc.pack(side="right", fill="y")
            txt.pack(fill="both", expand=True)
            txt.insert("1.0", section_text.strip())
            txt.configure(state="disabled")

        # Legal footer
        foot = tk.Frame(frame, bg=PANEL)
        foot.pack(fill="x", padx=10, pady=(0,10))
        tk.Label(foot, text=LEGAL_REF,
                  font=FONTS['ui_sm'], bg=PANEL, fg=GOLD).pack(pady=6)

    # ── ABOUT TAB ────────────────────────────────────────────────────────────
    def _build_about(self):
        t = self.t_about
        c = tk.Frame(t, bg=BG); c.pack(expand=True)

        # Large logo
        logo_lg = _load_tk_logo((110, 110))
        if logo_lg:
            lbl = tk.Label(c, image=logo_lg, bg=BG); lbl._photo = logo_lg
            lbl.pack(pady=(20, 8))

        tk.Label(c, text=f"⬡  {APP_NAME} v{APP_VERSION}",
                  font=(*FONTS['title'][:1], 30, 'bold'), bg=BG, fg=TEAL2).pack(pady=(0,4))
        tk.Label(c,
                  text="Production-Grade Hybrid-KEM Multi-Frame Video Steganography",
                  font=(*FONTS['ui'][:1], 12), bg=BG, fg=WHITE).pack()
        tk.Label(c,
                  text="AES-256-GCM  ·  X25519+Hybrid-KEM  ·  RSA-4096  "
                       "·  Pseudorandom LSB  ·  Scrypt Keystore  ·  HMAC Audit",
                  font=(*FONTS['ui_sm'][:1], 9, 'italic'), bg=BG, fg=MUTED).pack(pady=(2,14))

        info = [
            ("Developer",    DEVELOPER_NAME),
            ("Role",         DEVELOPER_ROLE),
            ("Institution",  DEVELOPER_ORG),
            ("Email",        DEVELOPER_EMAIL),
            ("Reg. No.",     APP_REG_NO),
            ("Supervisor",   "Assoc. Prof. Dr. Md. Azam Hossain, BUP CSE"),
            ("Platform",     f"{get_platform().title()} ({get_linux_distro() if is_linux() else 'Win11'})"),
            ("Security",     "36/36 tests passed — all 11 vulnerabilities fixed"),
            ("PQ Roadmap",   "Kyber-1024 auto-activates if kyber-py installed"),
            ("Copyright",    COPYRIGHT_LINE),
            ("Legal",        LEGAL_REF[:60] + "…"),
        ]
        for lbl_t, val_t in info:
            r = tk.Frame(c, bg=CARD, width=720)
            r.pack(pady=2); r.pack_propagate(False)
            tk.Label(r, text=lbl_t + ":",
                      font=FONTS['ui_bold'],
                      bg=CARD, fg=TEAL, width=14, anchor="e").pack(
                side="left", padx=(10,6), pady=5)
            tk.Label(r, text=val_t, font=FONTS['ui'],
                      bg=CARD, fg=WHITE, anchor="w").pack(side="left")

    # ── KEY MANAGEMENT ────────────────────────────────────────────────────────
    def _generate_keys(self):
        def _do():
            self._set_status("Generating RSA-4096 + X25519 keypairs…", ORANGE)
            self._log("head", f"\n{'─'*56}\n  v4 Key Generation\n{'─'*56}\n")
            t0 = time.time()
            self.rsa_priv, self.rsa_pub = generate_rsa_keypair(4096)
            self._log("ok", "  ✓ RSA-4096 ready\n")
            self.sender_x_priv, self.sender_x_pub = generate_x25519_keypair()
            self._log("ok", "  ✓ X25519 sender keypair ready\n")
            self.recv_x_priv, self.recv_x_pub = generate_x25519_keypair()
            self._log("ok", "  ✓ X25519 receiver keypair ready\n")
            shared = self.sender_x_priv.exchange(self.recv_x_pub)
            self.pixel_seed = hkdf_derive(
                shared, info=b"deepsteg-pixel-seed-v4")
            self._log("indigo",
                f"  ✓ Pixel seed (ECDH): {self.pixel_seed.hex()[:24]}…\n")
            elapsed = round(time.time()-t0, 1)
            self._log("metric", f"  Keygen time: {elapsed}s\n")
            self._log("gold",
                f"  © {DEVELOPER_NAME} | {DEVELOPER_ORG} | {APP_REG_NO}\n")
            self._log("warn",
                "  ✅ Save keys to keystore (Keystore tab)\n\n")
            self.audit.append("KEYGEN", {"elapsed": elapsed})
            self.after(0, lambda:
                self.key_status.configure(text="● Keys Ready", fg=SUCCESS))
            self._set_status("Keys ready (RSA-4096 + X25519 + pixel seed)",
                             SUCCESS)
            self.after(0, self._update_key_detail)
        threading.Thread(target=_do, daemon=True).start()

    def _save_keystore(self):
        if not self.rsa_priv:
            messagebox.showwarning("No Keys", "Generate keys first.")
            return
        path = self.ks_path.get() or KEYSTORE_DEFAULT
        pwd = self._ask_password(
            "Set Keystore Password",
            "Enter a strong password (≥ 8 characters):",
            confirm=True, min_length=8)
        if pwd is None: return
        try:
            ks = KeyStore(path)
            ks.save(pwd, {
                "rsa_priv":      self.rsa_priv,
                "sender_x_priv": self.sender_x_priv,
                "recv_x_priv":   self.recv_x_priv,
                "pixel_seed":    self.pixel_seed,
            })
            messagebox.showinfo("Saved", f"Keystore saved:\n{path}")
            self._log("ok", f"  💾 Keystore → {path}\n")
            self.audit.append("KEYSTORE_SAVE", {"path": path})
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _load_keystore_embed(self):
        path = filedialog.askopenfilename(
            filetypes=[("Keystore","*.bin"),("All","*.*")],
            initialdir=str(Path(KEYSTORE_DEFAULT).parent))
        if not path: return
        pwd = self._ask_password("Unlock Keystore",
                                  "Enter keystore password:",
                                  min_length=8)
        if pwd is None: return
        try:
            ks   = KeyStore(path)
            keys = ks.load(pwd)
            self.rsa_priv      = keys.get("rsa_priv")
            self.rsa_pub       = (self.rsa_priv.public_key()
                                  if self.rsa_priv else None)
            self.sender_x_priv = keys.get("sender_x_priv")
            self.sender_x_pub  = (self.sender_x_priv.public_key()
                                  if self.sender_x_priv else None)
            self.recv_x_priv   = keys.get("recv_x_priv")
            self.recv_x_pub    = (self.recv_x_priv.public_key()
                                  if self.recv_x_priv else None)
            self.pixel_seed    = keys.get("pixel_seed")
            self.key_status.configure(text="● Keys Loaded", fg=SUCCESS)
            self._log("ok", f"  📂 Keystore loaded: {path}\n")
            self.audit.append("KEYSTORE_LOAD", {"path": path})
            self._update_key_detail()
            messagebox.showinfo("Loaded", "Keystore loaded successfully.")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def _update_key_detail(self):
        lines = []
        if self.rsa_priv:
            lines.append(f"RSA-4096   : ✓  ({self.rsa_pub.key_size}-bit)")
        else:
            lines.append("RSA-4096   : ✗  not loaded")
        if self.sender_x_priv:
            raw = self.sender_x_pub.public_bytes(
                __import__('cryptography').hazmat.primitives.serialization.Encoding.Raw,
                __import__('cryptography').hazmat.primitives.serialization.PublicFormat.Raw)
            lines.append(f"X25519 sender: ✓  {raw.hex()[:20]}…")
        else:
            lines.append("X25519 sender: ✗  not loaded")
        if self.recv_x_priv:
            lines.append("X25519 recv  : ✓  loaded")
        if self.pixel_seed:
            lines.append(f"Pixel seed   : ✓  {self.pixel_seed.hex()[:20]}…")
        self.key_detail_lbl.configure(text="\n".join(lines))

    # ── EMBED PIPELINE ────────────────────────────────────────────────────────
    def _run_embed(self):
        if self.running:
            messagebox.showwarning("Busy", "Pipeline already running.")
            return
        if not self.rsa_priv:
            messagebox.showerror("No Keys",
                "Generate or load keys first.")
            return
        if not self.embed_input.get():
            messagebox.showerror("No Video", "Select a cover video.")
            return
        if not self.embed_out_dir.get():
            messagebox.showerror("No Output", "Set output folder.")
            return
        if not self.pixel_seed:
            messagebox.showerror("No Pixel Seed",
                "Generate keys first to derive the pixel seed.")
            return

        if self.payload_mode.get() == "file":
            fp = self.payload_file.get()
            if not fp or not Path(fp).exists():
                messagebox.showerror("No File", "Select a binary file.")
                return
            payload = Path(fp).read_bytes()
        else:
            msg = self._msg_box.get("1.0", "end-1c").strip()
            if not msg:
                messagebox.showerror("No Message", "Enter a message.")
                return
            payload = msg.encode('utf-8')

        self.running = True
        self._run_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        threading.Thread(target=self._embed_thread,
                         args=(payload,), daemon=True).start()

    def _stop(self):
        self.running = False
        self._log("warn", "\n⚠  Stopped by user.\n")
        self._set_status("Stopped", WARN)
        self._run_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

    def _embed_thread(self, payload: bytes):
        try:
            self._embed_inner(payload)
        except Exception as e:
            self._log("err", f"\n✗ Error: {e}\n{traceback.format_exc()}\n")
            self._set_status(f"Error: {e}", ERROR)
        finally:
            self.running = False
            self.after(0, lambda: self._run_btn.configure(state="normal"))
            self.after(0, lambda: self._stop_btn.configure(state="disabled"))
            self._set_prog(0)

    def _embed_inner(self, payload: bytes):
        t0  = time.time()
        nf  = self.n_frames_var.get()
        sf  = self.start_frame.get()
        ttl = self.ttl_mode.get()
        fr  = self.fill_ratio.get()

        self._log("head", f"\n{'═'*56}\n  DeepSteg v4 Embed  ({nf} frames)\n"
                          f"  {COPYRIGHT_LINE}\n{'═'*56}\n\n")

        self._log("head", "▶ Step 1/4 — Hybrid-KEM Encryption…\n")
        self._set_prog(5)
        bundle = build_bundle_v4(
            payload, self.rsa_pub,
            self.sender_x_priv, self.recv_x_pub,
            ttl_mode=ttl)
        self.last_bundle = bundle
        self._log("ok", "  ✓ AES-256-GCM + X25519 Hybrid-KEM done\n")
        self._log("indigo", "  ✓ Kyber-1024 ready (auto-activates if installed)\n")
        self._log("metric", f"  Bundle: {len(bundle)} bytes  |  "
                            f"Payload: {len(payload)} bytes\n")

        if not self.running: return

        self._log("head", "▶ Step 2/4 — Capacity check…\n")
        self._set_prog(15)
        cap = cv2.VideoCapture(self.embed_input.get())
        W   = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        H   = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        totf= int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        cap.release()
        self._log("info", f"  Video: {totf} frames, {W}×{H}  |  "
                          f"fill cap {fr:.0%}\n")

        if not self.running: return

        self._log("head", "▶ Step 3/4 — Pseudorandom LSB embed…\n")
        self._log("indigo",
            f"  Pixel seed: {self.pixel_seed.hex()[:20]}… (ECDH-derived)\n")

        def prog_cb(v, m):
            self._set_prog(v)
            self._log("info", f"  {m}\n")

        avg, per_f = embed_multiframe(
            self.embed_input.get(), self.embed_out_dir.get(),
            bundle, self.pixel_seed,
            n_frames=nf, start_frame=sf,
            max_fill_ratio=fr, progress_cb=prog_cb)

        self.last_metrics   = avg
        self.last_per_frame = per_f
        self.last_stego_pngs = avg["stego_pngs"]

        cap2 = cv2.VideoCapture(self.embed_input.get())
        cf   = None
        for _ in range(sf + 1):
            ret, tmp = cap2.read()
            if ret: cf = tmp
        cap2.release()
        self.last_cover_frame = (cf if cf is not None
                                  else np.zeros((H,W,3), dtype=np.uint8))
        self.last_stego_frame = (
            cv2.imread(avg["stego_pngs"][0]) if avg["stego_pngs"]
            else self.last_cover_frame)

        if not self.running: return

        self._log("head", "▶ Step 4/4 — Results…\n")
        self._set_prog(98)
        elapsed = round(time.time()-t0, 1)

        self._log("metric",
            f"  PSNR:{avg['PSNR']:.2f}dB  SSIM:{avg['SSIM']:.6f}  "
            f"MSE:{avg['MSE']:.6f}  NCC:{avg['NCC']:.6f}\n")
        self._log("metric", f"  Runtime: {elapsed}s\n")
        self._log("ok",   "\n✅  Embedding COMPLETE\n")
        self._log("indigo",
            f"\n📌 For extraction:\n"
            f"   Folder : {self.embed_out_dir.get()}\n"
            f"   Bundle : {len(bundle)} bytes  |  Frames: {nf}\n"
            f"   Seed   : {self.pixel_seed.hex()[:24]}…\n")
        self._log("gold",
            f"\n  © {DEVELOPER_NAME} | {DEVELOPER_ORG} | {APP_REG_NO}\n\n")

        self.audit.append("EMBED", {
            "n_frames": nf, "bundle_len": len(bundle),
            "psnr": avg["PSNR"], "ssim": avg["SSIM"],
            "elapsed": elapsed, "ttl": ttl,
        })

        self._set_status(
            f"Done {elapsed}s — PSNR:{avg['PSNR']:.1f}dB", SUCCESS)
        self._update_mcard(avg)
        self.after(0, self._refresh_chart)
        self.after(0, lambda: (
            self.ext_blen.set(len(bundle)),
            self.ext_nframes.set(nf),
            self.ext_input.set(self.embed_out_dir.get())
        ))
        self.after(0, self._refresh_audit)

    # ── EXTRACT PIPELINE ──────────────────────────────────────────────────────
    def _run_extract_session(self):
        if not self.rsa_priv:
            messagebox.showerror("No Key", "Generate or load keys first.")
            return
        self._extract(self.rsa_priv, self.recv_x_priv, self.pixel_seed)

    def _run_extract_keystore(self):
        path = self.ext_keystore.get()
        if not path or not Path(path).exists():
            messagebox.showerror("No Keystore", "Select a keystore file.")
            return
        pwd = self._ask_password("Unlock Keystore",
                                  "Enter keystore password:", min_length=8)
        if pwd is None: return
        try:
            ks   = KeyStore(path)
            keys = ks.load(pwd)
            self._extract(keys.get("rsa_priv"),
                          keys.get("recv_x_priv"),
                          keys.get("pixel_seed"))
        except Exception as e:
            messagebox.showerror("Keystore Error", str(e))

    def _extract(self, rsa_priv, recv_x_priv, pixel_seed):
        src    = self.ext_input.get()
        blen   = self.ext_blen.get() or len(self.last_bundle)
        nf_ext = self.ext_nframes.get()

        if blen <= 0:
            messagebox.showerror("Bundle Length",
                "Enter bundle length from Embed log.")
            return
        if not src:
            messagebox.showerror("No Folder", "Select the stego PNG folder.")
            return
        if not pixel_seed:
            messagebox.showerror("No Pixel Seed",
                "Load matching keystore or use session keys.")
            return

        def _do():
            self._set_status("Extracting…", ORANGE)
            try:
                src_path = Path(src)
                if (self.last_stego_pngs
                        and len(self.last_stego_pngs) >= nf_ext
                        and all(Path(p).exists()
                                for p in self.last_stego_pngs[:nf_ext])):
                    pngs = self.last_stego_pngs[:nf_ext]
                else:
                    found = sorted(src_path.glob("stego_frame_*.png"))
                    if not found:
                        raise RuntimeError(
                            f"No stego_frame_*.png found in:\n{src}")
                    pngs = [str(p) for p in found[:nf_ext]]

                dummy = split_into_chunks(b'\x00' * blen, len(pngs))
                chunk_sizes = [len(c) for c in dummy]
                bundle = extract_multiframe(pngs, chunk_sizes, pixel_seed)
                plaintext, ts, age = parse_bundle_v4(
                    bundle, rsa_priv, recv_x_priv)

                try:
                    text = plaintext.decode('utf-8')
                    mode = "text"
                except UnicodeDecodeError:
                    text = None
                    mode = "binary"

                self.audit.append("EXTRACT", {
                    "bundle_len": blen, "age": age, "n_frames": nf_ext})
                self.after(0, lambda: self._show_extract_result(
                    plaintext, text, mode, ts, age, len(pngs), blen))

            except Exception as e:
                self.after(0, lambda err=str(e): self._extract_error(err))

        threading.Thread(target=_do, daemon=True).start()

    def _show_extract_result(self, raw_bytes, text_str, mode,
                              ts, age, n_pngs, blen):
        self.out_text.configure(state="normal")
        self.out_text.delete("1.0", "end")
        hdr = (f"{'═'*52}\n  DeepSteg v4 — Decrypted Message\n"
               f"  {COPYRIGHT_LINE}\n{'═'*52}\n\n")
        body = (text_str if mode == "text"
                else f"[Binary: {len(raw_bytes)} bytes]\nHex: "
                     f"{raw_bytes[:64].hex()}…")
        foot = (f"\n\n{'═'*52}\n"
                f"  Frames   : {n_pngs}  |  Bundle: {blen} B\n"
                f"  Embedded : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}\n"
                f"  Age      : {age}s\n"
                f"  Crypto   : AES-256-GCM + Hybrid-KEM + RSA-4096 ✓\n"
                f"  HMAC     : VERIFIED ✓  |  GCM TAG: VERIFIED ✓\n"
                f"{'═'*52}")
        self.out_text.insert("1.0", hdr + body + foot)
        self.out_text.configure(state="disabled")
        self._set_status("Extraction & decryption successful ✓", SUCCESS)
        self.after(0, self._refresh_audit)

    def _extract_error(self, msg):
        self.out_text.configure(state="normal")
        self.out_text.delete("1.0", "end")
        self.out_text.insert("1.0",
            f"Extraction failed\n{'─'*40}\n{msg}\n{'─'*40}\n\n"
            "Checklist:\n"
            "1. Correct stego PNG folder?\n"
            "2. Bundle length exactly as shown in Embed log?\n"
            "3. Same frame count as embed?\n"
            "4. Matching keystore loaded?\n"
            "5. Bundle not expired? (re-embed or use demo TTL)")
        self.out_text.configure(state="disabled")
        self._set_status(f"Extraction failed: {msg[:50]}", ERROR)

    # ── VAPT ─────────────────────────────────────────────────────────────────
    def _vapt_log(self, msg, tag="info"):
        def _do():
            self.vapt_text.configure(state="normal")
            self.vapt_text.insert("end", msg, tag)
            self.vapt_text.see("end")
            self.vapt_text.configure(state="disabled")
        self.after(0, _do)

    def _run_vapt(self):
        src = self.vapt_target.get()
        if not src or not Path(src).exists():
            messagebox.showerror("No File", "Select a stego PNG.")
            return
        threading.Thread(target=lambda: self._vapt_inner([src]),
                         daemon=True).start()

    def _run_vapt_all(self):
        if not self.last_stego_pngs:
            messagebox.showinfo("No Session", "Run embed first.")
            return
        existing = [p for p in self.last_stego_pngs if Path(p).exists()]
        if not existing:
            messagebox.showerror("Not Found", "Session PNG files not found.")
            return
        threading.Thread(target=lambda: self._vapt_inner(existing),
                         daemon=True).start()

    def _vapt_inner(self, pngs):
        self._set_status("Running VAPT steganalysis…", ORANGE)
        self.vapt_text.configure(state="normal")
        self.vapt_text.delete("1.0", "end")
        self.vapt_text.configure(state="disabled")
        self._vapt_log(f"{'═'*54}\n  DeepSteg v4 VAPT\n"
                       f"  {COPYRIGHT_LINE}\n{'═'*54}\n\n", "head")

        all_r = []
        for png in pngs:
            r = full_steg_analysis_v4(png, 0.01)
            all_r.append(r)
            self._vapt_log(f"▶ {Path(png).name}\n", "head")
            for key, label in [("chi_square","Chi²"),("rs","RS Analysis"),
                                ("spa","Sample Pair"),("spatial_boundary","Boundary")]:
                d = r.get(key, {})
                self._vapt_log(
                    f"  {label:<15}: {d.get('verdict','N/A')}\n",
                    "err" if d.get("detected") else "ok")
            det = any(r.get(k,{}).get("detected") for k in
                      ["chi_square","rs","spatial_boundary"])
            self._vapt_log(
                f"\n  OVERALL: {'⚠ DETECTABLE' if det else '✓ NOT DETECTED'}\n\n",
                "err" if det else "indigo")

        det_count = sum(1 for r in all_r if any(
            r.get(k,{}).get("detected") for k in
            ["chi_square","rs","spatial_boundary"]))
        self._vapt_log(f"{'═'*54}\n  SUMMARY: {det_count}/{len(all_r)} detected\n",
                       "err" if det_count > 0 else "ok")
        self.audit.append("VAPT", {"n": len(all_r), "detected": det_count})
        self.after(0, self._refresh_audit)
        self._set_status(f"VAPT: {det_count}/{len(all_r)} detected",
                         ERROR if det_count > 0 else SUCCESS)

    # ── AUDIT ────────────────────────────────────────────────────────────────
    def _refresh_audit(self):
        entries = self.audit.tail(60)
        self.audit_text.configure(state="normal")
        self.audit_text.delete("1.0", "end")
        self.audit_text.insert("end",
            f"{'═'*54}\n  Audit Log  |  {COPYRIGHT_LINE}\n{'═'*54}\n\n",
            "head")
        for e in entries:
            self.audit_text.insert("end",
                f"[{e.get('seq','?'):04}] {e.get('ts','')}  "
                f"{e.get('event','')}\n", "ok")
            for k, v in e.get("detail", {}).items():
                self.audit_text.insert("end",
                    f"       {k}: {v}\n", "info")
        self.audit_text.configure(state="disabled")

    def _verify_audit_chain(self):
        r = self.audit.verify_chain()
        if r["valid"]:
            messagebox.showinfo("Audit Chain OK",
                f"✅ Chain VALID\n{r['entries']} entries verified.")
        else:
            messagebox.showerror("Audit Chain BROKEN",
                f"❌ Chain BROKEN at entry {r.get('first_bad')}\n"
                "Possible tampering!")

    # ── CHART ────────────────────────────────────────────────────────────────
    def _update_mcard(self, avg):
        def _do():
            upd = {
                "PSNR":   f"{avg['PSNR']:.1f} dB",
                "SSIM":   f"{avg['SSIM']:.6f}",
                "MSE":    f"{avg['MSE']:.6f}",
                "NCC":    f"{avg['NCC']:.6f}",
                "Frames": str(avg.get("n_frames","?")),
                "Bits":   f"{avg.get('total_bits',0):,}",
                "Method": "Pseudo-RNG LSB",
            }
            for k, v in upd.items():
                if k in self.mcard_lbls:
                    self.mcard_lbls[k].configure(text=v)
        self.after(0, _do)

    def _refresh_chart(self):
        if not self.last_metrics or not self.last_per_frame:
            messagebox.showinfo("No Data", "Run embed first.")
            return
        try:
            plt.style.use("dark_background")
            fig = plt.figure(figsize=(14, 7))
            fig.patch.set_facecolor("#0D1B2A")
            avg = self.last_metrics
            per = self.last_per_frame
            nums = [m["frame_num"] for m in per]
            C = {"teal":"#0A9EBF","mint":"#3EEDC8","orange":"#F4A832",
                 "purple":"#8E44AD","bg":"#112233","border":"#1E3A5F",
                 "white":"#F0F8FF","muted":"#6B8CAE","gold":"#D4A017"}

            def sax(ax):
                ax.set_facecolor(C["bg"])
                for sp in ax.spines.values(): sp.set_color(C["border"])
                ax.tick_params(colors=C["muted"], labelsize=7)
                return ax

            gs = fig.add_gridspec(2, 4, hspace=0.45, wspace=0.38)

            ax1 = sax(fig.add_subplot(gs[0,0]))
            ax1.imshow(cv2.cvtColor(self.last_cover_frame, cv2.COLOR_BGR2RGB))
            ax1.set_title("Cover Frame", color=C["white"], fontsize=8)
            ax1.axis("off")

            ax2 = sax(fig.add_subplot(gs[0,1]))
            ax2.imshow(cv2.cvtColor(self.last_stego_frame, cv2.COLOR_BGR2RGB))
            ax2.set_title("Stego Frame (v4)", color=C["mint"], fontsize=8)
            ax2.axis("off")

            diff = np.abs(self.last_cover_frame.astype(float) -
                          self.last_stego_frame.astype(float))
            ax3 = sax(fig.add_subplot(gs[0,2]))
            ax3.imshow(cv2.cvtColor(
                np.clip(diff*30,0,255).astype(np.uint8), cv2.COLOR_BGR2RGB))
            ax3.set_title("Diff ×30", color=C["orange"], fontsize=8)
            ax3.axis("off")

            ax4 = sax(fig.add_subplot(gs[0,3]))
            vals  = [avg["PSNR"]/100, avg["SSIM"], avg["NCC"]]
            tgts  = [0.80, 0.95, 0.99]
            x     = [0,1,2]; bw = 0.3
            ax4.bar([v-bw/2 for v in x], vals, bw,
                    color=[C["teal"],C["mint"],C["orange"]], alpha=0.9)
            ax4.bar([v+bw/2 for v in x], tgts, bw, color=C["muted"], alpha=0.5)
            ax4.set_xticks(x)
            ax4.set_xticklabels(["PSNR/100","SSIM","NCC"],
                                  fontsize=7, color=C["muted"])
            ax4.set_title("vs Target", color=C["white"], fontsize=8)

            ax5 = sax(fig.add_subplot(gs[1,0]))
            ax5.plot(nums, [m["PSNR"] for m in per], "o-",
                     color=C["teal"], lw=2, ms=5)
            ax5.axhline(40, ls="--", color="#EF4444", lw=1.2)
            ax5.set_title("PSNR/Frame", color=C["white"], fontsize=8)

            ax6 = sax(fig.add_subplot(gs[1,1]))
            ax6.plot(nums, [m["SSIM"] for m in per], "s-",
                     color=C["mint"], lw=2, ms=5)
            ax6.set_title("SSIM/Frame", color=C["white"], fontsize=8)

            ax7 = sax(fig.add_subplot(gs[1,2]))
            ax7.bar(nums, [m["MSE"] for m in per],
                    color=C["purple"], alpha=0.85)
            ax7.set_title("MSE/Frame", color=C["white"], fontsize=8)

            ax8 = sax(fig.add_subplot(gs[1,3]))
            ax8.bar(nums, [m["embed_ratio"] for m in per],
                    color=C["orange"], alpha=0.85)
            ax8.set_title("Embed%/Frame", color=C["white"], fontsize=8)

            fig.suptitle(
                f"DeepSteg v4 Quality Dashboard  |  "
                f"PSNR:{avg['PSNR']:.1f}dB  SSIM:{avg['SSIM']:.6f}  "
                f"© {DEVELOPER_NAME}",
                color=C["gold"], fontsize=10)

            self.last_fig = fig
            for w in self.chart_outer.winfo_children():
                w.destroy()
            canvas = FigureCanvasTkAgg(fig, master=self.chart_outer)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
        except Exception as e:
            messagebox.showerror("Chart Error", str(e))

    def _export_json(self):
        if not self.last_metrics:
            messagebox.showinfo("No Data", "Run embed first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="deepsteg_v4_results.json",
            filetypes=[("JSON","*.json")])
        if not p: return
        with open(p, "w") as f:
            json.dump({**self.last_metrics, "per_frame": self.last_per_frame,
                       "copyright": COPYRIGHT_FULL,
                       "developer": DEVELOPER_NAME,
                       "reg_no": APP_REG_NO}, f, indent=2)
        messagebox.showinfo("Saved", f"Results:\n{p}")

    def _save_chart(self):
        if self.last_fig is None:
            messagebox.showinfo("No Chart", "Refresh Chart first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".png",
            initialfile="deepsteg_v4_chart.png",
            filetypes=[("PNG","*.png")])
        if not p: return
        self.last_fig.savefig(p, dpi=150, bbox_inches="tight",
                              facecolor=self.last_fig.get_facecolor())
        messagebox.showinfo("Saved", f"Chart: {p}")

    # ── TEST VIDEO GENERATOR ─────────────────────────────────────────────────
    def _make_test_video(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".avi",
            initialfile="deepsteg_v4_cover.avi",
            filetypes=[("AVI","*.avi")])
        if not p: return

        def _do():
            self._set_status("Creating test video…", ORANGE)
            W, H, FPS, NF = 640, 480, 25, 40
            fourcc = cv2.VideoWriter_fourcc(*'HFYU')
            wr = cv2.VideoWriter(p, fourcc, FPS, (W, H))
            if not wr.isOpened():
                fourcc = cv2.VideoWriter_fourcc(*'XVID')
                wr = cv2.VideoWriter(p, fourcc, FPS, (W, H))
            np.random.seed(42)
            for i in range(NF):
                f = np.zeros((H, W, 3), dtype=np.uint8)
                for x in range(0, W, 20):
                    for y in range(0, H, 20):
                        col = (np.random.randint(30, 200),
                               np.random.randint(30, 200),
                               np.random.randint(30, 200))
                        cv2.rectangle(f, (x, y), (x+18, y+18), col, -1)
                noise = np.random.randint(0, 30, (H, W, 3), dtype=np.uint8)
                f = np.clip(f.astype(int) + noise, 0, 255).astype(np.uint8)
                cv2.putText(f, f"DeepSteg v4 | Frame {i:02d}",
                            (10, 36), cv2.FONT_HERSHEY_SIMPLEX,
                            0.8, (255, 255, 0), 2)
                cv2.putText(f, f"{DEVELOPER_NAME} | {DEVELOPER_ORG}",
                            (10, H-12), cv2.FONT_HERSHEY_SIMPLEX,
                            0.5, (180, 180, 255), 1)
                wr.write(f)
                self._set_prog((i+1)/NF*100)
            wr.release()
            def _set_paths():
                self.embed_input.set(p)
                if not self.embed_out_dir.get():
                    self.embed_out_dir.set(
                        str(Path(p).parent / (Path(p).stem + "_stego")))
            self.after(0, _set_paths)
            self._log("ok", f"  ✓ Test video: {NF}f {W}×{H} → {p}\n\n")
            self._set_status(f"Test video: {Path(p).name}", SUCCESS)
            self._set_prog(0)
            # _update_cap() touches Tk widgets directly and must run on the
            # main thread; this function executes on a background worker
            # thread, so schedule it via .after() instead of calling it
            # directly (calling Tk widget methods off the main thread is
            # unsafe and can crash or corrupt UI state).
            self.after(0, self._update_cap)
        threading.Thread(target=_do, daemon=True).start()

    # ── HELPERS ──────────────────────────────────────────────────────────────
    def _section(self, parent, text):
        f = tk.Frame(parent, bg=PANEL)
        f.pack(fill="x", pady=(7,3))
        tk.Label(f, text=text, font=FH, bg=PANEL, fg=TEAL2,
                  anchor="w").pack(fill="x", padx=10, pady=3)

    def _btn(self, parent, text, cmd, color=TEAL):
        b = tk.Button(parent, text=text, command=cmd, bg=color, fg=WHITE,
                       font=FONTS['ui_bold'], relief="flat",
                       cursor="hand2", padx=8, pady=6,
                       activebackground=TEAL2, activeforeground=WHITE)
        b.bind("<Enter>", lambda e: b.configure(bg=TEAL2 if color==TEAL else color))
        b.bind("<Leave>", lambda e: b.configure(bg=color))
        return b

    def _filerow(self, parent, label, var, cmd):
        bg = parent.cget("bg")
        f  = tk.Frame(parent, bg=bg)
        f.pack(fill="x", padx=10, pady=(3,0))
        tk.Label(f, text=label, font=FS, bg=bg, fg=MUTED, anchor="w").pack(fill="x")
        r = tk.Frame(f, bg=bg); r.pack(fill="x")
        e = tk.Entry(r, textvariable=var, bg=BG, fg=WHITE, font=FS,
                      relief="flat", highlightbackground=BORDER,
                      highlightthickness=1, state="readonly",
                      readonlybackground=BG)
        e.pack(side="left", fill="x", expand=True)
        tk.Button(r, text="Browse", command=cmd, bg=BORDER, fg=WHITE,
                   font=FS, relief="flat", cursor="hand2",
                   padx=7).pack(side="left", padx=(3,0))

    def _browse_open(self, var, types):
        p = filedialog.askopenfilename(filetypes=types)
        if p:
            var.set(p)
            if var is self.embed_input:
                base = Path(p)
                if not self.embed_out_dir.get():
                    self.embed_out_dir.set(
                        str(base.parent / (base.stem + "_stego")))
                self.after(100, self._update_cap)

    def _browse_folder(self, var):
        p = filedialog.askdirectory()
        if p: var.set(p)

    def _browse_save(self, var, ext, types):
        p = filedialog.asksaveasfilename(defaultextension=ext, filetypes=types)
        if p: var.set(p)

    def _ask_password(self, title: str, prompt: str,
                       confirm: bool = False, min_length: int = 8):
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.grab_set()

        # Logo in dialog
        logo_sm = _load_tk_logo((36, 36))
        if logo_sm:
            lbl = tk.Label(dlg, image=logo_sm, bg=BG); lbl._photo = logo_sm
            lbl.pack(pady=(12,2))

        tk.Label(dlg, text=prompt, font=FB, bg=BG, fg=WHITE).pack(padx=24, pady=(4,2))
        if min_length > 0:
            tk.Label(dlg,
                      text=f"Minimum {min_length} characters required.",
                      font=FS, bg=BG, fg=MUTED).pack(pady=(0,4))

        var = tk.StringVar()
        entry = tk.Entry(dlg, textvariable=var, show="●", font=FB,
                          bg=CARD, fg=WHITE, insertbackground=WHITE,
                          relief="flat", highlightbackground=BORDER,
                          highlightthickness=1, width=32)
        entry.pack(padx=24, pady=(0,6))
        entry.focus_set()

        var2 = None; entry2 = None
        if confirm:
            tk.Label(dlg, text="Confirm password:", font=FB, bg=BG, fg=WHITE
                     ).pack(padx=24, pady=(4,2))
            var2  = tk.StringVar()
            entry2 = tk.Entry(dlg, textvariable=var2, show="●", font=FB,
                               bg=CARD, fg=WHITE, insertbackground=WHITE,
                               relief="flat", highlightbackground=BORDER,
                               highlightthickness=1, width=32)
            entry2.pack(padx=24, pady=(0,6))

        err_lbl = tk.Label(dlg, text="", font=FS, bg=BG, fg=ERROR)
        err_lbl.pack(pady=(0,4))
        result  = [None]

        def ok():
            pw = var.get()
            if len(pw) < min_length:
                err_lbl.configure(
                    text=f"Too short ({len(pw)}/{min_length} chars).")
                return
            if confirm and var2 and pw != var2.get():
                err_lbl.configure(text="Passwords do not match.")
                var2.set(""); (entry2 or entry).focus_set(); return
            result[0] = pw
            var.set(""); (var2 and var2.set(""))
            dlg.destroy()

        def cancel():
            var.set(""); (var2 and var2.set("")); dlg.destroy()

        brow = tk.Frame(dlg, bg=BG); brow.pack(pady=(0,16))
        self._btn(brow, "OK", ok, TEAL).pack(
            side="left", padx=6, ipadx=10, ipady=3)
        self._btn(brow, "Cancel", cancel, BORDER).pack(
            side="left", padx=6, ipadx=10, ipady=3)
        entry.bind("<Return>", lambda e: ok())
        self.wait_window(dlg)
        return result[0]

    def _log(self, tag, msg):
        def _do():
            self.log.configure(state="normal")
            self.log.insert("end", msg, tag)
            self.log.see("end")
            self.log.configure(state="disabled")
        self.after(0, _do)

    def _set_status(self, msg, color=MINT):
        self.after(0, lambda: (
            self.status_var.set(msg),
            self.status_lbl.configure(fg=color)
        ))

    def _set_prog(self, v):
        self.after(0, lambda: self.progress_val.set(v))

    def _update_cap(self):
        try:
            p = self.embed_input.get()
            if not p or not Path(p).exists(): return
            cap = cv2.VideoCapture(p)
            w   = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            h   = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            n   = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            cap.release()
            if w == 0: return
            per = frame_capacity_bytes(w, h)
            nf  = self.n_frames_var.get()
            fr  = self.fill_ratio.get()
            self._cap_lbl.configure(
                text=f"Video: {n}f, {w}×{h}  |  "
                     f"{per:,}B/frame  |  "
                     f"{nf}×{int(per*fr):,}B = {nf*int(per*fr):,}B total")
        except Exception:
            pass

    def _print_startup_banner(self):
        self._log("head", get_startup_notice())
        self._log("gold",
            f"  Platform: {self._platform_info}\n\n")
        self._log("info",
            "  Step 1 → Generate / Load Keys (Keystore tab)\n"
            "  Step 2 → Load / Create Video\n"
            "  Step 3 → Type message → Embed\n"
            "  Step 4 → VAPT tab to verify stealth\n\n")


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Print copyright to console
    print(get_startup_notice())
    print(f"Platform: {get_platform_info()}")
    app = DeepStegApp()
    app.mainloop()


if __name__ == "__main__":
    main()
