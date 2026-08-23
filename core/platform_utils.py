"""
DeepSteg v4 — Platform Utilities
==================================
Detects Windows 11 / Linux and provides platform-specific:
  - Font stacks (Segoe UI on Win, Liberation/DejaVu on Linux)
  - DPI scaling
  - Theme colors
  - OS-specific install paths
  - System tray / taskbar integration hints

Author : Abu Arefin Aroop
Role   : AI-Assisted Cyber Security Engineer
Org    : Arslan Institute of Technology (AiT)
Copyright: © 2026 Abu Arefin Aroop — All Rights Reserved
"""

from __future__ import annotations
import sys, os, platform

# ── Platform detection ────────────────────────────────────────────────────────

def get_platform() -> str:
    """Returns 'windows', 'linux', or 'macos'."""
    s = sys.platform
    if s.startswith('win'):
        return 'windows'
    if s.startswith('linux'):
        return 'linux'
    if s.startswith('darwin'):
        return 'macos'
    return 'unknown'

def is_windows() -> bool:
    return get_platform() == 'windows'

def is_linux() -> bool:
    return get_platform() == 'linux'

def get_linux_distro() -> str:
    """Detect Linux distro (kali, parrot, ubuntu, etc.)."""
    try:
        with open('/etc/os-release') as f:
            content = f.read().lower()
        if 'kali' in content:   return 'kali'
        if 'parrot' in content: return 'parrot'
        if 'ubuntu' in content: return 'ubuntu'
        if 'debian' in content: return 'debian'
        if 'fedora' in content: return 'fedora'
        if 'arch' in content:   return 'arch'
    except Exception:
        pass
    return 'linux'

def get_windows_version() -> str:
    """Returns 'win11', 'win10', or 'windows'."""
    if not is_windows():
        return 'unknown'
    try:
        ver = platform.version()   # e.g. "10.0.22000"
        build = int(ver.split('.')[-1])
        if build >= 22000:
            return 'win11'
        return 'win10'
    except Exception:
        return 'windows'

# ── Font configuration ────────────────────────────────────────────────────────

def get_fonts() -> dict:
    """Return platform-appropriate font configuration."""
    plat = get_platform()

    if plat == 'windows':
        return {
            'ui':      ('Segoe UI', 10),
            'ui_bold': ('Segoe UI', 10, 'bold'),
            'ui_sm':   ('Segoe UI', 9),
            'header':  ('Segoe UI', 13, 'bold'),
            'mono':    ('Cascadia Code', 9),
            'mono_alt':('Consolas', 9),
            'title':   ('Segoe UI', 18, 'bold'),
        }
    else:
        # Linux — try preferred fonts with fallbacks
        return {
            'ui':      ('Liberation Sans', 10),
            'ui_bold': ('Liberation Sans', 10, 'bold'),
            'ui_sm':   ('Liberation Sans', 9),
            'header':  ('Liberation Sans', 13, 'bold'),
            'mono':    ('DejaVu Sans Mono', 9),
            'mono_alt':('Monospace', 9),
            'title':   ('Liberation Sans', 18, 'bold'),
        }

# ── DPI scaling ───────────────────────────────────────────────────────────────

def get_dpi_scale() -> float:
    """Estimate DPI scale factor for the current platform."""
    if is_windows():
        try:
            import ctypes
            awareness = ctypes.c_int()
            errorCode = ctypes.windll.shcore.GetProcessDpiAwareness(0, ctypes.byref(awareness))
            hdc = ctypes.windll.user32.GetDC(0)
            dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
            ctypes.windll.user32.ReleaseDC(0, hdc)
            return dpi / 96.0
        except Exception:
            return 1.0
    return 1.0

def set_windows_dpi_aware():
    """Enable DPI awareness on Windows so the app renders crisp on HiDPI."""
    if is_windows():
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

# ── Default paths ─────────────────────────────────────────────────────────────

def get_default_keystore_path() -> str:
    home = os.path.expanduser('~')
    if is_windows():
        appdata = os.environ.get('APPDATA', home)
        d = os.path.join(appdata, 'DeepSteg')
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, 'deepsteg_keystore.bin')
    else:
        d = os.path.join(home, '.config', 'deepsteg')
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, 'keystore.bin')

def get_default_audit_log_path() -> str:
    home = os.path.expanduser('~')
    if is_windows():
        appdata = os.environ.get('APPDATA', home)
        d = os.path.join(appdata, 'DeepSteg', 'logs')
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, 'audit.jsonl')
    else:
        d = os.path.join(home, '.local', 'share', 'deepsteg', 'logs')
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, 'audit.jsonl')

def get_default_output_path() -> str:
    home = os.path.expanduser('~')
    if is_windows():
        return os.path.join(home, 'Documents', 'DeepSteg')
    else:
        return os.path.join(home, 'DeepSteg')

# ── Platform info summary ─────────────────────────────────────────────────────

def get_platform_info() -> dict:
    plat = get_platform()
    info = {
        'platform':   plat,
        'os_name':    platform.system(),
        'os_version': platform.version(),
        'machine':    platform.machine(),
        'python':     platform.python_version(),
    }
    if plat == 'windows':
        info['win_version'] = get_windows_version()
    elif plat == 'linux':
        info['distro'] = get_linux_distro()
    return info
