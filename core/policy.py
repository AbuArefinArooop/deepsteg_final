"""
DeepSteg v4 — Intellectual Property & Policy Module
=====================================================
Enforces copyright notice, watermark display, and usage policy
at application startup and throughout the session.

Author    : Abu Arefin Aroop
Role      : AI-Assisted Cyber Security Engineer
Org       : Arslan Institute of Technology (AiT)
Reg. No.  : AiT-IP-2026-DS-0001
Copyright : © 2026 Abu Arefin Aroop — All Rights Reserved
Protected : WIPO Berne Convention | Bangladesh Copyright Act 2000
"""

from __future__ import annotations
import time

# ── Application identity ──────────────────────────────────────────────────────

APP_NAME        = "DeepSteg v4"
APP_VERSION     = "4.0.2"
APP_SUBTITLE    = "Production-Grade Hybrid-KEM Multi-Frame Video Steganography"
APP_REG_NO      = "AiT-IP-2026-DS-0001"
APP_YEAR        = "2026"

DEVELOPER_NAME  = "Abu Arefin Aroop"
DEVELOPER_ROLE  = "AI-Assisted Cyber Security Engineer"
DEVELOPER_EMAIL = "abu.arefin.aroop@ait.edu"
DEVELOPER_ORG   = "Arslan Institute of Technology (AiT)"
DEVELOPER_PROG  = "MCS-24 Program"

SUPERVISOR_NAME = "Assoc. Prof. Dr. Md. Azam Hossain"
SUPERVISOR_DEPT = "Dept. CSE, Bangladesh University of Professionals (BUP)"

# ── Legal constants ───────────────────────────────────────────────────────────

COPYRIGHT_SYMBOL   = "\u00A9"
COPYRIGHT_LINE     = f"\u00A9 {APP_YEAR} {DEVELOPER_NAME}. All Rights Reserved."
COPYRIGHT_FULL     = (
    f"\u00A9 {APP_YEAR} {DEVELOPER_NAME} & {DEVELOPER_ORG}. "
    "All Rights Reserved. "
    f"Registration: {APP_REG_NO}."
)
WATERMARK_TEXT     = f"\u00A9 {DEVELOPER_NAME} | {DEVELOPER_ORG} | {APP_REG_NO}"
CONFIDENTIAL_BADGE = "CONFIDENTIAL \u2014 INTELLECTUAL PROPERTY"

WIPO_REF  = "WIPO Berne Convention (1886), WCT (1996), TRIPS (1994)"
BD_LAW    = "Bangladesh Copyright Act 2000 (Act No. 28 of 2000)"
LEGAL_REF = f"Protected under: {WIPO_REF} | {BD_LAW}"

# ── Full policy text ──────────────────────────────────────────────────────────

POLICY_SECTIONS = {
    "Software License": """
DeepSteg v4 is the exclusive intellectual property of Abu Arefin Aroop
("Author"), developed at Arslan Institute of Technology (AiT).

PERMITTED USES (Academic & Educational):
  • Use for personal, non-commercial, educational research
  • Citation in academic works with proper attribution
  • Demonstration in academic settings

PROHIBITED WITHOUT WRITTEN PERMISSION:
  • Commercial use or deployment in any revenue-generating system
  • Redistribution of source code or compiled binaries
  • Modification and re-release under another name
  • Removal or alteration of copyright notices, watermarks, or branding
  • Reverse engineering for competitive product development
  • Use in classified or military systems without written agreement

ATTRIBUTION REQUIREMENT:
  All uses must prominently display:
  "DeepSteg v4 by Abu Arefin Aroop, Arslan Institute of Technology, 2026"
""",

    "Copyright & IP": f"""
Registration No. : {APP_REG_NO}
Copyright Owner  : {DEVELOPER_NAME}
Institution      : {DEVELOPER_ORG}
Year             : {APP_YEAR}

This software and all associated documentation, algorithms, protocols,
and creative expressions are protected under:

  1. WIPO Berne Convention for the Protection of Literary and Artistic
     Works (1886, as amended) — Article 2(1): Computer programs as
     literary works. Protection is automatic from creation.

  2. WIPO Copyright Treaty (WCT) 1996 — Article 4: Computer programs
     protected as literary works. Article 12: Rights Management
     Information (watermark) protection.

  3. TRIPS Agreement 1994 — Article 10: Software as literary work.

  4. Bangladesh Copyright Act 2000 (Act No. 28 of 2000):
     - Section 13: Copyright subsists from moment of creation
     - Section 14: Exclusive rights of the author
     - Section 68: Moral rights (attribution and integrity)
     - Section 71: Penalties for infringement
     - Section 72: Offences relating to rights management information
     - Section 82: Criminal penalties (up to 4 years imprisonment)

TERM OF PROTECTION:
  Lifetime of Author + 60 years (Section 61, Bangladesh Copyright Act 2000)
""",

    "Watermark Policy": f"""
This application embeds digital Rights Management Information (RMI)
consistent with Article 12 of the WIPO Copyright Treaty:

  • Author identification: {DEVELOPER_NAME}
  • Institution: {DEVELOPER_ORG}
  • Work identifier: DeepSteg v4 / {APP_REG_NO}
  • Copyright year: {APP_YEAR}

The AiT logo watermark, registration number, and copyright metadata
displayed throughout this application constitute protected Rights
Management Information (RMI).

CRIMINAL OFFENCE WARNING:
  Any person who knowingly removes, alters, or circumvents this
  watermarking information commits an offence under:
  - Section 72 of the Bangladesh Copyright Act 2000
  - Article 12 of the WIPO Copyright Treaty
  Subject to prosecution with fines and/or imprisonment.
""",

    "Disclaimer": """
THIS SOFTWARE IS PROVIDED FOR ACADEMIC AND RESEARCH PURPOSES.

THE AUTHOR AND AiT MAKE NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHOR OR AiT BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES ARISING IN ANY WAY FROM THE USE OF THIS SOFTWARE.

The cryptographic features of this software are provided for academic
demonstration. Users are responsible for compliance with applicable
export control laws and national cryptography regulations in their
jurisdiction before deploying this software.

For commercial licensing or permissions beyond the scope of this
license, contact: abu.arefin.aroop@ait.edu
""",
}

# ── Runtime copyright check ────────────────────────────────────────────────────

def get_startup_notice() -> str:
    """Returns the startup copyright notice shown at app launch."""
    return (
        f"  {APP_NAME} v{APP_VERSION}  —  {APP_SUBTITLE}\n"
        f"  {COPYRIGHT_LINE}\n"
        f"  {DEVELOPER_NAME}  |  {DEVELOPER_ROLE}  |  {DEVELOPER_ORG}\n"
        f"  Registration: {APP_REG_NO}\n"
        f"  {LEGAL_REF}\n"
    )

def get_about_text() -> str:
    """Full about text for the About dialog."""
    return (
        f"{APP_NAME} Version {APP_VERSION}\n"
        f"{APP_SUBTITLE}\n\n"
        f"Developer   : {DEVELOPER_NAME}\n"
        f"Role        : {DEVELOPER_ROLE}\n"
        f"Institution : {DEVELOPER_ORG}\n"
        f"Email       : {DEVELOPER_EMAIL}\n"
        f"Reg. No.    : {APP_REG_NO}\n\n"
        f"Supervisor  : {SUPERVISOR_NAME}\n"
        f"Dept.       : {SUPERVISOR_DEPT}\n\n"
        f"Cryptography : AES-256-GCM + X25519 Hybrid-KEM + RSA-4096-OAEP\n"
        f"Steganography: ECDH-Seeded Pseudorandom LSB  (36/36 security tests passed)\n"
        f"Keystore     : Scrypt (N=2\u00B9\u2077) Argon2-class password protection\n"
        f"Audit Log    : HMAC-SHA256 tamper-evident chain\n\n"
        f"{COPYRIGHT_FULL}\n"
        f"{LEGAL_REF}\n"
    )

def get_window_title() -> str:
    return (
        f"{APP_NAME} v{APP_VERSION}  \u2014  {DEVELOPER_NAME}  "
        f"\u00A9 {APP_YEAR} AiT  \u2014  {APP_REG_NO}"
    )
