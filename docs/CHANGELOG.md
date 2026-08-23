# Changelog

## v4.0.2 — Independent bug-fix review (this release)

This release fixes defects found while independently reviewing, running,
and testing the v4.0.1 codebase. Every fix below was verified either by
the existing 56-test security suite, a new end-to-end pipeline test
(keygen → encrypt → embed → steganalyze → extract → decrypt →
keystore round-trip), or by launching the actual GUI and clicking
through every tab.

### Fixed — app would not start at all

- **Startup `ImportError`.** `deepsteg_app.py` imported
  `get_platform_info` from `core.policy`, but that function only exists
  in `core.platform_utils` (and was already imported from there under
  its correct name a few lines above, unused). The app crashed
  immediately on launch, before any window appeared. *(core/policy.py
  import statement removed the bad alias.)*

### Fixed — app started but crashed building the UI

- **`_tkinter.TclError: Layout Vertical.D.TScrollbar not found`.** A
  custom ttk style, `"D.TScrollbar"`, had colors configured via
  `style.configure(...)` but was never given a widget *layout*. Tkinter
  requires an explicit layout for any non-built-in style name, or widget
  creation fails. This affected every scrollbar in the app (log panel,
  extraction output, VAPT output, audit log), so the app crashed the
  moment the Embed tab (the first tab built) tried to create its log
  scrollbar. *(Fixed by copying the layout from the theme's built-in
  `TScrollbar` before applying custom colors, in `_setup_styles`.)*

### Fixed — security/correctness bug, not a crash

- **Pixel-permutation seed used ~32 bits of entropy instead of 256.**
  `steg_engine._make_pixel_order` derived the Fisher-Yates shuffle seed
  with:
  ```python
  np.frombuffer(digest, dtype=np.uint8).astype(np.uint64)[:4]
  ```
  `.astype(np.uint64)` converts each **byte value** (0–255) to a
  `uint64` individually — it does not reinterpret the underlying bytes.
  The RNG therefore only ever saw four numbers in the range 0–255,
  instead of the intended four 64-bit words spanning the full 256-bit
  SHA-256 digest. This silently undermined the "computationally
  indistinguishable from a random permutation" claim (Theorem 3 in the
  accompanying paper) without producing any test failure, error, or
  visible symptom — the permutation was still valid and deterministic,
  just far more guessable than intended. *(Fixed with
  `np.frombuffer(digest, dtype=np.uint64)`, which correctly reinterprets
  the 32-byte digest as four native 64-bit words.)* Verified: a 1-bit
  flip in the input seed now changes ~99.7% of output positions (997/1000
  in a sample test), consistent with proper avalanche behavior.

### Fixed — Tkinter thread-safety bug

- **`_make_test_video()` touched widgets from a background thread.**
  The test-video generator runs in a worker `threading.Thread`, but
  called `self._update_cap()` (which directly configures a `tk.Label`)
  and set two `StringVar`s directly, outside of `self.after(...)`.
  Tkinter is not thread-safe; calling widget methods off the main
  thread is undefined behavior and can crash or corrupt UI state
  intermittently. Every other background operation in the file already
  routes UI updates through `self.after(0, ...)` — this one call site
  didn't. *(Fixed by wrapping both the path updates and `_update_cap()`
  call in `self.after(0, ...)`.)*

### Fixed — test suite / tooling

- **`tests/test_security.py` crashed `pytest` on collection.** The file
  is a script-style test runner: it executes all 56 checks as a
  side-effect of being imported, then called `sys.exit(0 if FAILED==0
  else 1)` unconditionally at module scope. Under `pytest`, this
  `sys.exit()` fired during collection and crashed the whole pytest
  process with an `INTERNALERROR`. Separately, pytest's test-discovery
  auto-collected the module's own `test(name, fn)` helper function
  (matching the `test*` naming pattern) and tried to inject `name`/`fn`
  as fixtures, producing a second, unrelated collection error.
  *(Fixed: renamed the helper `test()` → `_check()` throughout, and
  moved `sys.exit()` under `if __name__ == "__main__":`, adding a
  `test_deepsteg_v4_security_suite()` wrapper so pytest has a normal
  test function to run and report.)* Both `python3
  tests/test_security.py` and `pytest tests/test_security.py -q` now
  work correctly and report 56/56 passed.

### Fixed — minor / cosmetic

- **Hardcoded version string.** The VAPT+ tab's STRIDE panel literally
  read "All 6 STRIDE categories mitigated in v4.0.1" regardless of the
  actual running version. Now interpolates `APP_VERSION`.
- **Installers didn't ship `docs/` or a `requirements.txt`.** Both the
  Linux and Windows installers only copied `deepsteg_app.py`, `core`,
  `assets`, `tests`, and `__init__.py`. A `requirements.txt` has been
  added at the project root (previously dependencies were only listed
  inline in each installer script, in two places that could drift out
  of sync), and both installers now copy `docs/` and
  `requirements.txt`, and install from `requirements.txt` when present
  (falling back to an inline pinned list otherwise, so the installers
  remain self-sufficient even if that file is ever missing).
- **Windows installer never ran the security test suite** after
  installing (the Linux installer did). Added the same test-suite run
  step for parity, so a Windows install gets the same "56/56 passed"
  confirmation.

### Documented, not code-fixed (known limitations)

These were identified during review but are scope/design limitations
rather than bugs with a small, safe fix — see `README.md` and
`docs/DEPLOYMENT_GUIDE.md` §5 for details:

- **Kyber-1024 (post-quantum KEM) never actually activates.** The
  "real Kyber" code path in `hybrid_kem_encapsulate()` checks for a
  `_kyber_pub` attribute on the receiver's X25519 public key object — an
  attribute that a real `cryptography`-library `X25519PublicKey` will
  never have. The hybrid KEM therefore always falls back to its
  documented X25519+X25519 fallback, even with `kyber-py` installed.
  Classical security is unaffected; post-quantum security is not
  actually provided despite "Kyber-1024 ready" language in the UI.
- **RS Analysis and Sample Pair Analysis report low statistical power
  on synthetic (blurred-noise) cover frames**, as transparently
  documented in the accompanying paper. This is a property of the
  evaluation methodology on synthetic covers, not a defect in the
  implementation.

---

## v4.0.1 (prior release, from the original submission)

Baseline release accompanying the DeepSteg v4 research paper. See the
paper's Section III/IV and the in-code "Security hardening (v4.0.1)"
comments in `core/crypto_engine.py` and `core/steg_engine.py` for its
feature set and the bundle-parsing/keystore/chunk hardening it
introduced over v3.
