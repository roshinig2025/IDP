# SESSION HANDOFF — Bio-Crypt Lock (read this before touching the project)

Date of session: Sept 22, 2026 · Environment: Windows, Python 3.14.7, `cryptography` 50.0.1 (only pip dependency)
Project root: `C:\College study material\Innovative Design Project` — run ALL commands from here, NOT from inside `biocrypt/`.

## Project
Risk-Adaptive Multi-Factor Bio-Crypt Lock — IDP Review II software-only prototype (~20%).
Simulates hardware inputs (fingerprint match %, BLE RSSI, failed attempts), fuses them into a
0–100 risk score, routes through a tiered OTP challenge, and gates AES-256-GCM file decryption.
Team: Roshini G (lit survey + risk math), Sindhuja B (architecture + tier routing), K Aradhanaa (crypto + audit + GUI). Guide: Prof. Rathna R.

## File map
- `biocrypt/engine/risk_engine.py` — fusion formula + constants (single source of truth)
- `biocrypt/engine/tiers.py` — policy v2 (perfect match, 4/6/8-digit tiers, hard lock)
- `biocrypt/engine/otp.py` — counter-based RFC 4226 HOTP (NO clock), stdlib only
- `biocrypt/crypto/vault.py` — AES-256-GCM seal/unseal, PBKDF2-600k, path-as-AAD, manifest.bcl
- `biocrypt/audit/logger.py` — SQLite + SHA-256 hash chain (GENESIS = 64 zeros), CSV export
- `biocrypt/ui/app.py` — Lock console GUI (state machine, scenarios, vault, audit views)
- `biocrypt/ui/ble_link.py` — simulated BLE (latency/garbling scale with RSSI)
- `biocrypt/ui/device_window.py` — Trusted Device (phone) window that receives OTPs
- `biocrypt/main.py` — entrypoint; `--selftest` = headless full verification
- `tests/test_engine.py`, `tests/test_vault_audit.py` — 41 unit tests
- `tests/gui_smoke.py` — scripted end-to-end GUI test (9 stages)
- `PANEL_CHEATSHEET.md` — printable demo run-sheet + Q&A answers
- `SESSION_HANDOFF.md` — this file

## POLICY v2 (user-specified, final — do not regress)
| Case | Condition | Challenge | On exhaustion |
|---|---|---|---|
| Perfect match | fp = 100% AND RSSI ≥ −50 dBm | No OTP, instant unlock — EVEN with failed attempts > 0 | — |
| Low (risk ≤ 30) | not perfect | 4-digit OTP, 3 tries, NO timeout | HARD lock |
| Medium (31–70) | — | 6-digit OTP, 3 tries, 90 s per try | HARD lock |
| High (≥ 71) | — | 8-digit OTP, 1 try, 60 s | HARD lock |

- HARD LOCK (uniform, every tier): tries exhausted by wrong entries, timeout expiry, or replay → RUN + OTP entry disabled, NO automatic recovery. Only `⟳ RESET LOCK` button or app restart; every reset is audit-logged.
- Per-try timeout (Med/High): expiry consumes one try; fresh OTP re-issued if tries remain. Low has none.
- Risk formula UNCHANGED: risk = 0.50·(100−fp) + 0.35·proximity + 0.15·min(30, 15·fails); RSSI bands ≥−50→0, ≥−70→30, else 70; boundaries ≤30 Low, 31–70 Med, ≥71 High.
- OTP delivery: simulated Trusted Device window over BLE only — user explicitly rejected SMS/Gmail for the demo.

## Critical design decisions (OTP lifecycle v3 — latest change, do not regress)
1. PER CHALLENGE SESSION consumption: verify_otp accepts only `code == active_otp[0]` (shape check
   first; correctly-shaped-but-foreign codes → "replay"); re-submission after session close (even
   post-unlock) → logged as replay attempt, entry stays enabled so the panel can SEE it. No global
   used-codes set.
2. CLOCK-FREE codes (user-mandated, replaced RFC 6238 TOTP with RFC 4226 HOTP in engine/otp.py):
   codes NEVER rotate on a timer. The app holds otp_counter; _issue_otp increments it on EVERY
   issue, so each re-issued code is guaranteed different. Codes change ONLY on: Re-sync BLE
   (redelivers the SAME value, never a new code), wrong attempt (tries remain), attempt timeout
   (tries remain).
3. BLE resync is near-instant (0.3–0.8 s) and NEVER garbled (clean retransmission); first
   deliveries keep RSSI-scaled latency + garbling (the proximity demo). resync_ble() is app-owned,
   no-ops with a UI message when no challenge is active. Packet gained `resync` flag + "resynced"
   status; device window shows a distinct resync line.
4. Per-try deadline (Med 90 s / High 60 s) is armed in _issue_otp — i.e. at every issue/re-issue —
   so EVERY attempt gets its own full window (per-attempt, confirmed). Low has no deadline.
   The countdown label shows "try expires in Xs (timer resets each attempt)"; Low shows
   "no time limit — code valid until a new one is issued". No more "code rotates in Xs" text.

## Other decisions made this session
- LIVE PREVIEW added (latest change): sliders / spinbox / scenarios recompute the risk gauge,
  tier and predicted routing in real time (display-only, NOT audit-logged). Tag shows
  "LIVE PREVIEW · press RUN to attempt access", switches to "EVALUATED · attempt recorded in
  audit trail" after RUN; notes active-challenge/hard-lock states. Triggered via slider
  commands (_on_fp_changed/_on_rssi_changed), spinbox command, _inject_failure, _apply_scenario,
  reset_lock, and once at startup (_preview_ready flag guards pre-UI calls). _show_evaluated
  restores the evaluated verdict after mid-challenge slider moves.
- Demo scenarios retuned for v2: Trusted User fp=100/rssi=−45/fails=0 (risk 0.00, perfect match);
  Moderate fp=65/−68/2 (risk 32.50, Med); Spoof fp=15/−82/3 (risk 71.50, High).
- "Reset lock" button added under RUN; hard lock disables RUN until pressed.
- Audit tier field: perfect-match rows use the computed risk tier (decision is None on that path).
- User's original spec table had an inconsistency (fp=40/−82/3 = risk 59 = Med, not High); engine is
  correct, scenarios were retuned instead of the formula. If a panel member plugs those numbers in, stand by the math.

## Verification status (all green at handoff)
- `python -m pytest tests/ -q` → 43 passed (RFC 4226 Appendix-D vectors incl.)
- `python biocrypt/main.py --selftest` → PASSED (incl. counter-OTP + policy checks)
- `python tests/gui_smoke.py` → SMOKE PASSED (stages: perfect unlock, fails-override, live preview,
  Low hard lock, reset, Med 3-try flow w/ differing re-issued codes, resync (same code, no try
  consumed, no-op without challenge), replay rejection, High 1-try hard lock, vault auto-decrypt,
  chain intact)
- Live-preview smoke stage [2b] added: fp=13/−82 → PREVIEW Medium 68.00; fp=15 alone → High;
  fp=50/−45 → Low; RUN at fp=13/−82 issues 6-digit OTP and switches tag to EVALUATED.
- Real GUI launch verified (stays alive 7 s, clean kill)

## Run
```bash
cd "C:\College study material\Innovative Design Project"
python biocrypt\main.py              # two windows: Lock console + Trusted Device
python biocrypt\main.py --selftest   # headless fallback
python -m pytest tests/ -q           # unit tests
python tests\gui_smoke.py            # end-to-end GUI test
```
Demo passphrase (hardcoded, shown on UI): `biocrypt-demo`. Sample vault folder: `secure_vault/`.

## Known leftovers / cautions
- `~$Bio-Crypt_Lock.pptx` and `Bio-Crypt_Lock.pptx` in the root are the user's own files — never touch.
- A stray `biocrypt_audit.db` may appear in the root after GUI runs; it is the app's real audit DB —
  ask before deleting (contains demo audit history).
- Vaults seal/unseal IN PLACE with real deletion of plaintext; only demo folders should be sealed.
- Nothing has been git-committed (no repo initialised); all work is on disk only.
