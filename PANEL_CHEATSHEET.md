# Bio-Crypt Lock — Panel Presentation Kit

**Risk-Adaptive Multi-Factor Bio-Crypt Lock · Software Simulation Prototype**
Team: Roshini G (25BCE1676) · Sindhuja Bhaskar (25BCE5430) · K Aradhanaa (25BCE1994) · Guide: Prof. Rathna R

---

## 1. Setup checklist (do this BEFORE the panel enters)

1. Open a terminal in the project folder and run:
   ```
   python biocrypt/main.py
   ```
2. TWO windows appear — drag them side by side on the projector:
   - **Lock console** (960×700) — the protected machine
   - **Trusted Device** (phone window, stays topmost) — receives OTPs
3. Click **Create sample vault** once (folder opens in Explorer — close it).
4. Click **Seal folder…** to pre-seal it (so the demo ends with auto-decrypt).
5. Close other apps; set Windows display scale to 100%.

Fallback if the GUI misbehaves: `python biocrypt/main.py --selftest` (headless full demo in console).

---

## 2. The 5-minute run sheet

| Time | Click / action | Say |
|---|---|---|
| 0:00 | Point at sliders | "Static MFA asks the same question regardless of context. Ours fuses three live signals into one risk score." |
| 0:45 | **Trusted User** scenario | "Fingerprint 100% + adjacent BLE → risk 0 → **perfect match: instant unlock, no OTP** — zero friction for the genuine user." |
| 1:30 | **Moderate Risk** scenario | "Same lock, worse context: risk 32.5 → Medium. A **6-digit OTP** is generated and sent over BLE to the trusted device — note the delivery delay." |
| 2:15 | Type the code from the phone window | Code verified → unlock. |
| 2:45 | **Re-type the SAME code → Verify** | "**Replay attack rejected** — tokens are single-use per session, flagged in the audit ledger." |
| 3:15 | **Spoof / Anomaly** scenario | "Risk 71.5 → High: challenge escalates to **8 digits, ONE try, 60 s**." |
| 3:45 | Enter a wrong code once | "One wrong entry → **HARD LOCK**. Recovery only via Reset lock — every reset is audit-logged." |
| 4:15 | **⟳ Reset lock** → **Trusted User** | Vault **auto-decrypts**: "Cryptography is gated by the risk decision." |
| 4:45 | **View audit log** → **Verify hash chain** | "Every event is a hash-chained, tamper-evident record — edit any row and the chain breaks." |

Close: "Fixed MFA gives everyone the same challenge. Ours scales OTP length, tries, and timeouts with multi-factor risk — and when signals are perfect, friction is zero."

---

## 3. Flow of events — Input → Architecture → Output

```
INPUTS (Module 1 — sliders simulate hardware) · panel updates LIVE as sliders move
  fp_match_score : 0–100 %      (fingerprint optical match)
  rssi_dbm       : −90…−30 dBm  (BLE proximity; closer to 0 = nearer)
  failed_attempts: 0…5          (recent failure history)
        │
        ▼
ARCHITECTURE
  [1] CONTEXT FUSION RISK ENGINE        risk_engine.py
      risk = 0.50·(100 − fp)
           + 0.35·proximity(RSSI)        ≥−50→0 · ≥−70→30 · else→70
           + 0.15·min(30, 15·fails)
      → one live score, 0–100
  [2] TIERED ROUTER                      tiers.py
      perfect match (fp=100 AND RSSI≥−50) → no OTP, instant unlock
      Low ≤30  → 4-digit OTP · 3 tries · no timeout
      Med 31–70→ 6-digit OTP · 3 tries · 90 s/try
      High ≥71 → 8-digit OTP · 1 try · 60 s
  [3] OTP CHANNEL                        ble_link.py → device_window.py
      Counter-based OTP (RFC 4226) over simulated BLE; first delivery
      latency & garbling scale with RSSI — RE-SYNC BLE re-sends the SAME
      code in < 2 s, always clean (only a retransmission, never a new code)
  [4] VERIFIER                           otp.py
      constant-time compare vs the active challenge code · single-use
      per session → replay rejection · codes change ONLY on resync /
      wrong attempt / timeout — never on a clock
  [5] VAULT (on success)                 vault.py
      AES-256-GCM · PBKDF2-600k · path-as-AAD → folder auto-decrypts
  [6] AUDIT LOGGER (every event)         logger.py
      SQLite · session UUID · SHA-256 hash chain · replay flag · CSV export
        │
        ▼
OUTPUTS
  • Risk score + component breakdown (on gauge)
  • LIVE PREVIEW vs EVALUATED: slider moves recompute the score/tier in
    real time (display-only, NOT logged); RUN evaluates and audit-logs
  • Tier decision + challenge issued to Trusted Device
  • Unlock / denied / hard-lock verdict
  • Tamper-evident audit row for EVERY event (incl. resets)
```

---

## 4. Cheatsheet — numbers you must not fumble

| Thing | Value |
|---|---|
| Fusion weights | 0.50 biometric · 0.35 proximity · 0.15 history |
| RSSI bands | ≥ −50 → 0 · −70…−50 → 30 · < −70 → 70 |
| History | +15 per fail, capped at 30 |
| Tier boundaries | ≤30 Low · 31–70 Med · ≥71 High |
| Perfect match | fp = 100% AND RSSI ≥ −50 dBm (ignores fails) |
| Low challenge | 4 digits · 3 tries · no timeout |
| Med challenge | 6 digits · 3 tries · 90 s per try |
| High challenge | 8 digits · 1 try · 60 s |
| Exhaustion | Hard lock on EVERY tier; Reset lock (logged) or restart |
| OTP | RFC 4226 counter-based (HOTP), SHA-1, no clock — new code only on resync / wrong attempt / timeout; single-use per session |
| Vault | AES-256-GCM, PBKDF2-HMAC-SHA256 ×600 000, 12-byte nonces, path as AAD |
| Audit | SQLite + SHA-256 hash chain, genesis 000…0, CSV export |
| Demo passphrase | `biocrypt-demo` |
| Demo risk values | Trusted 0.00 · Moderate 32.50 · Spoof 71.50 |

---

## 5. Q&A — likely questions, ready answers

**"Where do the weights come from?"**
Hand-tuned for explainability: fingerprint is the primary identity proof (0.50), BLE is the presence token (0.35), history is supporting behavioural evidence (0.15), capped so a bad day can't permanently flag a user. The architecture accepts any scorer behind the same interface — a learned model is future work.

**"Why does history saturate?"**
30 raw points × 0.15 = 4.5 weighted max — history can raise friction but never dominate. High risk is driven by weak biometric + far proximity, which is exactly the spoof profile.

**"Where is the OTP received — SMS or email?"**
On the paired trusted device over BLE — matching our hardware plan (phone in proximity). The simulation shows delivery delay and garbling scaling with RSSI, which is precisely why proximity belongs in the risk score. SMS/email would add third-party dependencies without strengthening the BLE story.

**"What stops OTP brute force?"**
Tries are budgeted per tier (3/3/1), timeouts cap the window, and exhaustion hard-locks until an explicit, audit-logged reset. High risk gets exactly one attempt.

**"Is the biometric stored?"**
No — only the match *score* crosses the boundary. Templates never leave the sensor; non-invertible by design.

**"What if someone edits the audit log?"**
Each row's SHA-256 covers all fields plus the previous row's hash. Editing any historical row breaks every later link; "Verify hash chain" detects it instantly.

**"Why linear fusion and not ML?"**
Deterministic, auditable, real-time, and defensible — the panel can verify the math live. The interface is scorer-agnostic, so ML is an upgrade path, not a redesign.

**"What's the hardware plan?"**
ESP32 + optical fingerprint module + BLE RSSI feed the *same* engine through the Module-1 interface — the software layer is already the real logic; only the signal source changes.

**"What did each member do?"**
Roshini — literature survey, gap analysis, risk-engine math. Sindhuja — system architecture, tier routing, step-up policy. Aradhanaa — cryptographic vault, anti-replay audit logger, GUI.

---

## 6. If something goes wrong live

| Symptom | Fix |
|---|---|
| OTP garbled on phone window | Click **Re-sync BLE** (or narrate it as a feature: weak signal) |
| Accidentally hard-locked mid-demo | **⟳ Reset lock** — and say "audit-logged" |
| Vault already open | Seal folder… again before the unlock payoff |
| Windows overlap | Trusted Device is topmost — drag it right |
| GUI frozen | `python biocrypt/main.py --selftest` — headless demo, still impressive |
