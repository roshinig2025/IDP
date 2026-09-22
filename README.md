# Bio-Crypt Lock — Software Simulation & Cryptographic Access-Control Engine

Review II working prototype (~20% initial implementation): a desktop app that
demonstrates the project's core IP without hardware — the **context-fusion
risk engine**, **3-tier risk-adaptive authentication** with dynamic TOTP
step-up, **AES-256-GCM file/folder decryption**, and an **anti-replay,
tamper-evident audit logger**.

## Requirements

- Python 3.10+ (developed on 3.14)
- `cryptography` package — the **only** external dependency
  (`pip install cryptography`; already installed here, v50.0.1)
- Everything else is stdlib: `tkinter` (GUI), `sqlite3`, `hmac`, `hashlib`

## Run

From the project root (the folder containing `biocrypt/`):

```bash
python biocrypt/main.py             # full GUI demo (Lock console + Trusted Device window)
python biocrypt/main.py --selftest  # headless end-to-end verification
python -m pytest tests/ -q          # 37 unit tests
python tests/gui_smoke.py           # scripted end-to-end GUI test (headless-friendly)
```

## Demo flow (5 minutes, panel-ready)

1. **Launch** — two windows appear: the *Lock console* (the protected
   machine) and the *Trusted Device* (the simulated phone whose BLE
   proximity is measured).
2. **Module 1 — Input simulator (left panel):** drag the sliders for
   *Fingerprint optical match score (0–100 %)* and *BLE RSSI (−90…−30 dBm)*;
   spin *Attempt history* or hit *Inject failed attempt*. Or press one of the
   three one-click scenarios.
3. **Module 2 — Risk engine (right panel):** press **RUN ACCESS ATTEMPT**.
   The dynamic risk score (0–100) and its component breakdown appear live:

   ```
   risk = 0.50·(100 − fingerprint%)      ← biometric confidence
        + 0.35·proximity_risk(RSSI)      ← ≥−50 dBm→0 · ≥−70→30 · else→70
        + 0.15·min(30, 15·failed_attempts)
   ```

   | Tier | Score | Behaviour |
   |------|-------|-----------|
   | Low | 0–30 | Direct unlock, no OTP |
   | Medium | 31–70 | **6-digit** TOTP challenge |
   | High | 71–100 | **8-digit** TOTP + 60 s timed lockout |

4. **OTP delivery (the demo's centrepiece):** on Medium/High risk the code
   is transmitted over the simulated BLE channel to the *Trusted Device*
   window — **delay and reliability scale with RSSI** (at −85 dBm the packet
   may arrive garbled; use *Re-sync BLE*). Re-type the code in the Lock
   console. A replayed code is rejected and flagged in the audit log.
5. **Module 3 — Vault:** *Create sample vault* → *Seal folder…* (AES-256-GCM,
   per-file nonce, path bound as AAD) → the folder now shows `.bcl`
   containers + `manifest.bcl`. On a successful auth the vault
   **auto-decrypts** — cryptography gated by the risk decision.
6. **Module 4 — Audit:** *View audit log* (session id, inputs, component
   risks, risk score, tier, OTP verdict, replay flag, status),
   *Verify hash chain* (SHA-256-chained, tamper-evident), *Export CSV*.

### Suggested scenario runs

| Scenario | fp | RSSI | fails | risk | tier |
|----------|----|------|-------|------|------|
| Trusted User | 95 | −42 | 0 | 2.50 | Low → direct unlock |
| Moderate Risk | 65 | −68 | 2 | 32.50 | Med → 6-digit OTP |
| Spoof / Anomaly | 15 | −82 | 3 | 71.50 | High → 8-digit OTP + lockout |

## Architecture

```
Fingerprint %   BLE RSSI   Attempt history
      │             │             │
      └──────┬──────┴──────┬──────┘
             ▼             ▼
        ┌─────────────────────────┐
        │  CONTEXT FUSION RISK    │  biocrypt/engine/risk_engine.py
        │  ENGINE  (0–100)        │
        └───────────┬─────────────┘
                    ▼
        ┌─────────────────────────┐
        │  3-TIER ROUTER          │  biocrypt/engine/tiers.py
        │  Low / Med / High       │
        └───────┬─────────┬───────┘
        no OTP  │         │  TOTP over simulated BLE
                ▼         ▼  (biocrypt/ui/ble_link.py → Trusted Device)
        ┌───────────┐ ┌──────────────────┐
        │ 1-TOUCH   │ │ 6/8-DIGIT TOTP   │ biocrypt/engine/totp.py (RFC 6238,
        │ UNLOCK    │ │ STEP-UP + LOCKOUT│ single-use anti-replay)
        └─────┬─────┘ └────────┬─────────┘
              ▼                ▼
        ┌─────────────────────────────┐   ┌──────────────────────────┐
        │ AES-256-GCM VAULT           │   │ AUDIT LOGGER (SQLite)    │
        │ biocrypt/crypto/vault.py    │   │ biocrypt/audit/logger.py │
        │ seal / auto-unseal on auth  │   │ hash-chained + CSV       │
        └─────────────────────────────┘   └──────────────────────────┘
```

## Rubric mapping (Review II, ~20% prototype)

| Rubric item | Where it is demonstrated |
|---|---|
| Requirement analysis — why static MFA fails | Risk engine fusion vs fixed OTP: same user, different context → different challenge (run the 3 scenarios) |
| System design & architecture | Diagram above + modular package split (`engine` / `crypto` / `audit` / `ui`) |
| Component selection & justification | AES-256-GCM (authenticated encryption), RFC 6238 TOTP, PBKDF2-HMAC-SHA256 (600k iters), SQLite hash chain, RSSI bands |
| **Initial prototype (~20%)** | Live GUI: sliders → risk score → tier routing → dynamic OTP → file unlock → audit trail |
| Innovation & feasibility | Dynamic OTP complexity scaling with multi-factor risk; proximity-dependent OTP delivery; non-invertible biometric weighting (only the match *score* is consumed — templates never stored) |
| Q&A defence | Hardware phase next: ESP32 + optical fingerprint module + BLE RSSI feed the same engine via the Module-1 simulator interface |

## Security notes (defensible in Q&A)

- Only the fingerprint **match score** crosses the boundary — biometric
  templates are never stored or transmitted (non-invertible by design).
- Vault key is derived with PBKDF2-HMAC-SHA256 (600 000 iterations,
  random 16-byte salt); each file sealed with a fresh 12-byte nonce.
- Original file path is GCM AAD → ciphertexts cannot be swapped between
  files; any tampering fails the GCM tag and aborts the restore.
- OTPs are single-use; reuse is rejected as **replay** and flagged in the
  hash-chained audit ledger (editing any historical row breaks the chain).

## Layout

```
biocrypt/
├── main.py                  entrypoint (--selftest for headless demo)
├── engine/                  risk_engine.py · tiers.py · totp.py
├── crypto/vault.py          AES-256-GCM seal/unseal
├── audit/logger.py          hash-chained SQLite logger
└── ui/                      app.py · device_window.py · ble_link.py
tests/
├── test_engine.py           risk math, tier edges, TOTP vectors & replay
├── test_vault_audit.py      vault round-trip, tamper, chain integrity
└── gui_smoke.py             scripted end-to-end GUI run
```
