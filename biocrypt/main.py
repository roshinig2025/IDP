"""Bio-Crypt Lock — entrypoint.

Usage
-----
    python biocrypt/main.py             # launch the full GUI demo
    python biocrypt/main.py --selftest  # headless verification of all
                                        # modules (no GUI, exits with code)
Run from the project root (the folder containing `biocrypt/`).
"""

from __future__ import annotations

import os
import sys
import tempfile

# Allow `python biocrypt/main.py` from the project root: make the parent
# directory (which contains the `biocrypt` package) importable.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _selftest() -> int:
    """Headless end-to-end check of the three demo scenarios plus the
    crypto vault, counter-OTP anti-replay, and audit hash chain."""
    from biocrypt.audit.logger import AuditLogger, AuditRecord
    from biocrypt.crypto import vault
    from biocrypt.engine import otp
    from biocrypt.engine.risk_engine import compute_risk
    from biocrypt.engine.tiers import (TIER_HIGH, TIER_LOW, TIER_MED,
                                       OTP_HIGH_DIGITS, OTP_HIGH_TIMEOUT_S,
                                       OTP_HIGH_TRIES, OTP_LOW_DIGITS,
                                       OTP_LOW_TIMEOUT_S, OTP_LOW_TRIES,
                                       OTP_MED_DIGITS, OTP_MED_TIMEOUT_S,
                                       OTP_MED_TRIES, is_perfect_match,
                                       route_tier)

    print("=" * 62)
    print(" BIO-CRYPT LOCK - SELFTEST (headless)")
    print("=" * 62)

    failures: list[str] = []

    def check(label: str, cond: bool) -> None:
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
        if not cond:
            failures.append(label)

    # ---- Scenario runs -------------------------------------------------
    # Scenario inputs are tuned so each demo lands in its intended tier
    # under the fixed weights (High needs fp <= ~17 because the history
    # component saturates at 30 raw points = 4.5 weighted).
    scenarios = [
        ("Trusted User",    100.0, -45.0, 0, TIER_LOW,  0.00),
        ("Moderate Risk",   65.0, -68.0, 2, TIER_MED, 30.00),
        ("Spoof / Anomaly", 15.0, -82.0, 3, TIER_HIGH, 70.00),
    ]
    db_path = os.path.join(tempfile.gettempdir(), "biocrypt_selftest.db")
    if os.path.exists(db_path):
        os.remove(db_path)                  # deterministic row counts
    audit = AuditLogger(db_path)
    for name, fp, rssi, fails, want_tier, want_prox in scenarios:
        risk = compute_risk(fp, rssi, fails)
        decision = route_tier(risk.total_risk)
        print(f"\n--- {name}: fp={fp}%  rssi={rssi} dBm  fails={fails}")
        print(f"    components: {risk.components}")
        print(f"    risk={risk.total_risk}  tier={decision.tier}")
        print(f"    action: {decision.action}")
        check(f"{name}: risk in 0..100", 0.0 <= risk.total_risk <= 100.0)
        check(f"{name}: proximity={want_prox}",
              risk.proximity_risk == want_prox)
        check(f"{name}: tier={want_tier}", decision.tier == want_tier)
        audit.log(AuditRecord(
            fp_score=fp, rssi_dbm=rssi, failed_attempts=fails,
            biometric_risk=risk.biometric_risk,
            proximity_risk=risk.proximity_risk,
            history_risk=risk.history_risk, risk_score=risk.total_risk,
            tier=decision.tier, otp_issued=decision.requires_otp,
            otp_digits=decision.otp_digits, status=decision.status))

    # ---- Challenge policy v2 ---------------------------------------------
    print("\n--- Challenge policy (v2)")
    check("perfect match: fp=100 & rssi=-45 detected",
          is_perfect_match(100.0, -45.0))
    check("perfect match: rssi=-51 rejected",
          not is_perfect_match(100.0, -51.0))
    check("perfect match: fp=99 rejected",
          not is_perfect_match(99.0, -45.0))
    check("perfect match: overrides 3 failed attempts",
          is_perfect_match(100.0, -40.0))
    check("Low: 4-digit OTP",
          route_tier(20).otp_digits == OTP_LOW_DIGITS == 4)
    check("Low: 3 tries, no timeout",
          route_tier(20).otp_tries == OTP_LOW_TRIES == 3
          and route_tier(20).otp_timeout_s == OTP_LOW_TIMEOUT_S == 0)
    check("Med: 6-digit OTP, 3 tries, 90 s per try",
          route_tier(50).otp_digits == OTP_MED_DIGITS == 6
          and route_tier(50).otp_tries == OTP_MED_TRIES == 3
          and route_tier(50).otp_timeout_s == OTP_MED_TIMEOUT_S == 90)
    check("High: 8-digit OTP, 1 try, 60 s timeout",
          route_tier(90).otp_digits == OTP_HIGH_DIGITS == 8
          and route_tier(90).otp_tries == OTP_HIGH_TRIES == 1
          and route_tier(90).otp_timeout_s == OTP_HIGH_TIMEOUT_S == 60)
    check("exhaustion hard-locks on every tier",
          all(route_tier(s).hard_lock_on_exhaust for s in (20, 50, 90)))

    # ---- Counter-based OTP + anti-replay --------------------------------
    secret = otp.generate_secret()
    counter = otp.next_counter(0)
    code = otp.current_otp(secret, counter, 6)
    ok, why = otp.verify_otp(secret, counter, 6, code)
    check("OTP: active challenge code accepted", ok and why == "ok")
    next_code = otp.current_otp(secret, otp.next_counter(counter), 6)
    check("OTP: each (re)issue yields a different code", next_code != code)
    ok3, why3 = otp.verify_otp(secret, counter, 6, next_code)
    check("OTP: code from another challenge rejected",
          not ok3 and why3 == "invalid")
    ok4, why4 = otp.verify_otp(secret, counter, 6, "12ab")
    check("OTP: malformed code rejected", not ok4 and why4 == "malformed")
    code8 = otp.current_otp(secret, 7, 8)
    check("OTP: 8-digit mode produces 8 digits", len(code8) == 8)

    # ---- AES-256-GCM vault round-trip -----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        folder = os.path.join(tmp, "vault")
        os.makedirs(folder)
        secret_msg = "Bio-Crypt vault payload — TOP SECRET demo file.\n" * 5
        with open(os.path.join(folder, "report.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(secret_msg)
        os.makedirs(os.path.join(folder, "sub"))
        with open(os.path.join(folder, "sub", "data.bin"), "wb") as fh:
            fh.write(bytes(range(256)))

        vault.seal_folder(folder, "demo-passphrase")
        check("vault: sealed (manifest present)",
              vault.is_sealed(folder))
        check("vault: ciphertext replaced plaintext",
              not os.path.exists(os.path.join(folder, "report.txt"))
              and os.path.exists(os.path.join(folder, "report.txt.bcl")))

        # tamper test: flip a byte in the ciphertext
        blob_path = os.path.join(folder, "report.txt.bcl")
        blob = bytearray(open(blob_path, "rb").read())
        blob[-1] ^= 0xFF
        open(blob_path, "wb").write(bytes(blob))
        try:
            vault.unseal_folder(folder, "demo-passphrase")
            check("vault: tampered ciphertext rejected", False)
        except vault.VaultError:
            check("vault: tampered ciphertext rejected", True)
            # restore for the happy path
            blob[-1] ^= 0xFF
            open(blob_path, "wb").write(bytes(blob))

        vault.unseal_folder(folder, "demo-passphrase")
        check("vault: unsealed (manifest removed)",
              not vault.is_sealed(folder))
        with open(os.path.join(folder, "report.txt"), encoding="utf-8") as fh:
            check("vault: round-trip byte-identical",
                  fh.read() == secret_msg)

        try:
            vault.unseal_folder(folder, "WRONG passphrase")
            check("vault: wrong passphrase rejected", False)
        except (vault.VaultError, FileNotFoundError):
            check("vault: wrong passphrase rejected", True)

    # ---- Audit hash chain ------------------------------------------------
    ok_chain, msg = audit.verify_chain()
    check(f"audit: hash chain intact ({len(audit.fetch_all())} rows)",
          ok_chain)
    audit.close()

    print("\n" + "=" * 62)
    if failures:
        print(f" SELFTEST FAILED - {len(failures)} check(s):")
        for f in failures:
            print(f"   - {f}")
        return 1
    print(" SELFTEST PASSED - all modules operational.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in argv or "-t" in argv:
        return _selftest()
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0

    # GUI mode
    from biocrypt.audit.logger import AuditLogger
    from biocrypt.ui.app import BioCryptApp
    import tkinter as tk

    root = tk.Tk()
    app = BioCryptApp(root, audit=AuditLogger())
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
