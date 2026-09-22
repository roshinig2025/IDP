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
import time

# Allow `python biocrypt/main.py` from the project root: make the parent
# directory (which contains the `biocrypt` package) importable.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _selftest() -> int:
    """Headless end-to-end check of the three demo scenarios plus the
    crypto vault, TOTP anti-replay, and audit hash chain."""
    from biocrypt.audit.logger import AuditLogger, AuditRecord
    from biocrypt.crypto import vault
    from biocrypt.engine import totp
    from biocrypt.engine.risk_engine import compute_risk
    from biocrypt.engine.tiers import TIER_HIGH, TIER_LOW, TIER_MED, route_tier

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
        ("Trusted User",    95.0, -42.0, 0, TIER_LOW,  0.00),
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

    # ---- TOTP + anti-replay --------------------------------------------
    secret = totp.generate_secret()
    code = totp.current_totp(secret, 6)
    ok, why = totp.verify_totp(secret, 6, code, used_codes=set())
    check("TOTP: fresh code accepted", ok and why == "ok")
    ok2, why2 = totp.verify_totp(secret, 6, code,
                                 used_codes={code})
    check("TOTP: reuse rejected as replay",
          not ok2 and why2 == "replay")
    ok3, why3 = totp.verify_totp(secret, 6, "000000" if code != "000000"
                                 else "000001", used_codes=set(),
                                 now=time.time() + 10_000)
    check("TOTP: wrong/expired code rejected", not ok3)
    code8 = totp.current_totp(secret, 8)
    check("TOTP: 8-digit mode produces 8 digits", len(code8) == 8)

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
