"""Scripted GUI smoke test — drives BioCryptApp through the full demo flow
with a scripted BLE link (no randomness) and an in-memory audit DB.

Run:  python tests/gui_smoke.py
Pass: prints SMOKE PASSED and exit code 0.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import types

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import tkinter as tk

from biocrypt.audit.logger import AuditLogger
from biocrypt.crypto import vault
from biocrypt.engine import totp
from biocrypt.ui.app import DEMO_PASSPHRASE, SCENARIOS, BioCryptApp
from biocrypt.ui.ble_link import BlePacket


class ScriptedBleLink:
    """Deterministic BLE link: instant, always-clean delivery."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, float]] = []
        self.subscribers = []

    def subscribe(self, cb):
        self.subscribers.append(cb)

    def send_otp(self, otp: str, rssi_dbm: float) -> BlePacket:
        self.sent.append((otp, rssi_dbm))
        packet = BlePacket(otp=otp, rssi_dbm=rssi_dbm, garbled=False,
                           status="delivered", delivered_at=time.time(),
                           delivered_code=otp)
        for cb in self.subscribers:
            cb(packet)
        return packet

    def request_resync(self) -> None:
        pass

    def close(self) -> None:
        pass


def pump(root: tk.Tk, ms: int) -> None:
    end = time.time() + ms / 1000
    while time.time() < end:
        root.update()
        time.sleep(0.01)


def main() -> int:
    checks: list[tuple[str, bool]] = []

    def check(label: str, cond: bool) -> None:
        checks.append((label, bool(cond)))
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")

    tmp = tempfile.mkdtemp(prefix="biocrypt_smoke_")
    os.chdir(tmp)
    audit = AuditLogger(os.path.join(tmp, "smoke_audit.db"))

    root = tk.Tk()
    root.withdraw()                     # we manage our own windows
    app = BioCryptApp(root, audit=audit, link=ScriptedBleLink())
    root.deiconify()
    pump(root, 400)

    # -- 1. Trusted-user scenario: direct unlock --------------------------
    print("\n[1] Trusted User scenario")
    app._apply_scenario("Trusted User")
    pump(root, 300)
    risk = app._pending_risk if hasattr(app, "_pending_risk") else None
    check("no OTP issued", len(app.link.sent) == 0)
    check("status says Unlocked",
          "Unlocked" in app.result_lbl.cget("text"))

    # -- 2. Moderate scenario: 6-digit OTP via trusted device -------------
    print("\n[2] Moderate Risk scenario (OTP step-up)")
    app._apply_scenario("Moderate Risk")
    pump(root, 300)
    check("one OTP sent over BLE", len(app.link.sent) == 1)
    otp_code, rssi = app.link.sent[0]
    check("OTP is 6 digits", len(otp_code) == 6)
    check("OTP entry enabled",
          str(app.otp_entry.cget("state")) == "normal")

    # wrong code first (failure 1/3)
    app.otp_var.set("000000" if otp_code != "000000" else "000001")
    app.verify_otp()
    pump(root, 150)
    check("wrong OTP rejected",
          "denied" in app.result_lbl.cget("text").lower())

    # correct code
    app.otp_var.set(otp_code)
    app.verify_otp()
    pump(root, 150)
    check("correct OTP unlocks", "Unlocked" in app.result_lbl.cget("text"))

    # -- 3. Replay: re-submitting the same OTP must be rejected ------------
    print("\n[3] Anti-replay check")
    app.otp_var.set(otp_code)
    app.verify_otp()
    pump(root, 150)
    check("replayed OTP rejected",
          "replay" in app.result_lbl.cget("text").lower())

    # -- 4. High-risk scenario: 8-digit OTP + lockout ----------------------
    print("\n[4] Spoof/Anomaly scenario (high risk)")
    app._apply_scenario("Spoof / Anomaly")
    pump(root, 300)
    check("one more OTP sent", len(app.link.sent) == 2)
    code8, _ = app.link.sent[1]
    check("OTP is 8 digits", len(code8) == 8)

    app.otp_var.set("99999999" if code8 != "99999999" else "99999998")
    app.verify_otp()
    pump(root, 100)
    app.otp_var.set("88888888" if code8 != "88888888" else "88888887")
    app.verify_otp()
    pump(root, 100)
    app.otp_var.set("77777777" if code8 != "77777777" else "77777776")
    app.verify_otp()                    # 3rd failure -> lockout
    pump(root, 1400)                    # let a 1 Hz _tick pass first
    check("lockout engaged", app.lockout_until > 0)
    check("run button disabled", str(app.run_btn.cget("state")) == "disabled")

    # -- 5. Vault: seal -> authorised unlock -> auto-decrypt ---------------
    print("\n[5] AES-256-GCM vault flow")
    app.lockout_until = 0.0             # skip the wait for the test
    app.run_btn.config(state="normal")
    app.create_sample_vault()
    app.root.update()
    vault.seal_folder(app.vault_dir, DEMO_PASSPHRASE)
    app._refresh_vault_label()
    check("vault sealed", vault.is_sealed(app.vault_dir))

    app.fp_var.set(95.0)
    app.rssi_var.set(-42.0)
    app.fails_var.set(0)
    app.run_access_attempt()            # low risk -> unlock -> auto-unseal
    pump(root, 300)
    check("vault auto-decrypted after unlock",
          not vault.is_sealed(app.vault_dir))

    # -- 6. Audit log integrity --------------------------------------------
    print("\n[6] Audit log")
    ok, msg = audit.verify_chain()
    check("hash chain intact", ok)
    rows = audit.fetch_all()
    check(f"rows logged ({len(rows)})", len(rows) >= 6)
    check("replay flag persisted",
          any(r["token_replay"] for r in rows))
    check("lockout status persisted",
          any("lockout" in (r["status"] or "").lower() for r in rows))

    root.destroy()
    audit.close()

    print("\n" + "=" * 60)
    failed = [c for c, ok in checks if not ok]
    if failed:
        print(f" SMOKE FAILED - {len(failed)} check(s):")
        for label in failed:
            print(f"   - {label}")
        return 1
    print(" SMOKE PASSED - GUI flow fully operational.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
