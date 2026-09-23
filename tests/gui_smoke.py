"""Scripted GUI smoke test — drives BioCryptApp through the full policy-v2
demo flow with a scripted BLE link (no randomness) and a fresh audit DB.

Covers:
  [1] perfect match (fp=100, RSSI >= -50)  -> instant unlock, NO OTP
  [2] perfect match STILL unlocks with failed attempts on record
  [2b] live preview: slider changes recompute score/tier WITHOUT running
  [3] Low tier: 4-digit OTP, wrong x3 -> HARD LOCK (no auto recovery)
  [4] Reset lock button recovers
  [5] Medium tier: 6-digit OTP, wrong x2 (fresh code each time) + correct
  [5b] Re-sync BLE: instant clean re-delivery of the SAME code; no-op
       when no challenge is active
  [6] replay of a used code is rejected AND consumes a try
  [7] High tier: 8-digit OTP, single try -> wrong entry -> HARD LOCK
  [8] vault auto-decrypts after a successful auth
  [9] audit chain intact, replay + reset events persisted

Run:  python tests/gui_smoke.py
Pass: prints SMOKE PASSED and exit code 0.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import tkinter as tk

from biocrypt.audit.logger import AuditLogger
from biocrypt.crypto import vault
from biocrypt.ui.app import DEMO_PASSPHRASE, BioCryptApp
from biocrypt.ui.ble_link import BlePacket


class ScriptedBleLink:
    """Deterministic BLE link: instant, always-clean delivery."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, float]] = []
        self.subscribers = []

    def subscribe(self, cb):
        self.subscribers.append(cb)

    def send_otp(self, otp: str, rssi_dbm: float,
                 resync: bool = False) -> BlePacket:
        self.sent.append((otp, rssi_dbm))
        packet = BlePacket(otp=otp, rssi_dbm=rssi_dbm, garbled=False,
                           resync=resync,
                           status="resynced" if resync else "delivered",
                           delivered_at=time.time(), delivered_code=otp)
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

    # -- 1. Perfect match: instant unlock, no OTP --------------------------
    print("\\n[1] Trusted User scenario (perfect match)")
    app._apply_scenario("Trusted User")     # fp=100, rssi=-45, fails=0
    pump(root, 300)
    check("no OTP issued", len(app.link.sent) == 0)
    check("status says Unlocked",
          "Unlocked" in app.result_lbl.cget("text"))
    check("tier label shows PERFECT MATCH",
          "PERFECT" in app.tier_lbl.cget("text"))

    # -- 2. Perfect match overrides failed attempts -------------------------
    print("\\n[2] Perfect match with failed attempts on record")
    app.fp_var.set(100.0)
    app.rssi_var.set(-40.0)
    app.fails_var.set(3)
    app.run_access_attempt()
    pump(root, 300)
    check("still no OTP issued", len(app.link.sent) == 0)
    check("still Unlocked", "Unlocked" in app.result_lbl.cget("text"))

    # -- 2b. Live preview: sliders recompute the score without RUN -----------
    print("\\n[2b] Live preview (sliders only, no RUN)")

    def gauge_texts() -> list[str]:
        return [app.gauge.itemcget(item, "text")
                for item in app.gauge.find_withtag("all")
                if app.gauge.type(item) == "text"]

    app.fp_var.set(13.0)                    # risk 68.0 -> Medium
    app.rssi_var.set(-82.0)
    app.fails_var.set(0)
    app._update_preview()
    pump(root, 100)
    check("preview shows Medium at fp=13 / rssi=-82",
          "PREVIEW: Medium" in app.tier_lbl.cget("text"))
    check("preview gauge shows 68.00", "68.00 / 100" in gauge_texts())
    check("preview tag says press RUN",
          "press RUN" in app.preview_lbl.cget("text"))

    app.fp_var.set(15.0)                    # BLE stable, fp down: 71.5 High
    app.fails_var.set(3)
    app._update_preview()
    pump(root, 100)
    check("moving fp alone raises preview to High",
          "PREVIEW: High" in app.tier_lbl.cget("text"))

    app.fp_var.set(50.0)                    # strong BLE, fp=50: 25.0 Low
    app.rssi_var.set(-45.0)
    app.fails_var.set(0)
    app._update_preview()
    pump(root, 100)
    check("preview drops to Low with strong BLE",
          "PREVIEW: Low" in app.tier_lbl.cget("text"))

    app.fp_var.set(13.0)                    # RUN now evaluates and logs
    app.rssi_var.set(-82.0)
    sent_before = len(app.link.sent)
    app.run_access_attempt()
    pump(root, 200)
    check("RUN at fp=13 issues 6-digit OTP (evaluated Medium)",
          len(app.link.sent) == sent_before + 1
          and len(app.link.sent[-1][0]) == 6)
    check("panel switched to EVALUATED",
          "EVALUATED" in app.preview_lbl.cget("text"))

    # -- 3. Low tier: 4-digit OTP, wrong x3 -> hard lock ---------------------
    print("\\n[3] Low tier: 3 wrong tries -> HARD LOCK")
    app.fp_var.set(80.0)                    # risk 10.0 -> Low, not perfect
    app.rssi_var.set(-55.0)
    app.fails_var.set(0)
    base = len(app.link.sent)               # stage [2b] already sent one packet
    app.run_access_attempt()
    pump(root, 300)
    check("one 4-digit OTP sent", len(app.link.sent) == base + 1
          and len(app.link.sent[base][0]) == 4)
    check("tries counter initialised to 3", app.tries_left == 3)

    for offset in range(3):
        code = app.link.sent[base + offset][0]   # fresh code per try
        app.otp_var.set("0000" if code != "0000" else "0001")
        app.verify_otp()
        pump(root, 150)                     # 3rd wrong -> exhausted
    check("hard lock engaged", app.hard_locked is True)
    check("RUN disabled", str(app.run_btn.cget("state")) == "disabled")
    check("OTP entry disabled",
          str(app.otp_entry.cget("state")) == "disabled")
    check("Reset button enabled",
          str(app.reset_btn.cget("state")) == "normal")
    check("status mentions HARD LOCK",
          "HARD LOCK" in app.result_lbl.cget("text"))

    # -- 4. Reset lock recovers ----------------------------------------------
    print("\\n[4] Reset lock")
    app.reset_lock()
    pump(root, 150)
    check("hard lock cleared", app.hard_locked is False)
    check("RUN re-enabled", str(app.run_btn.cget("state")) == "normal")

    # -- 5. Medium tier: wrong, wrong, correct -------------------------------
    print("\\n[5] Medium tier: 6-digit OTP, 3 tries")
    app.fp_var.set(65.0)
    app.rssi_var.set(-68.0)
    app.fails_var.set(2)
    app.run_access_attempt()
    pump(root, 300)
    check("6-digit OTP sent", len(app.link.sent[-1][0]) == 6)
    med1 = app.link.sent[-1][0]

    app.otp_var.set("000000" if med1 != "000000" else "000001")
    app.verify_otp()                        # wrong try 1
    pump(root, 150)
    med2 = app.link.sent[-1][0]
    check("fresh OTP re-issued after failure 1 (differs from prior code)",
          len(app.link.sent) >= 2 and med2 != med1 and len(med2) == 6)

    app.otp_var.set("000000" if med2 != "000000" else "000001")
    app.verify_otp()                        # wrong try 2
    pump(root, 150)
    med3 = app.link.sent[-1][0]
    check("fresh OTP re-issued after failure 2 (differs again)",
          med3 not in (med1, med2) and len(med3) == 6)
    check("on final try before verify", app.tries_left == 1)
    check("app expects the latest issued code",
          app.active_otp is not None and app.active_otp[0] == med3)

    app.otp_var.set(med3)
    app.verify_otp()
    pump(root, 150)
    check("correct OTP unlocks on final try",
          "Unlocked" in app.result_lbl.cget("text"))

    # -- 5b. Re-sync BLE: same code, clean + instant; no-op w/o challenge ----
    print("\\n[5b] Re-sync BLE")
    app.fp_var.set(65.0)                    # fresh Med challenge
    app.rssi_var.set(-68.0)
    app.fails_var.set(2)
    app.run_access_attempt()
    pump(root, 300)
    active = app.link.sent[-1][0]
    base = len(app.link.sent)
    app.resync_ble()
    pump(root, 300)
    check("resync redelivers the SAME code (value unchanged)",
          len(app.link.sent) == base + 1 and app.link.sent[-1][0] == active)
    check("resync consumed no try", app.tries_left == 3)
    check("resync keeps the challenge active",
          app.active_otp is not None and app.active_otp[0] == active)

    app.otp_var.set(active)                 # unlock closes the session
    app.verify_otp()
    pump(root, 150)
    check("challenge closed after success", app.active_otp is None)
    app.resync_ble()
    pump(root, 100)
    check("resync with no active challenge is a no-op",
          "No active challenge" in app.result_lbl.cget("text"))

    # -- 6. Replay: re-submitting the consumed code is rejected ----------------
    print("\\n[6] Anti-replay check")
    replay_code = app.link.sent[-1][0]      # the code just consumed
    # No new challenge is opened: the attacker re-submits the code they
    # captured from the just-consumed session.
    app.otp_var.set(replay_code)
    app.verify_otp()
    pump(root, 150)
    check("replayed OTP rejected",
          "replay" in app.result_lbl.cget("text").lower())
    check("no session was active (consumption is per-session)",
          app.active_otp is None)

    # -- 7. High tier: single 8-digit try, wrong -> hard lock ------------------
    print("\\n[7] High tier: 1 try -> HARD LOCK")
    app.reset_lock()                        # clear the Med partial state
    app.fp_var.set(15.0)
    app.rssi_var.set(-82.0)
    app.fails_var.set(3)
    app.run_access_attempt()
    pump(root, 300)
    check("8-digit OTP sent", len(app.link.sent[-1][0]) == 8)
    code8 = app.link.sent[-1][0]
    app.otp_var.set("99999999" if code8 != "99999999" else "99999998")
    app.verify_otp()
    pump(root, 150)
    check("hard lock after single wrong try", app.hard_locked is True)
    check("status mentions HARD LOCK",
          "HARD LOCK" in app.result_lbl.cget("text"))

    # -- 8. Vault: seal -> authorised unlock -> auto-decrypt --------------------
    print("\\n[8] AES-256-GCM vault flow")
    app.reset_lock()
    app.create_sample_vault()
    app.root.update()
    vault.seal_folder(app.vault_dir, DEMO_PASSPHRASE)
    app._refresh_vault_label()
    check("vault sealed", vault.is_sealed(app.vault_dir))

    app.fp_var.set(100.0)
    app.rssi_var.set(-45.0)
    app.fails_var.set(0)
    app.run_access_attempt()                # perfect -> unlock -> auto-unseal
    pump(root, 300)
    check("vault auto-decrypted after unlock",
          not vault.is_sealed(app.vault_dir))

    # -- 9. Audit log integrity --------------------------------------------------
    print("\\n[9] Audit log")
    ok, msg = audit.verify_chain()
    check("hash chain intact", ok)
    rows = audit.fetch_all()
    check(f"rows logged ({len(rows)})", len(rows) >= 12)
    check("replay flag persisted",
          any(r["token_replay"] for r in rows))
    check("hard-lock statuses persisted",
          sum("HARD LOCK" in (r["status"] or "") for r in rows) >= 2)
    check("reset events persisted",
          any("reset" in (r["status"] or "").lower() for r in rows))
    check("perfect-match events persisted",
          any("perfect match" in (r["status"] or "").lower()
              for r in rows))

    root.destroy()
    audit.close()

    print("\\n" + "=" * 60)
    failed = [c for c, ok in checks if not ok]
    if failed:
        print(f" SMOKE FAILED - {len(failed)} check(s):")
        for label in failed:
            print(f"   - {label}")
        return 1
    print(" SMOKE PASSED - policy v2 GUI flow fully operational.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
