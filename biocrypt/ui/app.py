"""Bio-Crypt Lock — main GUI application (Lock console).

Single-window Lock dashboard:
  * Module 1 (left):  input parameter simulator (fingerprint match slider,
    BLE RSSI slider, attempt-history stepper).
  * Module 2 (right): live risk gauge + 3-tier routing decision.
  * Bottom:           vault (AES-256-GCM seal/unseal) + audit log viewer.

Challenge policy (v2):
  * Perfect match (fp = 100% AND RSSI >= -50 dBm): no OTP, instant unlock.
  * Low:  4-digit OTP, 3 tries, no timeout.
  * Med:  6-digit OTP, 3 tries, 90 s per try.
  * High: 8-digit OTP, 1 try, 60 s timeout.
  * Exhausted tries (wrong entry / expiry / replay) on ANY tier -> HARD
    LOCK: RUN and OTP entry stay disabled until "Reset lock" or restart.

On OTP tiers the challenge is delivered over the simulated BLE link to the
Trusted Device window; the user re-enters it here (the LOCK).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..audit.logger import AuditLogger, AuditRecord
from ..crypto import vault
from ..engine import totp
from ..engine.risk_engine import compute_risk
from ..engine.tiers import (TIER_HIGH, TIER_LOW, TIER_MED, is_perfect_match,
                            route_tier)
from .ble_link import BleLink
from .device_window import TrustedDeviceWindow

# ---- palette ----------------------------------------------------------
BG = "#0b132b"
PANEL = "#1c2541"
ACCENT = "#00e5a0"
WARN = "#ffc857"
DANGER = "#ff5c7a"
TEXT = "#e6f1ff"
MUTED = "#5bc0be"

TIER_COLORS = {TIER_LOW: ACCENT, TIER_MED: WARN, TIER_HIGH: DANGER}

# Demo scenarios (retuned for policy v2):
#   Trusted User  -> PERFECT match (fp=100, rssi=-45) -> instant unlock
#   Moderate Risk -> risk 32.50 -> Med (6-digit OTP)
#   Spoof         -> risk 71.50 -> High (8-digit OTP, 1 try)
SCENARIOS = {
    "Trusted User": dict(fp=100, rssi=-45, fails=0),
    "Moderate Risk": dict(fp=65, rssi=-68, fails=2),
    "Spoof / Anomaly": dict(fp=15, rssi=-82, fails=3),
}

VAULT_DIRNAME = "secure_vault"
DEMO_PASSPHRASE = "biocrypt-demo"   # fixed demo key (shown on the UI)


class BioCryptApp:
    def __init__(self, root: tk.Tk,
                 audit: AuditLogger | None = None,
                 link: BleLink | None = None) -> None:
        self.root = root
        self.audit = audit or AuditLogger()
        self.link = link or BleLink()
        self.device = TrustedDeviceWindow(self.link, master=root)

        self.totp_secret = totp.generate_secret()

        self.active_otp: tuple[str, int] | None = None   # (code, digits)
        self._pending: tuple | None = None               # (risk, decision)
        self.tries_left = 0
        self.try_deadline = 0.0                          # 0 = no timeout
        self.hard_locked = False
        self.vault_dir: str | None = None

        self._build_ui()
        self._position_device_window()
        self._tick()

    # ==================================================================
    # UI construction
    # ==================================================================
    def _build_ui(self) -> None:
        self.root.title("Bio-Crypt Lock — Risk-Adaptive Access Console")
        self.root.geometry("960x700")
        self.root.configure(bg=BG)
        self.root.minsize(900, 640)

        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=16, pady=(12, 6))
        tk.Label(header, text="BIO-CRYPT LOCK",
                 font=("Segoe UI", 16, "bold"), fg=ACCENT, bg=BG).pack(
            side="left")
        tk.Label(header,
                 text="Risk-Adaptive Multi-Factor Bio-Crypt Lock"
                      "  ·  Software Simulation Prototype",
                 font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(side="left",
                                                             padx=12)
        self.chain_lbl = tk.Label(header, text="", font=("Segoe UI", 8),
                                  fg=MUTED, bg=BG)
        self.chain_lbl.pack(side="right")
        self._refresh_chain_label()

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=6)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        body.columnconfigure(0, weight=1, uniform="cols")
        body.columnconfigure(1, weight=1, uniform="cols")
        self._build_input_panel(body).grid(row=0, column=0, sticky="nsew",
                                           padx=(0, 8))
        self._build_engine_panel(body).grid(row=0, column=1, sticky="nsew",
                                            padx=(8, 0))

        self._build_bottom_bar()

    # ---------------- Module 1: inputs -------------------------------
    def _build_input_panel(self, parent: tk.Misc) -> tk.Frame:
        panel = tk.Frame(parent, bg=PANEL, padx=14, pady=12)
        tk.Label(panel, text="MODULE 1 · INPUT PARAMETER SIMULATOR",
                 font=("Segoe UI", 10, "bold"), fg=TEXT, bg=PANEL).pack(
            anchor="w")

        # Fingerprint slider
        tk.Label(panel, text="Fingerprint optical match score (%)",
                 font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(
            anchor="w", pady=(12, 0))
        self.fp_var = tk.DoubleVar(value=100.0)
        fp_scale = ttk.Scale(panel, from_=0, to=100, variable=self.fp_var,
                             command=lambda *_: self._refresh_fp_label())
        fp_scale.pack(fill="x")
        self.fp_val_lbl = tk.Label(panel, text="100 %", font=("Consolas", 11,
                                                              "bold"),
                                   fg=TEXT, bg=PANEL)
        self.fp_val_lbl.pack(anchor="e")

        # RSSI slider
        tk.Label(panel, text="BLE RSSI signal strength (dBm)",
                 font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(
            anchor="w", pady=(10, 0))
        self.rssi_var = tk.DoubleVar(value=-45.0)
        rssi_scale = ttk.Scale(panel, from_=-90, to=-30, variable=self.rssi_var,
                               command=lambda *_: self._refresh_rssi_label())
        rssi_scale.pack(fill="x")
        self.rssi_val_lbl = tk.Label(panel, text="-45 dBm",
                                     font=("Consolas", 11, "bold"),
                                     fg=TEXT, bg=PANEL)
        self.rssi_val_lbl.pack(anchor="e")
        self.rssi_hint_lbl = tk.Label(panel, text="", font=("Segoe UI", 8),
                                      fg=MUTED, bg=PANEL)
        self.rssi_hint_lbl.pack(anchor="e")

        # Attempt history
        hist = tk.Frame(panel, bg=PANEL)
        hist.pack(fill="x", pady=(10, 0))
        tk.Label(hist, text="Attempt history (failed attempts)",
                 font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(side="left")
        self.fails_var = tk.IntVar(value=0)
        spin = tk.Spinbox(hist, from_=0, to=5, width=4, state="readonly",
                          textvariable=self.fails_var,
                          font=("Consolas", 10), bg="#0b132b", fg=TEXT,
                          buttonbackground=PANEL, relief="flat")
        spin.pack(side="right")
        tk.Button(hist, text="Inject failed attempt", font=("Segoe UI", 8),
                  bg="#3a506b", fg=TEXT, relief="flat",
                  command=self._inject_failure).pack(side="right", padx=6)

        # Scenario presets
        tk.Label(panel, text="Demo scenarios (one-click)",
                 font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(
            anchor="w", pady=(14, 2))
        row = tk.Frame(panel, bg=PANEL)
        row.pack(fill="x")
        for i, name in enumerate(SCENARIOS):
            tk.Button(row, text=name, font=("Segoe UI", 8), relief="flat",
                      bg="#3a506b", fg=TEXT, wraplength=90,
                      command=lambda n=name: self._apply_scenario(n)
                      ).grid(row=0, column=i, padx=2, sticky="nsew")
            row.columnconfigure(i, weight=1)

        # Run / Reset buttons
        self.run_btn = tk.Button(
            panel, text="▶  RUN ACCESS ATTEMPT",
            font=("Segoe UI", 12, "bold"), relief="flat",
            bg=ACCENT, fg=BG, activebackground="#00c98c", activeforeground=BG,
            command=self.run_access_attempt)
        self.run_btn.pack(fill="x", pady=(16, 2), ipady=6)

        self.reset_btn = tk.Button(
            panel, text="⟳  RESET LOCK (unlock console after hard lock)",
            font=("Segoe UI", 9, "bold"), relief="flat",
            bg="#3a506b", fg=TEXT, activebackground="#4a607d",
            activeforeground=TEXT, state="disabled",
            command=self.reset_lock)
        self.reset_btn.pack(fill="x", pady=(2, 2), ipady=3)

        self.lockout_lbl = tk.Label(panel, text="", font=("Segoe UI", 9,
                                                          "bold"),
                                    fg=DANGER, bg=PANEL)
        self.lockout_lbl.pack(anchor="w")
        return panel

    # ---------------- Module 2: engine output ------------------------
    def _build_engine_panel(self, parent: tk.Misc) -> tk.Frame:
        panel = tk.Frame(parent, bg=PANEL, padx=14, pady=12)
        tk.Label(panel, text="MODULE 2 · CONTEXT FUSION & RISK ENGINE",
                 font=("Segoe UI", 10, "bold"), fg=TEXT, bg=PANEL).pack(
            anchor="w")

        self.gauge = tk.Canvas(panel, width=380, height=110, bg=PANEL,
                               highlightthickness=0)
        self.gauge.pack(fill="x", pady=(8, 0))
        self._draw_gauge(0, MUTED)

        self.breakdown_lbl = tk.Label(
            panel, text="biometric —   ·  proximity —   ·  history —",
            font=("Consolas", 9), fg=MUTED, bg=PANEL)
        self.breakdown_lbl.pack(anchor="w", pady=(4, 8))

        self.tier_lbl = tk.Label(panel, text="TIER: —",
                                 font=("Segoe UI", 12, "bold"), fg=MUTED,
                                 bg=PANEL)
        self.tier_lbl.pack(anchor="w")
        self.action_lbl = tk.Label(panel, text="Run an access attempt…",
                                   font=("Segoe UI", 9), fg=TEXT, bg=PANEL,
                                   wraplength=380, justify="left")
        self.action_lbl.pack(anchor="w", pady=(2, 8))

        # OTP challenge area
        self.challenge = tk.Frame(panel, bg=PANEL)
        self.challenge.pack(fill="x", pady=(4, 0))
        tk.Label(self.challenge, text="TOTP challenge (re-type the code from"
                 " the Trusted Device):", font=("Segoe UI", 9), fg=MUTED,
                 bg=PANEL).pack(anchor="w")
        entry_row = tk.Frame(self.challenge, bg=PANEL)
        entry_row.pack(fill="x", pady=4)
        self.otp_var = tk.StringVar()
        self.otp_entry = tk.Entry(entry_row, textvariable=self.otp_var,
                                  font=("Consolas", 14, "bold"),
                                  bg="#0b132b", fg=TEXT, insertbackground=TEXT,
                                  relief="flat", width=12, justify="center",
                                  state="disabled")
        self.otp_entry.pack(side="left", ipady=5)
        self.verify_btn = tk.Button(entry_row, text="Verify OTP",
                                    font=("Segoe UI", 9, "bold"),
                                    relief="flat", bg="#3a506b", fg=TEXT,
                                    state="disabled",
                                    command=self.verify_otp)
        self.verify_btn.pack(side="left", padx=6, ipady=3)
        self.resync_btn = tk.Button(entry_row, text="Re-sync BLE",
                                    font=("Segoe UI", 8), relief="flat",
                                    bg="#3a506b", fg=MUTED,
                                    command=self.link.request_resync)
        self.resync_btn.pack(side="left", padx=2)
        self.otp_countdown_lbl = tk.Label(self.challenge, text="",
                                          font=("Segoe UI", 8), fg=MUTED,
                                          bg=PANEL)
        self.otp_countdown_lbl.pack(anchor="w")

        self.result_lbl = tk.Label(panel, text="", font=("Segoe UI", 11,
                                                         "bold"),
                                   fg=TEXT, bg=PANEL, wraplength=380,
                                   justify="left")
        self.result_lbl.pack(anchor="w", pady=(10, 0))
        return panel

    # ---------------- Bottom: vault + audit ---------------------------
    def _build_bottom_bar(self) -> None:
        bar = tk.Frame(self.root, bg=PANEL, padx=14, pady=10)
        bar.pack(fill="x", padx=16, pady=(6, 12))

        vault_grp = tk.Frame(bar, bg=PANEL)
        vault_grp.pack(side="left", fill="x", expand=True)
        tk.Label(vault_grp,
                 text=f"MODULE 3 · AES-256-GCM VAULT"
                      f"   (passphrase: {DEMO_PASSPHRASE})",
                 font=("Segoe UI", 9, "bold"), fg=TEXT, bg=PANEL).pack(
            anchor="w")
        self.vault_lbl = tk.Label(vault_grp, text="No vault selected",
                                  font=("Segoe UI", 8), fg=MUTED, bg=PANEL)
        self.vault_lbl.pack(anchor="w")
        btns = tk.Frame(vault_grp, bg=PANEL)
        btns.pack(anchor="w", pady=3)
        for text, cmd in (
                ("Create sample vault", self.create_sample_vault),
                ("Seal folder…", self.seal_folder_dialog),
                ("Unseal vault", self.unseal_vault),
                ("Open folder", self.open_vault_folder)):
            tk.Button(btns, text=text, font=("Segoe UI", 8), relief="flat",
                      bg="#3a506b", fg=TEXT, command=cmd).pack(side="left",
                                                               padx=2)

        audit_grp = tk.Frame(bar, bg=PANEL)
        audit_grp.pack(side="right", anchor="n")
        tk.Label(audit_grp, text="MODULE 4 · ANTI-REPLAY AUDIT LOGGER",
                 font=("Segoe UI", 9, "bold"), fg=TEXT, bg=PANEL).pack(
            anchor="w")
        btns2 = tk.Frame(audit_grp, bg=PANEL)
        btns2.pack(anchor="w", pady=3)
        for text, cmd in (
                ("View audit log", self.view_audit),
                ("Export CSV", self.export_csv),
                ("Verify hash chain", self.verify_chain)):
            tk.Button(btns2, text=text, font=("Segoe UI", 8), relief="flat",
                      bg="#3a506b", fg=TEXT, command=cmd).pack(side="left",
                                                               padx=2)

    # ==================================================================
    # Helpers: labels, gauge, scenarios
    # ==================================================================
    def _refresh_fp_label(self) -> None:
        self.fp_val_lbl.config(text=f"{int(round(self.fp_var.get()))} %")

    def _refresh_rssi_label(self) -> None:
        v = int(self.rssi_var.get())
        self.rssi_val_lbl.config(text=f"{v} dBm")
        if v >= -50:
            hint = "strong — adjacent / trusted"
        elif v >= -70:
            hint = "moderate — same room"
        else:
            hint = "weak — far / relay-attack range"
        self.rssi_hint_lbl.config(text=hint)

    def _inject_failure(self) -> None:
        self.fails_var.set(min(5, self.fails_var.get() + 1))

    def _apply_scenario(self, name: str) -> None:
        s = SCENARIOS[name]
        self.fp_var.set(float(s["fp"]))
        self.rssi_var.set(float(s["rssi"]))
        self.fails_var.set(s["fails"])
        self._refresh_fp_label()
        self._refresh_rssi_label()
        self.run_access_attempt()

    def _draw_gauge(self, score: float, color: str) -> None:
        c = self.gauge
        c.delete("all")
        w = int(c.winfo_width() or 380)
        bar_h, x0, y0 = 34, 4, 8
        c.create_rectangle(x0, y0, w - x0, y0 + bar_h, fill="#0b132b",
                           width=0)
        frac = max(0.0, min(100.0, score)) / 100.0
        if frac > 0:
            c.create_rectangle(x0, y0, x0 + int((w - 2 * x0) * frac),
                               y0 + bar_h, fill=color, width=0)
        c.create_text(w // 2, y0 + bar_h + 30,
                      text=f"{score:.2f} / 100",
                      font=("Consolas", 22, "bold"), fill=TEXT)
        c.create_text(w // 2, y0 + bar_h + 52, text="DYNAMIC RISK SCORE",
                      font=("Segoe UI", 7), fill=MUTED)

    def _position_device_window(self) -> None:
        try:
            x = self.root.winfo_x() + self.root.winfo_width() + 12
            y = self.root.winfo_y() + 40
            self.device.root.geometry(f"+{x}+{y}")
        except Exception:
            pass

    def _tick(self) -> None:
        """1 Hz housekeeping: TOTP-window countdown + per-try deadline."""
        now = time.time()
        if self.active_otp:
            secs = totp.seconds_remaining(now)
            self.otp_countdown_lbl.config(
                text=self._challenge_status(secs))
        if (self.active_otp and self.try_deadline
                and now > self.try_deadline):
            self._handle_try_expiry()
        self.root.after(1000, self._tick)

    def _challenge_status(self, totp_secs: int) -> str:
        """Countdown text: per-try deadline (Med/High) + 30 s TOTP window."""
        parts = []
        if self.try_deadline:
            left = max(0, int(self.try_deadline - time.time()))
            parts.append(f"try expires in {left}s")
        parts.append(f"code rotates in {totp_secs}s (30 s TOTP window)")
        return " · ".join(parts)

    # ==================================================================
    # Core flow: access attempt
    # ==================================================================
    def run_access_attempt(self) -> None:
        fp = float(self.fp_var.get())
        rssi = float(self.rssi_var.get())
        fails = int(self.fails_var.get())

        # Clear any previous challenge state before evaluating.
        self.active_otp = None
        self.try_deadline = 0.0
        self.otp_entry.config(state="disabled")
        self.verify_btn.config(state="disabled")
        self.otp_var.set("")
        self.otp_countdown_lbl.config(text="")

        if self.hard_locked:
            self._log_attempt(status="Blocked — hard lock, reset required",
                              otp_entered="")
            messagebox.showwarning(
                "Hard lock active",
                "Tries exhausted. Click 'Reset lock' to try again.")
            return

        risk = compute_risk(fp, rssi, fails)
        perfect = is_perfect_match(fp, rssi)
        if perfect:
            # Bypasses the tier decision entirely — the spec's override rule.
            self._draw_gauge(risk.total_risk, ACCENT)
            self.breakdown_lbl.config(
                text=f"biometric {risk.components['biometric']:>5.2f}  ·  "
                     f"proximity {risk.components['proximity']:>5.2f}  ·  "
                     f"history {risk.components['history']:>5.2f}")
            self.tier_lbl.config(text="TIER: PERFECT MATCH", fg=ACCENT)
            self.action_lbl.config(
                text="Fingerprint and BLE both perfect — "
                     "no OTP required, instant unlock.")
            self._finish_attempt(risk, None, otp_entered="", otp_valid=True,
                                 otp_reason="not-required",
                                 status="Unlocked — perfect match, no OTP")
            return

        decision = route_tier(risk.total_risk)

        self._draw_gauge(risk.total_risk, TIER_COLORS[decision.tier])
        self.breakdown_lbl.config(
            text=f"biometric {risk.components['biometric']:>5.2f}  ·  "
                 f"proximity {risk.components['proximity']:>5.2f}  ·  "
                 f"history {risk.components['history']:>5.2f}")
        self.tier_lbl.config(text=f"TIER: {decision.tier}",
                             fg=TIER_COLORS[decision.tier])
        self.action_lbl.config(text=decision.action)
        self.result_lbl.config(text="", fg=TEXT)

        self.tries_left = decision.otp_tries
        self.try_deadline = (time.time() + decision.otp_timeout_s
                             if decision.otp_timeout_s > 0 else 0.0)

        self._issue_otp(decision, risk)
        self._pending = (risk, decision)

    # ------------------------------------------------------------------
    def _issue_otp(self, decision, risk) -> None:
        """Fresh code over BLE; consumes nothing — used on issue and retry."""
        code = totp.current_totp(self.totp_secret, decision.otp_digits)
        self.active_otp = (code, decision.otp_digits)
        self.link.send_otp(code, float(self.rssi_var.get()))

        self.otp_entry.config(state="normal")
        self.otp_entry.delete(0, "end")
        self.otp_entry.focus_set()
        self.verify_btn.config(state="normal")
        self.otp_countdown_lbl.config(text=self._challenge_status(
            totp.seconds_remaining()))

    def _challenge_label(self, decision) -> str:
        timeout = (f", {decision.otp_timeout_s}s per try"
                   if decision.otp_timeout_s else ", no timeout")
        return (f"{decision.otp_digits}-digit OTP · "
                f"{self.tries_left}/{decision.otp_tries} tries left"
                f"{timeout}")

    def verify_otp(self) -> None:
        code = self.otp_var.get().strip()

        # No open challenge: any submitted code is a replay/reuse attempt.
        if not self.active_otp or not self._pending:
            if code:
                self._log_attempt(otp_entered=code, otp_valid=False,
                                  otp_reason="replay", token_replay=True,
                                  status="Blocked — no active challenge; "
                                         "code re-submission flagged (replay)")
                self.result_lbl.config(
                    text="✖ Code rejected — no active challenge "
                         "(replay attempt logged)", fg=DANGER)
            return

        risk, decision = self._pending
        digits = decision.otp_digits

        # Cryptographic validity (shape + 30 s window ±1).
        crypto_ok, crypto_reason = totp.verify_totp(
            self.totp_secret, digits, code)

        if crypto_ok and code == self.active_otp[0]:
            # Success closes the challenge session: the code is consumed —
            # it can never satisfy another verification.
            self.active_otp = None
            self._pending = None
            self.tries_left = 0
            self.try_deadline = 0.0
            self.verify_btn.config(state="normal")   # re-submit -> replay log
            self.otp_var.set("")
            self.otp_countdown_lbl.config(text="")
            # Entry stays enabled so a re-submission is visibly logged
            # as a replay attempt (the panel-ready anti-replay demo).
            self._finish_attempt(
                risk, decision, otp_entered=code, otp_valid=True,
                otp_reason="ok",
                status=f"Unlocked — {digits}-digit OTP verified")
            return

        # Valid TOTP value but not THIS challenge's code -> replay.
        reason = "replay" if crypto_ok else crypto_reason
        replay = (reason == "replay")

        # Any failure (wrong / expired / replay) consumes one try.
        self.tries_left -= 1
        if self.tries_left <= 0:
            self._hard_lock()
            self._finish_attempt(
                risk, decision, otp_entered=code, otp_valid=False,
                otp_reason=reason, token_replay=replay, otp_issued=True,
                status=f"Access denied — {reason} · tries exhausted"
                       f" → HARD LOCK (reset required)")
            return

        # Tries remain: fresh code for the next attempt.
        self._issue_otp(decision, risk)
        self._finish_attempt(
            risk, decision, otp_entered=code, otp_valid=False,
            otp_reason=reason, token_replay=replay, otp_issued=True,
            status=f"Access denied — {reason} · "
                   f"try {decision.otp_tries - self.tries_left}"
                   f"/{decision.otp_tries} failed, fresh OTP issued")

    def _handle_try_expiry(self) -> None:
        """Per-try timeout (Med/High only): consume a try, re-issue or lock."""
        if not self.active_otp or not self._pending:
            return
        risk, decision = self._pending
        self.active_otp = None
        self.otp_entry.config(state="disabled")
        self.verify_btn.config(state="disabled")
        self.otp_var.set("")

        self.tries_left -= 1
        if self.tries_left <= 0:
            self._hard_lock()
            self._log_attempt(
                risk=risk, decision=decision, otp_issued=True,
                otp_digits=decision.otp_digits, otp_entered="",
                otp_valid=False, otp_reason="timeout",
                status="Access denied — timeout · tries exhausted"
                       " → HARD LOCK (reset required)")
            self.result_lbl.config(
                text="✖ Try timed out — tries exhausted → HARD LOCK",
                fg=DANGER)
            return

        self.try_deadline = (time.time() + decision.otp_timeout_s
                             if decision.otp_timeout_s > 0 else 0.0)
        self._issue_otp(decision, risk)
        self._log_attempt(
            risk=risk, decision=decision, otp_issued=True,
            otp_digits=decision.otp_digits, otp_entered="",
            otp_valid=False, otp_reason="timeout",
            status=f"Try timed out — fresh OTP issued "
                   f"(try {decision.otp_tries - self.tries_left}"
                   f"/{decision.otp_tries})")
        self.result_lbl.config(
            text=f"⏳ Try timed out — {self.tries_left} "
             f"try/tries left, fresh OTP sent to device", fg=WARN)

    def _hard_lock(self) -> None:
        """Uniform exhaustion policy: disable everything until reset."""
        self.hard_locked = True
        self.active_otp = None
        self.try_deadline = 0.0
        self.otp_entry.config(state="disabled")
        self.verify_btn.config(state="disabled")
        self.otp_var.set("")
        self.otp_countdown_lbl.config(text="")
        self.run_btn.config(state="disabled")
        self.reset_btn.config(state="normal")

    def reset_lock(self) -> None:
        """Manual reset — the ONLY way out of a hard lock (besides restart)."""
        if not self.hard_locked:
            return
        self.hard_locked = False
        self.tries_left = 0
        self.try_deadline = 0.0
        self._pending = None
        self.run_btn.config(state="normal")
        self.reset_btn.config(state="disabled")
        self.lockout_lbl.config(text="")
        self.result_lbl.config(text="Lock reset — new attempt required",
                               fg=WARN)
        self._log_attempt(status="Lock reset (manual) — new attempt required",
                          otp_entered="")

    # ------------------------------------------------------------------
    def _finish_attempt(self, risk, decision, *, otp_entered: str,
                        otp_valid: bool, otp_reason: str,
                        status: str, token_replay: bool = False,
                        otp_issued: bool | None = None) -> None:
        if otp_issued is None:
            otp_issued = bool(self.active_otp)
        self._log_attempt(
            risk=risk, decision=decision, otp_issued=otp_issued,
            otp_digits=getattr(decision, "otp_digits", 0)
            if decision and getattr(decision, "requires_otp", False) else 0,
            otp_entered=otp_entered, otp_valid=otp_valid,
            otp_reason=otp_reason, token_replay=token_replay,
            status=status)

        color = ACCENT if status.startswith("Unlocked") else DANGER
        extra = ""
        if status.startswith("Unlocked") and self.vault_dir:
            extra = self._try_auto_unseal()
        self.result_lbl.config(text=("✔ " if status.startswith("Unlocked")
                                     else "✖ ") + status + extra, fg=color)

    def _log_attempt(self, *, risk=None, decision=None,
                     otp_issued: bool = False, otp_digits: int = 0,
                     otp_entered: str = "", otp_valid: bool = False,
                     otp_reason: str = "", token_replay: bool = False,
                     status: str = "") -> int:
        rec = AuditRecord(
            fp_score=float(self.fp_var.get()),
            rssi_dbm=float(self.rssi_var.get()),
            failed_attempts=int(self.fails_var.get()),
            biometric_risk=getattr(risk, "biometric_risk", 0.0),
            proximity_risk=getattr(risk, "proximity_risk", 0.0),
            history_risk=getattr(risk, "history_risk", 0.0),
            risk_score=getattr(risk, "total_risk", 0.0),
            tier=(getattr(decision, "tier", None)
                  or getattr(risk, "tier", "n/a")),
            otp_issued=otp_issued,
            otp_digits=otp_digits,
            otp_entered=otp_entered,
            otp_valid=otp_valid,
            otp_reason=otp_reason,
            token_replay=token_replay,
            status=status,
            details=json.dumps(getattr(risk, "components", {}),
                               sort_keys=True))
        row_id = self.audit.log(rec)
        self._refresh_chain_label()
        return row_id

    def _refresh_chain_label(self) -> None:
        n = len(self.audit.fetch_all())
        self.chain_lbl.config(
            text=f"audit: {n} events · hash-chain: verified on write")

    # ==================================================================
    # Module 3: vault
    # ==================================================================
    def create_sample_vault(self) -> None:
        path = os.path.join(os.getcwd(), VAULT_DIRNAME)
        os.makedirs(path, exist_ok=True)
        samples = {
            "project_report.txt": "Bio-Crypt Lock — Review II draft.\n"
                                  "Risk engine verified at 0.50/0.35/0.15"
                                  " weights.\n",
            "team_marks.xlsx.note": "Individual contribution matrix"
                                    " (dummy placeholder).\n",
        }
        for name, content in samples.items():
            with open(os.path.join(path, name), "w", encoding="utf-8") as fh:
                fh.write(content)
        self.vault_dir = path
        self._refresh_vault_label()
        self.open_vault_folder()

    def _refresh_vault_label(self) -> None:
        if not self.vault_dir:
            self.vault_lbl.config(text="No vault selected")
            return
        state = "SEALED 🔒" if vault.is_sealed(self.vault_dir) else "OPEN 🔓"
        self.vault_lbl.config(text=f"{self.vault_dir}  —  {state}")

    def seal_folder_dialog(self) -> None:
        if not self.vault_dir:
            chosen = filedialog.askdirectory(title="Choose folder to seal")
            if not chosen:
                return
            self.vault_dir = chosen
        if vault.is_sealed(self.vault_dir):
            messagebox.showinfo("Already sealed",
                                "This folder is already sealed.")
            return
        try:
            result = vault.seal_folder(self.vault_dir, DEMO_PASSPHRASE)
        except vault.VaultError as exc:
            messagebox.showerror("Seal failed", str(exc))
            return
        self._refresh_vault_label()
        self.result_lbl.config(
            text=f"🔒 Sealed {len(result.sealed_paths)} file(s) with"
                 f" AES-256-GCM", fg=WARN)

    def unseal_vault(self) -> None:
        if not self.vault_dir:
            messagebox.showinfo("No vault", "Create or select a vault first.")
            return
        try:
            result = vault.unseal_folder(self.vault_dir, DEMO_PASSPHRASE)
        except vault.VaultError as exc:
            messagebox.showerror("Unseal failed", str(exc))
            return
        self._refresh_vault_label()
        self.result_lbl.config(
            text=f"🔓 Restored {len(result.restored_paths)} file(s)",
            fg=ACCENT)

    def _try_auto_unseal(self) -> str:
        """On successful auth, decrypt the sealed vault automatically."""
        if not self.vault_dir or not vault.is_sealed(self.vault_dir):
            return ""
        try:
            result = vault.unseal_folder(self.vault_dir, DEMO_PASSPHRASE)
        except vault.VaultError as exc:
            return f"  (vault unseal failed: {exc})"
        self._refresh_vault_label()
        return f"  · vault decrypted ({len(result.restored_paths)} files)"

    def open_vault_folder(self) -> None:
        if not self.vault_dir or not os.path.isdir(self.vault_dir):
            return
        if sys.platform.startswith("win"):
            os.startfile(self.vault_dir)            # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", self.vault_dir])
        else:
            subprocess.Popen(["xdg-open", self.vault_dir])

    # ==================================================================
    # Module 4: audit
    # ==================================================================
    def view_audit(self) -> None:
        rows = self.audit.fetch_all()
        win = tk.Toplevel(self.root)
        win.title("Audit log — biocrypt_audit.db")
        win.geometry("1100x420")
        win.configure(bg=BG)

        cols = ("id", "timestamp", "fp", "rssi", "fails", "risk", "tier",
                "otp_issued", "otp_entered", "valid", "reason", "replay",
                "status")
        headers = ("#", "timestamp", "fp%", "rssi", "fails", "risk",
                   "tier", "otp?", "otp entered", "valid", "reason",
                   "replay", "status")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for col, head in zip(cols, headers):
            tree.heading(col, text=head)
            tree.column(col, width=90 if col != "status" else 220,
                        anchor="w")
        for r in rows:
            tree.insert("", "end", values=(
                r["id"], r["timestamp"], r["fp_score"], r["rssi_dbm"],
                r["failed_attempts"], r["risk_score"], r["tier"],
                "yes" if r["otp_issued"] else "no", r["otp_entered"] or "—",
                "yes" if r["otp_valid"] else "no", r["otp_reason"] or "—",
                "⚠" if r["token_replay"] else "—", r["status"]))
        tree.pack(fill="both", expand=True, padx=8, pady=8)

    def export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile="biocrypt_audit.csv",
            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        n = self.audit.export_csv(path)
        messagebox.showinfo("Export complete", f"{n} rows written to\\n{path}")

    def verify_chain(self) -> None:
        ok, msg = self.audit.verify_chain()
        messagebox.showinfo("Hash-chain verification",
                            ("✔ " if ok else "✖ ") + msg)

    # ------------------------------------------------------------------
    def on_close(self) -> None:
        self.link.close()
        self.audit.close()
        self.root.destroy()


def run() -> None:
    root = tk.Tk()
    app = BioCryptApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
