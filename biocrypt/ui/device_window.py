"""Trusted Device window — Bio-Crypt Lock.

Simulates the user's phone (the device whose BLE proximity is measured).
When the risk engine issues an OTP challenge, the code "arrives" here over
the simulated BLE channel after a distance-dependent delay — visibly
demonstrating why proximity is part of the risk score. A Re-sync BLE
request re-delivers the SAME code almost instantly and never garbled.

The user then re-types the code in the LOCK window, modelling the flow:
    risk engine -> OTP over BLE -> trusted device -> human re-entry -> lock
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from .ble_link import BleLink

PHONE_BG = "#0b132b"
PHONE_ACCENT = "#00e5a0"
PHONE_MUTED = "#5bc0be"


class TrustedDeviceWindow:
    """Standalone Toplevel widget simulating the trusted BLE device."""

    def __init__(self, link: BleLink, master: tk.Misc | None = None):
        self.link = link
        self.root = tk.Toplevel(master) if master else tk.Tk()
        self.root.title("Bio-Crypt Lock — Trusted Device (simulated phone)")
        self.root.geometry("340x560")
        self.root.configure(bg=PHONE_BG)
        self.root.attributes("-topmost", True)

        header = tk.Label(
            self.root, text="TRUSTED DEVICE", font=("Segoe UI", 11, "bold"),
            fg=PHONE_MUTED, bg=PHONE_BG)
        header.pack(pady=(14, 0))

        self.battery = tk.Label(self.root, text="\U0001F50B 87%   \U0001F4F6 BLE",
                                fg=PHONE_MUTED, bg=PHONE_BG,
                                font=("Segoe UI", 9))
        self.battery.pack()

        self.status_lbl = tk.Label(
            self.root, text="No BLE packets", font=("Segoe UI", 10),
            fg=PHONE_MUTED, bg=PHONE_BG)
        self.status_lbl.pack(pady=(10, 4))

        # Big OTP readout card
        self.otp_card = tk.Frame(self.root, bg="#1c2541", bd=0,
                                 highlightthickness=2,
                                 highlightbackground="#1c2541")
        self.otp_card.pack(pady=10, padx=18, fill="x")
        self.otp_lbl = tk.Label(self.otp_card, text="— — — — — —",
                                font=("Consolas", 26, "bold"),
                                fg=PHONE_BG, bg="#3a506b")
        self.otp_lbl.pack(pady=16, padx=10, fill="x")

        self.meta_lbl = tk.Label(self.root, text="", font=("Segoe UI", 9),
                                 fg=PHONE_MUTED, bg=PHONE_BG, wraplength=280)
        self.meta_lbl.pack(pady=(0, 8))

        self.history = tk.Text(self.root, height=8, bg="#0b132b",
                               fg=PHONE_MUTED, relief="flat",
                               font=("Consolas", 8), state="disabled")
        self.history.pack(fill="both", expand=True, padx=14, pady=8)

        link.subscribe(self._on_packet)

    # ------------------------------------------------------------------

    def _on_packet(self, packet) -> None:
        """BLE listener callback — runs on the Timer thread, marshal to UI."""
        self.root.after(0, self._render_packet, packet)

    def _render_packet(self, packet) -> None:
        if packet.status == "garbled":
            shown = packet.delivered_code or "??????"
            self.otp_lbl.config(text=shown, fg="#ff5c7a", bg="#3a506b")
            self.status_lbl.config(
                text="\u26A0  Packet corrupted — weak BLE signal",
                fg="#ff5c7a")
            self.meta_lbl.config(
                text="Tap RE-SYNC on the lock to request re-transmission.")
        elif packet.status == "resynced":
            self.otp_lbl.config(text=packet.otp, fg=PHONE_BG,
                                bg=PHONE_ACCENT)
            self.status_lbl.config(
                text="\u21BB  Re-synced — clean retransmission (same code)",
                fg=PHONE_ACCENT)
            self.meta_lbl.config(
                text="Enter this code in the LOCK window.")
        else:
            self.otp_lbl.config(text=packet.otp, fg=PHONE_BG,
                                bg=PHONE_ACCENT)
            self.status_lbl.config(
                text="\u2713  OTP received via BLE", fg=PHONE_ACCENT)
            self.meta_lbl.config(
                text="Enter this code in the LOCK window.")

        self._append_history(packet)

    def _append_history(self, packet) -> None:
        import time as _time
        self.history.configure(state="normal")
        stamp = _time.strftime("%H:%M:%S")
        tag = ("GARBLED" if packet.status == "garbled"
               else "RESYNC" if packet.status == "resynced" else "OK")
        self.history.insert("1.0", f"[{stamp}] OTP {tag}  rssi="
                            f"{packet.rssi_dbm if hasattr(packet, 'rssi_dbm') else '?'}\n")
        self.history.configure(state="disabled")

    def run(self) -> None:
        self.root.mainloop()
