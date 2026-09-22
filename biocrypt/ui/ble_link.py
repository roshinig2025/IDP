"""Simulated BLE channel — Bio-Crypt Lock.

Models the wireless link between the trusted device (e.g. the user's phone,
whose proximity is measured via BLE RSSI) and the lock. Two properties are
simulated so the panel can *see* why RSSI is a risk signal:

  * Latency scales with distance (weaker RSSI -> slower delivery).
  * Reliability scales with distance: at weak signal the packet may be
    garbled (a character is corrupted) and need a re-sync request.

Everything runs in-process (threads only), so the demo needs no radios.
"""

from __future__ import annotations

import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

RSSI_STRONG_DBM = -50
RSSI_MODERATE_DBM = -70

GARBLE_PROB_MODERATE = 0.15
GARBLE_PROB_WEAK = 0.45

_LATENCY_BY_BAND = {          # seconds of simulated transmission delay
    "strong": (0.4, 1.2),
    "moderate": (1.5, 3.0),
    "weak": (3.5, 6.0),
}


def _band(rssi_dbm: float) -> str:
    if rssi_dbm >= RSSI_STRONG_DBM:
        return "strong"
    if rssi_dbm >= RSSI_MODERATE_DBM:
        return "moderate"
    return "weak"


def _garble(code: str, prob: float) -> str:
    """Flip one digit with probability `prob` (radio interference)."""
    if not code or random.random() >= prob:
        return code
    i = random.randrange(len(code))
    wrong = random.choice([d for d in "0123456789" if d != code[i]])
    return code[:i] + wrong + code[i + 1:]


@dataclass
class BlePacket:
    otp: str
    rssi_dbm: float = -50.0
    sent_at: float = field(default_factory=time.time)
    delivered_at: float | None = None
    delivered_code: str | None = None
    garbled: bool = False
    status: str = "in-flight"   # in-flight -> delivered | garbled


class BleLink:
    """In-process BLE channel delivering OTP packets to the trusted device."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packets: deque[BlePacket] = deque()
        self._listeners: list[Callable[[BlePacket], None]] = []
        self._last_rssi = -50.0
        self._timers: list[threading.Timer] = []

    # -- listener (device window) API --------------------------------------

    def subscribe(self, callback: Callable[[BlePacket], None]) -> None:
        with self._lock:
            self._listeners.append(callback)

    # -- transmission -------------------------------------------------------

    def send_otp(self, otp: str, rssi_dbm: float) -> BlePacket:
        """Queue the OTP for delivery; latency/garbling depend on RSSI."""
        band = _band(rssi_dbm)
        prob = {"strong": 0.0,
                "moderate": GARBLE_PROB_MODERATE,
                "weak": GARBLE_PROB_WEAK}[band]
        lo, hi = _LATENCY_BY_BAND[band]
        delay = random.uniform(lo, hi)

        packet = BlePacket(otp=otp, rssi_dbm=float(rssi_dbm))
        delivered_code = _garble(otp, prob)
        packet.garbled = delivered_code != otp
        packet.status = "garbled" if packet.garbled else "delivered"

        with self._lock:
            self._packets.append(packet)
            self._last_rssi = rssi_dbm
            listeners = list(self._listeners)

        timer = threading.Timer(
            delay, self._deliver, args=(packet, delivered_code, listeners))
        timer.daemon = True
        timer.start()
        self._timers.append(timer)
        return packet

    def _deliver(self, packet: BlePacket, code: str,
                 listeners: list[Callable[[BlePacket], None]]) -> None:
        packet.delivered_at = time.time()
        packet.delivered_code = code
        for cb in listeners:
            try:
                cb(packet)
            except Exception:
                pass

    def request_resync(self) -> None:
        """Re-transmit the most recent OTP (used after a garbled delivery)."""
        with self._lock:
            if not self._packets:
                return
            last = self._packets[-1]
            rssi = self._last_rssi
        clean = last.otp
        self.send_otp(clean, rssi)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [
                {"otp": p.otp,
                 "status": p.status,
                 "garbled": p.garbled,
                 "delivered_code": p.delivered_code}
                for p in self._packets
            ]

    def close(self) -> None:
        for t in self._timers:
            t.cancel()
