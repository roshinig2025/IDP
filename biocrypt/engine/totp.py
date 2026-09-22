"""RFC 6238 TOTP with anti-replay — Bio-Crypt Lock.

Implements the standard time-based one-time password algorithm directly on
Python's stdlib (hmac/hashlib/base64) — the same algorithm used by Google
Authenticator / FreeOTP — with these project-specific properties:

  * 6-digit codes for the Medium tier, 8-digit for the High tier
    (challenge complexity scales dynamically with risk — the project's key
    innovation vs. static MFA).
  * +/- 1 time-step validation tolerance (30 s steps).
  * Single-use enforcement: a code is consumed on first successful check;
    re-presenting it is rejected as a REPLAY attack (logged by the caller).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

TIMESTEP_SECONDS = 30
VALID_WINDOWS = 1              # accept current step and +/- 1 neighbours
TOTP_ALPHABET = "0123456789"   # numeric codes (display-friendly)


def generate_secret(nbytes: int = 20) -> str:
    """Base32-encoded shared secret for the TOTP pairing."""
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii")


def _hotp(key: bytes, counter: int, digits: int) -> str:
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    bin_code = ((digest[offset] & 0x7F) << 24
                | digest[offset + 1] << 16
                | digest[offset + 2] << 8
                | digest[offset + 3])
    return str(bin_code % (10 ** digits)).zfill(digits)


def totp_at(secret_b32: str, digits: int, unix_time: float) -> str:
    """The TOTP code active at the given instant."""
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int(unix_time // TIMESTEP_SECONDS)
    return _hotp(key, counter, digits)


def current_totp(secret_b32: str, digits: int) -> str:
    return totp_at(secret_b32, digits, time.time())


def seconds_remaining(unix_time: float | None = None) -> int:
    """Seconds left in the current 30 s TOTP window (for the UI countdown)."""
    t = time.time() if unix_time is None else unix_time
    return TIMESTEP_SECONDS - int(t % TIMESTEP_SECONDS)


def verify_totp(secret_b32: str, digits: int, code: str,
                now: float | None = None,
                used_codes: set[str] | None = None) -> tuple[bool, str]:
    """Validate a candidate code.

    Returns (ok, reason) where reason is one of:
      "ok", "malformed", "invalid", "expired", "replay".
    On success the code is added to used_codes (single-use anti-replay).
    """
    if used_codes is None:
        used_codes = set()

    code = (code or "").strip()
    if len(code) != digits or not code.isdigit():
        return False, "malformed"

    t = time.time() if now is None else now
    key = base64.b32decode(secret_b32, casefold=True)

    for offset in range(-VALID_WINDOWS, VALID_WINDOWS + 1):
        counter = int(t // TIMESTEP_SECONDS) + offset
        candidate = _hotp(key, counter, digits)
        if hmac.compare_digest(candidate, code):
            if code in used_codes:
                return False, "replay"
            used_codes.add(code)
            return True, "ok"
    return False, "expired" if len(code) == digits else "invalid"
