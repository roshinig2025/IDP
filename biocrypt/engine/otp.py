"""Counter-based OTP with anti-replay — Bio-Crypt Lock.

Implements the standard event-driven one-time-password algorithm
(RFC 4226 HOTP) directly on Python's stdlib (hmac/hashlib/base64) — the
counter-based sibling of Google-Authenticator-style codes. There is NO
clock anywhere in this module: codes never rotate on their own.

Project-specific properties:

  * 4-digit codes for the Low tier, 6-digit for Medium, 8-digit for High
    (challenge complexity scales dynamically with risk — the project's
    key innovation vs. static MFA).
  * Codes change ONLY when the caller advances the counter — i.e. on a
    BLE re-sync, a wrong attempt (tries remaining), or an attempt
    timeout (tries remaining). Between those events the code is stable.
  * Verification is a constant-time comparison against the expected
    counter's code. Single-use / anti-replay enforcement lives at the
    application level (a consumed challenge session can never be
    satisfied again; re-submissions are logged as replay attempts).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct

OTP_ALPHABET = "0123456789"   # numeric codes (display-friendly)


def generate_secret(nbytes: int = 20) -> str:
    """Base32-encoded shared secret pairing the lock with its device."""
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii")


def hotp_at(secret_b32: str, counter: int, digits: int) -> str:
    """The OTP code for a given (secret, counter, digit-count).

    Standard RFC 4226: HMAC-SHA1 over the big-endian 8-byte counter,
    dynamic truncation (offset from the last nibble), 31-bit extraction,
    modulo 10^digits, zero-padded.
    """
    key = base64.b32decode(secret_b32, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(counter)),
                      hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    bin_code = ((digest[offset] & 0x7F) << 24
                | digest[offset + 1] << 16
                | digest[offset + 2] << 8
                | digest[offset + 3])
    return str(bin_code % (10 ** digits)).zfill(digits)


def current_otp(secret_b32: str, counter: int, digits: int) -> str:
    """The code currently active for `counter` (no time involvement)."""
    return hotp_at(secret_b32, counter, digits)


def next_counter(counter: int) -> int:
    """Advance the OTP counter — called on every (re)issue event."""
    return int(counter) + 1


def verify_otp(secret_b32: str, counter: int, digits: int,
               code: str) -> tuple[bool, str]:
    """Validate a candidate code against the active challenge.

    Returns (ok, reason) where reason is one of:
      "ok", "malformed", "invalid".
    A code is valid iff it has the right shape AND matches the code for
    the active counter — no time windows, no drift tolerance.
    """
    code = (code or "").strip()
    if len(code) != digits or not code.isdigit():
        return False, "malformed"

    expected = hotp_at(secret_b32, counter, digits)
    if hmac.compare_digest(expected, code):
        return True, "ok"
    return False, "invalid"
