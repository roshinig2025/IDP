"""3-Tier Risk-Adaptive Authentication Router — Bio-Crypt Lock.

Policy (v2 — "hard lock on exhaustion"):

    Perfect match : fingerprint = 100%  AND  RSSI >= -50 dBm
                    -> no OTP, instant unlock (even with failed attempts
                       on record).

    Low  (risk <= 30):  4-digit OTP, 3 tries, no per-try timeout.
    Med  (31..70):      6-digit OTP, 3 tries, 90 s timeout per try.
    High (71..100):     8-digit OTP, 1 try,  60 s timeout.

Exhaustion (all tiers): running out of tries — by wrong entries, expired
timeouts, or replays — HARD-LOCKS the lock. No automatic recovery: the
user must trigger an explicit reset (Reset lock button / app restart).
Every event, including resets, is audit-logged.
"""

from __future__ import annotations

from dataclasses import dataclass

from .risk_engine import TIER_LOW_MAX, TIER_MED_MAX

TIER_LOW = "Low Risk (0-30)"
TIER_MED = "Medium Risk (31-70)"
TIER_HIGH = "High Risk (71-100)"

# ---- perfect-match instant unlock ----------------------------------------
PERFECT_FP = 100.0         # required fingerprint match (%)
PERFECT_RSSI_DBM = -50.0   # required BLE RSSI (>= this value = adjacent)

# ---- per-tier OTP challenge policy ---------------------------------------
OTP_LOW_DIGITS = 4
OTP_LOW_TRIES = 3
OTP_LOW_TIMEOUT_S = 0      # 0 = no per-try timeout

OTP_MED_DIGITS = 6
OTP_MED_TRIES = 3
OTP_MED_TIMEOUT_S = 90     # per-try timeout; expiry consumes one try

OTP_HIGH_DIGITS = 8
OTP_HIGH_TRIES = 1
OTP_HIGH_TIMEOUT_S = 60

# Old timed-lockout behaviour is replaced by the uniform hard lock;
# the constant is kept (as 0) only so older imports keep working.
LOCKOUT_SECONDS = 0


@dataclass(frozen=True)
class TierDecision:
    tier: str
    requires_otp: bool
    otp_digits: int
    otp_tries: int
    otp_timeout_s: int        # 0 = no per-try timeout
    hard_lock_on_exhaust: bool
    action: str
    status: str


def is_perfect_match(fp_match_score: float, rssi_dbm: float) -> bool:
    """True when BOTH signals are perfect: fp = 100% AND RSSI >= -50 dBm.

    Deliberately ignores attempt history — perfect signals always unlock,
    per the approved spec.
    """
    return (float(fp_match_score) >= PERFECT_FP
            and float(rssi_dbm) >= PERFECT_RSSI_DBM)


def classify_tier(risk_score: float) -> str:
    """Map a risk score to its tier label (boundaries: 30 and 70)."""
    if risk_score <= TIER_LOW_MAX:
        return TIER_LOW
    if risk_score <= TIER_MED_MAX:
        return TIER_MED
    return TIER_HIGH


def route_tier(risk_score: float) -> TierDecision:
    """Produce the full access-policy decision for a risk score."""
    tier = classify_tier(risk_score)

    if tier == TIER_LOW:
        return TierDecision(
            tier=tier,
            requires_otp=True,
            otp_digits=OTP_LOW_DIGITS,
            otp_tries=OTP_LOW_TRIES,
            otp_timeout_s=OTP_LOW_TIMEOUT_S,
            hard_lock_on_exhaust=True,
            action=f"Low-risk protocol: {OTP_LOW_DIGITS}-digit OTP, "
                   f"{OTP_LOW_TRIES} tries, no timeout",
            status="Pending OTP verification",
        )
    if tier == TIER_MED:
        return TierDecision(
            tier=tier,
            requires_otp=True,
            otp_digits=OTP_MED_DIGITS,
            otp_tries=OTP_MED_TRIES,
            otp_timeout_s=OTP_MED_TIMEOUT_S,
            hard_lock_on_exhaust=True,
            action=f"Medium-risk protocol: {OTP_MED_DIGITS}-digit OTP, "
                   f"{OTP_MED_TRIES} tries, {OTP_MED_TIMEOUT_S} s per try",
            status="Pending OTP verification",
        )
    return TierDecision(
        tier=tier,
        requires_otp=True,
        otp_digits=OTP_HIGH_DIGITS,
        otp_tries=OTP_HIGH_TRIES,
        otp_timeout_s=OTP_HIGH_TIMEOUT_S,
        hard_lock_on_exhaust=True,
        action=f"High-risk protocol: {OTP_HIGH_DIGITS}-digit OTP, "
               f"{OTP_HIGH_TRIES} try, {OTP_HIGH_TIMEOUT_S} s timeout — "
               f"failure locks the console until reset",
        status="Lockout enforced",
    )
