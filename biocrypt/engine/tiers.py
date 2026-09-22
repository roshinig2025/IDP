"""3-Tier Risk-Adaptive Authentication Router — Bio-Crypt Lock.

    Low  (risk <= 30):  seamless 1-touch unlock, no OTP.
    Med  (31..70):      6-digit TOTP step-up challenge.
    High (71..100):     8-digit TOTP challenge + timed lockout protocol.
"""

from __future__ import annotations

from dataclasses import dataclass

from .risk_engine import TIER_LOW_MAX, TIER_MED_MAX

TIER_LOW = "Low Risk (0-30)"
TIER_MED = "Medium Risk (31-70)"
TIER_HIGH = "High Risk (71-100)"

OTP_MED_DIGITS = 6
OTP_HIGH_DIGITS = 8
LOCKOUT_SECONDS = 60          # timed lockout for the high-risk protocol
LOW_MAX_ATTEMPTS = 2          # OTP verification tries allowed before reset


@dataclass(frozen=True)
class TierDecision:
    tier: str
    requires_otp: bool
    otp_digits: int
    lockout_seconds: int
    action: str
    status: str


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
            requires_otp=False,
            otp_digits=0,
            lockout_seconds=0,
            action="Seamless 1-touch unlock (no OTP required)",
            status="Unlocked — single factor",
        )
    if tier == TIER_MED:
        return TierDecision(
            tier=tier,
            requires_otp=True,
            otp_digits=OTP_MED_DIGITS,
            lockout_seconds=0,
            action=f"Dynamic {OTP_MED_DIGITS}-digit TOTP step-up required",
            status="Pending OTP verification",
        )
    return TierDecision(
        tier=tier,
        requires_otp=True,
        otp_digits=OTP_HIGH_DIGITS,
        lockout_seconds=LOCKOUT_SECONDS,
        action=f"High-risk protocol: {OTP_HIGH_DIGITS}-digit TOTP + "
               f"{LOCKOUT_SECONDS}s timed lockout",
        status="Lockout enforced",
    )
