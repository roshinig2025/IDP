"""Context Fusion & Dynamic Risk Engine — Bio-Crypt Lock.

Fuses three independent hardware channels into a single 0-100 risk score:

    risk = W_BIO  * (100 - fingerprint_match%)      [biometric confidence]
         + W_PROX * proximity_risk(rssi_dbm)        [BLE proximity trust]
         + W_HIST * min(30, 15 * failed_attempts)   [attempt-history anomaly]

Weights (justified in Review II Q&A):
    W_BIO  = 0.50  — the fingerprint is the primary identity proof.
    W_PROX = 0.35  — presence token; RSSI degrades smoothly with distance.
    W_HIST = 0.15  — supporting behavioural signal, capped at 30 points.

RSSI proximity bands (dBm — closer to 0 is stronger/closer):
    >= -50  ->   0   (adjacent / trusted)
    >= -70  ->  30   (same room, moderate)
    <  -70  ->  70   (far / untrusted, potential relay attack)
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---- Tunable engine constants (single source of truth for tests & UI) ----
W_BIOMETRIC = 0.50
W_PROXIMITY = 0.35
W_HISTORY = 0.15
HISTORY_STEP = 15.0        # risk points added per failed attempt
HISTORY_CAP = 30.0         # history component saturates here

RSSI_STRONG_DBM = -50      # >= this -> zero proximity risk
RSSI_MODERATE_DBM = -70    # >= this (and < strong) -> moderate risk
PROXIMITY_MODERATE_RISK = 30.0
PROXIMITY_WEAK_RISK = 70.0

# ---- Tier boundaries (shared with tiers.py) ----
TIER_LOW_MAX = 30.0        # risk <= 30  -> Low
TIER_MED_MAX = 70.0        # risk <= 70  -> Medium, else High


@dataclass(frozen=True)
class RiskBreakdown:
    """Full transparency object for one risk evaluation (shown on the GUI
    and written verbatim to the audit log)."""

    fp_score: float
    rssi_dbm: float
    failed_attempts: int

    biometric_risk: float
    proximity_risk: float
    history_risk: float

    total_risk: float
    tier: str

    components: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "fp_score": self.fp_score,
            "rssi_dbm": self.rssi_dbm,
            "failed_attempts": self.failed_attempts,
            "biometric_risk": self.biometric_risk,
            "proximity_risk": self.proximity_risk,
            "history_risk": self.history_risk,
            "risk_score": self.total_risk,
            "tier": self.tier,
        }


def proximity_risk_from_rssi(rssi_dbm: float) -> float:
    """Map a BLE RSSI reading to its proximity-risk component (0-70)."""
    if rssi_dbm >= RSSI_STRONG_DBM:
        return 0.0
    if rssi_dbm >= RSSI_MODERATE_DBM:
        return PROXIMITY_MODERATE_RISK
    return PROXIMITY_WEAK_RISK


def compute_risk(fp_match_score: float, rssi_dbm: float,
                 failed_attempts: int) -> RiskBreakdown:
    """Fuse the three simulated hardware inputs into a 0-100 risk score.

    Parameters
    ----------
    fp_match_score : 0-100 optical fingerprint match percentage.
    rssi_dbm       : BLE RSSI in dBm (typically -90 .. -30).
    failed_attempts: count of recent failed authentication attempts.
    """
    if not 0.0 <= fp_match_score <= 100.0:
        raise ValueError("fp_match_score must be within 0..100")

    biometric_risk = max(0.0, 100.0 - float(fp_match_score))
    proximity_risk = proximity_risk_from_rssi(float(rssi_dbm))
    history_risk = min(HISTORY_CAP, HISTORY_STEP * max(0, int(failed_attempts)))

    total = (W_BIOMETRIC * biometric_risk
             + W_PROXIMITY * proximity_risk
             + W_HISTORY * history_risk)
    total = round(min(100.0, max(0.0, total)), 2)

    # Local import avoids a circular dependency (tiers -> engine constants).
    from .tiers import classify_tier
    tier = classify_tier(total)

    return RiskBreakdown(
        fp_score=float(fp_match_score),
        rssi_dbm=float(rssi_dbm),
        failed_attempts=int(failed_attempts),
        biometric_risk=round(biometric_risk, 2),
        proximity_risk=proximity_risk,
        history_risk=history_risk,
        total_risk=total,
        tier=tier,
        components={
            "biometric": round(W_BIOMETRIC * biometric_risk, 2),
            "proximity": round(W_PROXIMITY * proximity_risk, 2),
            "history": round(W_HISTORY * history_risk, 2),
        },
    )
