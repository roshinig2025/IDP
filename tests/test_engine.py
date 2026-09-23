"""Unit tests — risk engine, tier router, counter-based OTP anti-replay."""

import base64

import pytest

from biocrypt.engine import otp
from biocrypt.engine.risk_engine import (compute_risk,
                                         proximity_risk_from_rssi)
from biocrypt.engine.tiers import (OTP_HIGH_DIGITS, OTP_HIGH_TIMEOUT_S,
                                   OTP_HIGH_TRIES, OTP_LOW_DIGITS,
                                   OTP_LOW_TIMEOUT_S, OTP_LOW_TRIES,
                                   OTP_MED_DIGITS, OTP_MED_TIMEOUT_S,
                                   OTP_MED_TRIES, TIER_HIGH, TIER_LOW,
                                   TIER_MED, classify_tier, is_perfect_match,
                                   route_tier)


# ---------------------------------------------------------------------------
# Risk engine
# ---------------------------------------------------------------------------
class TestRiskEngine:
    def test_trusted_user_scores_low(self):
        risk = compute_risk(95, -42, 0)
        assert risk.total_risk == 2.5          # only 5% biometric residue
        assert risk.tier == TIER_LOW

    def test_exact_formula_components(self):
        # fp=40 -> bio 60*0.5=30 ; rssi=-82 -> prox 70*0.35=24.5 ;
        # fails=3 -> hist min(30,45)=30*0.15=4.5  => 59.0
        risk = compute_risk(40, -82, 3)
        assert risk.total_risk == 59.0
        assert risk.components == {"biometric": 30.0, "proximity": 24.5,
                                   "history": 4.5}

    def test_proximity_bands(self):
        assert proximity_risk_from_rssi(-50) == 0.0
        assert proximity_risk_from_rssi(-50.01) == 30.0
        assert proximity_risk_from_rssi(-70) == 30.0
        assert proximity_risk_from_rssi(-70.01) == 70.0
        assert proximity_risk_from_rssi(-90) == 70.0

    def test_history_cap(self):
        r2 = compute_risk(100, -40, 2)
        r9 = compute_risk(100, -40, 9)
        assert r2.history_risk == 30.0
        assert r9.history_risk == 30.0          # capped at 30 points
        assert r2.total_risk == r9.total_risk

    def test_perfect_biometric_zero_risk(self):
        assert compute_risk(100, -40, 0).total_risk == 0.0

    def test_worst_case_bounds_at_100(self):
        # fp=0 -> 50 ; prox 70*0.35=24.5 ; hist capped 30*0.15=4.5 => 79
        assert compute_risk(0, -90, 5).total_risk == 79.0

    def test_invalid_fp_rejected(self):
        with pytest.raises(ValueError):
            compute_risk(150, -40, 0)
        with pytest.raises(ValueError):
            compute_risk(-1, -40, 0)

    def test_breakdown_dict_serialisable(self):
        d = compute_risk(65, -68, 1).as_dict()
        assert set(d) >= {"fp_score", "rssi_dbm", "risk_score", "tier"}


# ---------------------------------------------------------------------------
# Tier router
# ---------------------------------------------------------------------------
class TestTiers:
    @pytest.mark.parametrize("score,expected", [
        (0, TIER_LOW), (30, TIER_LOW), (30.01, TIER_MED), (31, TIER_MED),
        (70, TIER_MED), (70.01, TIER_HIGH), (71, TIER_HIGH), (100, TIER_HIGH),
    ])
    def test_boundaries(self, score, expected):
        assert classify_tier(score) == expected

    def test_low_route_policy(self):
        d = route_tier(20)
        assert d.tier == TIER_LOW and d.requires_otp
        assert d.otp_digits == OTP_LOW_DIGITS == 4
        assert d.otp_tries == OTP_LOW_TRIES == 3
        assert d.otp_timeout_s == OTP_LOW_TIMEOUT_S == 0
        assert d.hard_lock_on_exhaust

    def test_med_route_policy(self):
        d = route_tier(50)
        assert d.tier == TIER_MED and d.requires_otp
        assert d.otp_digits == OTP_MED_DIGITS == 6
        assert d.otp_tries == OTP_MED_TRIES == 3
        assert d.otp_timeout_s == OTP_MED_TIMEOUT_S == 90
        assert d.hard_lock_on_exhaust

    def test_high_route_policy(self):
        d = route_tier(90)
        assert d.tier == TIER_HIGH and d.requires_otp
        assert d.otp_digits == OTP_HIGH_DIGITS == 8
        assert d.otp_tries == OTP_HIGH_TRIES == 1
        assert d.otp_timeout_s == OTP_HIGH_TIMEOUT_S == 60
        assert d.hard_lock_on_exhaust


class TestPerfectMatch:
    def test_true_when_both_signals_perfect(self):
        assert is_perfect_match(100.0, -45.0) is True
        assert is_perfect_match(100.0, -50.0) is True    # boundary inclusive
        assert is_perfect_match(100.0, -30.0) is True

    def test_false_when_any_signal_imperfect(self):
        assert is_perfect_match(99.9, -45.0) is False
        assert is_perfect_match(100.0, -50.01) is False
        assert is_perfect_match(85.0, -42.0) is False

    def test_overrides_failed_attempts(self):
        # Perfect signals always unlock, even with failures on record.
        assert is_perfect_match(100.0, -40.0) is True

    def test_independent_of_risk_score(self):
        # fp=100, rssi=-40 with 0 fails scores 0.0 (Low); the override must
        # not depend on the computed score, only on the two raw signals.
        risk = compute_risk(100, -40, 0)
        assert risk.total_risk == 0.0
        assert is_perfect_match(100, -40) is True


# ---------------------------------------------------------------------------
# Counter-based OTP
# ---------------------------------------------------------------------------
class TestOTP:
    def test_code_shape(self):
        secret = otp.generate_secret()
        assert len(otp.current_otp(secret, 1, 4)) == 4
        assert len(otp.current_otp(secret, 1, 6)) == 6
        assert len(otp.current_otp(secret, 1, 8)) == 8
        assert otp.current_otp(secret, 1, 6).isdigit()

    def test_rfc4226_vectors(self):
        # RFC 4226 Appendix D: secret = ASCII "12345678901234567890".
        secret = base64.b32encode(b"12345678901234567890").decode()
        assert otp.hotp_at(secret, 0, 6) == "755224"
        assert otp.hotp_at(secret, 1, 6) == "287082"
        assert otp.hotp_at(secret, 9, 6) == "520489"

    def test_no_clock_involvement(self):
        # Same counter -> identical code forever; no time-based API exists.
        secret = otp.generate_secret()
        assert (otp.current_otp(secret, 42, 6)
                == otp.current_otp(secret, 42, 6))
        assert not hasattr(otp, "seconds_remaining")
        assert not hasattr(otp, "TIMESTEP_SECONDS")

    def test_unique_code_per_counter(self):
        # Every (re)issue advances the counter -> guaranteed different code.
        secret = otp.generate_secret()
        codes = {otp.hotp_at(secret, c, 6) for c in range(1, 6)}
        assert len(codes) == 5

    def test_next_counter(self):
        assert otp.next_counter(0) == 1
        assert otp.next_counter(41) == 42

    def test_verify_ok(self):
        secret = otp.generate_secret()
        code = otp.current_otp(secret, 7, 6)
        ok, why = otp.verify_otp(secret, 7, 6, code)
        assert ok and why == "ok"

    def test_verify_foreign_counter_rejected(self):
        secret = otp.generate_secret()
        code = otp.current_otp(secret, 8, 6)
        ok, why = otp.verify_otp(secret, 7, 6, code)
        assert not ok and why == "invalid"

    def test_verify_malformed(self):
        secret = otp.generate_secret()
        ok, why = otp.verify_otp(secret, 7, 6, "12ab")
        assert not ok and why == "malformed"
        ok, why = otp.verify_otp(secret, 7, 6, "12345")
        assert not ok and why == "malformed"
        ok, why = otp.verify_otp(secret, 7, 6, "")
        assert not ok and why == "malformed"
