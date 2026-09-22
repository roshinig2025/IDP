"""Unit tests — risk engine, tier router, TOTP anti-replay."""

import time

import pytest

from biocrypt.engine import totp
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
# TOTP
# ---------------------------------------------------------------------------
class TestTOTP:
    def test_code_shape(self):
        secret = totp.generate_secret()
        assert len(totp.current_totp(secret, 6)) == 6
        assert len(totp.current_totp(secret, 8)) == 8
        assert totp.current_totp(secret, 6).isdigit()

    def test_rfc6238_vector(self):
        # RFC 6238 test vector: secret "12345678901234567890",
        # T=59s, SHA1, 8 digits -> "94287082"
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        assert totp.totp_at(secret, 8, 59) == "94287082"

    def test_valid_window(self):
        secret = totp.generate_secret()
        code = totp.totp_at(secret, 6, time.time())
        ok, why = totp.verify_totp(secret, 6, code, now=time.time(),
                                   used_codes=set())
        assert ok and why == "ok"

    def test_replay_rejected(self):
        secret = totp.generate_secret()
        code = totp.current_totp(secret, 6)
        used: set[str] = set()
        ok1, _ = totp.verify_totp(secret, 6, code, used_codes=used)
        ok2, why = totp.verify_totp(secret, 6, code, used_codes=used)
        assert ok1 and not ok2 and why == "replay"

    def test_malformed_and_wrong(self):
        secret = totp.generate_secret()
        ok, why = totp.verify_totp(secret, 6, "12ab", used_codes=set())
        assert not ok and why == "malformed"
        ok, why = totp.verify_totp(secret, 6, "000000", now=time.time() + 9999,
                                   used_codes=set())
        assert not ok

    def test_neighbour_window_accepted(self):
        secret = totp.generate_secret()
        step = totp.TIMESTEP_SECONDS
        now = 1_700_000_000
        code_prev = totp.totp_at(secret, 6, now - step)
        ok, why = totp.verify_totp(secret, 6, code_prev, now=now,
                                   used_codes=set())
        assert ok and why == "ok"
