"""
Test suite for AI Time-Scam Prevention System
==============================================
"""

import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.detector import (
    TimeScamDetector, RuleEngine, TimePressureAnalyzer,
    LinguisticAnalyzer, URLAnalyzer, ScamTypeClassifier,
    ScamSignal, RiskLevel
)


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def detector():
    return TimeScamDetector()


@pytest.fixture(scope="module")
def rule_engine():
    return RuleEngine()


@pytest.fixture(scope="module")
def time_analyzer():
    return TimePressureAnalyzer()


@pytest.fixture(scope="module")
def ling_analyzer():
    return LinguisticAnalyzer()


@pytest.fixture(scope="module")
def url_analyzer():
    return URLAnalyzer()


# ─────────────────────────────────────────────────────────────
# Scam Detection Tests
# ─────────────────────────────────────────────────────────────

class TestScamDetection:
    """Tests for known scam texts — should be flagged."""

    SCAM_TEXTS = [
        "ACT NOW! Your account expires in 2 hours! Click here immediately!",
        "GUARANTEED 500% returns on Bitcoin in 48 hours! Risk-free!",
        "URGENT: Your PayPal account will be suspended! Verify NOW!",
        "Mom I'm in jail! Need $500 in gift cards! Don't tell Dad!",
        "IRS: You owe taxes. Pay immediately or face arrest!",
        "Only 3 spots left! Offer expires at midnight TONIGHT!",
    ]

    @pytest.mark.parametrize("text", SCAM_TEXTS)
    def test_scam_detected(self, detector, text):
        result = detector.detect(text)
        assert result.is_scam, f"Should detect as scam: {text[:50]}..."
        assert result.overall_score > 0.3, f"Score too low for scam: {result.overall_score}"

    def test_critical_scam_scores_high(self, detector):
        text   = "ACT NOW! URGENT! LAST CHANCE! Your account expires in 30 minutes! Click immediately!"
        result = detector.detect(text)
        assert result.overall_score >= 0.5

    def test_financial_scam_flagged(self, detector):
        text   = "Guaranteed 500% return in 24 hours. Double your money! No risk!"
        result = detector.detect(text)
        assert result.is_scam

    def test_phishing_flagged(self, detector):
        text   = "Your Amazon account will be suspended in 24 hours. Verify immediately."
        result = detector.detect(text)
        assert result.is_scam


# ─────────────────────────────────────────────────────────────
# Legitimate Content Tests
# ─────────────────────────────────────────────────────────────

class TestLegitimateContent:
    """Tests for legitimate texts — should NOT be flagged as scam."""

    LEGIT_TEXTS = [
        "Hi, just a reminder about our meeting tomorrow at 10am.",
        "Your order has been shipped. Estimated delivery in 3-5 days.",
        "Please review the attached quarterly report at your convenience.",
        "Your dentist appointment is scheduled for Tuesday at 2 PM.",
        "New features are available in the latest update.",
    ]

    @pytest.mark.parametrize("text", LEGIT_TEXTS)
    def test_legit_not_flagged(self, detector, text):
        result = detector.detect(text)
        assert result.risk_level in ("safe", "low"), \
            f"Legitimate text flagged as {result.risk_level}: {text[:50]}"


# ─────────────────────────────────────────────────────────────
# Rule Engine Tests
# ─────────────────────────────────────────────────────────────

class TestRuleEngine:
    def test_urgency_pattern_matched(self, rule_engine):
        text            = "ACT NOW! This is your last chance!"
        signals, score  = rule_engine.analyze(text)
        assert len(signals) > 0
        assert score > 0

    def test_no_signals_for_clean_text(self, rule_engine):
        text            = "Please find attached the report for your review."
        signals, score  = rule_engine.analyze(text)
        assert len(signals) == 0
        assert score == 0.0

    def test_financial_pattern(self, rule_engine):
        text            = "Guaranteed 300% returns on your investment in 24 hours!"
        signals, score  = rule_engine.analyze(text)
        assert any("financial" in s.signal_type for s in signals)


# ─────────────────────────────────────────────────────────────
# Time Pressure Analyzer Tests
# ─────────────────────────────────────────────────────────────

class TestTimePressureAnalyzer:
    def test_countdown_detected(self, time_analyzer):
        text   = "Offer expires in 2 hours! Hurry now!"
        result = time_analyzer.analyze(text)
        assert result["countdown_detected"] is True
        assert result["shortest_deadline_seconds"] == 2 * 3600

    def test_no_countdown_in_legit(self, time_analyzer):
        text   = "Your package will arrive in 3-5 business days."
        result = time_analyzer.analyze(text)
        # 5 days = 432000 seconds — over 7-day threshold
        assert result["pressure_score"] < 0.3

    def test_urgency_density(self, time_analyzer):
        text   = "URGENT! Act now! Hurry! Today only! Expires tonight!"
        result = time_analyzer.analyze(text)
        assert result["urgency_word_density"] > 10.0


# ─────────────────────────────────────────────────────────────
# URL Analyzer Tests
# ─────────────────────────────────────────────────────────────

class TestURLAnalyzer:
    def test_ip_url_flagged(self, url_analyzer):
        text   = "Click here: http://192.168.1.1/steal-data"
        result = url_analyzer.analyze(text)
        assert result["url_score"] > 0.3

    def test_lookalike_flagged(self, url_analyzer):
        text   = "Login at http://amazon.phishing-site.xyz/login"
        result = url_analyzer.analyze(text)
        assert result["url_score"] > 0.3

    def test_clean_url_low_score(self, url_analyzer):
        text   = "Visit our site at https://example.com for more info."
        result = url_analyzer.analyze(text)
        assert result["url_score"] < 0.3


# ─────────────────────────────────────────────────────────────
# Detection Result Structure Tests
# ─────────────────────────────────────────────────────────────

class TestDetectionResult:
    def test_result_has_required_fields(self, detector):
        result = detector.detect("Test message for structure check.")
        d = result.to_dict()
        for field in ["content_hash", "timestamp", "is_scam", "risk_level",
                      "overall_score", "scam_types", "signals",
                      "recommendations", "processing_time_ms"]:
            assert field in d, f"Missing field: {field}"

    def test_score_in_range(self, detector):
        result = detector.detect("Buy now! Limited time!")
        assert 0.0 <= result.overall_score <= 1.0

    def test_processing_time_recorded(self, detector):
        result = detector.detect("Hello world, this is a test.")
        assert result.processing_time_ms > 0
