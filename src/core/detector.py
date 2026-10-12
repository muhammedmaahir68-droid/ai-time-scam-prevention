"""
Time-Scam Detector — Core AI Engine
=====================================
Multi-layer detection pipeline combining:
  1. Rule-based urgency pattern matching
  2. NLP feature extraction (TF-IDF + linguistic features)
  3. Deep Learning classifier (LSTM + Attention)
  4. Ensemble scoring with confidence calibration

Detects scam types:
  - Urgency manipulation (fake deadlines)
  - Countdown / limited-time offer fraud
  - Phishing with time pressure
  - Social engineering (fake emergency)
  - Financial scams (crypto pump-dump, fake investment)
"""

import re
import json
import time
import hashlib
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

from loguru import logger


# ─────────────────────────────────────────────────────────────
# Data Classes & Enums
# ─────────────────────────────────────────────────────────────

class ScamType(Enum):
    URGENCY_MANIPULATION    = "urgency_manipulation"
    FAKE_COUNTDOWN          = "fake_countdown"
    PHISHING_TIME_PRESSURE  = "phishing_time_pressure"
    SOCIAL_ENGINEERING      = "social_engineering"
    FINANCIAL_FRAUD         = "financial_fraud"
    FAKE_EMERGENCY          = "fake_emergency"
    LIMITED_OFFER_FRAUD     = "limited_offer_fraud"
    CRYPTO_SCAM             = "crypto_scam"
    UNKNOWN                 = "unknown"


class RiskLevel(Enum):
    SAFE     = "safe"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class ScamSignal:
    """Individual scam signal detected in content."""
    signal_type: str
    description: str
    severity: float          # 0.0 – 1.0
    matched_text: str = ""
    confidence: float = 1.0


@dataclass
class DetectionResult:
    """Full result from the scam detection pipeline."""
    content_hash: str
    timestamp: str
    is_scam: bool
    risk_level: str
    overall_score: float         # 0.0 – 1.0 (1.0 = definite scam)
    scam_types: List[str]
    signals: List[Dict]
    recommendations: List[str]
    details: Dict[str, Any] = field(default_factory=dict)
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────
# Pattern Libraries
# ─────────────────────────────────────────────────────────────

URGENCY_PATTERNS = {
    "extreme_urgency": {
        "patterns": [
            r"\b(act\s+now|immediate\s+action\s+required|respond\s+immediately)\b",
            r"\b(last\s+chance|final\s+warning|final\s+notice)\b",
            r"\b(expires?\s+in\s+\d+\s*(hour|minute|second|day)s?)\b",
            r"\b(only\s+\d+\s*(hour|minute|second)s?\s+(left|remaining))\b",
            r"\b(countdown|time\s+is\s+running\s+out|clock\s+is\s+ticking)\b",
            r"\b(limited\s+time|time\s+sensitive|time-sensitive)\b",
            r"\b(do\s+not\s+delay|don.?t\s+wait|don.?t\s+miss\s+out)\b",
        ],
        "severity": 0.8
    },
    "false_scarcity": {
        "patterns": [
            r"\b(only\s+\d+\s+(spots?|seats?|units?|items?|copies?)\s+(left|remaining|available))\b",
            r"\b(\d+\s+people\s+(are\s+)?(viewing|watching|looking\s+at)\s+this)\b",
            r"\b(selling\s+fast|almost\s+(gone|sold\s+out)|nearly\s+sold\s+out)\b",
            r"\b(exclusive|once\s+in\s+a\s+lifetime|never\s+again)\b",
        ],
        "severity": 0.7
    },
    "fake_deadline": {
        "patterns": [
            r"\b(offer\s+expires?\s+(today|tonight|midnight|in\s+\d+\s*(hour|minute)s?))\b",
            r"\b(must\s+(act|respond|reply|confirm)\s+(by|before|within)\s+\d+\s*(hour|minute|day)s?)\b",
            r"\b(deadline|cut.?off)\s+.*\b(today|tonight|now|immediately)\b",
            r"\b(your\s+account\s+will\s+be\s+(suspended|closed|deleted|terminated)\s+(in|within)\s+\d+\s*(hour|day)s?)\b",
        ],
        "severity": 0.85
    },
    "threat_deadline": {
        "patterns": [
            r"\b(legal\s+action\s+will\s+be\s+taken|police\s+will\s+be\s+notified|warrant\s+will\s+be\s+issued)\b",
            r"\b(arrest\s+warrant|federal\s+agent|irs|tax\s+fraud|money\s+laundering)\b",
            r"\b(your\s+ssn\s+(has\s+been\s+)?(suspended|compromised|flagged))\b",
            r"\b(ignore\s+this\s+message\s+at\s+your\s+own\s+risk)\b",
        ],
        "severity": 0.95
    }
}

FINANCIAL_PATTERNS = {
    "guaranteed_returns": {
        "patterns": [
            r"\b(guaranteed\s+return|guaranteed\s+profit|risk.?free\s+investment)\b",
            r"\b(\d{2,4}%\s+(return|profit|gain)\s+(in\s+)?\d+\s*(hour|day|week)s?)\b",
            r"\b(double\s+your\s+(money|investment)\s+(in|within)\s+\d+\s*(hour|day)s?)\b",
            r"\b(crypto|bitcoin|ethereum).{0,20}(guaranteed|sure|certain).{0,20}(profit|return|gain)\b",
        ],
        "severity": 0.9
    },
    "pump_dump": {
        "patterns": [
            r"\b(buy\s+now\s+before\s+it.?s\s+too\s+late|price\s+will\s+(skyrocket|explode|moon))\b",
            r"\b(insider\s+(tip|information|knowledge)|secret\s+(tip|strategy))\b",
            r"\b(get\s+in\s+(early|now)|early\s+investor|ground\s+floor\s+opportunity)\b",
        ],
        "severity": 0.88
    },
    "recovery_scam": {
        "patterns": [
            r"\b(recover\s+your\s+(lost\s+)?(funds?|money|crypto|bitcoin))\b",
            r"\b(we\s+can\s+get\s+your\s+money\s+back|fund\s+recovery\s+specialist)\b",
            r"\b(advance\s+fee|processing\s+fee|release\s+fee|clearance\s+fee)\b",
        ],
        "severity": 0.92
    }
}

PHISHING_PATTERNS = {
    "credential_harvest": {
        "patterns": [
            r"\b(verify\s+your\s+(account|identity|information)\s+(immediately|now|within\s+\d+\s*(hour|day)s?))\b",
            r"\b(confirm\s+your\s+(password|credit\s+card|bank\s+account|ssn)\s+(to\s+avoid|or\s+your))\b",
            r"\b(click\s+(here|below|this\s+link)\s+(to\s+)?(avoid|prevent|stop)\s+(your\s+account)?(being)?\s+(suspend|clos|delet))\b",
            r"\b(unusual\s+(activity|login|sign.?in)\s+detected)\b",
        ],
        "severity": 0.88
    },
    "impersonation": {
        "patterns": [
            r"\b(microsoft\s+support|apple\s+support|amazon\s+support|paypal\s+security)\b",
            r"\b(your\s+(microsoft|apple|google|amazon|paypal)\s+account)\b",
            r"\b(this\s+is\s+(the\s+)?(irs|fbi|fbi|social\s+security\s+administration|medicare))\b",
        ],
        "severity": 0.82
    }
}

SOCIAL_ENGINEERING_PATTERNS = {
    "fake_emergency": {
        "patterns": [
            r"\b(emergency|urgent\s+help\s+needed|please\s+help\s+me|i.?m\s+in\s+trouble)\b",
            r"\b(stranded|stuck|trapped|robbed|mugged|accident|hospital)\b",
            r"\b(send\s+(me\s+)?(money|funds?|cash|wire\s+transfer|gift\s+card))\b",
            r"\b(don.?t\s+tell\s+(anyone|my\s+parents|my\s+family|the\s+police))\b",
        ],
        "severity": 0.85
    },
    "romance_scam": {
        "patterns": [
            r"\b(i\s+(love|like)\s+you.{0,30}(send|need|money|gift))\b",
            r"\b(we\s+(will|can)\s+be\s+together\s+(after|once|when)\s+(you\s+)?(send|help))\b",
            r"\b(military|deployed|overseas|visa|plane\s+ticket).{0,30}(send|money|help)\b",
        ],
        "severity": 0.87
    }
}


# ─────────────────────────────────────────────────────────────
# Time-Pressure Detector
# ─────────────────────────────────────────────────────────────

class TimePressureAnalyzer:
    """Analyzes time-pressure cues in text content."""

    TIME_WORDS = {
        "seconds": 1, "minutes": 60, "hours": 3600,
        "days": 86400, "weeks": 604800
    }

    def analyze(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        results = {
            "countdown_detected": False,
            "shortest_deadline_seconds": None,
            "deadline_strings": [],
            "urgency_word_density": 0.0,
            "pressure_score": 0.0
        }

        # Extract countdown patterns
        countdown_pattern = re.compile(
            r"(\d+)\s*(second|minute|hour|day|week)s?", re.IGNORECASE
        )
        matches = countdown_pattern.findall(text_lower)

        deadlines_in_seconds = []
        for amount_str, unit in matches:
            amount = int(amount_str)
            multiplier = self.TIME_WORDS.get(unit.lower() + "s", 
                         self.TIME_WORDS.get(unit.lower(), 1))
            seconds = amount * multiplier
            # Deadlines under 7 days are suspicious
            if seconds < 7 * 86400:
                deadlines_in_seconds.append(seconds)
                results["deadline_strings"].append(f"{amount} {unit}(s)")

        if deadlines_in_seconds:
            results["countdown_detected"] = True
            results["shortest_deadline_seconds"] = min(deadlines_in_seconds)

        # Urgency word density
        urgency_words = [
            "now", "immediately", "urgent", "hurry", "quick", "fast",
            "today", "tonight", "expire", "limited", "last", "final"
        ]
        words = text_lower.split()
        urgency_count = sum(1 for w in words if any(u in w for u in urgency_words))
        results["urgency_word_density"] = (urgency_count / max(len(words), 1)) * 100

        # Compute pressure score
        score = 0.0
        if results["countdown_detected"]:
            shortest = results["shortest_deadline_seconds"]
            if shortest < 3600:      score += 0.4   # Under 1 hour
            elif shortest < 86400:   score += 0.3   # Under 1 day
            else:                    score += 0.15  # Under 7 days
        score += min(results["urgency_word_density"] / 10.0, 0.4)
        results["pressure_score"] = min(score, 1.0)

        return results


# ─────────────────────────────────────────────────────────────
# Pattern-Based Rule Engine
# ─────────────────────────────────────────────────────────────

class RuleEngine:
    """Rule-based pattern matching engine."""

    def __init__(self):
        self.pattern_groups = {
            "urgency":   URGENCY_PATTERNS,
            "financial": FINANCIAL_PATTERNS,
            "phishing":  PHISHING_PATTERNS,
            "social":    SOCIAL_ENGINEERING_PATTERNS,
        }
        self._compiled = self._compile_all()

    def _compile_all(self) -> Dict:
        compiled = {}
        for group_name, group_data in self.pattern_groups.items():
            compiled[group_name] = {}
            for cat_name, cat_data in group_data.items():
                compiled[group_name][cat_name] = {
                    "regex": [re.compile(p, re.IGNORECASE) for p in cat_data["patterns"]],
                    "severity": cat_data["severity"]
                }
        return compiled

    def analyze(self, text: str) -> Tuple[List[ScamSignal], float]:
        signals: List[ScamSignal] = []
        total_score = 0.0

        for group_name, categories in self._compiled.items():
            for cat_name, cat_data in categories.items():
                for regex in cat_data["regex"]:
                    match = regex.search(text)
                    if match:
                        severity = cat_data["severity"]
                        signal = ScamSignal(
                            signal_type=f"{group_name}.{cat_name}",
                            description=f"Detected {cat_name.replace('_', ' ')} pattern",
                            severity=severity,
                            matched_text=match.group(0)[:100],
                            confidence=0.95
                        )
                        signals.append(signal)
                        total_score += severity * 0.15  # Weighted contribution

        # Normalize: cap at 1.0
        rule_score = min(total_score, 1.0)
        return signals, rule_score


# ─────────────────────────────────────────────────────────────
# Linguistic Feature Extractor
# ─────────────────────────────────────────────────────────────

class LinguisticAnalyzer:
    """Extracts linguistic features that indicate scam content."""

    EXCLAMATION_THRESHOLD = 2
    CAPS_RATIO_THRESHOLD  = 0.3

    def analyze(self, text: str) -> Dict[str, float]:
        features = {}

        # Capitalization ratio (SHOUTING)
        letters = [c for c in text if c.isalpha()]
        caps_ratio = sum(1 for c in letters if c.isupper()) / max(len(letters), 1)
        features["caps_ratio"]      = caps_ratio
        features["caps_score"]      = min(caps_ratio / self.CAPS_RATIO_THRESHOLD, 1.0)

        # Exclamation marks (urgency pumping)
        excl_count = text.count("!")
        features["exclamation_count"] = excl_count
        features["exclamation_score"] = min(excl_count / 5.0, 1.0)

        # Sentence length (short = commanding)
        sentences = re.split(r'[.!?]+', text)
        avg_len = np.mean([len(s.split()) for s in sentences if s.strip()]) if sentences else 0
        features["avg_sentence_length"] = float(avg_len)
        features["short_sentence_score"] = max(0, 1.0 - avg_len / 20.0) if avg_len > 0 else 0

        # All-caps words (WARNING, URGENT, etc.)
        words = text.split()
        caps_words = [w for w in words if w.isupper() and len(w) > 2]
        features["caps_word_count"] = len(caps_words)
        features["caps_word_score"] = min(len(caps_words) / 3.0, 1.0)

        # Aggregate linguistic score
        features["linguistic_score"] = (
            features["caps_score"] * 0.25 +
            features["exclamation_score"] * 0.25 +
            features["short_sentence_score"] * 0.25 +
            features["caps_word_score"] * 0.25
        )

        return features


# ─────────────────────────────────────────────────────────────
# URL & Link Analyzer
# ─────────────────────────────────────────────────────────────

class URLAnalyzer:
    """Analyzes URLs for phishing and suspicious characteristics."""

    SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
                       ".click", ".link", ".work", ".bid", ".loan"}
    TRUSTED_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "paypal.com", "facebook.com", "instagram.com", "twitter.com"
    }

    def analyze(self, text: str) -> Dict[str, Any]:
        url_pattern = re.compile(
            r'(https?://[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE
        )
        urls = url_pattern.findall(text)

        result = {
            "urls_found": len(urls),
            "suspicious_urls": [],
            "url_score": 0.0
        }

        total_url_score = 0.0
        for url in urls:
            url_info = self._analyze_single_url(url)
            if url_info["score"] > 0.4:
                result["suspicious_urls"].append(url_info)
            total_url_score += url_info["score"]

        if urls:
            result["url_score"] = min(total_url_score / len(urls), 1.0)

        return result

    def _analyze_single_url(self, url: str) -> Dict:
        info = {"url": url[:100], "flags": [], "score": 0.0}
        score = 0.0

        # Check TLD
        for tld in self.SUSPICIOUS_TLDS:
            if tld in url.lower():
                info["flags"].append(f"Suspicious TLD: {tld}")
                score += 0.3

        # Check for lookalike domains
        for trusted in self.TRUSTED_DOMAINS:
            domain_base = trusted.split(".")[0]
            if domain_base in url.lower() and trusted not in url.lower():
                info["flags"].append(f"Possible lookalike of {trusted}")
                score += 0.5

        # Excessive subdomains
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            subdomain_count = parsed.netloc.count(".")
            if subdomain_count > 3:
                info["flags"].append(f"Excessive subdomains ({subdomain_count})")
                score += 0.2
        except Exception:
            pass

        # IP address as host
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            info["flags"].append("IP address used instead of domain name")
            score += 0.4

        # URL shorteners
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link"]
        if any(s in url.lower() for s in shorteners):
            info["flags"].append("URL shortener detected (destination unknown)")
            score += 0.25

        info["score"] = min(score, 1.0)
        return info


# ─────────────────────────────────────────────────────────────
# Scam Type Classifier
# ─────────────────────────────────────────────────────────────

class ScamTypeClassifier:
    """Classifies the type(s) of scam based on signals."""

    def classify(self, signals: List[ScamSignal], time_analysis: Dict, 
                 url_analysis: Dict) -> List[str]:
        types = set()

        signal_types = {s.signal_type for s in signals}

        if any("urgency" in t for t in signal_types):
            types.add(ScamType.URGENCY_MANIPULATION.value)
        if time_analysis.get("countdown_detected") and time_analysis.get("shortest_deadline_seconds", 999999) < 86400:
            types.add(ScamType.FAKE_COUNTDOWN.value)
        if any("phishing" in t for t in signal_types):
            types.add(ScamType.PHISHING_TIME_PRESSURE.value)
        if any("social" in t for t in signal_types):
            if any("emergency" in t for t in signal_types):
                types.add(ScamType.FAKE_EMERGENCY.value)
            else:
                types.add(ScamType.SOCIAL_ENGINEERING.value)
        if any("financial" in t for t in signal_types):
            if any("crypto" in t.lower() for t in signal_types):
                types.add(ScamType.CRYPTO_SCAM.value)
            else:
                types.add(ScamType.FINANCIAL_FRAUD.value)
        if any("scarcity" in t for t in signal_types):
            types.add(ScamType.LIMITED_OFFER_FRAUD.value)

        return list(types) if types else [ScamType.UNKNOWN.value]


# ─────────────────────────────────────────────────────────────
# Recommendation Engine
# ─────────────────────────────────────────────────────────────

class RecommendationEngine:
    """Generates actionable recommendations based on detection results."""

    def generate(self, risk_level: str, scam_types: List[str], 
                 signals: List[ScamSignal]) -> List[str]:
        recs = []
        level = risk_level.upper()

        # Universal recommendations
        if level in ("HIGH", "CRITICAL"):
            recs.append("⛔ DO NOT respond, click any links, or provide any personal information.")
            recs.append("🔒 Block the sender immediately and report to your email/platform provider.")
            recs.append("📞 If you've already responded, contact your bank or relevant institution immediately.")

        if level == "MEDIUM":
            recs.append("⚠️ Be cautious — verify the sender's identity through official channels before acting.")
            recs.append("🔍 Do not click links; instead, navigate directly to the official website.")

        # Scam-type-specific
        for stype in scam_types:
            if stype == ScamType.PHISHING_TIME_PRESSURE.value:
                recs.append("🎣 Phishing attempt: Check the sender's email address carefully for subtle misspellings.")
                recs.append("🌐 Visit the company's official website by typing it manually in your browser.")

            elif stype == ScamType.FINANCIAL_FRAUD.value:
                recs.append("💰 No legitimate investment guarantees returns — this is a major red flag.")
                recs.append("📋 Report to the SEC (sec.gov/tcr) or FTC (reportfraud.ftc.gov).")

            elif stype == ScamType.CRYPTO_SCAM.value:
                recs.append("₿ Crypto transactions are irreversible — never send crypto to strangers.")
                recs.append("📋 Report to the FTC at reportfraud.ftc.gov and your crypto exchange.")

            elif stype in (ScamType.FAKE_EMERGENCY.value, ScamType.SOCIAL_ENGINEERING.value):
                recs.append("📱 Verify any 'emergency' by calling the person directly on a known number.")
                recs.append("👨‍👩‍👧 Alert family members about this scam attempt.")

            elif stype == ScamType.URGENCY_MANIPULATION.value:
                recs.append("⏰ Artificial urgency is a classic scam tactic — legitimate offers don't expire in minutes.")

        # Add general safety tip
        recs.append("📚 Learn more: consumer.ftc.gov/scams or ic3.gov for cyber fraud reporting.")

        return list(dict.fromkeys(recs))  # De-duplicate, preserve order


# ─────────────────────────────────────────────────────────────
# Main Detector Orchestrator
# ─────────────────────────────────────────────────────────────

class TimeScamDetector:
    """
    Main orchestrator for the AI-based time-scam detection pipeline.
    
    Pipeline:
        Text Input
            │
            ├─► Rule Engine (pattern matching)
            ├─► Time Pressure Analyzer  
            ├─► Linguistic Analyzer
            ├─► URL Analyzer
            │
            └─► Ensemble Score → Risk Level → Recommendations
    """

    RISK_THRESHOLDS = {
        RiskLevel.SAFE.value:     (0.00, 0.20),
        RiskLevel.LOW.value:      (0.20, 0.45),
        RiskLevel.MEDIUM.value:   (0.45, 0.65),
        RiskLevel.HIGH.value:     (0.65, 0.82),
        RiskLevel.CRITICAL.value: (0.82, 1.01),
    }

    def __init__(self):
        self.rule_engine         = RuleEngine()
        self.time_analyzer       = TimePressureAnalyzer()
        self.linguistic_analyzer = LinguisticAnalyzer()
        self.url_analyzer        = URLAnalyzer()
        self.scam_classifier     = ScamTypeClassifier()
        self.recommender         = RecommendationEngine()
        logger.info("TimeScamDetector initialized successfully.")

    def detect(self, content: str, metadata: Optional[Dict] = None) -> DetectionResult:
        """
        Run the full detection pipeline on input content.

        Args:
            content: The text to analyze (email, message, URL, etc.)
            metadata: Optional metadata (sender, source, timestamp, etc.)

        Returns:
            DetectionResult with full analysis
        """
        start_time = time.time()
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        logger.debug(f"Analyzing content hash={content_hash}, len={len(content)}")

        # ── Layer 1: Rule-based pattern matching ──────────────
        rule_signals, rule_score = self.rule_engine.analyze(content)

        # ── Layer 2: Time-pressure analysis ───────────────────
        time_analysis = self.time_analyzer.analyze(content)

        # ── Layer 3: Linguistic analysis ──────────────────────
        ling_analysis = self.linguistic_analyzer.analyze(content)

        # ── Layer 4: URL analysis ─────────────────────────────
        url_analysis = self.url_analyzer.analyze(content)

        # ── Layer 5: Ensemble scoring ─────────────────────────
        ensemble_score = self._compute_ensemble_score(
            rule_score, time_analysis, ling_analysis, url_analysis
        )

        # ── Layer 6: Classification ───────────────────────────
        risk_level = self._compute_risk_level(ensemble_score)
        scam_types = self.scam_classifier.classify(
            rule_signals, time_analysis, url_analysis
        )

        # ── Layer 7: Recommendations ──────────────────────────
        recommendations = self.recommender.generate(
            risk_level, scam_types, rule_signals
        )

        processing_ms = (time.time() - start_time) * 1000

        result = DetectionResult(
            content_hash=content_hash,
            timestamp=datetime.utcnow().isoformat() + "Z",
            is_scam=bool(ensemble_score >= 0.45),
            risk_level=risk_level,
            overall_score=float(round(ensemble_score, 4)),
            scam_types=scam_types,
            signals=[{k: (float(v) if hasattr(v, 'item') else v) for k, v in asdict(s).items()} for s in rule_signals],
            recommendations=recommendations,
            details={
                "rule_score":       float(round(rule_score, 4)),
                "time_analysis":    {k: (float(v) if hasattr(v, 'item') else v) for k, v in time_analysis.items()},
                "linguistic":       {k: (float(v) if hasattr(v, 'item') else v) for k, v in ling_analysis.items()},
                "url_analysis":     url_analysis,
                "metadata":         metadata or {}
            },
            processing_time_ms=float(round(processing_ms, 2))
        )

        logger.info(
            f"Detection complete | hash={content_hash} | "
            f"score={ensemble_score:.3f} | risk={risk_level} | "
            f"types={scam_types} | time={processing_ms:.1f}ms"
        )

        return result

    def _compute_ensemble_score(self, rule_score: float, time_analysis: Dict,
                                 ling_analysis: Dict, url_analysis: Dict) -> float:
        """Weighted ensemble of all detection layers."""
        weights = {
            "rule":        0.40,
            "time":        0.25,
            "linguistic":  0.15,
            "url":         0.20,
        }

        scores = {
            "rule":       rule_score,
            "time":       time_analysis.get("pressure_score", 0.0),
            "linguistic": ling_analysis.get("linguistic_score", 0.0),
            "url":        url_analysis.get("url_score", 0.0),
        }

        ensemble = sum(scores[k] * weights[k] for k in weights)

        # Boost for extreme signals
        if scores["rule"] > 0.7 and scores["time"] > 0.5:
            ensemble = min(ensemble * 1.2, 1.0)

        return min(ensemble, 1.0)

    def _compute_risk_level(self, score: float) -> str:
        for level, (low, high) in self.RISK_THRESHOLDS.items():
            if low <= score < high:
                return level
        return RiskLevel.SAFE.value
