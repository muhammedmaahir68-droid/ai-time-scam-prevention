"""
API endpoint tests.
"""

import pytest
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.app import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.app_context():
        from src.core.database import db
        db.create_all()
    with app.test_client() as client:
        yield client


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "healthy"


class TestAnalyzeEndpoint:
    def test_analyze_scam_text(self, client):
        payload = {"content": "ACT NOW! Your account expires in 2 hours! Click immediately!"}
        r = client.post("/api/v1/analyze", json=payload)
        assert r.status_code == 200
        data = r.get_json()
        assert "overall_score" in data
        assert "risk_level" in data
        assert "is_scam" in data

    def test_analyze_requires_content(self, client):
        r = client.post("/api/v1/analyze", json={})
        assert r.status_code == 400

    def test_analyze_rejects_too_short(self, client):
        r = client.post("/api/v1/analyze", json={"content": "hi"})
        assert r.status_code == 400

    def test_analyze_with_source(self, client):
        payload = {"content": "URGENT verify now!", "source": "email"}
        r = client.post("/api/v1/analyze", json=payload)
        assert r.status_code == 200


class TestEmailEndpoint:
    def test_analyze_email(self, client):
        payload = {
            "subject": "URGENT: Account suspension notice",
            "body":    "Your account will be closed in 24 hours. Verify immediately.",
            "sender":  "noreply@suspicious.xyz"
        }
        r = client.post("/api/v1/analyze/email", json=payload)
        assert r.status_code == 200
        data = r.get_json()
        assert "email" in data

    def test_email_requires_content(self, client):
        r = client.post("/api/v1/analyze/email", json={})
        assert r.status_code == 400


class TestURLEndpoint:
    def test_analyze_url(self, client):
        payload = {"url": "http://192.168.1.1/paypal-login"}
        r = client.post("/api/v1/analyze/url", json=payload)
        assert r.status_code == 200
        data = r.get_json()
        assert "analyzed_url" in data

    def test_url_requires_url_field(self, client):
        r = client.post("/api/v1/analyze/url", json={})
        assert r.status_code == 400


class TestStatsEndpoint:
    def test_stats_returns_data(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert "total_analyzed" in data
        assert "scams_detected" in data
