"""
Flask REST API for AI Time-Scam Prevention System
==================================================
Endpoints:
  POST /api/v1/analyze        — analyze text content for scams
  POST /api/v1/analyze/url    — analyze a URL for phishing/scam indicators
  POST /api/v1/analyze/email  — analyze email (subject + body)
  POST /api/v1/train          — submit labeled training examples
  GET  /api/v1/stats          — system statistics & model metrics
  GET  /api/v1/health         — health check
  GET  /                      — dashboard UI
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from loguru import logger

from src.core.detector import TimeScamDetector
from src.core.database import db, AnalysisLog, TrainingExample
from src.protection.automated import AutomatedProtection
from src.utils.validators import validate_analyze_request, validate_train_request


def create_app() -> Flask:
    """Application factory."""
    app = Flask(
        __name__,
        template_folder="../../frontend/templates",
        static_folder="../../frontend/static"
    )

    # ── Configuration ─────────────────────────────────────────
    app.config["SECRET_KEY"]           = os.getenv("FLASK_SECRET_KEY", "dev-key-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///scam_prevention.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ── Extensions ────────────────────────────────────────────
    CORS(app, origins="*")

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[
            os.getenv("RATE_LIMIT_PER_MINUTE", "60") + " per minute",
            os.getenv("RATE_LIMIT_PER_HOUR",   "500") + " per hour",
        ],
        storage_uri="memory://"
    )

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # ── Initialize AI Components ──────────────────────────────
    detector    = TimeScamDetector()
    protection  = AutomatedProtection(detector)

    # ─────────────────────────────────────────────────────────
    # Dashboard UI Route
    # ─────────────────────────────────────────────────────────

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    # ─────────────────────────────────────────────────────────
    # Health Check
    # ─────────────────────────────────────────────────────────

    @app.route("/api/v1/health", methods=["GET"])
    def health():
        return jsonify({
            "status":    "healthy",
            "service":   "AI Time-Scam Prevention System",
            "version":   "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ─────────────────────────────────────────────────────────
    # Main Analysis Endpoint
    # ─────────────────────────────────────────────────────────

    @app.route("/api/v1/analyze", methods=["POST"])
    @limiter.limit("30 per minute")
    def analyze():
        """
        Analyze text content for time-scam indicators.
        
        Body (JSON):
          content  (str, required): The text to analyze
          source   (str, optional): Origin (email, sms, chat, web, unknown)
          sender   (str, optional): Sender identifier (anonymized)
        """
        data = request.get_json(silent=True) or {}
        error = validate_analyze_request(data)
        if error:
            return jsonify({"error": error}), 400

        content  = data["content"].strip()
        source   = data.get("source", "unknown")
        sender   = data.get("sender", "")

        try:
            result = detector.detect(content, metadata={"source": source, "sender": sender})

            # Persist to DB
            _log_analysis(result, source, sender)

            # Trigger automated protection if needed
            protection_actions = []
            if result.is_scam and result.overall_score >= 0.65:
                protection_actions = protection.respond(result, source)

            response = result.to_dict()
            response["protection_actions"] = protection_actions
            return jsonify(response), 200

        except Exception as e:
            logger.exception(f"Analysis error: {e}")
            return jsonify({"error": "Internal analysis error", "detail": str(e)}), 500

    # ─────────────────────────────────────────────────────────
    # Email Analysis Endpoint
    # ─────────────────────────────────────────────────────────

    @app.route("/api/v1/analyze/email", methods=["POST"])
    @limiter.limit("20 per minute")
    def analyze_email():
        """
        Analyze email for scam indicators.
        
        Body (JSON):
          subject  (str): Email subject
          body     (str): Email body
          sender   (str, optional): Sender email address
          headers  (dict, optional): Email headers
        """
        data    = request.get_json(silent=True) or {}
        subject = data.get("subject", "")
        body    = data.get("body", "")
        sender  = data.get("sender", "")

        if not subject and not body:
            return jsonify({"error": "At least 'subject' or 'body' is required."}), 400

        # Combine for analysis, weight subject heavily
        combined = f"SUBJECT: {subject}\n\nBODY:\n{body}"
        metadata = {
            "source": "email",
            "sender": sender,
            "subject": subject,
            "headers": data.get("headers", {})
        }

        try:
            result              = detector.detect(combined, metadata=metadata)
            _log_analysis(result, "email", sender)

            response            = result.to_dict()
            response["email"]   = {"subject": subject, "sender": sender}
            return jsonify(response), 200

        except Exception as e:
            logger.exception(f"Email analysis error: {e}")
            return jsonify({"error": str(e)}), 500

    # ─────────────────────────────────────────────────────────
    # URL Analysis Endpoint
    # ─────────────────────────────────────────────────────────

    @app.route("/api/v1/analyze/url", methods=["POST"])
    @limiter.limit("30 per minute")
    def analyze_url():
        """
        Analyze a URL for phishing / scam indicators.
        
        Body (JSON):
          url       (str): The URL to analyze
          page_text (str, optional): The text content of the page
        """
        data     = request.get_json(silent=True) or {}
        url      = data.get("url", "").strip()
        page_txt = data.get("page_text", "")

        if not url:
            return jsonify({"error": "'url' field is required."}), 400

        content = f"URL: {url}\n\n{page_txt}" if page_txt else url

        try:
            result   = detector.detect(content, metadata={"source": "url", "url": url})
            _log_analysis(result, "url", url)
            response = result.to_dict()
            response["analyzed_url"] = url
            return jsonify(response), 200

        except Exception as e:
            logger.exception(f"URL analysis error: {e}")
            return jsonify({"error": str(e)}), 500

    # ─────────────────────────────────────────────────────────
    # Training Endpoint
    # ─────────────────────────────────────────────────────────

    @app.route("/api/v1/train", methods=["POST"])
    @limiter.limit("10 per hour")
    def submit_training():
        """
        Submit labeled training examples to improve the AI model.
        
        Body (JSON):
          examples (list of {text: str, label: int (1=scam, 0=legit)})
        """
        data    = request.get_json(silent=True) or {}
        error   = validate_train_request(data)
        if error:
            return jsonify({"error": error}), 400

        examples = data["examples"]

        # Persist training examples
        with db.session.begin():
            for ex in examples:
                db.session.add(TrainingExample(
                    text=ex["text"][:2000],
                    label=int(ex["label"]),
                    submitted_at=datetime.now(timezone.utc)
                ))

        return jsonify({
            "message":        f"Accepted {len(examples)} training example(s).",
            "total_accepted": len(examples),
        }), 202

    # ─────────────────────────────────────────────────────────
    # Stats Endpoint
    # ─────────────────────────────────────────────────────────

    @app.route("/api/v1/stats", methods=["GET"])
    def stats():
        """Return system statistics."""
        try:
            total_analyzed  = db.session.query(AnalysisLog).count()
            scam_detected   = db.session.query(AnalysisLog).filter_by(is_scam=True).count()
            safe_count      = total_analyzed - scam_detected
            training_count  = db.session.query(TrainingExample).count()

            # Recent breakdown by risk level
            from sqlalchemy import func
            risk_breakdown = dict(
                db.session.query(AnalysisLog.risk_level, func.count(AnalysisLog.id))
                  .group_by(AnalysisLog.risk_level)
                  .all()
            )

            return jsonify({
                "total_analyzed":     total_analyzed,
                "scams_detected":     scam_detected,
                "safe_content":       safe_count,
                "training_examples":  training_count,
                "detection_rate":     round(scam_detected / max(total_analyzed, 1) * 100, 2),
                "risk_breakdown":     risk_breakdown,
                "uptime":             "OK",
                "timestamp":          datetime.now(timezone.utc).isoformat(),
            }), 200

        except Exception as e:
            logger.exception(f"Stats error: {e}")
            return jsonify({"error": str(e)}), 500

    # ─────────────────────────────────────────────────────────
    # Recent Detections Endpoint
    # ─────────────────────────────────────────────────────────

    @app.route("/api/v1/detections/recent", methods=["GET"])
    def recent_detections():
        """Return the last N detections."""
        limit  = min(int(request.args.get("limit", 20)), 100)
        offset = int(request.args.get("offset", 0))

        logs = (db.session.query(AnalysisLog)
                  .order_by(AnalysisLog.id.desc())
                  .offset(offset).limit(limit).all())

        return jsonify({
            "detections": [log.to_dict() for log in logs],
            "count":      len(logs),
        }), 200

    # ─────────────────────────────────────────────────────────
    # Error Handlers
    # ─────────────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app


# ─────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────

def _log_analysis(result, source: str, sender: str):
    """Persist analysis result to database."""
    try:
        import json
        log = AnalysisLog(
            content_hash=result.content_hash,
            timestamp=datetime.now(timezone.utc),
            is_scam=result.is_scam,
            risk_level=result.risk_level,
            overall_score=result.overall_score,
            scam_types=json.dumps(result.scam_types),
            source=source,
            sender=sender[:100] if sender else "",
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.warning(f"Failed to log analysis: {e}")
        db.session.rollback()
