"""
Database Models for AI Time-Scam Prevention System
====================================================
"""

import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class AnalysisLog(db.Model):
    """Records every analysis performed by the system."""
    __tablename__ = "analysis_logs"

    id            = db.Column(db.Integer, primary_key=True)
    content_hash  = db.Column(db.String(16), nullable=False, index=True)
    timestamp     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_scam       = db.Column(db.Boolean, nullable=False, default=False)
    risk_level    = db.Column(db.String(20), nullable=False, default="safe")
    overall_score = db.Column(db.Float, nullable=False, default=0.0)
    scam_types    = db.Column(db.Text, default="[]")  # JSON list
    source        = db.Column(db.String(50), default="unknown")
    sender        = db.Column(db.String(100), default="")

    def to_dict(self):
        return {
            "id":            self.id,
            "content_hash":  self.content_hash,
            "timestamp":     self.timestamp.isoformat() if self.timestamp else None,
            "is_scam":       self.is_scam,
            "risk_level":    self.risk_level,
            "overall_score": self.overall_score,
            "scam_types":    json.loads(self.scam_types) if self.scam_types else [],
            "source":        self.source,
            "sender":        self.sender,
        }


class TrainingExample(db.Model):
    """Labeled training examples submitted by users/admins."""
    __tablename__ = "training_examples"

    id           = db.Column(db.Integer, primary_key=True)
    text         = db.Column(db.Text, nullable=False)
    label        = db.Column(db.Integer, nullable=False)  # 1=scam, 0=legit
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    used_in_training = db.Column(db.Boolean, default=False)


class BlockList(db.Model):
    """Blocked senders / domains / URLs."""
    __tablename__ = "block_list"

    id          = db.Column(db.Integer, primary_key=True)
    entry_type  = db.Column(db.String(20), nullable=False)   # sender|domain|url|ip
    value       = db.Column(db.String(255), nullable=False, unique=True, index=True)
    reason      = db.Column(db.String(500), default="")
    added_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    added_by    = db.Column(db.String(100), default="system")
    times_hit   = db.Column(db.Integer, default=0)


def init_db():
    """Initialize database tables (called on startup)."""
    from loguru import logger
    logger.info("Database initialized.")
