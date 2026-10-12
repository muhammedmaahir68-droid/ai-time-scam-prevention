"""
Automated Protection Module
============================
Responds automatically when high-confidence scams are detected.

Actions:
  - Block sender / domain / URL
  - Generate real-time alerts (console, webhook, email)
  - Quarantine content
  - Rate-limit repeat offenders
  - Generate incident reports
"""

import os
import json
import hashlib
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

from loguru import logger


class AutomatedProtection:
    """
    Automated response engine triggered by high-confidence detections.
    
    Response tiers:
      MEDIUM   → Flag & log
      HIGH     → Block + Alert
      CRITICAL → Block + Alert + Quarantine + Incident Report
    """

    RESPONSE_TIERS = {
        "medium":   ["flag", "log"],
        "high":     ["flag", "block", "alert"],
        "critical": ["flag", "block", "alert", "quarantine", "incident_report"],
    }

    def __init__(self, detector=None):
        self.detector         = detector
        self.blocked_senders  = set()
        self.blocked_domains  = set()
        self.blocked_urls     = set()
        self.incident_dir     = Path("./data/incidents")
        self.incident_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir   = Path("./data/quarantine")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def respond(self, result, source: str = "unknown") -> List[Dict]:
        """
        Execute automated protection actions based on detection result.
        
        Returns list of actions taken.
        """
        actions_taken = []
        risk_level    = result.risk_level.lower()

        if risk_level not in ("medium", "high", "critical"):
            return actions_taken

        actions = self.RESPONSE_TIERS.get(risk_level, [])
        metadata = result.details.get("metadata", {})
        sender   = metadata.get("sender", "")
        url      = metadata.get("url", "")

        for action in actions:
            try:
                if action == "flag":
                    action_result = self._flag_content(result)
                elif action == "block":
                    action_result = self._block_entity(sender, url, result)
                elif action == "alert":
                    action_result = self._send_alert(result, source)
                elif action == "quarantine":
                    action_result = self._quarantine(result)
                elif action == "incident_report":
                    action_result = self._generate_incident_report(result, source)
                else:
                    continue

                actions_taken.append({"action": action, **action_result})

            except Exception as e:
                logger.error(f"Protection action '{action}' failed: {e}")
                actions_taken.append({"action": action, "status": "failed", "error": str(e)})

        return actions_taken

    # ─────────────────────────────────────────────────────────
    # Action Implementations
    # ─────────────────────────────────────────────────────────

    def _flag_content(self, result) -> Dict:
        """Mark content as suspicious in logs."""
        logger.warning(
            f"[FLAGGED] hash={result.content_hash} | "
            f"score={result.overall_score:.3f} | risk={result.risk_level}"
        )
        return {"status": "flagged", "content_hash": result.content_hash}

    def _block_entity(self, sender: str, url: str, result) -> Dict:
        """Add sender/URL to block list."""
        blocked = []

        if sender and "@" in sender:
            domain = sender.split("@")[-1].lower()
            if result.overall_score >= 0.82:
                self.blocked_domains.add(domain)
                blocked.append(f"domain:{domain}")
            self.blocked_senders.add(sender.lower())
            blocked.append(f"sender:{sender}")

        if url:
            self.blocked_urls.add(url[:200])
            blocked.append(f"url:{url[:50]}")

        if blocked:
            logger.warning(f"[BLOCKED] {', '.join(blocked)}")

        return {
            "status":  "blocked",
            "blocked": blocked,
        }

    def _send_alert(self, result, source: str) -> Dict:
        """Send alert via configured webhook/log."""
        alert_msg = {
            "alert_type":    "SCAM_DETECTED",
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "risk_level":    result.risk_level.upper(),
            "scam_score":    result.overall_score,
            "scam_types":    result.scam_types,
            "source":        source,
            "content_hash":  result.content_hash,
            "top_signals":   [s["signal_type"] for s in result.signals[:3]],
        }

        # Console alert
        logger.critical(
            f"[ALERT] risk={result.risk_level.upper()} | "
            f"score={result.overall_score:.3f} | types={result.scam_types}"
        )

        # Slack webhook (optional)
        slack_url = os.getenv("SLACK_WEBHOOK_URL")
        if slack_url and slack_url.startswith("https://"):
            try:
                slack_payload = {
                    "text": (
                        f"[THREAT DETECTED] Risk: `{result.risk_level.upper()}` | "
                        f"Score: `{result.overall_score:.2f}` | "
                        f"Types: `{', '.join(result.scam_types)}`\n"
                        f"Content Hash: `{result.content_hash}`"
                    )
                }
                requests.post(slack_url, json=slack_payload, timeout=5)
                alert_msg["slack"] = "sent"
            except Exception as e:
                logger.warning(f"Slack alert failed: {e}")
                alert_msg["slack"] = "failed"

        # Discord webhook (optional)
        discord_url = os.getenv("DISCORD_WEBHOOK_URL")
        if discord_url and discord_url.startswith("https://"):
            try:
                discord_payload = {
                    "embeds": [{
                        "title": "Threat Detected",
                        "color": 0xFF0000 if result.risk_level == "critical" else 0xFF6600,
                        "fields": [
                            {"name": "Risk Level",  "value": result.risk_level.upper(), "inline": True},
                            {"name": "Score",        "value": f"{result.overall_score:.3f}", "inline": True},
                            {"name": "Scam Types",   "value": ", ".join(result.scam_types)},
                            {"name": "Source",       "value": source, "inline": True},
                        ],
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }]
                }
                requests.post(discord_url, json=discord_payload, timeout=5)
                alert_msg["discord"] = "sent"
            except Exception as e:
                logger.warning(f"Discord alert failed: {e}")

        return {"status": "alert_sent", "channels": alert_msg}

    def _quarantine(self, result) -> Dict:
        """Store content in quarantine zone for review."""
        filename = self.quarantine_dir / f"{result.content_hash}_{int(datetime.now().timestamp())}.json"
        data = {
            "quarantine_reason": "high_confidence_scam",
            "detection_result":  result.to_dict(),
            "quarantined_at":    datetime.now(timezone.utc).isoformat(),
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"[QUARANTINE] {filename}")
        return {"status": "quarantined", "file": str(filename)}

    def _generate_incident_report(self, result, source: str) -> Dict:
        """Generate a structured incident report."""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{result.content_hash}"
        report = {
            "incident_id":      incident_id,
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "source":           source,
            "risk_level":       result.risk_level,
            "scam_score":       result.overall_score,
            "scam_types":       result.scam_types,
            "signals_detected": result.signals,
            "recommendations":  result.recommendations,
            "detection_details": result.details,
        }

        filepath = self.incident_dir / f"{incident_id}.json"
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"[INCIDENT] {incident_id}")
        return {"status": "report_generated", "incident_id": incident_id, "file": str(filepath)}

    # ─────────────────────────────────────────────────────────
    # Block-List Queries
    # ─────────────────────────────────────────────────────────

    def is_blocked(self, value: str, check_type: str = "all") -> bool:
        """Check if an entity is blocked."""
        value_lower = value.lower()

        if check_type in ("sender", "all") and value_lower in self.blocked_senders:
            return True
        if check_type in ("domain", "all"):
            if "@" in value_lower:
                domain = value_lower.split("@")[-1]
                if domain in self.blocked_domains:
                    return True
            elif value_lower in self.blocked_domains:
                return True
        if check_type in ("url", "all") and any(value_lower in u for u in self.blocked_urls):
            return True

        return False

    def get_block_list(self) -> Dict:
        """Return current block lists."""
        return {
            "senders": list(self.blocked_senders),
            "domains": list(self.blocked_domains),
            "urls":    list(self.blocked_urls),
        }

    def unblock(self, value: str) -> bool:
        """Remove an entity from block lists."""
        value_lower = value.lower()
        removed = False
        if value_lower in self.blocked_senders:
            self.blocked_senders.discard(value_lower)
            removed = True
        if value_lower in self.blocked_domains:
            self.blocked_domains.discard(value_lower)
            removed = True
        return removed
