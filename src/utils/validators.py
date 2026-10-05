"""
Validation utilities for API request payloads.
"""

from typing import Dict, Any, Optional


def validate_analyze_request(data: Dict[str, Any]) -> Optional[str]:
    """Validate /api/v1/analyze request. Returns error message or None."""
    if not data:
        return "Request body must be JSON."

    content = data.get("content")
    if not content:
        return "'content' field is required."

    if not isinstance(content, str):
        return "'content' must be a string."

    if len(content.strip()) < 5:
        return "'content' must be at least 5 characters."

    if len(content) > 50_000:
        return "'content' must be under 50,000 characters."

    valid_sources = {"email", "sms", "chat", "web", "phone", "social_media", "unknown"}
    source = data.get("source", "unknown")
    if source not in valid_sources:
        return f"'source' must be one of: {', '.join(sorted(valid_sources))}."

    return None


def validate_train_request(data: Dict[str, Any]) -> Optional[str]:
    """Validate /api/v1/train request. Returns error message or None."""
    if not data:
        return "Request body must be JSON."

    examples = data.get("examples")
    if not examples:
        return "'examples' field is required."

    if not isinstance(examples, list):
        return "'examples' must be a list."

    if len(examples) == 0:
        return "'examples' list cannot be empty."

    if len(examples) > 1000:
        return "Maximum 1000 examples per request."

    for i, ex in enumerate(examples):
        if not isinstance(ex, dict):
            return f"Example #{i+1} must be an object."
        if "text" not in ex:
            return f"Example #{i+1} missing 'text' field."
        if "label" not in ex:
            return f"Example #{i+1} missing 'label' field."
        if ex["label"] not in (0, 1):
            return f"Example #{i+1}: 'label' must be 0 (legitimate) or 1 (scam)."
        if not isinstance(ex["text"], str) or len(ex["text"].strip()) < 5:
            return f"Example #{i+1}: 'text' must be a non-empty string."

    return None
