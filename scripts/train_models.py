"""
Training Script for AI Time-Scam Prevention Models
====================================================
Generates synthetic training data and trains both the
Gradient Boosting and LSTM classifiers.

Usage:
    python scripts/train_models.py
    python scripts/train_models.py --epochs 30 --augment
"""

import sys
import json
import random
import argparse
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger
from src.models.classifier import ModelManager


# ─────────────────────────────────────────────────────────────
# Synthetic Training Data
# ─────────────────────────────────────────────────────────────

SCAM_TEXTS = [
    # Urgency manipulation
    "ACT NOW! This offer expires in 2 hours. Click here or lose your chance FOREVER!",
    "URGENT: Your account will be suspended in 24 hours. Verify immediately.",
    "LAST CHANCE! Only 3 spots left. Must respond in the next 30 minutes!",
    "Final warning: Your subscription ends tonight. Renew NOW or lose access!",
    "HURRY! Limited time offer expires at midnight. Don't miss out!",
    "You have been selected! But you must respond within the next 10 minutes.",
    "IMMEDIATE ACTION REQUIRED: Your payment is overdue. Pay now to avoid legal action!",
    "WARNING: Your Microsoft account will be closed in 12 hours. Click here to verify!",

    # Financial scams
    "Guaranteed 500% returns in just 48 hours! Our crypto bot never fails. Invest now!",
    "Bitcoin will SKYROCKET tomorrow! Insider tip - buy before it's too late!",
    "Double your money in 3 days! Risk-free investment opportunity. Act fast!",
    "Exclusive offer: 200% ROI guaranteed. Only 5 investors accepted. Apply today!",
    "Our secret trading algorithm made $10,000 in just 2 hours. Join now!",
    "FREE money! Government stimulus program - claim your $2,500 before deadline.",
    "We can recover your lost crypto funds. Pay a small fee and get it all back!",
    "FLASH SALE: Investment property - 80% off market value. Offer ends in 6 hours!",

    # Phishing with urgency
    "Your Amazon account has been compromised! Verify your identity in the next hour!",
    "PayPal security alert: Unusual activity detected. Confirm account NOW or it will be locked!",
    "Apple ID suspended: Verify your information within 24 hours or lose your account!",
    "IRS URGENT: You owe $3,400 in back taxes. Pay immediately to avoid arrest warrant!",
    "Your bank account has been frozen. Call this number NOW to unlock it!",
    "Google detected suspicious login! Verify your Google account in 15 minutes!",
    "Netflix subscription will be cancelled. Update payment details immediately!",
    "Social Security Administration: Your SSN has been suspended. Call now!",

    # Social engineering / fake emergency
    "Mom I'm in trouble! I got arrested and need $500 in gift cards. Don't tell Dad!",
    "This is the FBI. You are under investigation. Cooperate now or face consequences.",
    "Hi dear, I'm stranded in London after being robbed. Please send $200 via Western Union!",
    "URGENT: Your grandson is in hospital! Send money immediately to help him!",
    "I found your number. I love you and need your help. Please send gift cards.",
    "You've won $1,000,000 in our lottery! But you must claim within 24 hours!",

    # Time-pressure countdown
    "⏰ COUNTDOWN: Only 2 hours left to claim your prize! Timer is ticking!",
    "The clock is ticking! Your exclusive discount disappears at midnight TONIGHT!",
    "FLASH DEAL: 95% off - expires in 00:47:23! Buy now or pay full price!",
    "Limited time: Act in the next 5 minutes or this deal is gone forever!",
]

LEGITIMATE_TEXTS = [
    # Normal emails
    "Hi John, I wanted to follow up on our meeting from last week. Let me know if you have questions.",
    "Your order #12345 has been shipped. Estimated delivery: 3-5 business days.",
    "Monthly newsletter: Here are the top news stories from October 2024.",
    "Reminder: Your dentist appointment is scheduled for next Tuesday at 2 PM.",
    "Thank you for your purchase! Your receipt is attached.",
    "Team meeting tomorrow at 10am. Agenda: Q4 planning and budget review.",
    "Your account statement for September is now available. Log in to view it.",
    "We'd love your feedback! How was your experience with our service?",

    # Legitimate offers
    "Our annual sale starts Friday! Up to 30% off select items. No rush - sale runs all weekend.",
    "New blog post: 5 tips for better time management. Read when you get a chance.",
    "Your free trial ends in 7 days. Upgrade anytime at your convenience.",
    "Friendly reminder: Project deadline is end of month. Let us know if you need help.",
    "Enjoy 15% off your next purchase with code WELCOME15. Valid for 30 days.",
    "We're updating our privacy policy on November 1st. Please review the changes.",
    "Your package was delivered at 2:34 PM. A photo was left at the door.",
    "Congratulations on your 1-year anniversary with us! Here's a small thank-you gift.",

    # Professional communications
    "Please find attached the quarterly report for your review.",
    "I'll be out of office next week. For urgent matters, contact my colleague Sarah.",
    "Your application has been received. We'll be in touch within 2 weeks.",
    "Schedule a demo at your convenience: calendly.com/ourcompany",
    "New features available in the latest app update. Update at your leisure.",
    "Account password changed successfully. If this wasn't you, contact support.",
    "Your subscription renews on December 15th. Manage preferences in your account.",
    "We noticed you haven't logged in recently. We're here if you need help.",
]


def augment_text(text: str, n: int = 2) -> list:
    """Simple text augmentation by synonym replacement."""
    augmented = [text]
    replacements = {
        "now":       ["immediately", "right away", "at once"],
        "urgent":    ["critical", "emergency", "pressing"],
        "click":     ["tap", "press", "select"],
        "account":   ["profile", "membership"],
        "offer":     ["deal", "opportunity", "promotion"],
    }
    for _ in range(n - 1):
        new_text = text
        for word, synonyms in replacements.items():
            if word in new_text.lower():
                new_text = new_text.replace(word, random.choice(synonyms), 1)
        augmented.append(new_text)
    return augmented


def generate_training_data(augment: bool = False):
    """Build labeled training dataset."""
    texts  = []
    labels = []

    scam_set = SCAM_TEXTS.copy()
    legit_set = LEGITIMATE_TEXTS.copy()

    if augment:
        augmented_scams = []
        for t in SCAM_TEXTS:
            augmented_scams.extend(augment_text(t, 3))
        scam_set = augmented_scams

    for text in scam_set:
        texts.append(text)
        labels.append(1)

    for text in legit_set:
        texts.append(text)
        labels.append(0)

    # Shuffle
    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)

    return list(texts), list(labels)


# ─────────────────────────────────────────────────────────────
# Main Training Routine
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train AI Scam Detection Models")
    parser.add_argument("--epochs",  type=int, default=20, help="Training epochs for LSTM")
    parser.add_argument("--augment", action="store_true", help="Augment training data")
    parser.add_argument("--model-dir", default="./data/models", help="Model output directory")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  AI Time-Scam Detection — Model Training")
    logger.info("=" * 60)

    texts, labels = generate_training_data(augment=args.augment)

    scam_count = sum(labels)
    legit_count = len(labels) - scam_count
    logger.info(f"Dataset: {len(texts)} total | {scam_count} scam | {legit_count} legitimate")

    # Save training data sample
    sample_path = Path("./data/samples/training_sample.json")
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    with open(sample_path, "w") as f:
        json.dump(
            [{"text": t, "label": l} for t, l in zip(texts[:10], labels[:10])],
            f, indent=2
        )

    # Train models
    manager = ModelManager(model_dir=args.model_dir)
    results = manager.train(texts, labels)

    logger.info("=" * 60)
    logger.info("Training Complete! Results:")
    for model_name, metrics in results.items():
        logger.info(f"  {model_name}: {metrics}")
    logger.info("=" * 60)
    logger.success("Models saved and ready for inference.")


if __name__ == "__main__":
    main()
