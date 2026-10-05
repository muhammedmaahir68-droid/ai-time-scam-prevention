# 🛡️ AI-Based Time-Scam Prevention & Automated Protection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15-orange?logo=tensorflow)
![License](https://img.shields.io/badge/License-MIT-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**An enterprise-grade AI system that detects and automatically responds to time-pressure-based scams in real time.**

[🔍 Features](#features) · [🚀 Quick Start](#quick-start) · [📡 API Reference](#api-reference) · [🧠 AI Pipeline](#ai-pipeline) · [🐳 Docker](#docker)

</div>

---

## 🎯 What It Does

ScamGuard AI detects **time-pressure manipulation tactics** used by scammers — fake deadlines, countdown urgency, phishing with time pressure, financial fraud, social engineering, and more — using a **multi-layer AI detection pipeline** that combines deep learning, NLP, and rule-based heuristics.

### Scam Types Detected

| Type | Examples |
|------|----------|
| ⏰ **Urgency Manipulation** | "Act NOW!", "Expires in 2 hours!", "Last chance!" |
| 🔢 **Fake Countdowns** | Fake timers, "Only 3 spots left!", false scarcity |
| 🎣 **Phishing + Time Pressure** | "Verify account in 24 hours or lose access!" |
| 💰 **Financial Fraud** | "500% guaranteed returns in 48 hours!", crypto pump-and-dump |
| 🆘 **Fake Emergencies** | "Mom I'm in jail!", stranded relative scams |
| 👤 **Social Engineering** | Impersonation (IRS, Microsoft, Apple), romance scams |
| ₿ **Crypto Scams** | "Buy before it moons!", "Insider tip!" |
| 🔗 **Malicious URLs** | Lookalike domains, IP-based URLs, suspicious TLDs |

---

## 🧠 AI Pipeline

```
Text Input
    │
    ├─► 📋 Rule Engine        (40% weight) — Pattern matching on 60+ scam patterns
    ├─► ⏰ Time Pressure      (25% weight) — Countdown & urgency word analysis  
    ├─► 🔤 Linguistic         (15% weight) — Caps ratio, exclamations, sentence structure
    ├─► 🌐 URL Analysis       (20% weight) — Lookalike domains, suspicious TLDs, IP hosts
    │
    └─► 🎯 Ensemble Score → Risk Level → Automated Protection → Response
```

**Risk Levels:**
| Level | Score | Action |
|-------|-------|--------|
| ✅ Safe | < 0.20 | Log only |
| 🟡 Low | 0.20–0.45 | Flag |
| 🟠 Medium | 0.45–0.65 | Flag + Alert |
| 🔴 High | 0.65–0.82 | Block + Alert |
| 💀 Critical | > 0.82 | Block + Alert + Quarantine + Incident Report |

---

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/YOUR_USERNAME/ai-time-scam-prevention.git
cd ai-time-scam-prevention

# Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings (optional for basic usage)
```

### 3. Run the Server

```bash
python main.py
```

Open your browser at **http://localhost:5000** — the dashboard is ready!

### 4. CLI Quick Test

```bash
# Interactive CLI
python scripts/cli.py analyze --interactive

# Demo mode (shows 5 sample detections)
python scripts/cli.py demo

# Analyze a specific message
python scripts/cli.py analyze "ACT NOW! Your account expires in 2 hours!"

# Train AI models
python scripts/train_models.py --augment
```

---

## 📡 API Reference

### `POST /api/v1/analyze`
Analyze any text content for scam indicators.

**Request:**
```json
{
  "content": "ACT NOW! Your PayPal account expires in 2 hours! Verify immediately!",
  "source": "email"
}
```

**Response:**
```json
{
  "content_hash": "a1b2c3d4",
  "is_scam": true,
  "risk_level": "critical",
  "overall_score": 0.8834,
  "scam_types": ["urgency_manipulation", "phishing_time_pressure"],
  "signals": [
    {
      "signal_type": "urgency.extreme_urgency",
      "severity": 0.8,
      "matched_text": "ACT NOW"
    }
  ],
  "recommendations": [
    "⛔ DO NOT respond or click any links.",
    "🔒 Block the sender immediately."
  ],
  "processing_time_ms": 12.4
}
```

### `POST /api/v1/analyze/email`
```json
{
  "subject": "URGENT: Account suspended",
  "body":    "Your account will be closed in 24 hours...",
  "sender":  "alert@suspicious.xyz"
}
```

### `POST /api/v1/analyze/url`
```json
{
  "url": "http://paypa1-verify.xyz.tk/login"
}
```

### `POST /api/v1/train`
Submit labeled training examples to improve the model.
```json
{
  "examples": [
    {"text": "ACT NOW! Last chance!", "label": 1},
    {"text": "Your meeting is at 3pm.", "label": 0}
  ]
}
```

### `GET /api/v1/stats`
Returns system statistics and detection rate.

### `GET /api/v1/health`
Health check endpoint.

---

## 🔒 Automated Protection Features

When high-confidence scams are detected, the system automatically:

- **🚩 Flags** — Marks content in the database
- **🔒 Blocks** — Adds sender/domain to block list
- **🔔 Alerts** — Sends real-time notifications (Slack/Discord/console)
- **🗄️ Quarantines** — Stores flagged content in `./data/quarantine/`
- **📋 Reports** — Generates structured incident reports in `./data/incidents/`

Configure webhooks in `.env`:
```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## 🤖 AI Models

The system uses **two complementary ML models**:

### 1. BiLSTM + Multi-Head Attention
- Deep learning architecture for sequence-level understanding
- Bidirectional LSTM captures contextual relationships
- Multi-head self-attention for key phrase focus
- Trained with early stopping and learning rate scheduling

### 2. Gradient Boosting on TF-IDF
- Fast, interpretable alternative
- TF-IDF with unigrams and trigrams (1–3 n-grams)
- 200 estimators with max depth 5
- Used as ensemble complement to LSTM

**Train the models:**
```bash
python scripts/train_models.py --epochs 30 --augment
```

---

## 🐳 Docker

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src --cov-report=html

# Specific test file
pytest tests/test_detector.py -v
```

---

## 📁 Project Structure

```
ai-time-scam-prevention/
├── main.py                    # Application entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── src/
│   ├── api/
│   │   └── app.py             # Flask REST API (all endpoints)
│   ├── core/
│   │   ├── detector.py        # Main AI detection pipeline
│   │   └── database.py        # SQLAlchemy models
│   ├── models/
│   │   └── classifier.py      # LSTM + Gradient Boosting classifiers
│   ├── protection/
│   │   └── automated.py       # Automated response engine
│   └── utils/
│       ├── validators.py      # Request validation
│       └── logger.py          # Logging configuration
│
├── frontend/
│   ├── templates/
│   │   └── dashboard.html     # Web dashboard
│   └── static/
│       ├── css/dashboard.css
│       └── js/dashboard.js
│
├── scripts/
│   ├── train_models.py        # Model training script
│   └── cli.py                 # Command-line tool
│
├── tests/
│   ├── test_detector.py       # Detection engine tests
│   └── test_api.py            # API endpoint tests
│
└── data/
    ├── models/                # Trained model files
    ├── incidents/             # Generated incident reports
    ├── quarantine/            # Quarantined content
    └── samples/               # Training data samples
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -m 'Add my feature'`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This system is designed for educational and defensive security purposes. Always validate results through multiple channels. Not a substitute for professional cybersecurity advice.

---

<div align="center">
Built with ❤️ to fight scammers | <strong>ScamGuard AI v1.0</strong>
</div>
