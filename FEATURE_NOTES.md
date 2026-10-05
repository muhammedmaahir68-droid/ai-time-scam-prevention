# Feature: AI Detection Engine

## Branch: `feature/ai-detection`

This branch contains the full AI-based time-scam detection engine including:

### New in this branch:
- ✅ Multi-layer detection pipeline (Rule Engine + Time Pressure + Linguistic + URL)
- ✅ BiLSTM + Multi-Head Attention classifier (`src/models/classifier.py`)
- ✅ Gradient Boosting on TF-IDF features
- ✅ 60+ scam pattern rules across 8 scam types
- ✅ Automated protection engine with Slack/Discord alerting
- ✅ Real-time web dashboard
- ✅ REST API (6 endpoints)
- ✅ CLI tool with interactive mode
- ✅ Pytest test suite

### How to test:
```bash
# Run demo
python scripts/cli.py demo

# Interactive mode
python scripts/cli.py analyze --interactive

# Train models
python scripts/train_models.py --augment
```
