"""
AI-Based Time-Scam Prevention & Automated Protection System
===========================================================
Main application entry point.

This system uses deep learning, NLP, and rule-based heuristics
to detect and prevent time-pressure based scams in real-time.
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
from loguru import logger

# Load environment variables
load_dotenv()

from src.api.app import create_app
from src.core.database import init_db
from src.utils.logger import setup_logger

def main():
    """Main entry point for the AI Scam Prevention System."""
    setup_logger()
    
    logger.info("=" * 60)
    logger.info("  AI Time-Scam Prevention & Protection System v1.0")
    logger.info("=" * 60)
    logger.info("Initializing system components...")
    
    # Initialize database
    init_db()
    
    # Create Flask app
    app = create_app()
    
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "True").lower() == "true"
    
    logger.info(f"Starting server on http://0.0.0.0:{port}")
    logger.info("AI models loaded and protection system active!")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        use_reloader=False  # Prevents double model loading
    )


if __name__ == "__main__":
    main()
