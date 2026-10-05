"""
Logger configuration using Loguru.
"""

import os
import sys
from pathlib import Path
from loguru import logger


def setup_logger():
    """Configure the Loguru logger for the application."""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_file  = os.getenv("LOG_FILE", "./logs/app.log")

    # Ensure log directory exists
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    # Remove default handler
    logger.remove()

    # Console handler (colored)
    logger.add(
        sys.stdout,
        level=log_level,
        colorize=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        )
    )

    # File handler (JSON, rotating)
    logger.add(
        log_file,
        level="DEBUG",
        rotation="10 MB",
        retention="30 days",
        compression="gz",
        serialize=True,  # JSON format for log analysis
        enqueue=True      # Thread-safe
    )

    logger.info(f"Logger initialized. Level={log_level}, File={log_file}")
