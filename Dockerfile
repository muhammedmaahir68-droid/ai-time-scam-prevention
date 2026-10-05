FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc g++ git curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download NLP data
RUN python -m nltk.downloader punkt stopwords wordnet averaged_perceptron_tagger

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/models data/incidents data/quarantine logs

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/health || exit 1

# Run application
CMD ["python", "main.py"]
