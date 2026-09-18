FROM python:3.11-slim

WORKDIR /app

# Install system deps for build & spaCy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy language model for Presidio PII analyzer
RUN python -m spacy download en_core_web_lg

# Copy source code
COPY . .

# Create data directory for persistent SQLite audit log
RUN mkdir -p data

EXPOSE 8000 8501

# Default: Run FastAPI Gateway
CMD ["uvicorn", "gateway.api:app", "--host", "0.0.0.0", "--port", "8000"]