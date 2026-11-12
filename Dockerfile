# Production Multi-Stage Dockerfile for PS13 GovPII Detector
FROM python:3.11-slim

# Install system dependencies including Tesseract OCR and OpenCV libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Pre-generate sample documents
RUN python -c "from backend.assets.generator import create_all_sample_assets; create_all_sample_assets('backend/assets/samples')"

EXPOSE 8000 8501

# Entrypoint script to start both FastAPI Backend and Streamlit Frontend
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port 8000 & streamlit run frontend/app.py --server.port 8501 --server.address 0.0.0.0"]
