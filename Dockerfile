FROM python:3.11-slim

LABEL maintainer="HoneyMed Project"
LABEL description="IoMT Honeypot with ML-based Attack Detection"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create data directories
RUN mkdir -p data/raw data/processed data/models logs

# Expose ports
# 80    - Web Portal (Patient Monitor UI)
# 22    - SSH Honeypot
# 1883  - MQTT Listener
# 2575  - HL7 Listener
# 11112 - DICOM Listener
# 5001  - Dashboard API
# 8501  - Streamlit Dashboard
EXPOSE 80 22 1883 2575 11112 5001 8501

# Default: run full system
CMD ["python", "main.py", "--mode", "full"]
