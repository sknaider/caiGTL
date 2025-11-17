FROM python:3.11-slim

LABEL maintainer="GTL Security Peru <dev@gtl.pe>"
LABEL description="GTL AI Security Platform"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libpq-dev \
    nmap \
    nikto \
    sqlmap \
    netcat-openbsd \
    curl \
    wget \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (latest version from GitHub)
RUN wget -qO- https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    -O nuclei.zip && \
    unzip nuclei.zip -d /usr/local/bin && \
    rm nuclei.zip && \
    chmod +x /usr/local/bin/nuclei

# Install Nuclei templates
RUN nuclei -update-templates || true

# Install CAI Framework (optional - uncomment if using CAI)
# RUN git clone https://github.com/aliasrobotics/cai /opt/cai && \
#     cd /opt/cai && \
#     pip install -e .

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/scan_results /app/logs /var/log/gtl

# Expose ports
EXPOSE 8000

# Default command (overridden in docker-compose.yml)
CMD ["uvicorn", "gtl_api_gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
