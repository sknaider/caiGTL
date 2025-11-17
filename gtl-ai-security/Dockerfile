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
    netcat-openbsd \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

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
