# GTL AI Security Platform - Installation Guide

**Version**: 1.0
**Last Updated**: November 2025
**Target Audience**: System Administrators, DevOps Engineers

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation Methods](#installation-methods)
4. [Step-by-Step Installation](#step-by-step-installation)
5. [Configuration](#configuration)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)
8. [Upgrade Procedures](#upgrade-procedures)
9. [Uninstallation](#uninstallation)

---

## Prerequisites

### Required Software

| Software | Minimum Version | Recommended Version | Purpose |
|----------|----------------|---------------------|---------|
| **Operating System** | Ubuntu 20.04 LTS | Ubuntu 22.04 LTS | Host OS |
| **Docker** | 20.10+ | 24.0+ | Containerization |
| **Docker Compose** | 2.0+ | 2.20+ | Multi-container orchestration |
| **Python** | 3.9 | 3.11+ | Application runtime |
| **Git** | 2.25+ | 2.40+ | Version control |

### Optional Software

- **nmap** 7.80+ - Network scanning
- **nuclei** 2.9+ - Vulnerability scanning
- **nikto** 2.1+ - Web server scanning
- **sqlmap** 1.6+ - SQL injection testing

### API Keys Required

1. **LLM Provider** (Choose one):
   - DeepSeek API Key (Recommended - most cost-effective)
   - OpenAI API Key
   - Anthropic API Key

2. **Security Tools** (Optional but recommended):
   - Shodan API Key - Internet-wide device discovery
   - Perplexity API Key - Web search capabilities
   - Google Search API - OSINT gathering

---

## System Requirements

### Minimum Requirements (Development/Testing)

```yaml
Environment: Development
CPU: 2 cores
RAM: 4 GB
Storage: 20 GB SSD
Network: 10 Mbps internet
OS: Ubuntu 20.04 LTS or equivalent
```

### Recommended Requirements (Production)

```yaml
Environment: Production
CPU: 4+ cores (8 recommended)
RAM: 16 GB (32 GB for high-traffic)
Storage: 100 GB SSD (NVMe preferred)
Network: 100 Mbps internet (1 Gbps preferred)
OS: Ubuntu 22.04 LTS
Backup: Daily automated backups
Monitoring: Prometheus + Grafana
```

### Storage Breakdown

| Component | Storage Required | Purpose |
|-----------|-----------------|---------|
| Application Code | 500 MB | GTL platform binaries |
| Docker Images | 2-3 GB | Container images |
| PostgreSQL Database | 10-50 GB | Scan results, client data |
| Redis Cache | 1-2 GB | Temporary cache |
| Scan Results | 20-50 GB | PDF reports, JSON outputs |
| Logs | 5-10 GB | Application logs |
| **Total** | **~100 GB** | **Full deployment** |

---

## Installation Methods

### Method 1: Docker Compose (Recommended)

**Best For**: Quick deployment, testing, production
**Time**: 10-15 minutes
**Difficulty**: Easy

### Method 2: Manual Installation

**Best For**: Custom deployments, development
**Time**: 30-45 minutes
**Difficulty**: Intermediate

### Method 3: Kubernetes (Advanced)

**Best For**: Large-scale deployments, auto-scaling
**Time**: 1-2 hours
**Difficulty**: Advanced

---

## Step-by-Step Installation

### Method 1: Docker Compose Installation (Recommended)

#### Step 1: Install Docker & Docker Compose

**Ubuntu/Debian:**

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo apt install docker-compose-plugin

# Verify installation
docker --version
docker compose version
```

**Expected Output:**
```
Docker version 24.0.7, build afdd53b
Docker Compose version v2.23.0
```

#### Step 2: Clone Repository

```bash
# Navigate to installation directory
cd /opt

# Clone GTL platform (replace with your repository URL)
sudo git clone https://github.com/your-org/gtl-ai-security.git
cd gtl-ai-security

# Set ownership
sudo chown -R $USER:$USER /opt/gtl-ai-security
```

#### Step 3: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit environment file
nano .env
```

**Required Configuration (.env):**

```bash
# ============================================
# CRITICAL: Must configure before starting
# ============================================

# LLM Provider (Choose one - DeepSeek recommended)
CAI_MODEL=alias0
DEEPSEEK_API_KEY=sk-your-deepseek-api-key-here

# Database
DATABASE_URL=postgresql://gtl_user:CHANGE_THIS_PASSWORD@postgres:5432/gtl_security

# Security
API_SECRET_KEY=GENERATE_RANDOM_64_CHAR_STRING_HERE

# Optional but recommended
SHODAN_API_KEY=your-shodan-key-here

# Email Alerts (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@gtl.pe
SMTP_PASSWORD=your-smtp-password
ALERT_EMAIL_TO=security@gtl.pe
```

**Generate Secure Secrets:**

```bash
# Generate API secret key
python3 -c "import secrets; print(secrets.token_urlsafe(64))"

# Generate database password
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

#### Step 4: Install Security Tools (Optional)

```bash
# Install nmap
sudo apt install -y nmap

# Install nuclei (vulnerability scanner)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install nikto (web scanner)
sudo apt install -y nikto

# Verify installations
nmap --version
nuclei -version
```

#### Step 5: Launch Platform

```bash
# Start all services
docker compose up -d

# Check service status
docker compose ps
```

**Expected Output:**
```
NAME                STATUS              PORTS
gtl_postgres        Up 10 seconds       0.0.0.0:5432->5432/tcp
gtl_redis           Up 10 seconds       0.0.0.0:6379->6379/tcp
gtl_api             Up 8 seconds        0.0.0.0:8000->8000/tcp
gtl_celery_worker   Up 8 seconds
gtl_celery_beat     Up 8 seconds
gtl_flower          Up 8 seconds        0.0.0.0:5555->5555/tcp
gtl_nginx           Up 5 seconds        0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
```

#### Step 6: Initialize Database

```bash
# Run database migrations
docker compose exec api alembic upgrade head

# Create initial admin user
docker compose exec api python -c "
from gtl_api_gateway.auth import create_user
create_user('admin', 'admin@gtl.pe', 'CHANGE_THIS_PASSWORD')
"
```

#### Step 7: Verify Installation

```bash
# Check API health
curl http://localhost:8000/api/v1/health

# Expected: {"status":"healthy","version":"1.0.0"}

# Check Celery workers
docker compose exec celery_worker celery -A gtl_security_scanner.scheduler inspect active

# View logs
docker compose logs -f api
```

---

### Method 2: Manual Installation (Without Docker)

#### Step 1: Install System Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.11
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install Redis
sudo apt install -y redis-server

# Install build tools
sudo apt install -y build-essential libpq-dev
```

#### Step 2: Setup PostgreSQL

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE gtl_security;
CREATE USER gtl_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE gtl_security TO gtl_user;
\q
```

#### Step 3: Clone and Setup Application

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/your-org/gtl-ai-security.git
cd gtl-ai-security

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

#### Step 4: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit with your settings
nano .env

# Update DATABASE_URL for local PostgreSQL
# DATABASE_URL=postgresql://gtl_user:your_password@localhost:5432/gtl_security
```

#### Step 5: Run Database Migrations

```bash
# Initialize database
alembic upgrade head

# Verify
psql -U gtl_user -d gtl_security -c "\dt"
```

#### Step 6: Start Services

**Terminal 1 - API Server:**
```bash
source venv/bin/activate
uvicorn gtl_api_gateway.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 - Celery Worker:**
```bash
source venv/bin/activate
celery -A gtl_security_scanner.scheduler worker --loglevel=info
```

**Terminal 3 - Celery Beat:**
```bash
source venv/bin/activate
celery -A gtl_security_scanner.scheduler beat --loglevel=info
```

**Terminal 4 - Flower (Optional):**
```bash
source venv/bin/activate
celery -A gtl_security_scanner.scheduler flower --port=5555
```

---

## Configuration

### Core Configuration Files

#### 1. Environment Variables (.env)

See [Step 3](#step-3-configure-environment) above for complete `.env` configuration.

#### 2. Scanner Profiles (config/scanner_profiles.yaml)

```yaml
# Customize scan profiles for your clients
logistics:
  name: "Logistics Security Assessment"
  tools:
    nmap:
      args: "-sV -sC -p-"
    nuclei:
      templates: [cves, exposures, misconfiguration]
  schedule:
    frequency: weekly
    day: sunday
    time: "02:00"
```

**Edit scanner profiles:**
```bash
nano config/scanner_profiles.yaml
```

#### 3. CAI Framework (config/cai_config.yaml)

```yaml
model:
  provider: deepseek
  name: alias0
  temperature: 0.7

pricing:
  daily_limit: 50.0  # USD
  monthly_limit: 1000.0
```

**Edit CAI config:**
```bash
nano config/cai_config.yaml
```

### Advanced Configuration

#### SSL/TLS Setup (Production)

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d gtl.pe -d www.gtl.pe

# Auto-renewal
sudo certbot renew --dry-run
```

#### Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# Verify
sudo ufw status
```

#### Backup Configuration

```bash
# Create backup script
cat > /opt/gtl-ai-security/scripts/backup.sh <<'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/gtl"

# Backup database
docker compose exec -T postgres pg_dump -U gtl_user gtl_security | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Backup scan results
tar -czf $BACKUP_DIR/scans_$DATE.tar.gz scan_results/

# Keep only last 7 days
find $BACKUP_DIR -type f -mtime +7 -delete
EOF

chmod +x /opt/gtl-ai-security/scripts/backup.sh

# Schedule daily backups
(crontab -l 2>/dev/null; echo "0 3 * * * /opt/gtl-ai-security/scripts/backup.sh") | crontab -
```

---

## Verification

### Health Checks

```bash
# 1. API Health Check
curl http://localhost:8000/api/v1/health

# Expected:
# {"status":"healthy","version":"1.0.0","database":"connected","redis":"connected"}

# 2. Database Connection
docker compose exec postgres psql -U gtl_user -d gtl_security -c "SELECT version();"

# 3. Redis Connection
docker compose exec redis redis-cli ping
# Expected: PONG

# 4. Celery Workers
docker compose exec celery_worker celery -A gtl_security_scanner.scheduler inspect ping

# 5. Check running containers
docker compose ps
# All services should show "Up"
```

### Functional Tests

```bash
# Test scanner module
python3 <<EOF
import asyncio
from gtl_security_scanner import SecurityScanner, ScanConfig, ScanTarget

async def test():
    scanner = SecurityScanner()
    config = ScanConfig(
        client_id="test",
        profile="quick_scan",
        target=ScanTarget(ip_address="127.0.0.1"),
        tools_enabled={"nmap": True}
    )
    result = await scanner.run_scan(config)
    print(f"✓ Scanner test passed: {result.status}")

asyncio.run(test())
EOF
```

### Access Web Interfaces

| Service | URL | Credentials |
|---------|-----|-------------|
| **API Documentation** | http://localhost:8000/docs | N/A (public) |
| **Flower (Celery Monitor)** | http://localhost:5555 | N/A (public) |
| **Production Dashboard** | http://localhost:80 | admin / (set password) |

---

## Troubleshooting

### Issue 1: Docker Compose Fails to Start

**Symptoms:**
```
Error: Cannot connect to Docker daemon
```

**Solution:**
```bash
# Check Docker service
sudo systemctl status docker

# Start Docker if stopped
sudo systemctl start docker

# Enable Docker on boot
sudo systemctl enable docker

# Verify user in docker group
groups $USER
# If docker not listed:
sudo usermod -aG docker $USER
newgrp docker
```

### Issue 2: Database Connection Refused

**Symptoms:**
```
psycopg2.OperationalError: could not connect to server
```

**Solution:**
```bash
# Check PostgreSQL container
docker compose ps postgres

# View PostgreSQL logs
docker compose logs postgres

# Verify DATABASE_URL in .env
grep DATABASE_URL .env

# Restart PostgreSQL
docker compose restart postgres
```

### Issue 3: API Returns 500 Error

**Symptoms:**
```
{"detail":"Internal Server Error"}
```

**Solution:**
```bash
# Check API logs
docker compose logs api

# Common issues:
# 1. Missing API key
grep DEEPSEEK_API_KEY .env

# 2. Database not migrated
docker compose exec api alembic current
docker compose exec api alembic upgrade head

# 3. Restart API
docker compose restart api
```

### Issue 4: Celery Worker Not Processing Tasks

**Symptoms:**
```
No active tasks in Celery
```

**Solution:**
```bash
# Check Celery worker logs
docker compose logs celery_worker

# Verify Redis connection
docker compose exec redis redis-cli ping

# Check worker status
docker compose exec celery_worker celery -A gtl_security_scanner.scheduler inspect active

# Restart workers
docker compose restart celery_worker celery_beat
```

### Issue 5: Scans Timing Out

**Symptoms:**
```
ScanResult: status=failed, error=timeout
```

**Solution:**
```bash
# Increase timeout in .env
SCAN_TIMEOUT_MINUTES=60

# Restart services
docker compose restart

# Check system resources
docker stats
```

### Issue 6: High Memory Usage

**Symptoms:**
```
Container killed due to OOM
```

**Solution:**
```bash
# Check container resource usage
docker stats

# Limit container memory in docker-compose.yml:
services:
  api:
    mem_limit: 2g

# Restart with new limits
docker compose down && docker compose up -d
```

### Issue 7: SSL Certificate Issues

**Symptoms:**
```
ERR_CERT_AUTHORITY_INVALID
```

**Solution:**
```bash
# Verify certificate
sudo certbot certificates

# Renew if expired
sudo certbot renew --force-renewal

# Restart nginx
docker compose restart nginx
```

---

## Upgrade Procedures

### Minor Version Upgrade (1.0.x → 1.0.y)

```bash
# 1. Backup current installation
./scripts/backup.sh

# 2. Pull latest code
cd /opt/gtl-ai-security
git pull origin main

# 3. Update dependencies
docker compose build --no-cache

# 4. Restart services
docker compose down && docker compose up -d

# 5. Verify
curl http://localhost:8000/api/v1/health
```

### Major Version Upgrade (1.x → 2.x)

```bash
# 1. Read upgrade guide
cat UPGRADE_GUIDE.md

# 2. Full backup
./scripts/backup.sh

# 3. Stop services
docker compose down

# 4. Upgrade database schema
docker compose up -d postgres
docker compose exec api alembic upgrade head

# 5. Update code
git checkout v2.0.0

# 6. Rebuild containers
docker compose build --no-cache

# 7. Start services
docker compose up -d

# 8. Verify and test
./scripts/verify_installation.sh
```

---

## Uninstallation

### Complete Removal

```bash
# 1. Stop all services
cd /opt/gtl-ai-security
docker compose down

# 2. Remove containers and volumes
docker compose down -v

# 3. Remove images
docker rmi $(docker images | grep gtl | awk '{print $3}')

# 4. Remove application directory
sudo rm -rf /opt/gtl-ai-security

# 5. Remove PostgreSQL data (if manual install)
sudo systemctl stop postgresql
sudo apt remove --purge postgresql postgresql-contrib

# 6. Remove Redis (if manual install)
sudo systemctl stop redis
sudo apt remove --purge redis-server

# 7. Clean up user
sudo userdel gtl_user
```

### Partial Removal (Keep Data)

```bash
# Stop services but keep data
docker compose down

# Remove only application code
cd /opt
sudo rm -rf gtl-ai-security

# Data volumes preserved in:
# - Docker volumes (docker volume ls)
# - /var/lib/postgresql/data
```

---

## Post-Installation Steps

### 1. Create First Admin User

```bash
docker compose exec api python -c "
from gtl_api_gateway.auth import create_user
create_user('admin', 'admin@gtl.pe', 'SecurePassword123!')
print('Admin user created')
"
```

### 2. Schedule First Scan

```python
# In Python shell or script
from gtl_security_scanner import ScanScheduler, ScanTarget

scheduler = ScanScheduler()
scheduler.add_job(
    client_id="demo_client",
    target=ScanTarget(network_range="192.168.1.0/24"),
    schedule="weekly",
    profile="logistics"
)
```

### 3. Configure Monitoring

```bash
# Install Prometheus & Grafana
docker run -d -p 9090:9090 prom/prometheus
docker run -d -p 3000:3000 grafana/grafana

# Import GTL dashboard
# (dashboard JSON provided separately)
```

### 4. Setup Alerts

Edit `.env`:
```bash
# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Email
ALERT_EMAIL_TO=security-team@gtl.pe

# Webhooks
CUSTOM_WEBHOOK_URL=https://your-siem.com/webhooks
```

---

## Support

### Documentation
- **Installation Issues**: This guide
- **API Reference**: `/docs/technical/API_REFERENCE.md`
- **Development Guide**: `/docs/technical/AGENT_DEVELOPMENT.md`

### Community
- **GitHub Issues**: https://github.com/your-org/gtl-ai-security/issues
- **Slack**: https://gtl-security.slack.com
- **Email**: support@gtl.pe

### Professional Support
- **Starter Tier**: Email support (48h response)
- **Professional Tier**: Email + phone (24h response)
- **Enterprise Tier**: Dedicated support engineer

---

**Installation Complete!** 🎉

Next: [API Reference](API_REFERENCE.md) | [Agent Development](AGENT_DEVELOPMENT.md)
