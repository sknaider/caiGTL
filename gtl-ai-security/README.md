# GTL AI Security Platform

**Automated Penetration Testing + Threat Detection for Peruvian Logistics Sector**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 🎯 Overview

GTL AI Security Platform provides AI-powered automated security assessments specifically designed for:
- **Logistics Companies** - EDI systems, customs data, supply chain security
- **Medical AI Providers** - HIPAA compliance, PHI protection, endpoint security
- **E-commerce** - Payment security, data protection, API security

Built on the [CAI Framework](https://github.com/aliasrobotics/cai) with custom agents for Peruvian market.

---

## ✨ Features

### 🔍 Automated Security Scanning
- Network discovery and port scanning (nmap)
- Web vulnerability scanning (nuclei, nikto)
- SQL injection testing (sqlmap)
- Scheduled continuous scanning (daily/weekly/monthly)

### 🚨 Threat Detection
- Real-time network traffic analysis
- ML-based anomaly detection
- MITRE ATT&CK mapping
- Instant alert notifications

### 📋 Compliance Auditing
- HIPAA compliance automation
- ISO 27001 assessment
- Peruvian customs regulations (SUNAT)
- Evidence collection and reporting

### 🤖 AI-Powered Agents
- Logistics security specialist
- Medical AI compliance expert
- Customs data protection auditor
- Multi-agent orchestration

### 📊 Client Dashboard
- Real-time vulnerability metrics
- Executive and technical reports
- PDF/HTML/JSON export
- Webhook integrations

---

## 🚀 Quick Start (< 5 minutes)

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- 4GB RAM minimum

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/gtl-ai-security.git
cd gtl-ai-security

# Copy environment template
cp .env.example .env

# Edit .env with your API keys
nano .env

# Start all services with Docker Compose
docker-compose up -d

# Verify installation
curl http://localhost:8000/api/v1/health
```

**Dashboard**: http://localhost:3000
**API Docs**: http://localhost:8000/docs

---

## 📦 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    GTL Dashboard                         │
│              (React + TypeScript)                        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  API Gateway (FastAPI)                   │
│     Authentication │ Rate Limiting │ Webhooks            │
└──────────────────────┬──────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Security   │ │   Threat    │ │ Compliance  │
│  Scanner    │ │  Detector   │ │  Auditor    │
└─────────────┘ └─────────────┘ └─────────────┘
        │              │              │
        └──────────────┼──────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              CAI Framework + Custom Agents               │
│   Logistics Agent │ Medical AI Agent │ Customs Agent    │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 Configuration

### Environment Variables

Create `.env` file:

```bash
# CAI Framework
CAI_MODEL=alias0
DEEPSEEK_API_KEY=sk-your-key-here
SHODAN_API_KEY=your-shodan-key

# Database
DATABASE_URL=postgresql://gtl:password@localhost:5432/gtl_security

# Redis
REDIS_URL=redis://localhost:6379/0

# API Gateway
API_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Scanning
SCAN_TIMEOUT_MINUTES=30
MAX_CONCURRENT_SCANS=5

# Alerts
WEBHOOK_URL=https://your-webhook.com/alerts
ALERT_EMAIL=security@gtl.pe
```

---

## 📖 Usage

### 1. Create a Scan via API

```bash
curl -X POST http://localhost:8000/api/v1/scans/create \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24",
    "scan_type": "comprehensive",
    "client_id": "logistics_company_1"
  }'
```

### 2. Schedule Automated Scans

```python
from gtl_security_scanner.scheduler import ScanScheduler

scheduler = ScanScheduler()
scheduler.add_job(
    client_id="logistics_company_1",
    target="192.168.1.0/24",
    schedule="daily",
    scan_profile="logistics"
)
```

### 3. Use Custom Agents Directly

```python
import asyncio
from gtl_agents.logistics_security_agent import logistics_security_agent
from cai.sdk.agents import Runner

async def main():
    result = await Runner.run(
        logistics_security_agent,
        input="Assess security of EDI system at 10.0.1.50"
    )
    print(result.final_output)

asyncio.run(main())
```

### 4. Generate Compliance Report

```python
from gtl_compliance_auditor.hipaa_checker import HIPAAChecker

checker = HIPAAChecker()
report = checker.audit_system(
    target="medical_ai_server.example.com",
    scope=["encryption", "access_control", "logging"]
)
print(report.to_pdf("hipaa_report.pdf"))
```

---

## 🏗️ Development

### Local Setup (without Docker)

```bash
# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install CAI framework
pip install cai-framework

# Run database migrations
alembic upgrade head

# Start API server
uvicorn gtl_api_gateway.main:app --reload --port 8000

# Start Celery worker (in another terminal)
celery -A gtl_security_scanner.tasks worker --loglevel=info

# Start scheduler (in another terminal)
celery -A gtl_security_scanner.tasks beat --loglevel=info
```

### Run Tests

```bash
# All tests
pytest

# Specific module
pytest gtl_security_scanner/tests/

# With coverage
pytest --cov=gtl_security_scanner --cov-report=html
```

### Code Quality

```bash
# Format code
black .
isort .

# Lint
ruff check .

# Type checking
mypy gtl_security_scanner gtl_api_gateway gtl_agents
```

---

## 📁 Project Structure

```
gtl-ai-security/
├── config/                      # Configuration files
│   ├── cai_config.yaml         # CAI framework settings
│   ├── scanner_profiles.yaml   # Scan profiles by sector
│   └── compliance_rules.yaml   # Compliance check definitions
│
├── gtl_security_scanner/        # Core vulnerability scanner
│   ├── scanner.py              # Main scanner orchestrator
│   ├── scheduler.py            # Automated scan scheduling
│   ├── reporter.py             # Report generation
│   ├── parsers/                # Tool output parsers
│   └── tests/                  # Unit tests
│
├── gtl_threat_detector/         # Real-time threat detection
│   ├── network_analyzer.py     # Network traffic analysis
│   ├── ml_models/              # Anomaly detection models
│   └── alerting.py             # Alert management
│
├── gtl_compliance_auditor/      # Compliance automation
│   ├── hipaa_checker.py        # HIPAA compliance
│   ├── iso27001_checker.py     # ISO 27001 assessment
│   └── sunat_compliance.py     # Peruvian regulations
│
├── gtl_api_gateway/             # RESTful API
│   ├── main.py                 # FastAPI application
│   ├── auth.py                 # Authentication/authorization
│   ├── routes/                 # API endpoints
│   └── models/                 # Pydantic models
│
├── gtl_agents/                  # Custom CAI agents
│   ├── logistics_security_agent.py
│   ├── medical_ai_compliance_agent.py
│   └── customs_data_protection_agent.py
│
├── gtl_dashboard/               # React web UI
│   └── src/
│
├── scripts/                     # Utility scripts
│   ├── setup.sh                # Initial setup
│   ├── deploy.sh               # Deployment script
│   └── seed_data.py            # Sample data
│
├── docs/                        # Documentation
│   ├── API.md                  # API reference
│   ├── DEPLOYMENT.md           # Deployment guide
│   └── USAGE.md                # Usage examples
│
├── docker-compose.yml           # Multi-container setup
├── requirements.txt             # Python dependencies
└── .env.example                # Environment template
```

---

## 🔐 Security

### API Authentication

All API endpoints require authentication via API keys or JWT tokens:

```bash
# Get API key
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin&password=password"

# Use API key
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8000/api/v1/scans
```

### Data Protection

- All data encrypted at rest (PostgreSQL encryption)
- TLS/SSL for all network communication
- API keys hashed with bcrypt
- Rate limiting to prevent abuse
- RBAC (Role-Based Access Control)

---

## 📊 Pricing Tiers

### Logistics Companies

| Tier | Price/Month | Features |
|------|-------------|----------|
| **Starter** | $500 | 2 scans/month, basic reporting |
| **Professional** | $1,500 | 8 scans/month, compliance audits |
| **Enterprise** | $5,000 | Unlimited scans, 24/7 monitoring |

### Medical AI Providers

| Tier | Price/Month | Features |
|------|-------------|----------|
| **HIPAA Basic** | $800 | Monthly compliance checks |
| **HIPAA Pro** | $2,000 | Weekly audits + PHI scanning |
| **HIPAA Enterprise** | $6,000 | Continuous monitoring + consultation |

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **Email**: support@gtl.pe
- **Documentation**: https://docs.gtl.pe
- **GitHub Issues**: https://github.com/your-org/gtl-ai-security/issues
- **Slack Community**: https://gtl-security.slack.com

---

## 🙏 Acknowledgments

- Built on [CAI Framework](https://github.com/aliasrobotics/cai) by Alias Robotics
- Security tools: nmap, nuclei, nikto, sqlmap
- MITRE ATT&CK Framework

---

**Made with ❤️ in Peru for the global cybersecurity community**
