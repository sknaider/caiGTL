# CAI Framework - Installation Guide
**Complete Setup for GTL AI Security Platform**

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Detailed Installation Steps](#detailed-installation-steps)
4. [API Key Configuration](#api-key-configuration)
5. [Security Tools Installation](#security-tools-installation)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)
8. [Production Deployment](#production-deployment)
9. [GTL-Specific Setup](#gtl-specific-setup)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+), macOS 11+, Windows 10+ (WSL2) |
| **Python** | 3.9 or higher (3.11+ recommended) |
| **RAM** | 4 GB minimum, 8 GB recommended |
| **Disk Space** | 2 GB for framework + tools |
| **Network** | Internet connection for LLM APIs |

### Recommended for GTL Production

| Component | Recommendation |
|-----------|----------------|
| **OS** | Ubuntu 22.04 LTS |
| **Python** | 3.11 or 3.12 |
| **RAM** | 16 GB |
| **CPU** | 4+ cores |
| **Disk** | 20 GB SSD |
| **Network** | High-speed connection, static IP for production |

### Python Version Check

```bash
python3 --version
# Should output: Python 3.9.x or higher
```

If Python 3.9+ is not installed:

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev
```

**macOS**:
```bash
brew install python@3.11
```

**CentOS/RHEL**:
```bash
sudo dnf install python3.11 python3.11-devel
```

---

## Quick Installation

### Option 1: Install from PyPI (Recommended)

```bash
# Create virtual environment
python3 -m venv cai-env
source cai-env/bin/activate  # On Windows: cai-env\Scripts\activate

# Install CAI Framework
pip install cai-framework

# Verify installation
cai --version
```

### Option 2: Install from Source (For Development)

```bash
# Clone repository
git clone https://github.com/aliasrobotics/cai.git
cd cai

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in editable mode with development dependencies
pip install -e .
pip install -r requirements-dev.txt

# Verify installation
cai --version
```

### Option 3: Using UV (Faster Package Manager)

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install CAI Framework
uv pip install cai-framework

# Or from source
git clone https://github.com/aliasrobotics/cai.git
cd cai
uv pip install -e .
```

---

## Detailed Installation Steps

### Step 1: System Preparation

**Ubuntu/Debian**:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build tools and dependencies
sudo apt install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3-pip \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    nmap \
    netcat \
    curl \
    wget \
    sshpass
```

**macOS**:
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.11 git nmap netcat
```

**Windows (WSL2)**:
```bash
# Enable WSL2 and install Ubuntu 22.04
wsl --install -d Ubuntu-22.04

# Inside WSL, run Ubuntu commands above
```

### Step 2: Create Project Directory

```bash
# Create GTL project directory
mkdir -p ~/gtl-security-platform
cd ~/gtl-security-platform

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate
```

### Step 3: Install CAI Framework

```bash
# Upgrade pip
pip install --upgrade pip

# Install CAI Framework
pip install cai-framework

# Install optional dependencies
pip install cai-framework[voice]  # For voice capabilities
pip install cai-framework[viz]    # For visualization
```

### Step 4: Install Additional Python Dependencies

```bash
# For SAP integration (GTL-specific)
pip install pyrfc  # SAP NetWeaver RFC SDK

# For Oracle integration (GTL-specific)
pip install cx_Oracle  # Oracle Database driver

# For web scraping and OSINT
pip install beautifulsoup4 scrapy

# For network analysis
pip install scapy

# For reporting
pip install jinja2 markdown
```

### Step 5: Verify Installation

```bash
# Check CAI version
cai --version

# List available agents
cai --list-agents

# Test basic functionality
echo "Hello CAI" | cai
```

---

## API Key Configuration

### Create Environment File

```bash
cd ~/gtl-security-platform

# Copy example environment file
cp .env.example .env

# Edit with your API keys
nano .env
```

### Required API Keys

**.env file**:

```bash
# ============================================
# CORE LLM PROVIDERS (Choose at least one)
# ============================================

# DeepSeek (Recommended - Most cost-effective)
DEEPSEEK_API_KEY=sk-your-deepseek-api-key-here
CAI_MODEL=alias0

# OpenAI (Alternative - Higher quality, higher cost)
# OPENAI_API_KEY=sk-your-openai-api-key-here
# CAI_MODEL=gpt-4o

# Anthropic Claude (Alternative - Best reasoning)
# ANTHROPIC_API_KEY=sk-ant-your-anthropic-api-key-here
# CAI_MODEL=claude-sonnet-4-20250514

# ============================================
# SECURITY TOOLS API KEYS
# ============================================

# Shodan (Recommended for OSINT)
SHODAN_API_KEY=your-shodan-api-key-here

# Perplexity (Optional - Web search)
PERPLEXITY_API_KEY=your-perplexity-api-key-here

# Google Search (Optional - Google dorking)
GOOGLE_SEARCH_API_KEY=your-google-api-key-here
GOOGLE_SEARCH_CX=your-custom-search-engine-id-here

# C99.nl (Optional - Subdomain discovery)
C99_API_KEY=your-c99-api-key-here

# ============================================
# CAI CONFIGURATION
# ============================================

CAI_AGENT_TYPE=one_tool_agent    # Default agent
CAI_DEBUG=1                       # Debug level (0-2)
CAI_GUARDRAILS=true               # Enable security guardrails
CAI_TRACING=false                 # OpenTelemetry tracing
CAI_PRICE_LIMIT=100.0             # Cost limit in USD
CAI_PARALLEL=0                    # Number of parallel agents

# ============================================
# GTL-SPECIFIC CONFIGURATION
# ============================================

GTL_REPORT_LANGUAGE=es            # Spanish reports
GTL_COMPLIANCE_REGION=peru        # Peruvian regulations
GTL_CLIENT_DATABASE=./clients.db  # Client information
```

### How to Get API Keys

#### 1. DeepSeek (Recommended - Budget-Friendly)

**Cost**: ~$0.27/M tokens (cheapest option)

```bash
# Visit: https://platform.deepseek.com/
# Sign up and create API key
# Add to .env: DEEPSEEK_API_KEY=sk-...
```

#### 2. OpenAI (Alternative)

**Cost**: GPT-4o: $2.50/M input, $10/M output

```bash
# Visit: https://platform.openai.com/
# Sign up and create API key
# Add to .env: OPENAI_API_KEY=sk-...
```

#### 3. Anthropic Claude (Alternative)

**Cost**: Claude Sonnet: $3/M input, $15/M output

```bash
# Visit: https://console.anthropic.com/
# Sign up and create API key
# Add to .env: ANTHROPIC_API_KEY=sk-ant-...
```

#### 4. Shodan (Recommended for Security)

**Cost**: Free tier (1 credit/month), Membership: $59/month

```bash
# Visit: https://account.shodan.io/
# Sign up (free account available)
# Copy API key from account page
# Add to .env: SHODAN_API_KEY=...
```

#### 5. Perplexity (Optional)

**Cost**: $0.20/1K tokens

```bash
# Visit: https://www.perplexity.ai/
# Sign up for API access
# Add to .env: PERPLEXITY_API_KEY=...
```

### Load Environment Variables

```bash
# Option 1: Use direnv (recommended)
sudo apt install direnv
echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
source ~/.bashrc
direnv allow .

# Option 2: Manual export
export $(cat .env | xargs)

# Option 3: Source in each session
echo 'source ~/gtl-security-platform/.env' >> ~/.bashrc
```

---

## Security Tools Installation

### Core Security Tools

**Ubuntu/Debian**:
```bash
sudo apt install -y \
    nmap \
    netcat \
    curl \
    wget \
    sshpass \
    tcpdump \
    wireshark-common \
    tshark \
    hashcat \
    john \
    hydra \
    sqlmap \
    nikto \
    dirb \
    gobuster
```

**macOS**:
```bash
brew install nmap netcat curl wget tcpdump wireshark hashcat john-jumbo hydra sqlmap nikto
```

### Optional: Metasploit Framework

**Ubuntu/Debian**:
```bash
# Install Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

### Optional: Burp Suite

```bash
# Download from: https://portswigger.net/burp/communitydownload
# Community Edition is free
# Professional Edition: $449/year (recommended for GTL)

# Ubuntu/Debian installation
wget 'https://portswigger-cdn.net/burp/releases/download?product=community&version=2024.1&type=Linux' -O burpsuite.sh
chmod +x burpsuite.sh
./burpsuite.sh
```

### Docker Installation (Recommended for Isolation)

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify Docker
docker --version
```

### CAI Docker Image (Optional)

```bash
# Build CAI Docker image
cd ~/gtl-security-platform
git clone https://github.com/aliasrobotics/cai.git
cd cai

# Build image
docker build -t cai-framework .

# Run CAI in Docker
docker run -it --rm \
    -e OPENAI_API_KEY=$OPENAI_API_KEY \
    -e SHODAN_API_KEY=$SHODAN_API_KEY \
    cai-framework cai
```

---

## Verification

### Test 1: Basic Agent Execution

```bash
# Test default agent
cai "What are the OWASP Top 10?"

# Expected output: List of OWASP Top 10 vulnerabilities
```

### Test 2: Tool Execution

```bash
# Test nmap tool
CAI_AGENT_TYPE=redteam_agent cai "Scan localhost for open ports using nmap"

# Expected output: Nmap scan results
```

### Test 3: Shodan Integration

```bash
# Test Shodan (requires API key)
CAI_AGENT_TYPE=redteam_agent cai "Search Shodan for apache servers in Lima, Peru"

# Expected output: Shodan search results
```

### Test 4: Python SDK

Create `test_cai.py`:

```python
import asyncio
from cai.sdk.agents import Agent, Runner

async def main():
    agent = Agent(
        name="Test Agent",
        instructions="You are a helpful assistant."
    )

    result = await Runner.run(agent, "Say hello!")
    print(result.final_output)

if __name__ == "__main__":
    asyncio.run(main())
```

Run:
```bash
python test_cai.py

# Expected output: "Hello!" or similar greeting
```

### Test 5: Custom Tool

Create `test_custom_tool.py`:

```python
import asyncio
from cai.sdk.agents import Agent, Runner, function_tool

@function_tool
def test_tool(message: str) -> str:
    """A simple test tool."""
    return f"Received: {message}"

async def main():
    agent = Agent(
        name="Tool Test Agent",
        instructions="Use the test_tool to echo messages.",
        tools=[test_tool]
    )

    result = await Runner.run(agent, "Echo 'Hello GTL!'")
    print(result.final_output)

if __name__ == "__main__":
    asyncio.run(main())
```

Run:
```bash
python test_custom_tool.py

# Expected output: "Received: Hello GTL!"
```

---

## Troubleshooting

### Issue 1: Python Version Mismatch

**Error**: `CAI requires Python 3.9 or higher`

**Solution**:
```bash
# Check Python version
python3 --version

# Install Python 3.11
sudo apt install python3.11 python3.11-venv

# Use correct Python version
python3.11 -m venv venv
source venv/bin/activate
```

### Issue 2: Missing API Key

**Error**: `OpenAI API key not found`

**Solution**:
```bash
# Verify .env file exists
cat .env | grep API_KEY

# Export manually
export OPENAI_API_KEY=sk-your-key-here

# Or use CAI_MODEL with different provider
export CAI_MODEL=alias0
export DEEPSEEK_API_KEY=sk-your-deepseek-key
```

### Issue 3: Nmap Permission Denied

**Error**: `nmap: permission denied`

**Solution**:
```bash
# Option 1: Run as root (not recommended)
sudo cai

# Option 2: Set nmap capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Option 3: Add user to netdev group
sudo usermod -aG netdev $USER
```

### Issue 4: Connection Timeout

**Error**: `Connection timeout to OpenAI API`

**Solution**:
```bash
# Check internet connection
ping api.openai.com

# Check firewall
sudo ufw status

# Use proxy if needed
export HTTPS_PROXY=http://your-proxy:8080
```

### Issue 5: Module Not Found

**Error**: `ModuleNotFoundError: No module named 'cai'`

**Solution**:
```bash
# Verify virtual environment is activated
which python  # Should show venv path

# Reinstall CAI
pip uninstall cai-framework
pip install cai-framework

# Or install from source
cd ~/gtl-security-platform/cai
pip install -e .
```

---

## Production Deployment

### Server Setup (Ubuntu 22.04 LTS)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    nginx \
    postgresql \
    redis \
    supervisor \
    certbot \
    python3-certbot-nginx

# Create GTL user
sudo adduser gtl-security
sudo usermod -aG sudo gtl-security

# Switch to GTL user
sudo su - gtl-security
```

### GTL Platform Installation

```bash
# Clone CAI and GTL customizations
cd /opt
sudo git clone https://github.com/aliasrobotics/cai.git
sudo chown -R gtl-security:gtl-security cai
cd cai

# Install CAI
python3.11 -m venv venv
source venv/bin/activate
pip install -e .

# Install GTL-specific tools
pip install pyrfc cx_Oracle
```

### Environment Configuration

```bash
# Create production .env
sudo nano /opt/cai/.env

# Add production API keys and settings
# (Same format as above, but with production keys)

# Secure .env file
sudo chmod 600 /opt/cai/.env
sudo chown gtl-security:gtl-security /opt/cai/.env
```

### Systemd Service

Create `/etc/systemd/system/gtl-cai.service`:

```ini
[Unit]
Description=GTL AI Security Platform (CAI Framework)
After=network.target

[Service]
Type=simple
User=gtl-security
Group=gtl-security
WorkingDirectory=/opt/cai
Environment="PATH=/opt/cai/venv/bin"
EnvironmentFile=/opt/cai/.env
ExecStart=/opt/cai/venv/bin/cai --server --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable gtl-cai
sudo systemctl start gtl-cai
sudo systemctl status gtl-cai
```

### Nginx Reverse Proxy

Create `/etc/nginx/sites-available/gtl-cai`:

```nginx
server {
    listen 80;
    server_name gtl-security.pe www.gtl-security.pe;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and configure SSL:
```bash
sudo ln -s /etc/nginx/sites-available/gtl-cai /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d gtl-security.pe -d www.gtl-security.pe
```

### Monitoring

```bash
# Install monitoring tools
pip install prometheus-client grafana-api

# Monitor logs
sudo journalctl -u gtl-cai -f

# Monitor resource usage
htop
```

---

## GTL-Specific Setup

### Custom Agent Installation

```bash
# Create GTL agent directory
mkdir -p /opt/cai/src/cai/agents/gtl

# Copy GTL-specific agents
cp ~/gtl-logistics-agent.py /opt/cai/src/cai/agents/gtl/
cp ~/gtl-sap-agent.py /opt/cai/src/cai/agents/gtl/
cp ~/gtl-oracle-agent.py /opt/cai/src/cai/agents/gtl/
```

### GTL Tools Installation

```bash
# Create GTL tools directory
mkdir -p /opt/cai/src/cai/tools/gtl

# Copy GTL-specific tools
cp ~/sap_security_scanner.py /opt/cai/src/cai/tools/gtl/
cp ~/oracle_security_checker.py /opt/cai/src/cai/tools/gtl/
cp ~/peruvian_compliance_checker.py /opt/cai/src/cai/tools/gtl/
```

### Client Database Setup

```bash
# Install PostgreSQL client library
pip install psycopg2-binary

# Create GTL database
sudo -u postgres createdb gtl_clients
sudo -u postgres createuser gtl_user

# Set password
sudo -u postgres psql
ALTER USER gtl_user WITH PASSWORD 'secure-password-here';
GRANT ALL PRIVILEGES ON DATABASE gtl_clients TO gtl_user;
\q
```

### Compliance Module Setup

```bash
# Download Peruvian compliance rulesets
mkdir -p /opt/cai/compliance/peru
cd /opt/cai/compliance/peru

# Create Ley 29733 compliance checks
cat > ley_29733.json <<EOF
{
  "regulation": "Ley 29733 - Protección de Datos Personales",
  "checks": [
    {
      "id": "L29733-01",
      "requirement": "Consent for data collection",
      "severity": "HIGH"
    },
    {
      "id": "L29733-02",
      "requirement": "Data encryption at rest",
      "severity": "CRITICAL"
    }
  ]
}
EOF
```

### GTL Configuration File

Create `gtl_config.yml`:

```yaml
gtl_platform:
  name: "GTL AI Security Platform"
  version: "1.0.0"
  region: "Peru"

clients:
  database: "postgresql://gtl_user:password@localhost/gtl_clients"
  retention_days: 365

compliance:
  enabled: true
  regulations:
    - ley_29733  # Peruvian data protection
    - pcidss     # Payment Card Industry
    - iso27001   # Information security

reporting:
  language: "es"  # Spanish
  formats: ["pdf", "html", "json"]
  templates: "/opt/cai/templates/gtl/"

agents:
  default: "gtl_logistics_agent"
  available:
    - gtl_logistics_agent
    - gtl_sap_agent
    - gtl_oracle_agent
    - gtl_iot_agent
```

---

## Next Steps

1. ✅ Complete installation verification
2. ✅ Configure API keys
3. ✅ Test basic agents
4. 📝 Review `quick_start_examples.py` for practical examples
5. 📝 Read `api_documentation.md` to create custom agents
6. 📝 Study `architecture_analysis.md` for framework understanding
7. 🚀 Deploy GTL-specific agents
8. 🚀 Set up client portal
9. 🚀 Configure automated reporting

---

## Support and Resources

- **CAI Documentation**: `/opt/cai/docs/`
- **GTL Documentation**: This installation guide + other deliverables
- **CAI GitHub**: https://github.com/aliasrobotics/cai
- **Issue Tracker**: https://github.com/aliasrobotics/cai/issues

---

**Document Version**: 1.0
**Created**: November 2025
**For**: GTL AI Security Platform
**Tested On**: Ubuntu 22.04 LTS, Python 3.11
