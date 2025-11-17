# GTL AI Engine - Installation Guide

Complete setup guide for your AI-powered cybersecurity system.

---

## System Requirements

### Hardware
✅ **You have**:
- AMD Ryzen 9 9950X (16 cores, 32 threads)
- NVIDIA RTX 5090 (24GB VRAM)
- 128GB DDR5 RAM

✅ **Minimum recommended**:
- 16GB VRAM GPU
- 32GB RAM
- 8 CPU cores

### Software
- Ubuntu 22.04+ or Windows 11 with WSL2
- Python 3.10+
- CUDA 12.0+
- Docker (optional)

---

## Installation Steps

### Step 1: Install NVIDIA Drivers and CUDA

```bash
# Check if you have NVIDIA drivers
nvidia-smi

# If not installed:
# Ubuntu
sudo apt update
sudo apt install nvidia-driver-535 nvidia-cuda-toolkit

# Verify
nvidia-smi
nvcc --version
```

### Step 2: Install Ollama (Local LLM Server)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
ollama serve &

# Pull models (this will take time due to size)
# Llama 3.1 70B (~40GB download)
ollama pull llama3.1:70b

# CodeLlama 34B (~20GB download)
ollama pull codellama:34b

# Mistral Large (~50GB download)
ollama pull mistral:latest

# Verify models are installed
ollama list

# Test that it works
ollama run llama3.1:70b "Hello, test response"
```

**Note**: With your RTX 5090 (24GB VRAM), you can run:
- Llama 3.1 70B with 4-bit quantization (fits in VRAM)
- Multiple smaller models simultaneously
- Or Llama 3.1 405B with CPU offloading

### Step 3: Install Python Dependencies

```bash
cd /home/user/caiGTL/gtl-ai-security/gtl_ai_engine

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install PyTorch with CUDA support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Install other dependencies
pip install -r requirements.txt

# Verify PyTorch can see your GPU
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}'); print(f'GPU: {torch.cuda.get_device_name(0)}')"
```

Expected output:
```
CUDA available: True
GPU: NVIDIA GeForce RTX 5090
```

### Step 4: Configure Environment

```bash
# Create .env file
cat > .env <<EOF
# LLM Configuration
OLLAMA_BASE_URL=http://localhost:11434
DEFAULT_MODEL=llama3.1:70b
CODE_MODEL=codellama:34b

# GPU Configuration
CUDA_VISIBLE_DEVICES=0
GPU_MEMORY_FRACTION=0.9

# API Configuration
API_HOST=0.0.0.0
API_PORT=8001

# Database (optional)
DATABASE_URL=sqlite:///gtl_ai.db

# Redis (optional, for caching)
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=INFO
EOF
```

### Step 5: Verify Installation

```bash
# Test LLM client
python -c "
from core.llm_client import LLMClient
import asyncio

async def test():
    client = LLMClient()
    response = await client.generate('What is 2+2?')
    print(response)

asyncio.run(test())
"
```

If you see a response, everything is working!

---

## Optional Components

### Redis (for caching)

```bash
# Ubuntu
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis

# Verify
redis-cli ping
# Should return: PONG
```

### PostgreSQL (for persistent storage)

```bash
# Ubuntu
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database
sudo -u postgres psql -c "CREATE DATABASE gtl_ai;"
sudo -u postgres psql -c "CREATE USER gtl_user WITH PASSWORD 'secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE gtl_ai TO gtl_user;"
```

### Docker (for easy deployment)

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker-compose --version
```

---

## Running the AI Engine

### Quick Start

```bash
# Activate virtual environment
source venv/bin/activate

# Run vulnerability analyzer
python examples/analyze_vulnerability.py

# Run malware analyzer
python examples/analyze_malware.py

# Start API server
python api/server.py
```

### Production Mode

```bash
# Using Docker
docker-compose up -d

# Or using systemd service
sudo cp gtl-ai-engine.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start gtl-ai-engine
sudo systemctl enable gtl-ai-engine
```

---

## Performance Tuning

### GPU Optimization

```bash
# Enable persistence mode (reduces latency)
sudo nvidia-smi -pm 1

# Set power limit (optional, for stability)
sudo nvidia-smi -pl 450  # 450W for RTX 5090

# Monitor GPU usage
watch -n 1 nvidia-smi
```

### Ollama Optimization

Edit `/etc/systemd/system/ollama.service` (or wherever Ollama is installed):

```ini
[Service]
Environment="OLLAMA_NUM_PARALLEL=4"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="CUDA_VISIBLE_DEVICES=0"
```

Then restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

### System Optimization

```bash
# Increase file descriptors
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize TCP
echo "net.ipv4.tcp_tw_reuse=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Benchmarking

Test your system's performance:

```bash
python benchmarks/run_benchmarks.py
```

Expected performance on your hardware:
- Vulnerability analysis: 10-30 seconds
- Code analysis (1000 LOC): 2-5 minutes
- Malware analysis: 1-2 seconds (static), 5-10 min (dynamic)
- LLM inference: 20-50 tokens/second (Llama 70B)

---

## Troubleshooting

### Ollama Not Responding

```bash
# Check if Ollama is running
ps aux | grep ollama

# Check logs
journalctl -u ollama -f

# Restart Ollama
sudo systemctl restart ollama

# Or manually
killall ollama
ollama serve &
```

### CUDA Out of Memory

If you get OOM errors:

1. Use smaller models:
```bash
ollama pull llama3.1:13b  # Smaller variant
```

2. Enable model quantization:
```python
config = LLMConfig(
    model="llama3.1:70b-q4_0",  # 4-bit quantization
    gpu_layers=35  # Offload some layers to CPU
)
```

3. Reduce batch size in config

### Slow Inference

1. Check GPU utilization:
```bash
nvidia-smi dmon
```

2. Enable flash attention (if not already):
```bash
export OLLAMA_FLASH_ATTENTION=1
```

3. Reduce context length:
```python
config = LLMConfig(context_length=4096)  # Instead of 32768
```

### Import Errors

```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Or specific package
pip install --upgrade transformers torch
```

---

## Upgrading

### Update Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama list
# Pull updated models if available
```

### Update Python Packages

```bash
pip install --upgrade -r requirements.txt
```

### Update Models

```bash
# Check for updates
ollama list

# Pull latest version
ollama pull llama3.1:70b
```

---

## Monitoring

### GPU Monitoring

```bash
# Real-time monitoring
nvidia-smi dmon -s pucvmet

# Or use GUI
nvidia-smi dmon -s pucvmet -d 1 | tee gpu_usage.log
```

### System Monitoring

```bash
# Install htop
sudo apt install htop
htop

# Or install nvtop for GPU
sudo apt install nvtop
nvtop
```

### Application Monitoring

```bash
# View logs
tail -f logs/gtl_ai_engine.log

# Monitor API
curl http://localhost:8001/health

# Check metrics
curl http://localhost:8001/metrics
```

---

## Next Steps

1. ✅ Complete installation
2. ✅ Run test examples
3. 📚 Read usage documentation: `USAGE.md`
4. 🎯 Integrate with GTL Scanner: `docs/integration.md`
5. 🎓 Train custom models: `docs/training.md`

---

## Support

If you encounter issues:

1. Check logs: `logs/gtl_ai_engine.log`
2. Run diagnostics: `python utils/diagnostics.py`
3. Check GPU status: `nvidia-smi`
4. Verify Ollama: `ollama list`
5. Review this guide again

---

**Installation complete! You now have a powerful AI cybersecurity engine.** 🚀

Your investment: $500 in code
Market value: $50,000-$100,000/year in SaaS equivalents

Time to start analyzing! 🔥
