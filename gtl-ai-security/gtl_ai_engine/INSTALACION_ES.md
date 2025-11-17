# Motor de IA GTL - Guía de Instalación Completa

Guía completa de configuración para tu sistema de ciberseguridad potenciado por IA.

---

## Requisitos del Sistema

### Hardware
✅ **Lo que tienes**:
- AMD Ryzen 9 9950X (16 núcleos, 32 hilos)
- NVIDIA RTX 5090 (24GB VRAM)
- 128GB RAM DDR5

✅ **Mínimo recomendado**:
- GPU con 16GB VRAM
- 32GB RAM
- 8 núcleos de CPU

### Software
- Ubuntu 22.04+ o Windows 11 con WSL2
- Python 3.10+
- CUDA 12.0+
- Docker (opcional)

---

## Pasos de Instalación

### Paso 1: Instalar Drivers NVIDIA y CUDA

```bash
# Verificar si tienes drivers NVIDIA
nvidia-smi

# Si no están instalados:
# Ubuntu
sudo apt update
sudo apt install nvidia-driver-535 nvidia-cuda-toolkit

# Verificar
nvidia-smi
nvcc --version
```

### Paso 2: Instalar Ollama (Servidor LLM Local)

```bash
# Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Iniciar servicio de Ollama
ollama serve &

# Descargar modelos (esto tomará tiempo debido al tamaño)
# Llama 3.1 70B (~40GB de descarga)
ollama pull llama3.1:70b

# CodeLlama 34B (~20GB de descarga)
ollama pull codellama:34b

# Mistral Large (~50GB de descarga)
ollama pull mistral:latest

# Verificar que los modelos están instalados
ollama list

# Probar que funciona
ollama run llama3.1:70b "Hola, respuesta de prueba"
```

**Nota**: Con tu RTX 5090 (24GB VRAM), puedes ejecutar:
- Llama 3.1 70B con cuantización de 4-bit (cabe en VRAM)
- Múltiples modelos más pequeños simultáneamente
- O Llama 3.1 405B con offloading a CPU

### Paso 3: Instalar Dependencias de Python

```bash
cd /home/user/caiGTL/gtl-ai-security/gtl_ai_engine

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Actualizar pip
pip install --upgrade pip

# Instalar PyTorch con soporte CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Instalar otras dependencias
pip install -r requirements.txt

# Verificar que PyTorch puede ver tu GPU
python -c "import torch; print(f'CUDA disponible: {torch.cuda.is_available()}'); print(f'GPU: {torch.cuda.get_device_name(0)}')"
```

Salida esperada:
```
CUDA disponible: True
GPU: NVIDIA GeForce RTX 5090
```

### Paso 4: Configurar Variables de Entorno

```bash
# Crear archivo .env
cat > .env <<EOF
# Configuración de LLM
OLLAMA_BASE_URL=http://localhost:11434
DEFAULT_MODEL=llama3.1:70b
CODE_MODEL=codellama:34b

# Configuración de GPU
CUDA_VISIBLE_DEVICES=0
GPU_MEMORY_FRACTION=0.9

# Configuración de API
API_HOST=0.0.0.0
API_PORT=8001

# Base de datos (opcional)
DATABASE_URL=sqlite:///gtl_ai.db

# Redis (opcional, para caché)
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=INFO
EOF
```

### Paso 5: Verificar Instalación

```bash
# Probar cliente LLM
python -c "
from core.llm_client import LLMClient
import asyncio

async def test():
    client = LLMClient()
    response = await client.generate('¿Cuánto es 2+2?')
    print(response)

asyncio.run(test())
"
```

¡Si ves una respuesta, todo está funcionando!

---

## Componentes Opcionales

### Redis (para caché)

```bash
# Ubuntu
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis

# Verificar
redis-cli ping
# Debe retornar: PONG
```

### PostgreSQL (para almacenamiento persistente)

```bash
# Ubuntu
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Crear base de datos
sudo -u postgres psql -c "CREATE DATABASE gtl_ai;"
sudo -u postgres psql -c "CREATE USER gtl_user WITH PASSWORD 'contraseña_segura';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE gtl_ai TO gtl_user;"
```

### Docker (para despliegue fácil)

```bash
# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Instalar Docker Compose
sudo apt install docker-compose

# Agregar usuario al grupo docker
sudo usermod -aG docker $USER
newgrp docker

# Verificar
docker --version
docker-compose --version
```

---

## Ejecutar el Motor de IA

### Inicio Rápido

```bash
# Activar entorno virtual
source venv/bin/activate

# Ejecutar analizador de vulnerabilidades
python ejemplos/analizar_vulnerabilidad.py

# Ejecutar analizador de malware
python ejemplos/analizar_malware.py

# Iniciar servidor API
python api/server.py
```

### Modo Producción

```bash
# Usando Docker
docker-compose up -d

# O usando servicio systemd
sudo cp gtl-ai-engine.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start gtl-ai-engine
sudo systemctl enable gtl-ai-engine
```

---

## Ajuste de Rendimiento

### Optimización de GPU

```bash
# Habilitar modo de persistencia (reduce latencia)
sudo nvidia-smi -pm 1

# Establecer límite de potencia (opcional, para estabilidad)
sudo nvidia-smi -pl 450  # 450W para RTX 5090

# Monitorear uso de GPU
watch -n 1 nvidia-smi
```

### Optimización de Ollama

Editar `/etc/systemd/system/ollama.service` (o donde esté instalado Ollama):

```ini
[Service]
Environment="OLLAMA_NUM_PARALLEL=4"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="CUDA_VISIBLE_DEVICES=0"
```

Luego reiniciar:
```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

### Optimización del Sistema

```bash
# Aumentar descriptores de archivo
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimizar TCP
echo "net.ipv4.tcp_tw_reuse=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Benchmarking

Prueba el rendimiento de tu sistema:

```bash
python benchmarks/ejecutar_benchmarks.py
```

Rendimiento esperado en tu hardware:
- Análisis de vulnerabilidades: 10-30 segundos
- Análisis de código (1000 LOC): 2-5 minutos
- Análisis de malware: 1-2 segundos (estático), 5-10 min (dinámico)
- Inferencia LLM: 20-50 tokens/segundo (Llama 70B)

---

## Solución de Problemas

### Ollama No Responde

```bash
# Verificar si Ollama está ejecutándose
ps aux | grep ollama

# Revisar logs
journalctl -u ollama -f

# Reiniciar Ollama
sudo systemctl restart ollama

# O manualmente
killall ollama
ollama serve &
```

### CUDA Sin Memoria (Out of Memory)

Si obtienes errores OOM:

1. Usar modelos más pequeños:
```bash
ollama pull llama3.1:13b  # Variante más pequeña
```

2. Habilitar cuantización del modelo:
```python
config = LLMConfig(
    model="llama3.1:70b-q4_0",  # Cuantización de 4-bit
    gpu_layers=35  # Offload algunas capas a CPU
)
```

3. Reducir tamaño de batch en config

### Inferencia Lenta

1. Verificar utilización de GPU:
```bash
nvidia-smi dmon
```

2. Habilitar flash attention (si no está ya):
```bash
export OLLAMA_FLASH_ATTENTION=1
```

3. Reducir longitud de contexto:
```python
config = LLMConfig(context_length=4096)  # En lugar de 32768
```

### Errores de Importación

```bash
# Reinstalar dependencias
pip install --force-reinstall -r requirements.txt

# O paquete específico
pip install --upgrade transformers torch
```

---

## Actualización

### Actualizar Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama list
# Descargar modelos actualizados si están disponibles
```

### Actualizar Paquetes de Python

```bash
pip install --upgrade -r requirements.txt
```

### Actualizar Modelos

```bash
# Verificar actualizaciones
ollama list

# Descargar última versión
ollama pull llama3.1:70b
```

---

## Monitoreo

### Monitoreo de GPU

```bash
# Monitoreo en tiempo real
nvidia-smi dmon -s pucvmet

# O usar GUI
nvidia-smi dmon -s pucvmet -d 1 | tee uso_gpu.log
```

### Monitoreo del Sistema

```bash
# Instalar htop
sudo apt install htop
htop

# O instalar nvtop para GPU
sudo apt install nvtop
nvtop
```

### Monitoreo de Aplicación

```bash
# Ver logs
tail -f logs/gtl_ai_engine.log

# Monitorear API
curl http://localhost:8001/health

# Revisar métricas
curl http://localhost:8001/metrics
```

---

## Próximos Pasos

1. ✅ Completar instalación
2. ✅ Ejecutar ejemplos de prueba
3. 📚 Leer documentación de uso: `USO_ES.md`
4. 🎯 Integrar con GTL Scanner: `docs/integracion_es.md`
5. 🎓 Entrenar modelos personalizados: `docs/entrenamiento_es.md`

---

## Soporte

Si encuentras problemas:

1. Revisa logs: `logs/gtl_ai_engine.log`
2. Ejecuta diagnósticos: `python utils/diagnostics.py`
3. Verifica estado de GPU: `nvidia-smi`
4. Verifica Ollama: `ollama list`
5. Revisa esta guía nuevamente

---

**¡Instalación completa! Ahora tienes un motor de ciberseguridad con IA potente.** 🚀

Tu inversión: $500 en código
Valor de mercado: $50,000-$100,000/año en equivalentes SaaS

¡Es hora de empezar a analizar! 🔥
