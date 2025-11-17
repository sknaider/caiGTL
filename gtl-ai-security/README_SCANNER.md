# GTL Security Scanner

Módulo de escaneo de seguridad automatizado para GTL AI Security Platform.

## Descripción

El GTL Security Scanner es un motor de pentesting automatizado que integra múltiples herramientas de seguridad (Nmap, Nuclei, SQLMap, Nikto) en un pipeline unificado con análisis inteligente, generación de informes y programación de escaneos.

## Características

- **Escaneo Multi-Etapa**: Pipeline de 7 etapas con progreso en tiempo real
- **Herramientas Integradas**:
  - Nmap: Descubrimiento de red y enumeración de servicios
  - Nuclei: Detección de vulnerabilidades basada en plantillas
  - SQLMap: Testing de inyección SQL
  - Nikto: Escaneo de servidores web
- **CAI Framework**: Soporte para análisis de sistemas robóticos
- **Análisis de Riesgo**: Algoritmo de scoring 0-100
- **Reportes Profesionales**: Ejecutivos y técnicos en PDF/HTML/JSON
- **Programación de Escaneos**: Diarios, semanales, mensuales con Celery Beat
- **API RESTful**: Endpoints seguros con JWT + RBAC

## Arquitectura

```
gtl_security_scanner/
├── scanner.py              # Orchestrador principal
├── cai_integration.py      # Wrapper CAI Framework
├── tools/                  # Wrappers de herramientas
│   ├── nmap_scanner.py
│   ├── nuclei_scanner.py
│   ├── sqlmap_scanner.py
│   └── nikto_scanner.py
├── parsers/                # Parsers de salida
├── reporters/              # Generación de informes
│   ├── report_generator.py
│   ├── templates/
│   └── exporters/
└── scheduler.py            # Tareas Celery
```

## Instalación

### Requisitos Previos

- Python 3.11+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Dependencias del Sistema

```bash
# Debian/Ubuntu
sudo apt-get install -y nmap nikto sqlmap

# Nuclei
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip
unzip nuclei_3.1.0_linux_amd64.zip -d /usr/local/bin
nuclei -update-templates
```

### Instalación con Docker (Recomendado)

```bash
# Clonar repositorio
git clone https://github.com/gtl-security/gtl-ai-security.git
cd gtl-ai-security

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus credenciales

# Levantar servicios
docker-compose up -d

# Verificar servicios
docker-compose ps
```

### Instalación Manual

```bash
# Instalar dependencias Python
pip install -r requirements.txt

# Iniciar base de datos
docker-compose up -d postgres redis

# Migrar base de datos
alembic upgrade head

# Iniciar API Gateway
uvicorn gtl_api_gateway.main:app --host 0.0.0.0 --port 8000

# En otra terminal, iniciar Celery worker
celery -A gtl_security_scanner.scheduler worker --loglevel=info

# En otra terminal, iniciar Celery beat
celery -A gtl_security_scanner.scheduler beat --loglevel=info
```

## Uso

### Escaneo Programático

```python
import asyncio
from gtl_security_scanner.scanner import SecurityScanner, ScanTarget, ScanType

async def run_scan():
    # Inicializar scanner
    scanner = SecurityScanner()

    # Definir target
    target = ScanTarget(
        url="https://example.com",
        scan_type=ScanType.WEBAPP
    )

    # Ejecutar escaneo
    result = await scanner.scan(target, scan_id="scan-001")

    # Ver resultados
    print(f"Risk Score: {result.risk_score}/100")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")

    for vuln in result.vulnerabilities:
        print(f"  [{vuln.severity}] {vuln.title} (CVSS: {vuln.cvss_score})")

# Ejecutar
asyncio.run(run_scan())
```

### API REST

#### Iniciar Escaneo

```bash
curl -X POST "http://localhost:8000/api/v1/scanner/scan" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "scan_type": "webapp",
    "priority": "normal"
  }'
```

Respuesta:
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "queued",
  "message": "Scan has been queued and will start shortly",
  "started_at": "2025-11-17T10:30:00Z",
  "estimated_duration_seconds": 1800
}
```

#### Consultar Estado del Escaneo

```bash
curl "http://localhost:8000/api/v1/scanner/scan/{scan_id}/status" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Respuesta:
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "running",
  "progress": 45,
  "current_stage": "vulnerability_scanning",
  "vulnerabilities_found": 12
}
```

#### Obtener Resultados

```bash
curl "http://localhost:8000/api/v1/scanner/scan/{scan_id}/results" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Respuesta:
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "completed",
  "risk_score": 75.5,
  "total_vulnerabilities": 23,
  "severity_breakdown": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 6,
    "info": 2
  },
  "vulnerabilities": [ ... ],
  "services": [ ... ],
  "duration_seconds": 1234.5
}
```

#### Generar Informe

```bash
curl -X POST "http://localhost:8000/api/v1/scanner/scan/{scan_id}/report" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "report_type": "technical",
    "format": "pdf",
    "language": "es",
    "include_remediation": true
  }'
```

### Programar Escaneo Recurrente

```bash
curl -X POST "http://localhost:8000/api/v1/scanner/scan/schedule" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "logistics_company_1",
    "target_url": "https://cliente.com",
    "scan_type": "full",
    "schedule": "weekly",
    "day_of_week": 6,
    "time": "02:00"
  }'
```

### Uso con CAI Framework (Robots/IoT)

```python
from gtl_security_scanner.cai_integration import CAIIntegration, CAITarget

async def scan_robot():
    cai = CAIIntegration()

    target = CAITarget(
        target_type="robot",
        ip_address="192.168.1.100",
        protocol="ros",
        vendor="Universal Robots",
        model="UR5"
    )

    vulnerabilities = await cai.scan(target, scan_type="comprehensive")

    for vuln in vulnerabilities:
        print(f"[{vuln.severity}] {vuln.title}")
        if vuln.robot_specific:
            print("  ⚠️  Robot-specific vulnerability!")

asyncio.run(scan_robot())
```

## Pipeline de Escaneo

El scanner ejecuta un pipeline multi-etapa:

1. **Network Discovery** (15%): Nmap descubre hosts y puertos abiertos
2. **Service Enumeration** (30%): Identifica servicios y versiones
3. **Vulnerability Scanning** (50%): Nuclei busca CVEs y misconfigs
4. **Specialized Tests** (70%): SQLMap y Nikto según tipo de target
5. **Risk Analysis** (85%): Calcula risk score y prioriza vulnerabilities
6. **Compliance Check** (95%): Verifica contra frameworks (OWASP, PCI-DSS)
7. **Report Generation** (100%): Genera informes ejecutivos y técnicos

## Algoritmo de Risk Scoring

```python
# Pesos por severidad
critical: 3.0
high: 2.0
medium: 1.0
low: 0.5
info: 0.1

# Penalizaciones
critical_penalty = count_critical * 5
high_penalty = count_high * 2

# Score final (0-100)
risk_score = min(base_score + penalties, 100.0)
```

## Niveles de Riesgo

- **90-100**: CRITICAL - Acción inmediata requerida
- **60-89**: HIGH - Atención urgente
- **40-59**: MEDIUM - Remediar en 30 días
- **20-39**: LOW - Remediar en 90 días
- **0-19**: MINIMAL - Monitorear

## Configuración

### Variables de Entorno

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/gtl_security

# Redis/Celery
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0

# API Keys
SHODAN_API_KEY=your_shodan_key
DEEPSEEK_API_KEY=your_deepseek_key

# Scanner Config
NMAP_PATH=/usr/bin/nmap
NUCLEI_PATH=/usr/local/bin/nuclei
SQLMAP_PATH=/usr/bin/sqlmap
NIKTO_PATH=/usr/bin/nikto
CAI_PATH=/opt/cai
```

### Perfiles de Escaneo

Crear perfiles personalizados en `gtl_security_scanner/profiles/`:

```python
# profiles/logistics.py
PROFILE = {
    "name": "logistics",
    "scan_types": ["network", "webapp"],
    "nmap_options": {
        "ports": "1-65535",
        "scan_type": "full"
    },
    "nuclei_options": {
        "severity": ["critical", "high", "medium"],
        "tags": ["cve", "iot", "scada"]
    },
    "compliance": ["ISO-27001", "NIST-CSF"]
}
```

## Testing

```bash
# Ejecutar todos los tests
pytest

# Con cobertura
pytest --cov=gtl_security_scanner --cov-report=html

# Solo unit tests
pytest -m unit

# Solo integration tests (requiere herramientas instaladas)
pytest -m integration

# Test específico
pytest tests/scanner/test_scanner.py::TestSecurityScanner::test_scan_execution
```

## Monitoreo

### Celery Flower

Acceder a http://localhost:5555 para monitorear:
- Tareas en ejecución
- Colas de trabajo
- Estadísticas de workers
- Historial de tareas

### Logs

```bash
# Logs del API Gateway
docker-compose logs -f api

# Logs del Celery Worker
docker-compose logs -f celery_worker

# Logs del Scanner
tail -f /var/log/gtl/scanner.log
```

### Métricas

El scanner expone métricas Prometheus en `/metrics`:

```
scanner_scans_total{status="completed"} 156
scanner_scans_total{status="failed"} 3
scanner_vulnerabilities_total{severity="critical"} 45
scanner_scan_duration_seconds_sum 12345.6
```

## Troubleshooting

### Escaneo Falla con "Tool not found"

```bash
# Verificar que las herramientas estén instaladas
which nmap nuclei sqlmap nikto

# Verificar permisos
ls -la /usr/bin/nmap
# Debe tener setuid bit para escaneos SYN

# Reinstalar si es necesario
sudo apt-get install --reinstall nmap
```

### Celery Worker no procesa tareas

```bash
# Verificar Redis está corriendo
redis-cli ping

# Reiniciar worker
docker-compose restart celery_worker

# Ver logs
docker-compose logs celery_worker
```

### Timeout en escaneos largos

Ajustar timeouts en `scanner.py`:

```python
# Aumentar timeout de Nmap
nmap_scanner = NmapScanner(timeout=1200)  # 20 minutos

# Ajustar timeout global del scan
result = await scanner.scan(target, scan_id, timeout=3600)
```

## Roadmap

- [ ] Integración con MITRE ATT&CK
- [ ] Machine Learning para priorización de vulnerabilidades
- [ ] Detección de falsos positivos automática
- [ ] Integración con ticketing systems (Jira, ServiceNow)
- [ ] Dashboard web interactivo
- [ ] Mobile app para alertas
- [ ] Soporte para escaneos distribuidos
- [ ] Integración con WAF para remediación automática

## Contribuir

Ver [CONTRIBUTING.md](CONTRIBUTING.md) para guidelines.

## Licencia

Copyright © 2025 GTL Security Peru. Todos los derechos reservados.

## Soporte

- Email: soporte@gtl.pe
- Slack: gtl-security.slack.com
- Docs: https://docs.gtl.pe/scanner

## Autores

GTL Security Team - Perú

---

**⚠️ DISCLAIMER**: Esta herramienta es para uso autorizado únicamente. El uso no autorizado de escaneo de vulnerabilidades puede ser ilegal. Obtener permiso explícito antes de escanear cualquier sistema que no sea de su propiedad.
