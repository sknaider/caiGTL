# GTL AI Security Platform - Production Deployment Guide

**Version**: 1.0
**Target Audience**: DevOps Engineers, System Administrators

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Cloud Deployment (AWS)](#cloud-deployment-aws)
3. [Cloud Deployment (Azure)](#cloud-deployment-azure)
4. [On-Premises Deployment](#on-premises-deployment)
5. [Security Hardening](#security-hardening)
6. [Backup & Disaster Recovery](#backup--disaster-recovery)
7. [Monitoring & Logging](#monitoring--logging)
8. [Performance Tuning](#performance-tuning)
9. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

### Infrastructure Requirements

**Minimum Resources (Tier 1 - Small Clients)**:
- 4 vCPUs
- 16 GB RAM
- 200 GB SSD storage
- 100 Mbps network bandwidth

**Recommended Resources (Tier 2 - Mid-Size Clients)**:
- 8 vCPUs
- 32 GB RAM
- 500 GB SSD storage
- 1 Gbps network bandwidth

**Enterprise Resources (Tier 3 - Large Clients)**:
- 16+ vCPUs
- 64+ GB RAM
- 1+ TB SSD storage
- 10 Gbps network bandwidth

### Required Credentials

```bash
# Create .env.production file
cat > .env.production <<EOF
# Database
DATABASE_PASSWORD=<strong-password-here>
POSTGRES_DB=gtl_security_prod

# Redis
REDIS_PASSWORD=<strong-password-here>

# API Keys
DEEPSEEK_API_KEY=<your-deepseek-key>
SHODAN_API_KEY=<your-shodan-key>

# JWT Secret
JWT_SECRET_KEY=<generate-with-openssl-rand-hex-32>

# Email (for alerts)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@gtl.pe
SMTP_PASSWORD=<app-password>

# Domain
DOMAIN=gtl.yourdomain.com

# Environment
ENVIRONMENT=production
DEBUG=false
EOF
```

### SSL/TLS Certificates

```bash
# Option 1: Let's Encrypt (free, auto-renew)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d gtl.yourdomain.com

# Option 2: Commercial certificate
# Place certificate files in ./ssl/
# - gtl.yourdomain.com.crt
# - gtl.yourdomain.com.key
# - ca_bundle.crt
```

---

## Cloud Deployment (AWS)

### Architecture

```
┌─────────────────────────────────────────────────┐
│  Route 53 DNS                                   │
│  gtl.yourdomain.com → ALB                       │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  Application Load Balancer (ALB)                │
│  - SSL termination                              │
│  - Health checks                                │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  ECS Fargate Cluster                            │
│  - gtl-api (2 tasks)                            │
│  - gtl-celery-worker (3 tasks)                  │
│  - gtl-celery-beat (1 task)                     │
└─────────────────────────────────────────────────┘
                    ↓
┌──────────────────┬──────────────────┬───────────┐
│  RDS PostgreSQL  │  ElastiCache     │  EFS      │
│  Multi-AZ        │  Redis           │  Scan     │
│                  │                  │  Results  │
└──────────────────┴──────────────────┴───────────┘
```

### Step 1: Create VPC

```bash
# Use Terraform (recommended)
cd deployment/terraform/aws

# Edit terraform.tfvars
cat > terraform.tfvars <<EOF
aws_region = "us-east-1"
environment = "production"
vpc_cidr = "10.0.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b"]
EOF

terraform init
terraform plan
terraform apply
```

### Step 2: Deploy Database

```bash
# RDS PostgreSQL (Multi-AZ for high availability)
aws rds create-db-instance \
  --db-instance-identifier gtl-postgres-prod \
  --db-instance-class db.r6g.xlarge \
  --engine postgres \
  --engine-version 15.4 \
  --master-username gtl_admin \
  --master-user-password <strong-password> \
  --allocated-storage 500 \
  --storage-type gp3 \
  --vpc-security-group-ids sg-xxxxxxxxx \
  --db-subnet-group-name gtl-db-subnet \
  --multi-az \
  --backup-retention-period 30 \
  --preferred-backup-window "03:00-04:00" \
  --preferred-maintenance-window "mon:04:00-mon:05:00"
```

### Step 3: Deploy Redis

```bash
# ElastiCache Redis (Cluster mode)
aws elasticache create-replication-group \
  --replication-group-id gtl-redis-prod \
  --replication-group-description "GTL Redis Cluster" \
  --engine redis \
  --cache-node-type cache.r6g.large \
  --num-cache-clusters 2 \
  --automatic-failover-enabled \
  --at-rest-encryption-enabled \
  --transit-encryption-enabled \
  --auth-token <strong-password> \
  --cache-subnet-group-name gtl-redis-subnet
```

### Step 4: Build and Push Docker Images

```bash
# ECR (Elastic Container Registry)
aws ecr create-repository --repository-name gtl-api
aws ecr create-repository --repository-name gtl-celery

# Get login credentials
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build and push
docker build -t gtl-api:latest .
docker tag gtl-api:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/gtl-api:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/gtl-api:latest
```

### Step 5: Deploy ECS Services

```bash
# Create ECS cluster
aws ecs create-cluster --cluster-name gtl-production

# Register task definitions
aws ecs register-task-definition --cli-input-json file://deployment/ecs/gtl-api-task.json
aws ecs register-task-definition --cli-input-json file://deployment/ecs/gtl-celery-task.json

# Create services
aws ecs create-service \
  --cluster gtl-production \
  --service-name gtl-api \
  --task-definition gtl-api:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-zzz],assignPublicIp=DISABLED}" \
  --load-balancers targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=gtl-api,containerPort=8000
```

---

## Cloud Deployment (Azure)

### Architecture

```
┌─────────────────────────────────────────────────┐
│  Azure Front Door                               │
│  gtl.yourdomain.com → App Gateway               │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  Azure Kubernetes Service (AKS)                 │
│  - gtl-api (2 pods)                             │
│  - gtl-celery (3 pods)                          │
└─────────────────────────────────────────────────┘
                    ↓
┌──────────────────┬──────────────────┬───────────┐
│  Azure Database  │  Azure Cache     │  Azure    │
│  for PostgreSQL  │  for Redis       │  Files    │
└──────────────────┴──────────────────┴───────────┘
```

### Step 1: Create Resource Group

```bash
az group create \
  --name gtl-production-rg \
  --location eastus
```

### Step 2: Deploy PostgreSQL

```bash
az postgres flexible-server create \
  --resource-group gtl-production-rg \
  --name gtl-postgres-prod \
  --location eastus \
  --admin-user gtl_admin \
  --admin-password <strong-password> \
  --sku-name Standard_D4s_v3 \
  --tier GeneralPurpose \
  --storage-size 512 \
  --version 15 \
  --high-availability ZoneRedundant \
  --backup-retention 30
```

### Step 3: Deploy AKS Cluster

```bash
az aks create \
  --resource-group gtl-production-rg \
  --name gtl-aks-cluster \
  --node-count 3 \
  --node-vm-size Standard_D8s_v3 \
  --enable-managed-identity \
  --generate-ssh-keys \
  --network-plugin azure \
  --enable-addons monitoring

# Get credentials
az aks get-credentials --resource-group gtl-production-rg --name gtl-aks-cluster
```

### Step 4: Deploy with Helm

```bash
# Add Helm repo
helm repo add gtl https://charts.gtl.pe

# Install GTL platform
helm install gtl-production gtl/gtl-platform \
  --set image.tag=v1.0.0 \
  --set postgresql.host=gtl-postgres-prod.postgres.database.azure.com \
  --set redis.host=gtl-redis-prod.redis.cache.windows.net \
  --set ingress.enabled=true \
  --set ingress.host=gtl.yourdomain.com
```

---

## On-Premises Deployment

### Step 1: Prepare Server

```bash
# Ubuntu 22.04 LTS (recommended)
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### Step 2: Clone Repository

```bash
cd /opt
sudo git clone https://github.com/gtl-security/gtl-platform.git
cd gtl-platform
sudo chown -R $USER:$USER .
```

### Step 3: Configure Environment

```bash
# Copy production environment file
cp .env.example .env.production
nano .env.production  # Edit with production values

# Copy production docker-compose
cp docker-compose.yml docker-compose.production.yml
```

### Step 4: Configure Nginx Reverse Proxy

```bash
# Edit nginx.conf for production
cat > nginx.conf <<'EOF'
events {
    worker_connections 4096;
}

http {
    upstream gtl_api {
        server api:8000;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

    server {
        listen 80;
        server_name gtl.yourdomain.com;

        # Redirect to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name gtl.yourdomain.com;

        # SSL certificates
        ssl_certificate /etc/nginx/ssl/gtl.yourdomain.com.crt;
        ssl_certificate_key /etc/nginx/ssl/gtl.yourdomain.com.key;

        # SSL security
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;

        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;

        location / {
            limit_req zone=api_limit burst=20 nodelay;

            proxy_pass http://gtl_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }
}
EOF
```

### Step 5: Deploy

```bash
# Start services
docker-compose -f docker-compose.production.yml --env-file .env.production up -d

# Check status
docker-compose -f docker-compose.production.yml ps

# View logs
docker-compose -f docker-compose.production.yml logs -f
```

---

## Security Hardening

### 1. Database Security

```sql
-- Connect to PostgreSQL
psql -h localhost -U gtl_admin -d gtl_security_prod

-- Create read-only user for reporting
CREATE USER gtl_reader WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE gtl_security_prod TO gtl_reader;
GRANT USAGE ON SCHEMA public TO gtl_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO gtl_reader;

-- Enable SSL connections only
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';

-- Configure pg_hba.conf
# TYPE  DATABASE        USER            ADDRESS         METHOD
hostssl all            all             0.0.0.0/0       scram-sha-256
```

### 2. Network Security

```bash
# Configure firewall (ufw)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH (restrict to known IPs)
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Restrict SSH to specific IPs (recommended)
sudo ufw delete allow 22/tcp
sudo ufw allow from 203.0.113.0/24 to any port 22 proto tcp
```

### 3. Container Security

```yaml
# docker-compose.production.yml - Add security options
services:
  api:
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined
    read_only: true
    tmpfs:
      - /tmp
      - /var/tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

### 4. Secrets Management

```bash
# Use Docker Secrets (Swarm mode)
echo "my_database_password" | docker secret create db_password -

# Or use HashiCorp Vault
vault kv put secret/gtl/production \
  database_password="..." \
  jwt_secret="..." \
  deepseek_api_key="..."
```

### 5. API Security

```python
# gtl_api_gateway/main.py - Add rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/v1/scans/create")
@limiter.limit("10/minute")
async def create_scan(request: Request, ...):
    ...
```

---

## Backup & Disaster Recovery

### 1. Database Backups

```bash
# Automated daily backups (cron job)
cat > /opt/gtl-platform/scripts/backup_db.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/gtl"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_HOST="localhost"
DB_NAME="gtl_security_prod"
DB_USER="gtl_admin"

# Create backup
mkdir -p $BACKUP_DIR
PGPASSWORD=$DATABASE_PASSWORD pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME | \
  gzip > $BACKUP_DIR/gtl_db_$TIMESTAMP.sql.gz

# Upload to S3
aws s3 cp $BACKUP_DIR/gtl_db_$TIMESTAMP.sql.gz s3://gtl-backups/database/

# Delete backups older than 30 days
find $BACKUP_DIR -name "gtl_db_*.sql.gz" -mtime +30 -delete

echo "Backup completed: gtl_db_$TIMESTAMP.sql.gz"
EOF

chmod +x /opt/gtl-platform/scripts/backup_db.sh

# Add to crontab
crontab -e
# Add line: 0 2 * * * /opt/gtl-platform/scripts/backup_db.sh >> /var/log/gtl_backup.log 2>&1
```

### 2. Volume Backups

```bash
# Backup scan results volume
docker run --rm \
  -v gtl_scan_results:/data \
  -v /var/backups/gtl:/backup \
  alpine tar czf /backup/scan_results_$(date +%Y%m%d).tar.gz -C /data .

# Restore from backup
docker run --rm \
  -v gtl_scan_results:/data \
  -v /var/backups/gtl:/backup \
  alpine tar xzf /backup/scan_results_20240101.tar.gz -C /data
```

### 3. Disaster Recovery Plan

**RTO (Recovery Time Objective)**: 4 hours
**RPO (Recovery Point Objective)**: 24 hours

**Recovery Steps**:

1. **Database Recovery** (30 min):
   ```bash
   # Restore from latest backup
   LATEST_BACKUP=$(aws s3 ls s3://gtl-backups/database/ | sort | tail -n 1 | awk '{print $4}')
   aws s3 cp s3://gtl-backups/database/$LATEST_BACKUP /tmp/restore.sql.gz
   gunzip /tmp/restore.sql.gz
   psql -h new-db-host -U gtl_admin -d gtl_security_prod < /tmp/restore.sql
   ```

2. **Redeploy Services** (2 hours):
   ```bash
   # Pull latest images
   docker-compose -f docker-compose.production.yml pull

   # Start services
   docker-compose -f docker-compose.production.yml up -d
   ```

3. **Verify System** (1.5 hours):
   ```bash
   # Health checks
   curl https://gtl.yourdomain.com/health

   # Run test scan
   curl -X POST https://gtl.yourdomain.com/api/v1/scans/create ...
   ```

---

## Monitoring & Logging

### 1. Prometheus + Grafana

```yaml
# docker-compose.monitoring.yml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=30d'

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=<strong-password>
      - GF_INSTALL_PLUGINS=redis-datasource
```

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'gtl-api'
    static_configs:
      - targets: ['api:8000']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

### 2. ELK Stack (Elasticsearch, Logstash, Kibana)

```yaml
# docker-compose.logging.yml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "5601:5601"
```

### 3. CloudWatch (AWS)

```python
# gtl_api_gateway/main.py - Add CloudWatch logging
import watchtower
import logging

logger = logging.getLogger(__name__)
logger.addHandler(watchtower.CloudWatchLogHandler(
    log_group='/gtl/production/api',
    stream_name='api-{machine_name}'
))

@app.post("/api/v1/scans/create")
async def create_scan(...):
    logger.info(f"Scan created: client={client_id}, target={target}")
```

---

## Performance Tuning

### 1. PostgreSQL Optimization

```sql
-- postgresql.conf optimizations for 32GB RAM server
ALTER SYSTEM SET shared_buffers = '8GB';
ALTER SYSTEM SET effective_cache_size = '24GB';
ALTER SYSTEM SET maintenance_work_mem = '2GB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET min_wal_size = '1GB';
ALTER SYSTEM SET max_wal_size = '4GB';
ALTER SYSTEM SET max_worker_processes = 8;
ALTER SYSTEM SET max_parallel_workers_per_gather = 4;
ALTER SYSTEM SET max_parallel_workers = 8;

-- Reload configuration
SELECT pg_reload_conf();

-- Add indexes for common queries
CREATE INDEX idx_scans_client_created ON scans(client_id, created_at DESC);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity, cvss_score DESC);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
```

### 2. Redis Optimization

```conf
# redis.conf
maxmemory 4gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec
```

### 3. Celery Worker Tuning

```python
# gtl_security_scanner/scheduler.py
celery_app = Celery(
    'gtl_security_scanner',
    broker=redis_url,
    backend=redis_url,
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='America/Lima',
    enable_utc=True,
    worker_prefetch_multiplier=4,  # Increase for I/O-bound tasks
    worker_max_tasks_per_child=1000,  # Restart workers to prevent memory leaks
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
)
```

---

## Troubleshooting

### Common Issues

**1. High Memory Usage**

```bash
# Check memory usage
docker stats

# Fix: Increase container limits
# docker-compose.production.yml
services:
  api:
    mem_limit: 4g
    mem_reservation: 2g
```

**2. Slow Scan Performance**

```bash
# Check Celery queue length
redis-cli -h localhost -p 6379
> LLEN celery

# Fix: Add more workers
docker-compose -f docker-compose.production.yml scale celery_worker=5
```

**3. Database Connection Pool Exhausted**

```python
# gtl_api_gateway/database.py
engine = create_async_engine(
    database_url,
    pool_size=20,  # Increase from default 5
    max_overflow=40,  # Increase from default 10
    pool_pre_ping=True,
)
```

**4. SSL Certificate Renewal Failed**

```bash
# Check certbot logs
sudo journalctl -u certbot

# Manual renewal
sudo certbot renew --force-renewal

# Auto-renewal (cron)
0 0 1 * * certbot renew --quiet && systemctl reload nginx
```

---

## Maintenance Schedule

**Daily**:
- Check system health dashboards
- Review error logs
- Monitor disk space usage

**Weekly**:
- Review security scan results
- Check backup integrity
- Update threat intelligence feeds

**Monthly**:
- Apply security patches
- Review access logs
- Update SSL certificates if needed
- Performance optimization review

**Quarterly**:
- Disaster recovery drill
- Security audit
- Capacity planning review

---

## Support

**Production Issues**: support@gtl.pe
**Emergency Hotline**: +51 1 234 5678 (24/7)
**Documentation**: https://docs.gtl.pe

---

**GTL AI Security Platform - Deployment Guide v1.0**
