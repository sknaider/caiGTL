# GTL AI Security Platform - API Reference

**Version**: 1.0
**Base URL**: `https://api.gtl.pe/api/v1`
**Authentication**: Bearer Token (JWT) or API Key

---

## Authentication

### POST /auth/login
Authenticate and receive JWT token.

**Request:**
```json
{
  "username": "admin@gtl.pe",
  "password": "your_password"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**Usage:**
```bash
curl -X POST https://api.gtl.pe/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@gtl.pe","password":"pass"}'
```

---

## Scans

### POST /scans/create
Create new security scan.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**
```json
{
  "client_id": "logistics_company_1",
  "target": {
    "ip_address": "192.168.1.50",
    "domain": null,
    "network_range": null
  },
  "profile": "logistics",
  "tools_enabled": {
    "nmap": true,
    "nuclei": true,
    "nikto": false,
    "sqlmap": false
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_abc123def456",
  "status": "pending",
  "created_at": "2025-11-17T12:00:00Z",
  "estimated_duration": 1800
}
```

**cURL Example:**
```bash
curl -X POST https://api.gtl.pe/api/v1/scans/create \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "logistics_company_1",
    "target": {"ip_address": "192.168.1.50"},
    "profile": "logistics"
  }'
```

### GET /scans/{scan_id}
Get scan status and results.

**Response:**
```json
{
  "scan_id": "scan_abc123def456",
  "client_id": "logistics_company_1",
  "status": "completed",
  "started_at": "2025-11-17T12:00:00Z",
  "completed_at": "2025-11-17T12:30:00Z",
  "duration_seconds": 1800,
  "findings": [
    {
      "severity": "critical",
      "title": "SQL Injection Vulnerability",
      "description": "SQL injection in login form",
      "cvss_score": 9.8,
      "cve": ["CVE-2024-1234"]
    }
  ],
  "total_findings": 15
}
```

### GET /scans?client_id={id}&status={status}
List scans with filters.

**Query Parameters:**
- `client_id` (optional): Filter by client
- `status` (optional): pending, running, completed, failed
- `limit` (default: 50): Results per page
- `offset` (default: 0): Pagination offset

**Response:**
```json
{
  "total": 150,
  "limit": 50,
  "offset": 0,
  "scans": [...]
}
```

---

## Reports

### GET /reports/{scan_id}
Generate report from scan results.

**Query Parameters:**
- `format`: pdf, html, json (default: pdf)
- `language`: es, en (default: es)
- `include_executive_summary`: true/false
- `cvss_threshold`: Minimum CVSS score (0.0-10.0)

**Response (JSON format):**
```json
{
  "scan_id": "scan_abc123def456",
  "report_format": "pdf",
  "report_url": "https://api.gtl.pe/reports/scan_abc123def456.pdf",
  "generated_at": "2025-11-17T12:35:00Z",
  "expires_at": "2025-11-24T12:35:00Z"
}
```

**Response (PDF/HTML):**
Binary download of report file.

**cURL Example:**
```bash
# Download PDF report
curl -H "Authorization: Bearer <token>" \
  "https://api.gtl.pe/api/v1/reports/scan_abc123def456?format=pdf&language=es" \
  -o security_report.pdf
```

---

## Webhooks

### POST /webhooks/alerts
Configure webhook for real-time alerts.

**Request:**
```json
{
  "client_id": "logistics_company_1",
  "webhook_url": "https://your-server.com/alerts",
  "webhook_secret": "your_webhook_secret",
  "events": ["scan_completed", "vulnerability_critical", "compliance_failed"],
  "enabled": true
}
```

**Webhook Payload (sent to your URL):**
```json
{
  "event": "vulnerability_critical",
  "timestamp": "2025-11-17T12:00:00Z",
  "scan_id": "scan_abc123def456",
  "client_id": "logistics_company_1",
  "data": {
    "severity": "critical",
    "title": "SQL Injection",
    "cvss_score": 9.8
  },
  "signature": "sha256=abc123..."
}
```

**Verify Webhook Signature (Python):**
```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    computed = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={computed}", signature)
```

---

## Agents

### POST /agents/run
Execute custom CAI agent.

**Request:**
```json
{
  "agent_name": "logistics_security_agent",
  "input": "Evaluar seguridad de sistema EDI en 192.168.1.50",
  "stream": false
}
```

**Response:**
```json
{
  "agent_run_id": "run_xyz789",
  "status": "completed",
  "output": "INFORME DE SEGURIDAD:\n...",
  "tokens_used": 1500,
  "cost_usd": 0.0405
}
```

### GET /agents/list
List available agents.

**Response:**
```json
{
  "agents": [
    {
      "name": "logistics_security_agent",
      "description": "Especialista en seguridad logística",
      "tools": ["nmap", "check_edi_security", "validate_bill_of_lading"]
    },
    {
      "name": "medical_ai_compliance_agent",
      "description": "HIPAA compliance specialist",
      "tools": ["check_hipaa_compliance", "check_rtx5090_endpoint"]
    }
  ]
}
```

---

## Rate Limits

| Tier | Scans/Month | API Requests/Minute | Concurrent Scans |
|------|-------------|---------------------|------------------|
| **Starter** | 8 | 100 | 1 |
| **Professional** | 32 | 500 | 3 |
| **Enterprise** | Unlimited | 2000 | 10 |

**Rate Limit Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1637155200
```

**429 Too Many Requests Response:**
```json
{
  "error": "rate_limit_exceeded",
  "message": "API rate limit exceeded",
  "retry_after": 60
}
```

---

## Error Codes

| Code | Meaning | Common Causes |
|------|---------|---------------|
| 400 | Bad Request | Invalid JSON, missing required fields |
| 401 | Unauthorized | Missing or invalid token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |
| 503 | Service Unavailable | Maintenance or overload |

**Error Response Format:**
```json
{
  "error": "validation_error",
  "message": "Invalid target IP address",
  "details": {
    "field": "target.ip_address",
    "constraint": "Must be valid IPv4 address"
  }
}
```

---

## SDK Examples

### Python SDK
```python
from gtl_sdk import GTLClient

# Initialize client
client = GTLClient(
    api_key="your_api_key",
    base_url="https://api.gtl.pe/api/v1"
)

# Create scan
scan = client.scans.create(
    client_id="logistics_co",
    target={"ip_address": "192.168.1.50"},
    profile="logistics"
)

# Wait for completion
scan.wait_for_completion(timeout=3600)

# Get results
results = scan.get_results()
print(f"Found {len(results.findings)} vulnerabilities")

# Download PDF report
scan.download_report("report.pdf", format="pdf", language="es")
```

### JavaScript/TypeScript SDK
```typescript
import { GTLClient } from '@gtl/sdk';

const client = new GTLClient({
  apiKey: 'your_api_key',
  baseUrl: 'https://api.gtl.pe/api/v1'
});

// Create scan
const scan = await client.scans.create({
  clientId: 'logistics_co',
  target: { ipAddress: '192.168.1.50' },
  profile: 'logistics'
});

// Poll for completion
const result = await scan.waitForCompletion();
console.log(`Found ${result.findings.length} vulnerabilities`);
```

### cURL Scripts
```bash
#!/bin/bash
# scan.sh - Create and monitor scan

API_KEY="your_api_key"
BASE_URL="https://api.gtl.pe/api/v1"

# Create scan
SCAN_ID=$(curl -s -X POST "$BASE_URL/scans/create" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "logistics_co",
    "target": {"ip_address": "192.168.1.50"},
    "profile": "logistics"
  }' | jq -r '.scan_id')

echo "Scan created: $SCAN_ID"

# Poll for completion
while true; do
  STATUS=$(curl -s "$BASE_URL/scans/$SCAN_ID" \
    -H "Authorization: Bearer $API_KEY" \
    | jq -r '.status')

  echo "Status: $STATUS"

  if [ "$STATUS" = "completed" ]; then
    break
  fi

  sleep 30
done

# Download report
curl -H "Authorization: Bearer $API_KEY" \
  "$BASE_URL/reports/$SCAN_ID?format=pdf&language=es" \
  -o "report_$SCAN_ID.pdf"

echo "Report downloaded: report_$SCAN_ID.pdf"
```

---

## OpenAPI Specification

Full OpenAPI 3.0 specification available at:
- **Swagger UI**: https://api.gtl.pe/docs
- **ReDoc**: https://api.gtl.pe/redoc
- **JSON**: https://api.gtl.pe/openapi.json

**Import into Postman:**
```bash
# Import URL
https://api.gtl.pe/openapi.json
```

---

**Next**: [Agent Development Guide](AGENT_DEVELOPMENT.md) | [Deployment Guide](DEPLOYMENT.md)
