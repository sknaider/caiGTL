"""
Configuration management for GTL API Gateway
Loads settings from environment variables with secure defaults
"""

from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """Application settings with secure defaults"""

    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://gtl_admin:changeme@postgres:5432/gtl_security_prod"
    )

    # Redis (for rate limiting and caching)
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")

    # JWT Configuration
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # 1 hour
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30  # 30 days

    # Security
    ALLOWED_ORIGINS: List[str] = [
        "https://gtl.yourdomain.com",
        "https://dashboard.gtl.pe",
    ] if ENVIRONMENT == "production" else ["http://localhost:3000", "http://localhost:8000"]

    ALLOWED_HOSTS: List[str] = [
        "gtl.yourdomain.com",
        "api.gtl.pe",
    ] if ENVIRONMENT == "production" else ["localhost", "127.0.0.1", "*"]

    # Rate Limiting (requests per minute per IP)
    RATE_LIMIT_DEFAULT: int = 60
    RATE_LIMIT_AUTH: int = 5  # Strict for login endpoints
    RATE_LIMIT_SCAN: int = 20  # Limit scan creation

    # Password Policy
    MIN_PASSWORD_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # Audit Logging
    AUDIT_LOG_RETENTION_DAYS: int = 365
    AUDIT_LOG_TO_FILE: bool = True
    AUDIT_LOG_FILE_PATH: str = "/var/log/gtl/audit.log"

    # HashiCorp Vault (for secrets management)
    VAULT_ENABLED: bool = os.getenv("VAULT_ENABLED", "false").lower() == "true"
    VAULT_ADDR: str = os.getenv("VAULT_ADDR", "http://vault:8200")
    VAULT_TOKEN: str = os.getenv("VAULT_TOKEN", "")
    VAULT_SECRET_PATH: str = "secret/gtl/production"

    # Monitoring
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090

    # External APIs
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Email Alerts
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "alerts@gtl.pe")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.getenv("SMTP_FROM", "GTL Security <alerts@gtl.pe>")

    # Webhook Notifications
    WEBHOOK_ENABLED: bool = os.getenv("WEBHOOK_ENABLED", "false").lower() == "true"
    WEBHOOK_URL: str = os.getenv("WEBHOOK_URL", "")

    # Scan Limits
    MAX_CONCURRENT_SCANS: int = 10
    MAX_SCAN_DURATION_MINUTES: int = 60
    MAX_TARGETS_PER_SCAN: int = 100

    # File Upload
    MAX_UPLOAD_SIZE_MB: int = 10
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = [".txt", ".csv", ".json"]

    # SSRF Protection
    BLOCKED_IP_RANGES: List[str] = [
        "127.0.0.0/8",      # Loopback
        "10.0.0.0/8",       # Private
        "172.16.0.0/12",    # Private
        "192.168.0.0/16",   # Private
        "169.254.0.0/16",   # Link-local
        "::1/128",          # IPv6 loopback
        "fc00::/7",         # IPv6 private
    ]

    BLOCKED_DOMAINS: List[str] = [
        "localhost",
        "metadata.google.internal",  # GCP metadata
        "169.254.169.254",           # AWS/Azure metadata
    ]

    class Config:
        env_file = ".env"
        case_sensitive = True


# Create global settings instance
settings = Settings()


# Validate critical settings on startup
def validate_settings():
    """Validate critical configuration on startup"""
    errors = []

    # Check JWT secret in production
    if settings.ENVIRONMENT == "production":
        if settings.JWT_SECRET_KEY == "CHANGE_THIS_IN_PRODUCTION":
            errors.append("JWT_SECRET_KEY must be changed in production")

        if "localhost" in settings.ALLOWED_ORIGINS:
            errors.append("localhost should not be in ALLOWED_ORIGINS in production")

        if not settings.VAULT_ENABLED:
            errors.append("HashiCorp Vault should be enabled in production")

    # Check database URL
    if "changeme" in settings.DATABASE_URL.lower():
        errors.append("Database password should be changed from default")

    # Check API keys
    if not settings.DEEPSEEK_API_KEY and settings.ENVIRONMENT == "production":
        errors.append("DEEPSEEK_API_KEY is required for AI functionality")

    if errors:
        raise ValueError(f"Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))


# Run validation
if __name__ != "__main__":
    try:
        validate_settings()
    except ValueError as e:
        if settings.ENVIRONMENT == "production":
            raise
        else:
            print(f"WARNING: {e}")
