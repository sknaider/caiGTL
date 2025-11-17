"""
Security utilities for GTL API Gateway
Provides authentication, authorization, password hashing, JWT tokens, audit logging
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import secrets
import hashlib
import logging

from gtl_api_gateway.config import settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,
    argon2__parallelism=4,
)


def get_password_hash(password: str) -> str:
    """Hash password using Argon2"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token (longer expiration)"""
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )

        # Verify token type
        if payload.get("type") != token_type:
            raise jwt.InvalidTokenError(f"Invalid token type. Expected {token_type}")

        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        raise


def generate_api_key() -> tuple[str, str]:
    """
    Generate API key for programmatic access
    Returns: (api_key, api_key_hash)
    """
    # Generate random API key (32 bytes = 64 hex chars)
    api_key = f"gtl_{secrets.token_urlsafe(32)}"

    # Hash for storage
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    return api_key, api_key_hash


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    """Verify API key against stored hash"""
    computed_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return secrets.compare_digest(computed_hash, api_key_hash)


async def audit_log(
    db: AsyncSession,
    user_id: Optional[str],
    action: str,
    ip_address: str,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Create audit log entry

    Args:
        db: Database session
        user_id: User ID performing the action (None for unauthenticated actions)
        action: Action being performed (e.g., "auth.login.success", "scan.create")
        ip_address: Client IP address
        metadata: Additional metadata (JSON)
    """
    try:
        log_id = secrets.token_hex(16)

        await db.execute(
            text("""
                INSERT INTO audit_logs (id, user_id, action, ip_address, metadata, timestamp)
                VALUES (:id, :user_id, :action, :ip_address, :metadata, :timestamp)
            """),
            {
                "id": log_id,
                "user_id": user_id,
                "action": action,
                "ip_address": ip_address,
                "metadata": str(metadata) if metadata else None,
                "timestamp": datetime.utcnow()
            }
        )
        await db.commit()

        # Also log to file if enabled
        if settings.AUDIT_LOG_TO_FILE:
            log_entry = f"[{datetime.utcnow().isoformat()}] user={user_id} action={action} ip={ip_address} metadata={metadata}\n"

            try:
                with open(settings.AUDIT_LOG_FILE_PATH, "a") as f:
                    f.write(log_entry)
            except Exception as e:
                logger.error(f"Failed to write audit log to file: {e}")

    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")
        # Don't raise - audit logging failures shouldn't break the application


def require_role(allowed_roles: list[str]):
    """
    Decorator to enforce role-based access control

    Usage:
        @app.get("/admin/endpoint")
        @require_role(["admin"])
        async def admin_endpoint(current_user: User = Depends(get_current_user)):
            ...
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get current_user from kwargs
            current_user = kwargs.get("current_user")

            if not current_user:
                from fastapi import HTTPException, status
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            if current_user.role not in allowed_roles:
                from fastapi import HTTPException, status
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"This action requires one of these roles: {', '.join(allowed_roles)}"
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for storage (one-way)"""
    return hashlib.sha256(data.encode()).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks"""
    return secrets.compare_digest(a.encode(), b.encode())


class SecurityHeaders:
    """Security headers for HTTP responses"""

    @staticmethod
    def get_headers() -> Dict[str, str]:
        """Get recommended security headers"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "X-Permitted-Cross-Domain-Policies": "none",
        }


def generate_csrf_token() -> str:
    """Generate CSRF token for form protection"""
    return secrets.token_urlsafe(32)


def verify_csrf_token(token: str, stored_token: str) -> bool:
    """Verify CSRF token"""
    return constant_time_compare(token, stored_token)


# Rate limiting helper
class RateLimiter:
    """Simple in-memory rate limiter (use Redis in production)"""

    def __init__(self):
        self._requests: Dict[str, list] = {}

    def is_allowed(self, key: str, max_requests: int, window_seconds: int = 60) -> bool:
        """
        Check if request is allowed based on rate limit

        Args:
            key: Unique identifier (IP address, user ID, etc.)
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds

        Returns:
            True if request is allowed, False otherwise
        """
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)

        # Get existing requests for this key
        if key not in self._requests:
            self._requests[key] = []

        # Remove old requests outside window
        self._requests[key] = [
            req_time for req_time in self._requests[key]
            if req_time > window_start
        ]

        # Check if limit exceeded
        if len(self._requests[key]) >= max_requests:
            return False

        # Add current request
        self._requests[key].append(now)
        return True

    def get_remaining(self, key: str, max_requests: int, window_seconds: int = 60) -> int:
        """Get remaining requests in current window"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)

        if key not in self._requests:
            return max_requests

        # Count requests in current window
        current_requests = sum(
            1 for req_time in self._requests[key]
            if req_time > window_start
        )

        return max(0, max_requests - current_requests)


# Global rate limiter instance (use Redis in production)
rate_limiter = RateLimiter()


# Input sanitization
def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal"""
    import os.path
    # Remove path separators
    filename = os.path.basename(filename)
    # Remove null bytes
    filename = filename.replace('\0', '')
    # Limit length
    filename = filename[:255]
    return filename


def check_password_strength(password: str) -> Dict[str, Any]:
    """
    Check password strength and return detailed feedback

    Returns:
        {
            "is_strong": bool,
            "score": int (0-100),
            "feedback": list of strings
        }
    """
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 25
    else:
        feedback.append(f"Password should be at least 12 characters (current: {len(password)})")

    if len(password) >= 16:
        score += 10

    # Character variety checks
    if any(c.isupper() for c in password):
        score += 15
    else:
        feedback.append("Add uppercase letters")

    if any(c.islower() for c in password):
        score += 15
    else:
        feedback.append("Add lowercase letters")

    if any(c.isdigit() for c in password):
        score += 15
    else:
        feedback.append("Add numbers")

    import string
    if any(c in string.punctuation for c in password):
        score += 20
    else:
        feedback.append("Add special characters (!@#$%^&*)")

    # Check for common patterns
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if password.lower() in common_passwords:
        score = 0
        feedback.append("This is a very common password. Choose something unique.")

    # Check for repeated characters
    if len(set(password)) < len(password) * 0.5:
        score -= 10
        feedback.append("Too many repeated characters")

    is_strong = score >= 70 and len(feedback) == 0

    return {
        "is_strong": is_strong,
        "score": max(0, min(100, score)),
        "feedback": feedback
    }


# HashiCorp Vault integration
class VaultClient:
    """HashiCorp Vault client for secrets management"""

    def __init__(self):
        self.enabled = settings.VAULT_ENABLED
        if self.enabled:
            try:
                import hvac
                self.client = hvac.Client(
                    url=settings.VAULT_ADDR,
                    token=settings.VAULT_TOKEN
                )
                if not self.client.is_authenticated():
                    logger.error("Vault authentication failed")
                    self.enabled = False
            except ImportError:
                logger.warning("hvac library not installed. Vault disabled.")
                self.enabled = False
            except Exception as e:
                logger.error(f"Failed to initialize Vault client: {e}")
                self.enabled = False

    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve secret from Vault"""
        if not self.enabled:
            return None

        try:
            secret_path = f"{settings.VAULT_SECRET_PATH}/{key}"
            secret = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            return secret['data']['data'].get('value')
        except Exception as e:
            logger.error(f"Failed to retrieve secret from Vault: {e}")
            return None

    def set_secret(self, key: str, value: str) -> bool:
        """Store secret in Vault"""
        if not self.enabled:
            return False

        try:
            secret_path = f"{settings.VAULT_SECRET_PATH}/{key}"
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                secret={'value': value}
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store secret in Vault: {e}")
            return False


# Global Vault client
vault_client = VaultClient()
