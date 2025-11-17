"""
GTL API Gateway - Enterprise-Grade REST API
Provides secure access to GTL AI Security Platform with:
- JWT authentication & authorization
- RBAC (Role-Based Access Control)
- Rate limiting & DDoS protection
- Input validation & sanitization
- Comprehensive audit logging
- CORS & security headers
"""

from fastapi import FastAPI, Depends, HTTPException, Request, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator, IPvAnyAddress
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON, text
import jwt
import hashlib
import secrets
import re
import logging
from contextlib import asynccontextmanager
import asyncio

# Configuration
from gtl_api_gateway.config import settings
from gtl_api_gateway.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    verify_token,
    require_role,
    audit_log
)
from gtl_api_gateway.models import (
    User,
    APIKey,
    AuditLog,
    RateLimitRule
)
from gtl_api_gateway.validators import (
    validate_ip_address,
    validate_scan_target,
    sanitize_input,
    prevent_ssrf
)

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Database setup
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True,
)
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting GTL API Gateway...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized")

    yield

    # Shutdown
    logger.info("Shutting down GTL API Gateway...")
    await engine.dispose()

# Initialize FastAPI app
app = FastAPI(
    title="GTL AI Security Platform API",
    description="Enterprise-grade security scanning and threat detection API",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    lifespan=lifespan,
)

# Security middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS configuration (restrictive in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    max_age=3600,
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.utcnow()

    # Generate request ID
    request_id = secrets.token_hex(16)
    request.state.request_id = request_id

    # Log request
    logger.info(f"[{request_id}] {request.method} {request.url.path} - Client: {request.client.host}")

    response = await call_next(request)

    # Calculate duration
    duration = (datetime.utcnow() - start_time).total_seconds()

    # Log response
    logger.info(f"[{request_id}] Status: {response.status_code} - Duration: {duration:.3f}s")

    # Add request ID to response
    response.headers["X-Request-ID"] = request_id

    return response

# Database dependency
async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# Authentication dependency
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Verify JWT token and return current user"""
    token = credentials.credentials

    try:
        payload = verify_token(token)
        user_id = payload.get("sub")

        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user from database
        result = await db.execute(
            text("SELECT * FROM users WHERE id = :user_id AND is_active = true"),
            {"user_id": user_id}
        )
        user = result.first()

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Pydantic models for API
class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")

    @validator('email')
    def validate_email(cls, v):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', v):
            raise ValueError('Invalid email format')
        return v.lower()

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    user: Dict[str, Any]

class CreateUserRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=12, description="Strong password (12+ chars)")
    full_name: str = Field(..., min_length=2, max_length=100)
    organization: str = Field(..., min_length=2, max_length=100)
    role: str = Field(default="user", description="User role: admin, analyst, user")

    @validator('email')
    def validate_email(cls, v):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', v):
            raise ValueError('Invalid email format')
        return v.lower()

    @validator('password')
    def validate_password(cls, v):
        # Enforce strong password policy
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain special character')
        return v

    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ['admin', 'analyst', 'user', 'readonly']
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v

class ScanTarget(BaseModel):
    ip_address: Optional[str] = Field(None, description="IPv4 or IPv6 address")
    domain: Optional[str] = Field(None, description="Domain name")
    url: Optional[str] = Field(None, description="Full URL")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Port number")

    @validator('ip_address')
    def validate_ip(cls, v):
        if v:
            return validate_ip_address(v)
        return v

    @validator('domain')
    def validate_domain(cls, v):
        if v:
            # Prevent SSRF to internal domains
            if prevent_ssrf(v):
                raise ValueError('Target domain is not allowed (internal/private)')
            if not re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$', v, re.IGNORECASE):
                raise ValueError('Invalid domain format')
        return v

    @validator('url')
    def validate_url(cls, v):
        if v:
            # Sanitize and validate URL
            v = sanitize_input(v)
            if prevent_ssrf(v):
                raise ValueError('Target URL is not allowed (internal/private)')
            if not re.match(r'^https?://', v, re.IGNORECASE):
                raise ValueError('URL must start with http:// or https://')
        return v

    class Config:
        # Require at least one target
        @staticmethod
        def schema_extra(schema, model):
            schema['anyOf'] = [
                {'required': ['ip_address']},
                {'required': ['domain']},
                {'required': ['url']}
            ]

class CreateScanRequest(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=100, description="Client identifier")
    profile: str = Field(..., description="Scan profile: logistics, medical_ai, ecommerce, etc.")
    target: ScanTarget = Field(..., description="Scan target (IP, domain, or URL)")
    tools_enabled: Dict[str, bool] = Field(
        default={"nmap": True, "nuclei": True, "nikto": False, "sqlmap": False},
        description="Tools to enable for this scan"
    )
    schedule: Optional[str] = Field(None, description="Cron schedule for recurring scans")

    @validator('client_id')
    def sanitize_client_id(cls, v):
        return sanitize_input(v)

    @validator('profile')
    def validate_profile(cls, v):
        allowed_profiles = ['logistics', 'medical_ai', 'ecommerce', 'quick_scan', 'comprehensive', 'custom']
        if v not in allowed_profiles:
            raise ValueError(f'Profile must be one of: {", ".join(allowed_profiles)}')
        return v

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    created_at: datetime
    estimated_duration: int  # seconds

# ===========================
# Health & Status Endpoints
# ===========================

@app.get("/health")
@limiter.limit("100/minute")
async def health_check(request: Request):
    """Health check endpoint for load balancers"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT
    }

@app.get("/api/v1/status")
@limiter.limit("60/minute")
async def api_status(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get API status and statistics (requires authentication)"""

    # Audit log
    await audit_log(db, current_user.id, "api.status.check", request.client.host)

    # Get statistics
    result = await db.execute(text("SELECT COUNT(*) FROM scans WHERE status = 'running'"))
    active_scans = result.scalar()

    result = await db.execute(text("SELECT COUNT(*) FROM users WHERE is_active = true"))
    active_users = result.scalar()

    return {
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "statistics": {
            "active_scans": active_scans,
            "active_users": active_users,
            "uptime": "99.9%",  # TODO: Calculate real uptime
        },
        "rate_limits": {
            "remaining": 60,  # TODO: Get from rate limiter
            "reset_at": (datetime.utcnow() + timedelta(minutes=1)).isoformat()
        }
    }

# ===========================
# Authentication Endpoints
# ===========================

@app.post("/api/v1/auth/login", response_model=LoginResponse)
@limiter.limit("5/minute")  # Strict rate limit for login
async def login(
    request: Request,
    login_req: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Authenticate user and return JWT tokens"""

    # Get user from database
    result = await db.execute(
        text("SELECT * FROM users WHERE email = :email AND is_active = true"),
        {"email": login_req.email}
    )
    user = result.first()

    if not user or not verify_password(login_req.password, user.password_hash):
        # Audit failed login attempt
        await audit_log(db, None, "auth.login.failed", request.client.host, {"email": login_req.email})

        # Generic error to prevent user enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create tokens
    access_token = create_access_token(data={"sub": user.id, "role": user.role})
    refresh_token = create_refresh_token(data={"sub": user.id})

    # Update last login
    await db.execute(
        text("UPDATE users SET last_login = :now WHERE id = :user_id"),
        {"now": datetime.utcnow(), "user_id": user.id}
    )
    await db.commit()

    # Audit successful login
    await audit_log(db, user.id, "auth.login.success", request.client.host)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "organization": user.organization
        }
    )

@app.post("/api/v1/auth/logout")
@limiter.limit("10/minute")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Logout user (invalidate token)"""

    # Audit logout
    await audit_log(db, current_user.id, "auth.logout", request.client.host)

    # TODO: Add token to blacklist/revocation list

    return {"message": "Successfully logged out"}

@app.post("/api/v1/auth/refresh")
@limiter.limit("10/minute")
async def refresh_token_endpoint(
    request: Request,
    refresh_token: str = Header(..., description="Refresh token"),
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token using refresh token"""

    try:
        payload = verify_token(refresh_token, token_type="refresh")
        user_id = payload.get("sub")

        # Get user
        result = await db.execute(
            text("SELECT * FROM users WHERE id = :user_id AND is_active = true"),
            {"user_id": user_id}
        )
        user = result.first()

        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        # Create new access token
        new_access_token = create_access_token(data={"sub": user.id, "role": user.role})

        # Audit token refresh
        await audit_log(db, user.id, "auth.token.refresh", request.client.host)

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 3600
        }

    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

# ===========================
# User Management Endpoints
# ===========================

@app.post("/api/v1/users", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")  # Limit user creation
async def create_user(
    request: Request,
    user_req: CreateUserRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create new user (requires admin role)"""

    # Check authorization (only admins can create users)
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create users"
        )

    # Check if user already exists
    result = await db.execute(
        text("SELECT id FROM users WHERE email = :email"),
        {"email": user_req.email}
    )
    if result.first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists"
        )

    # Hash password
    password_hash = get_password_hash(user_req.password)

    # Create user
    user_id = secrets.token_hex(16)
    await db.execute(
        text("""
            INSERT INTO users (id, email, password_hash, full_name, organization, role, is_active, created_at)
            VALUES (:id, :email, :password_hash, :full_name, :organization, :role, true, :created_at)
        """),
        {
            "id": user_id,
            "email": user_req.email,
            "password_hash": password_hash,
            "full_name": user_req.full_name,
            "organization": user_req.organization,
            "role": user_req.role,
            "created_at": datetime.utcnow()
        }
    )
    await db.commit()

    # Audit user creation
    await audit_log(db, current_user.id, "user.create", request.client.host, {
        "new_user_id": user_id,
        "email": user_req.email,
        "role": user_req.role
    })

    return {
        "message": "User created successfully",
        "user_id": user_id,
        "email": user_req.email
    }

@app.get("/api/v1/users/me")
@limiter.limit("30/minute")
async def get_current_user_info(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Get current user information"""

    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "organization": current_user.organization,
        "role": current_user.role,
        "created_at": current_user.created_at.isoformat() if hasattr(current_user, 'created_at') else None,
        "last_login": current_user.last_login.isoformat() if hasattr(current_user, 'last_login') else None
    }

# ===========================
# Scan Management Endpoints
# ===========================

@app.post("/api/v1/scans/create", response_model=ScanResponse)
@limiter.limit("20/minute")
async def create_scan(
    request: Request,
    scan_req: CreateScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create new security scan (requires analyst or admin role)"""

    # Check authorization
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only analysts and administrators can create scans"
        )

    # Validate scan target
    target_validated = validate_scan_target(scan_req.target)

    # Create scan ID
    scan_id = secrets.token_hex(16)

    # Insert scan into database
    await db.execute(
        text("""
            INSERT INTO scans (id, client_id, profile, target, tools_enabled, status, created_by, created_at)
            VALUES (:id, :client_id, :profile, :target, :tools_enabled, 'queued', :created_by, :created_at)
        """),
        {
            "id": scan_id,
            "client_id": scan_req.client_id,
            "profile": scan_req.profile,
            "target": target_validated.json(),
            "tools_enabled": str(scan_req.tools_enabled),
            "created_by": current_user.id,
            "created_at": datetime.utcnow()
        }
    )
    await db.commit()

    # Audit scan creation
    await audit_log(db, current_user.id, "scan.create", request.client.host, {
        "scan_id": scan_id,
        "client_id": scan_req.client_id,
        "profile": scan_req.profile
    })

    # TODO: Queue scan in Celery
    # from gtl_security_scanner.scheduler import run_scheduled_scan_task
    # run_scheduled_scan_task.delay(scan_req.client_id, scan_req.profile, scan_req.target.dict())

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan created successfully and queued for execution",
        created_at=datetime.utcnow(),
        estimated_duration=300  # 5 minutes
    )

@app.get("/api/v1/scans/{scan_id}")
@limiter.limit("60/minute")
async def get_scan_status(
    request: Request,
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get scan status and results"""

    # Get scan from database
    result = await db.execute(
        text("SELECT * FROM scans WHERE id = :scan_id"),
        {"scan_id": scan_id}
    )
    scan = result.first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    # TODO: Check authorization (user can only see their own scans unless admin)

    return {
        "scan_id": scan.id,
        "client_id": scan.client_id,
        "profile": scan.profile,
        "status": scan.status,
        "created_at": scan.created_at.isoformat() if hasattr(scan, 'created_at') else None,
        "progress": 0,  # TODO: Get real progress
        "vulnerabilities_found": 0,  # TODO: Get from results
    }

@app.get("/api/v1/scans")
@limiter.limit("60/minute")
async def list_scans(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
    status_filter: Optional[str] = None
):
    """List all scans (with pagination)"""

    # Build query
    query = "SELECT * FROM scans WHERE 1=1"
    params = {}

    # Apply filters
    if current_user.role not in ["admin"]:
        # Users can only see their own scans
        query += " AND created_by = :user_id"
        params["user_id"] = current_user.id

    if status_filter:
        query += " AND status = :status"
        params["status"] = status_filter

    # Add pagination
    query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    params["limit"] = limit
    params["offset"] = offset

    # Execute query
    result = await db.execute(text(query), params)
    scans = result.fetchall()

    return {
        "scans": [
            {
                "scan_id": scan.id,
                "client_id": scan.client_id,
                "profile": scan.profile,
                "status": scan.status,
                "created_at": scan.created_at.isoformat() if hasattr(scan, 'created_at') else None
            }
            for scan in scans
        ],
        "total": len(scans),
        "limit": limit,
        "offset": offset
    }

# ===========================
# Admin Endpoints
# ===========================

@app.get("/api/v1/admin/audit-logs")
@limiter.limit("30/minute")
async def get_audit_logs(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 100,
    offset: int = 0
):
    """Get audit logs (admin only)"""

    # Check authorization
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can view audit logs"
        )

    # Get audit logs
    result = await db.execute(
        text("""
            SELECT * FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset}
    )
    logs = result.fetchall()

    return {
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp.isoformat() if hasattr(log, 'timestamp') else None,
                "metadata": log.metadata if hasattr(log, 'metadata') else None
            }
            for log in logs
        ],
        "total": len(logs),
        "limit": limit,
        "offset": offset
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )
