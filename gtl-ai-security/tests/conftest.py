"""
Pytest configuration and shared fixtures
"""

import asyncio
import os
from typing import AsyncGenerator, Generator
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from redis import Redis
from faker import Faker

# Set test environment
os.environ["TESTING"] = "1"
os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost:5432/gtl_test"
os.environ["REDIS_URL"] = "redis://localhost:6379/1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["JWT_ALGORITHM"] = "HS256"


# ==========================================
# Database Fixtures
# ==========================================

@pytest_asyncio.fixture
async def db_engine():
    """Create async database engine for testing"""
    from gtl_api_gateway.config import settings

    engine = create_async_engine(
        settings.DATABASE_URL,
        poolclass=NullPool,  # Disable pooling for tests
        echo=False,
    )

    # Create all tables
    from gtl_api_gateway.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Drop all tables after tests
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create async database session for testing"""
    async_session = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    async with async_session() as session:
        yield session
        await session.rollback()


# ==========================================
# Redis Fixtures
# ==========================================

@pytest.fixture
def redis_client():
    """Create Redis client for testing"""
    from gtl_api_gateway.config import settings

    client = Redis.from_url(
        settings.REDIS_URL,
        decode_responses=True
    )

    yield client

    # Clear test database
    client.flushdb()
    client.close()


# ==========================================
# FastAPI Fixtures
# ==========================================

@pytest.fixture
def api_client(db_session):
    """Create FastAPI test client"""
    from gtl_api_gateway.main import app

    # Override database dependency
    async def override_get_db():
        yield db_session

    from gtl_api_gateway.main import get_db
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


# ==========================================
# Authentication Fixtures
# ==========================================

@pytest_asyncio.fixture
async def test_user(db_session):
    """Create test user"""
    from gtl_api_gateway.security import get_password_hash
    from gtl_api_gateway.models import User
    from sqlalchemy import text
    import secrets

    user_id = secrets.token_hex(16)
    password_hash = get_password_hash("TestPassword123!")

    await db_session.execute(
        text("""
            INSERT INTO users (id, email, password_hash, full_name, organization, role, is_active, created_at)
            VALUES (:id, :email, :password_hash, :full_name, :organization, :role, true, :created_at)
        """),
        {
            "id": user_id,
            "email": "test@example.com",
            "password_hash": password_hash,
            "full_name": "Test User",
            "organization": "Test Org",
            "role": "user",
            "created_at": datetime.utcnow()
        }
    )
    await db_session.commit()

    return {
        "id": user_id,
        "email": "test@example.com",
        "password": "TestPassword123!",
        "role": "user"
    }


@pytest_asyncio.fixture
async def test_admin(db_session):
    """Create test admin user"""
    from gtl_api_gateway.security import get_password_hash
    from sqlalchemy import text
    import secrets

    user_id = secrets.token_hex(16)
    password_hash = get_password_hash("AdminPassword123!")

    await db_session.execute(
        text("""
            INSERT INTO users (id, email, password_hash, full_name, organization, role, is_active, created_at)
            VALUES (:id, :email, :password_hash, :full_name, :organization, :role, true, :created_at)
        """),
        {
            "id": user_id,
            "email": "admin@example.com",
            "password_hash": password_hash,
            "full_name": "Admin User",
            "organization": "Test Org",
            "role": "admin",
            "created_at": datetime.utcnow()
        }
    )
    await db_session.commit()

    return {
        "id": user_id,
        "email": "admin@example.com",
        "password": "AdminPassword123!",
        "role": "admin"
    }


@pytest.fixture
def auth_headers(test_user):
    """Generate authentication headers"""
    from gtl_api_gateway.security import create_access_token

    token = create_access_token(
        data={"sub": test_user["id"], "role": test_user["role"]}
    )

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(test_admin):
    """Generate admin authentication headers"""
    from gtl_api_gateway.security import create_access_token

    token = create_access_token(
        data={"sub": test_admin["id"], "role": test_admin["role"]}
    )

    return {"Authorization": f"Bearer {token}"}


# ==========================================
# Data Fixtures
# ==========================================

@pytest.fixture
def faker_instance():
    """Faker instance for generating test data"""
    return Faker()


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability data for testing"""
    return {
        "id": "vuln-001",
        "title": "SQL Injection in login form",
        "description": "User input is directly concatenated into SQL query without sanitization",
        "severity": "critical",
        "category": "Injection",
        "affected_url": "https://example.com/login",
        "cvss_score": 9.8,
        "cwe_id": "CWE-89"
    }


@pytest.fixture
def sample_scan_config():
    """Sample scan configuration for testing"""
    return {
        "client_id": "test-client-001",
        "profile": "logistics",
        "target": {
            "ip_address": "192.168.1.1"
        },
        "tools_enabled": {
            "nmap": True,
            "nuclei": False,
            "nikto": False,
            "sqlmap": False
        }
    }


# ==========================================
# Mock Fixtures
# ==========================================

@pytest.fixture
def mock_llm_response():
    """Mock LLM response for AI tests"""
    return """
## Risk Assessment
This is a critical SQL injection vulnerability with a risk score of 9.8/10.
The vulnerability allows attackers to bypass authentication and access sensitive data.

## Exploit Complexity
Low - This vulnerability is trivial to exploit with basic SQL injection techniques.

## Attack Scenarios
1. Authentication bypass using ' OR '1'='1
2. Data extraction using UNION SELECT
3. Remote code execution using xp_cmdshell

## Business Impact
Complete compromise of the application and database. Potential data breach affecting
all user records, financial information, and business-critical data.

## Remediation Plan
1. Implement parameterized queries immediately
2. Use ORM with built-in SQL injection protection
3. Add input validation and sanitization
4. Implement least privilege database access

## Prevention
- Always use parameterized queries or prepared statements
- Implement proper input validation
- Use ORM frameworks correctly
- Regular security training for developers

## References
- CVE-2021-12345
- OWASP SQL Injection
- CWE-89
"""


@pytest.fixture
def mock_scan_results():
    """Mock scan results for testing"""
    return {
        "scan_id": "scan-001",
        "status": "completed",
        "findings": [
            {
                "source": "nmap",
                "type": "open_port",
                "severity": "info",
                "title": "Open Port: 22/tcp",
                "description": "Service: ssh",
                "host": "192.168.1.1",
                "port": 22
            },
            {
                "source": "nuclei",
                "type": "vulnerability",
                "severity": "high",
                "title": "Apache Struts RCE",
                "description": "Remote code execution vulnerability",
                "cve": ["CVE-2017-5638"],
                "cvss_score": 8.1
            }
        ]
    }


# ==========================================
# Event Loop Configuration
# ==========================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ==========================================
# Cleanup Fixtures
# ==========================================

@pytest.fixture(autouse=True)
def cleanup_files(tmp_path):
    """Cleanup temporary files after each test"""
    yield
    # Cleanup logic here if needed


# ==========================================
# Performance Fixtures
# ==========================================

@pytest.fixture
def benchmark_timer():
    """Simple benchmark timer"""
    import time

    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()
            return self.elapsed()

        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

    return Timer()
