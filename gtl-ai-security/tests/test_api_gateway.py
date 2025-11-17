"""
Comprehensive test suite for GTL API Gateway
Tests authentication, authorization, input validation, rate limiting, security
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import jwt
import time

from gtl_api_gateway.main import app
from gtl_api_gateway.config import settings
from gtl_api_gateway.security import create_access_token, get_password_hash
from gtl_api_gateway.models import Base, User


# Test database setup
TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

client = TestClient(app)


# ===========================
# Fixtures
# ===========================

@pytest.fixture
def test_db():
    """Create test database session"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def test_user(test_db):
    """Create test user"""
    user = User(
        id="test_user_123",
        email="test@example.com",
        password_hash=get_password_hash("TestPassword123!"),
        full_name="Test User",
        organization="Test Org",
        role="user",
        is_active=True
    )
    test_db.add(user)
    test_db.commit()
    return user


@pytest.fixture
def test_admin(test_db):
    """Create test admin user"""
    admin = User(
        id="test_admin_456",
        email="admin@example.com",
        password_hash=get_password_hash("AdminPassword123!"),
        full_name="Admin User",
        organization="Test Org",
        role="admin",
        is_active=True
    )
    test_db.add(admin)
    test_db.commit()
    return admin


@pytest.fixture
def user_token(test_user):
    """Generate valid user JWT token"""
    return create_access_token(data={"sub": test_user.id, "role": "user"})


@pytest.fixture
def admin_token(test_admin):
    """Generate valid admin JWT token"""
    return create_access_token(data={"sub": test_admin.id, "role": "admin"})


# ===========================
# Health & Status Tests
# ===========================

def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "version" in data


def test_api_status_requires_auth():
    """Test that API status requires authentication"""
    response = client.get("/api/v1/status")
    assert response.status_code == 401


def test_api_status_with_auth(user_token):
    """Test API status with authentication"""
    response = client.get(
        "/api/v1/status",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "statistics" in data


# ===========================
# Authentication Tests
# ===========================

def test_login_success(test_user):
    """Test successful login"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data


def test_login_invalid_password(test_user):
    """Test login with invalid password"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "WrongPassword"
        }
    )
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]


def test_login_nonexistent_user():
    """Test login with non-existent user"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "nonexistent@example.com",
            "password": "SomePassword123!"
        }
    )
    assert response.status_code == 401


def test_login_weak_password():
    """Test login with weak password (should fail validation)"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "weak"
        }
    )
    assert response.status_code == 422  # Validation error


def test_logout(user_token):
    """Test logout"""
    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200


def test_expired_token():
    """Test authentication with expired token"""
    # Create token that expired 1 hour ago
    expired_token = jwt.encode(
        {
            "sub": "test_user",
            "exp": datetime.utcnow() - timedelta(hours=1),
            "iat": datetime.utcnow() - timedelta(hours=2),
            "type": "access"
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    response = client.get(
        "/api/v1/status",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


# ===========================
# Authorization Tests (RBAC)
# ===========================

def test_user_cannot_create_users(user_token):
    """Test that regular user cannot create new users"""
    response = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "full_name": "New User",
            "organization": "Test Org",
            "role": "user"
        }
    )
    assert response.status_code == 403


def test_admin_can_create_users(admin_token):
    """Test that admin can create new users"""
    response = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "full_name": "New User",
            "organization": "Test Org",
            "role": "user"
        }
    )
    assert response.status_code == 201


def test_user_cannot_view_audit_logs(user_token):
    """Test that regular user cannot view audit logs"""
    response = client.get(
        "/api/v1/admin/audit-logs",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403


def test_admin_can_view_audit_logs(admin_token):
    """Test that admin can view audit logs"""
    response = client.get(
        "/api/v1/admin/audit-logs",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200


# ===========================
# Input Validation Tests
# ===========================

def test_sql_injection_protection(user_token):
    """Test protection against SQL injection"""
    malicious_inputs = [
        "'; DROP TABLE users--",
        "1' OR '1'='1",
        "admin'--",
        "1 UNION SELECT * FROM users",
    ]

    for payload in malicious_inputs:
        response = client.post(
            "/api/v1/scans/create",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "client_id": payload,
                "profile": "logistics",
                "target": {"ip_address": "192.168.1.1"}
            }
        )
        # Should either reject (400) or sanitize
        assert response.status_code in [400, 422]


def test_xss_protection(user_token):
    """Test protection against XSS"""
    malicious_inputs = [
        "<script>alert('XSS')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<iframe src='evil.com'>",
    ]

    for payload in malicious_inputs:
        response = client.post(
            "/api/v1/scans/create",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "client_id": payload,
                "profile": "logistics",
                "target": {"ip_address": "192.168.1.1"}
            }
        )
        assert response.status_code in [400, 422]


def test_ssrf_protection(user_token):
    """Test protection against SSRF attacks"""
    malicious_targets = [
        {"ip_address": "127.0.0.1"},
        {"ip_address": "169.254.169.254"},  # AWS metadata
        {"domain": "localhost"},
        {"domain": "metadata.google.internal"},
        {"url": "http://127.0.0.1:8000/admin"},
    ]

    for target in malicious_targets:
        response = client.post(
            "/api/v1/scans/create",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "client_id": "test_client",
                "profile": "logistics",
                "target": target
            }
        )
        # Should be rejected
        assert response.status_code in [400, 422]


def test_path_traversal_protection():
    """Test protection against path traversal"""
    malicious_paths = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2f",
    ]

    # Test in file upload or path parameters
    # (Implementation depends on specific endpoints)
    pass


def test_command_injection_protection(user_token):
    """Test protection against command injection"""
    malicious_commands = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(cat /etc/passwd)",
    ]

    for payload in malicious_commands:
        response = client.post(
            "/api/v1/scans/create",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "client_id": payload,
                "profile": "logistics",
                "target": {"ip_address": "192.168.1.1"}
            }
        )
        assert response.status_code in [400, 422]


# ===========================
# Rate Limiting Tests
# ===========================

def test_rate_limiting_login():
    """Test rate limiting on login endpoint"""
    # Attempt 10 logins rapidly (limit is 5/minute)
    for i in range(10):
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "TestPassword123!"
            }
        )

        if i < 5:
            # First 5 should succeed (or fail with 401 for bad credentials)
            assert response.status_code in [200, 401]
        else:
            # After 5, should be rate limited
            assert response.status_code == 429


def test_rate_limiting_scan_creation(user_token):
    """Test rate limiting on scan creation"""
    # Attempt 25 scan creations rapidly (limit is 20/minute)
    responses = []

    for i in range(25):
        response = client.post(
            "/api/v1/scans/create",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "client_id": "test_client",
                "profile": "logistics",
                "target": {"ip_address": f"192.168.1.{i}"}
            }
        )
        responses.append(response.status_code)

    # At least one should be rate limited
    assert 429 in responses


# ===========================
# Scan Management Tests
# ===========================

def test_create_scan_success(user_token):
    """Test successful scan creation"""
    response = client.post(
        "/api/v1/scans/create",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "client_id": "test_client_001",
            "profile": "logistics",
            "target": {"ip_address": "192.168.1.100"},
            "tools_enabled": {
                "nmap": True,
                "nuclei": True
            }
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "queued"


def test_create_scan_invalid_profile(user_token):
    """Test scan creation with invalid profile"""
    response = client.post(
        "/api/v1/scans/create",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "client_id": "test_client",
            "profile": "invalid_profile",
            "target": {"ip_address": "192.168.1.100"}
        }
    )
    assert response.status_code == 422


def test_get_scan_status(user_token):
    """Test retrieving scan status"""
    # First create a scan
    create_response = client.post(
        "/api/v1/scans/create",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "client_id": "test_client",
            "profile": "logistics",
            "target": {"ip_address": "192.168.1.100"}
        }
    )
    scan_id = create_response.json()["scan_id"]

    # Get status
    response = client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == scan_id


def test_list_scans(user_token):
    """Test listing scans"""
    response = client.get(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "scans" in data
    assert "total" in data


# ===========================
# Security Headers Tests
# ===========================

def test_security_headers():
    """Test that security headers are present"""
    response = client.get("/health")

    assert "X-Content-Type-Options" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"

    assert "X-Frame-Options" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"

    assert "X-XSS-Protection" in response.headers
    assert response.headers["X-XSS-Protection"] == "1; mode=block"

    assert "Strict-Transport-Security" in response.headers

    assert "Content-Security-Policy" in response.headers


def test_no_server_header():
    """Test that Server header is not exposed"""
    response = client.get("/health")
    assert "Server" not in response.headers or response.headers.get("Server") == ""


# ===========================
# Password Policy Tests
# ===========================

def test_weak_password_rejected():
    """Test that weak passwords are rejected"""
    weak_passwords = [
        "short",
        "NoNumber!",
        "nonumber123",
        "NOUPPER123",
        "NoSpecial123",
        "password123!",  # Common password
    ]

    for password in weak_passwords:
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": password
            }
        )
        # Should fail validation
        assert response.status_code == 422


# ===========================
# Audit Logging Tests
# ===========================

def test_audit_log_login(test_db, test_user):
    """Test that login attempts are logged"""
    from gtl_api_gateway.models import AuditLog

    # Perform login
    client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
    )

    # Check audit log
    logs = test_db.query(AuditLog).filter(
        AuditLog.action == "auth.login.success"
    ).all()

    assert len(logs) > 0
    assert logs[0].user_id == test_user.id


def test_audit_log_scan_creation(test_db, user_token, test_user):
    """Test that scan creation is logged"""
    from gtl_api_gateway.models import AuditLog

    # Create scan
    client.post(
        "/api/v1/scans/create",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "client_id": "test_client",
            "profile": "logistics",
            "target": {"ip_address": "192.168.1.100"}
        }
    )

    # Check audit log
    logs = test_db.query(AuditLog).filter(
        AuditLog.action == "scan.create"
    ).all()

    assert len(logs) > 0


# ===========================
# Edge Cases & Error Handling
# ===========================

def test_malformed_json():
    """Test handling of malformed JSON"""
    response = client.post(
        "/api/v1/auth/login",
        data="not valid json",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422


def test_missing_required_fields(user_token):
    """Test handling of missing required fields"""
    response = client.post(
        "/api/v1/scans/create",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "client_id": "test_client"
            # Missing profile and target
        }
    )
    assert response.status_code == 422


def test_invalid_json_types(user_token):
    """Test handling of invalid JSON types"""
    response = client.post(
        "/api/v1/scans/create",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "client_id": 12345,  # Should be string
            "profile": "logistics",
            "target": {"ip_address": "192.168.1.100"}
        }
    )
    assert response.status_code in [400, 422]


# ===========================
# Performance Tests
# ===========================

def test_concurrent_requests(user_token):
    """Test handling of concurrent requests"""
    import concurrent.futures

    def make_request():
        return client.get(
            "/api/v1/status",
            headers={"Authorization": f"Bearer {user_token}"}
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request) for _ in range(50)]
        responses = [f.result() for f in concurrent.futures.as_completed(futures)]

    # All should succeed (or some rate limited)
    success_count = sum(1 for r in responses if r.status_code == 200)
    assert success_count > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
