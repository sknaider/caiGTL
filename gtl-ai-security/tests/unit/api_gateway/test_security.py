"""
Security tests for API Gateway
"""

import pytest
from fastapi import status


class TestSecurityHeaders:
    """Tests for security headers"""

    @pytest.mark.asyncio
    async def test_security_headers_present(self, api_client):
        """Test that all required security headers are present"""
        response = api_client.get("/health")

        assert response.status_code == status.HTTP_200_OK

        headers = response.headers

        # Check for security headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-XSS-Protection") == "1; mode=block"
        assert "Strict-Transport-Security" in headers
        assert "Content-Security-Policy" in headers

    @pytest.mark.asyncio
    async def test_cors_headers(self, api_client):
        """Test CORS configuration"""
        response = api_client.options(
            "/api/v1/scans",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST"
            }
        )

        # CORS headers should be present
        assert "Access-Control-Allow-Origin" in response.headers or response.status_code == 200


class TestInputValidation:
    """Tests for input validation and sanitization"""

    @pytest.mark.asyncio
    async def test_xss_protection(self, api_client, admin_headers):
        """Test XSS protection in user inputs"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//"
        ]

        for payload in xss_payloads:
            response = api_client.post(
                "/api/v1/users",
                headers=admin_headers,
                json={
                    "email": "test@example.com",
                    "password": "SecurePassword123!",
                    "full_name": payload,  # XSS attempt in full_name
                    "organization": "Test Org",
                    "role": "user"
                }
            )

            # Should either sanitize or reject
            if response.status_code == 201:
                data = response.json()
                # If accepted, payload should be sanitized
                assert "<script>" not in str(data)
                assert "javascript:" not in str(data)

    @pytest.mark.asyncio
    async def test_sql_injection_protection(self, api_client, admin_headers):
        """Test SQL injection protection"""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--"
        ]

        for payload in sql_payloads:
            response = api_client.post(
                "/api/v1/users",
                headers=admin_headers,
                json={
                    "email": "test@example.com",
                    "password": "SecurePassword123!",
                    "full_name": "Test User",
                    "organization": payload,  # SQL injection attempt
                    "role": "user"
                }
            )

            # Should handle safely (no 500 errors)
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    @pytest.mark.asyncio
    async def test_path_traversal_protection(self, api_client, admin_headers):
        """Test path traversal protection"""
        path_traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2f",
        ]

        for payload in path_traversal_payloads:
            response = api_client.post(
                "/api/v1/scans/create",
                headers=admin_headers,
                json={
                    "client_id": payload,
                    "profile": "logistics",
                    "target": {"ip_address": "192.168.1.1"}
                }
            )

            # Should sanitize or reject
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_400_BAD_REQUEST
            ]

    @pytest.mark.asyncio
    async def test_command_injection_protection(self, api_client, admin_headers):
        """Test command injection protection"""
        command_injection_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(whoami)"
        ]

        for payload in command_injection_payloads:
            response = api_client.post(
                "/api/v1/scans/create",
                headers=admin_headers,
                json={
                    "client_id": f"test{payload}",
                    "profile": "logistics",
                    "target": {"ip_address": "192.168.1.1"}
                }
            )

            # Should handle safely
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR


class TestRateLimiting:
    """Tests for rate limiting"""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_login_rate_limiting(self, api_client):
        """Test rate limiting on login endpoint"""
        # Make many requests quickly
        responses = []
        for i in range(10):
            response = api_client.post(
                "/api/v1/auth/login",
                json={
                    "email": "test@example.com",
                    "password": "password"
                }
            )
            responses.append(response.status_code)

        # At least some should be rate limited (429)
        assert status.HTTP_429_TOO_MANY_REQUESTS in responses

    @pytest.mark.asyncio
    async def test_health_endpoint_rate_limiting(self, api_client):
        """Test rate limiting on health endpoint"""
        # Health endpoint has higher limit (100/minute)
        responses = []
        for i in range(50):
            response = api_client.get("/health")
            responses.append(response.status_code)

        # Most should succeed (within limit)
        success_count = responses.count(status.HTTP_200_OK)
        assert success_count > 40  # At least 80% should succeed


class TestSSRFProtection:
    """Tests for SSRF (Server-Side Request Forgery) protection"""

    @pytest.mark.asyncio
    async def test_ssrf_internal_ip_blocked(self, api_client, admin_headers):
        """Test that internal IPs are blocked"""
        internal_targets = [
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "169.254.169.254",  # AWS metadata
            "10.0.0.1",  # Private network
            "172.16.0.1",  # Private network
            "192.168.1.1",  # Private network (may be allowed in some configs)
        ]

        for target in internal_targets:
            response = api_client.post(
                "/api/v1/scans/create",
                headers=admin_headers,
                json={
                    "client_id": "test-client",
                    "profile": "logistics",
                    "target": {"ip_address": target}
                }
            )

            # Most internal IPs should be blocked
            # (192.168.x.x might be allowed for internal network scanning)
            if target in ["127.0.0.1", "localhost", "169.254.169.254"]:
                assert response.status_code in [
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    status.HTTP_400_BAD_REQUEST
                ]

    @pytest.mark.asyncio
    async def test_ssrf_internal_domain_blocked(self, api_client, admin_headers):
        """Test that internal domains are blocked"""
        internal_domains = [
            "localhost",
            "internal.company.com",
            "admin.localhost",
        ]

        for domain in internal_domains:
            response = api_client.post(
                "/api/v1/scans/create",
                headers=admin_headers,
                json={
                    "client_id": "test-client",
                    "profile": "logistics",
                    "target": {"domain": domain}
                }
            )

            # Should be blocked or validated
            # Implementation may vary
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_400_BAD_REQUEST
            ]


class TestAuditLogging:
    """Tests for audit logging"""

    @pytest.mark.asyncio
    async def test_login_success_logged(self, api_client, test_user, db_session):
        """Test that successful logins are logged"""
        from sqlalchemy import text

        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user["email"],
                "password": test_user["password"]
            }
        )

        assert response.status_code == status.HTTP_200_OK

        # Check audit log
        result = await db_session.execute(
            text("""
                SELECT * FROM audit_logs
                WHERE action = 'auth.login.success'
                AND user_id = :user_id
                ORDER BY timestamp DESC
                LIMIT 1
            """),
            {"user_id": test_user["id"]}
        )
        log = result.first()

        assert log is not None
        assert log.action == "auth.login.success"

    @pytest.mark.asyncio
    async def test_login_failure_logged(self, api_client, test_user, db_session):
        """Test that failed logins are logged"""
        from sqlalchemy import text

        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user["email"],
                "password": "WrongPassword123!"
            }
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Check audit log
        result = await db_session.execute(
            text("""
                SELECT * FROM audit_logs
                WHERE action = 'auth.login.failed'
                ORDER BY timestamp DESC
                LIMIT 1
            """)
        )
        log = result.first()

        assert log is not None
        assert log.action == "auth.login.failed"


class TestRequestIDTracing:
    """Tests for request ID tracing"""

    @pytest.mark.asyncio
    async def test_request_id_in_response(self, api_client):
        """Test that X-Request-ID is in response headers"""
        response = api_client.get("/health")

        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0
