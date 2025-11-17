"""
Tests for authentication endpoints
"""

import pytest
from fastapi import status
from datetime import datetime, timedelta


class TestLogin:
    """Tests for login endpoint"""

    @pytest.mark.asyncio
    async def test_login_success(self, api_client, test_user):
        """Test successful login with valid credentials"""
        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user["email"],
                "password": test_user["password"]
            }
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify response structure
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 3600

        # Verify user data
        assert "user" in data
        assert data["user"]["email"] == test_user["email"]
        assert data["user"]["role"] == test_user["role"]

    @pytest.mark.asyncio
    async def test_login_invalid_email(self, api_client):
        """Test login with invalid email"""
        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "SomePassword123!"
            }
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Incorrect email or password" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, api_client, test_user):
        """Test login with invalid password"""
        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user["email"],
                "password": "WrongPassword123!"
            }
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Incorrect email or password" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_malformed_email(self, api_client):
        """Test login with malformed email"""
        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": "not-an-email",
                "password": "SomePassword123!"
            }
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_login_rate_limiting(self, api_client, test_user):
        """Test rate limiting on login endpoint"""
        # Make 6 requests (limit is 5/minute)
        for i in range(6):
            response = api_client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user["email"],
                    "password": "WrongPassword123!"
                }
            )

            if i < 5:
                assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_200_OK]
            else:
                # 6th request should be rate limited
                assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    @pytest.mark.asyncio
    async def test_login_sql_injection_attempt(self, api_client):
        """Test SQL injection protection"""
        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin' OR '1'='1",
                "password": "anything"
            }
        )

        # Should return 401, not 500 (internal error)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestLogout:
    """Tests for logout endpoint"""

    @pytest.mark.asyncio
    async def test_logout_success(self, api_client, auth_headers):
        """Test successful logout"""
        response = api_client.post(
            "/api/v1/auth/logout",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK
        assert "Successfully logged out" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_logout_without_auth(self, api_client):
        """Test logout without authentication"""
        response = api_client.post("/api/v1/auth/logout")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestTokenRefresh:
    """Tests for token refresh endpoint"""

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, api_client, test_user):
        """Test successful token refresh"""
        from gtl_api_gateway.security import create_refresh_token

        refresh_token = create_refresh_token(data={"sub": test_user["id"]})

        response = api_client.post(
            "/api/v1/auth/refresh",
            headers={"refresh_token": refresh_token}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 3600

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, api_client):
        """Test token refresh with invalid token"""
        response = api_client.post(
            "/api/v1/auth/refresh",
            headers={"refresh_token": "invalid-token"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_refresh_token_expired(self, api_client, test_user):
        """Test token refresh with expired token"""
        from gtl_api_gateway.security import create_refresh_token

        # Create expired token (expired 1 hour ago)
        refresh_token = create_refresh_token(
            data={"sub": test_user["id"]},
            expires_delta=timedelta(hours=-1)
        )

        response = api_client.post(
            "/api/v1/auth/refresh",
            headers={"refresh_token": refresh_token}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestCurrentUser:
    """Tests for current user endpoint"""

    @pytest.mark.asyncio
    async def test_get_current_user_success(self, api_client, auth_headers, test_user):
        """Test getting current user info"""
        response = api_client.get(
            "/api/v1/users/me",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["email"] == test_user["email"]
        assert data["role"] == test_user["role"]
        assert "password" not in data  # Password should never be returned

    @pytest.mark.asyncio
    async def test_get_current_user_without_auth(self, api_client):
        """Test getting current user without authentication"""
        response = api_client.get("/api/v1/users/me")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, api_client):
        """Test getting current user with invalid token"""
        response = api_client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer invalid-token"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
