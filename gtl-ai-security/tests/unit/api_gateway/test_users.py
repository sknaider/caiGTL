"""
Tests for user management endpoints
"""

import pytest
from fastapi import status


class TestCreateUser:
    """Tests for user creation endpoint"""

    @pytest.mark.asyncio
    async def test_create_user_success_as_admin(self, api_client, admin_headers):
        """Test successful user creation by admin"""
        response = api_client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "newuser@example.com",
                "password": "SecurePassword123!",
                "full_name": "New User",
                "organization": "Test Organization",
                "role": "analyst"
            }
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        assert "user_id" in data
        assert data["email"] == "newuser@example.com"
        assert "password" not in data  # Password should not be in response

    @pytest.mark.asyncio
    async def test_create_user_forbidden_for_non_admin(self, api_client, auth_headers):
        """Test user creation fails for non-admin users"""
        response = api_client.post(
            "/api/v1/users",
            headers=auth_headers,
            json={
                "email": "newuser@example.com",
                "password": "SecurePassword123!",
                "full_name": "New User",
                "organization": "Test Organization",
                "role": "analyst"
            }
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Only administrators can create users" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_user_weak_password(self, api_client, admin_headers):
        """Test user creation with weak password"""
        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoNumbers!",  # No numbers
            "NoSpecial123",  # No special characters
        ]

        for weak_password in weak_passwords:
            response = api_client.post(
                "/api/v1/users",
                headers=admin_headers,
                json={
                    "email": f"user{weak_password}@example.com",
                    "password": weak_password,
                    "full_name": "Test User",
                    "organization": "Test Org",
                    "role": "user"
                }
            )

            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self, api_client, admin_headers):
        """Test user creation with invalid email"""
        invalid_emails = [
            "not-an-email",
            "@example.com",
            "user@",
            "user space@example.com"
        ]

        for invalid_email in invalid_emails:
            response = api_client.post(
                "/api/v1/users",
                headers=admin_headers,
                json={
                    "email": invalid_email,
                    "password": "SecurePassword123!",
                    "full_name": "Test User",
                    "organization": "Test Org",
                    "role": "user"
                }
            )

            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, api_client, admin_headers, test_user):
        """Test user creation with duplicate email"""
        response = api_client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": test_user["email"],  # Already exists
                "password": "SecurePassword123!",
                "full_name": "Duplicate User",
                "organization": "Test Org",
                "role": "user"
            }
        )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_user_invalid_role(self, api_client, admin_headers):
        """Test user creation with invalid role"""
        response = api_client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "user@example.com",
                "password": "SecurePassword123!",
                "full_name": "Test User",
                "organization": "Test Org",
                "role": "super_admin"  # Not a valid role
            }
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestPasswordSecurity:
    """Tests for password security"""

    @pytest.mark.asyncio
    async def test_password_not_returned_in_responses(self, api_client, auth_headers):
        """Test that passwords are never included in API responses"""
        response = api_client.get(
            "/api/v1/users/me",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "password" not in data
        assert "password_hash" not in data

    @pytest.mark.asyncio
    async def test_password_properly_hashed(self, db_session, test_user):
        """Test that passwords are properly hashed in database"""
        from sqlalchemy import text

        result = await db_session.execute(
            text("SELECT password_hash FROM users WHERE email = :email"),
            {"email": test_user["email"]}
        )
        row = result.first()

        # Password hash should not equal plain password
        assert row.password_hash != test_user["password"]

        # Password hash should start with bcrypt prefix
        assert row.password_hash.startswith("$2b$")


class TestUserAuthorization:
    """Tests for user authorization and role-based access control"""

    @pytest.mark.asyncio
    async def test_analyst_can_create_scans(self, api_client, db_session):
        """Test that analyst role can create scans"""
        from gtl_api_gateway.security import get_password_hash, create_access_token
        from sqlalchemy import text
        import secrets
        from datetime import datetime

        # Create analyst user
        analyst_id = secrets.token_hex(16)
        await db_session.execute(
            text("""
                INSERT INTO users (id, email, password_hash, full_name, organization, role, is_active, created_at)
                VALUES (:id, :email, :password_hash, :full_name, :organization, :role, true, :created_at)
            """),
            {
                "id": analyst_id,
                "email": "analyst@example.com",
                "password_hash": get_password_hash("AnalystPass123!"),
                "full_name": "Analyst User",
                "organization": "Test Org",
                "role": "analyst",
                "created_at": datetime.utcnow()
            }
        )
        await db_session.commit()

        # Create token for analyst
        token = create_access_token(data={"sub": analyst_id, "role": "analyst"})
        headers = {"Authorization": f"Bearer {token}"}

        # Try to create scan
        response = api_client.post(
            "/api/v1/scans/create",
            headers=headers,
            json={
                "client_id": "test-client",
                "profile": "logistics",
                "target": {"ip_address": "192.168.1.1"}
            }
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_readonly_cannot_create_scans(self, api_client, db_session):
        """Test that readonly role cannot create scans"""
        from gtl_api_gateway.security import get_password_hash, create_access_token
        from sqlalchemy import text
        import secrets
        from datetime import datetime

        # Create readonly user
        readonly_id = secrets.token_hex(16)
        await db_session.execute(
            text("""
                INSERT INTO users (id, email, password_hash, full_name, organization, role, is_active, created_at)
                VALUES (:id, :email, :password_hash, :full_name, :organization, :role, true, :created_at)
            """),
            {
                "id": readonly_id,
                "email": "readonly@example.com",
                "password_hash": get_password_hash("ReadonlyPass123!"),
                "full_name": "Readonly User",
                "organization": "Test Org",
                "role": "readonly",
                "created_at": datetime.utcnow()
            }
        )
        await db_session.commit()

        # Create token for readonly user
        token = create_access_token(data={"sub": readonly_id, "role": "readonly"})
        headers = {"Authorization": f"Bearer {token}"}

        # Try to create scan (should fail)
        response = api_client.post(
            "/api/v1/scans/create",
            headers=headers,
            json={
                "client_id": "test-client",
                "profile": "logistics",
                "target": {"ip_address": "192.168.1.1"}
            }
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
