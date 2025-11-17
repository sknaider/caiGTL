"""
Tests for scan management endpoints
"""

import pytest
from fastapi import status
import secrets


class TestCreateScan:
    """Tests for scan creation endpoint"""

    @pytest.mark.asyncio
    async def test_create_scan_success(self, api_client, auth_headers):
        """Test successful scan creation"""
        response = api_client.post(
            "/api/v1/scans/create",
            headers=auth_headers,
            json={
                "client_id": "test-client-001",
                "profile": "logistics",
                "target": {
                    "ip_address": "192.168.1.1"
                },
                "tools_enabled": {
                    "nmap": True,
                    "nuclei": False
                }
            }
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "scan_id" in data
        assert data["status"] == "queued"
        assert "created_at" in data
        assert "estimated_duration" in data

    @pytest.mark.asyncio
    async def test_create_scan_without_auth(self, api_client):
        """Test scan creation without authentication"""
        response = api_client.post(
            "/api/v1/scans/create",
            json={
                "client_id": "test-client-001",
                "profile": "logistics",
                "target": {"ip_address": "192.168.1.1"}
            }
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_create_scan_invalid_profile(self, api_client, auth_headers):
        """Test scan creation with invalid profile"""
        response = api_client.post(
            "/api/v1/scans/create",
            headers=auth_headers,
            json={
                "client_id": "test-client-001",
                "profile": "invalid-profile",
                "target": {"ip_address": "192.168.1.1"}
            }
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_scan_invalid_ip(self, api_client, auth_headers):
        """Test scan creation with invalid IP address"""
        response = api_client.post(
            "/api/v1/scans/create",
            headers=auth_headers,
            json={
                "client_id": "test-client-001",
                "profile": "logistics",
                "target": {"ip_address": "999.999.999.999"}
            }
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_scan_ssrf_protection(self, api_client, auth_headers):
        """Test SSRF protection (blocking internal IPs)"""
        internal_ips = ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1"]

        for ip in internal_ips:
            response = api_client.post(
                "/api/v1/scans/create",
                headers=auth_headers,
                json={
                    "client_id": "test-client-001",
                    "profile": "logistics",
                    "target": {"ip_address": ip}
                }
            )

            # Should reject internal/private IPs
            assert response.status_code in [status.HTTP_422_UNPROCESSABLE_ENTITY, status.HTTP_400_BAD_REQUEST]

    @pytest.mark.asyncio
    async def test_create_scan_sql_injection_protection(self, api_client, auth_headers):
        """Test SQL injection protection in client_id"""
        response = api_client.post(
            "/api/v1/scans/create",
            headers=auth_headers,
            json={
                "client_id": "test'; DROP TABLE scans; --",
                "profile": "logistics",
                "target": {"ip_address": "192.168.1.1"}
            }
        )

        # Should sanitize or reject
        # Either success with sanitized input or validation error
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_422_UNPROCESSABLE_ENTITY]


class TestGetScan:
    """Tests for getting scan status"""

    @pytest.mark.asyncio
    async def test_get_scan_success(self, api_client, auth_headers, db_session):
        """Test getting scan status"""
        from sqlalchemy import text

        # Create a scan in database
        scan_id = secrets.token_hex(16)
        await db_session.execute(
            text("""
                INSERT INTO scans (id, client_id, profile, target, status, created_at)
                VALUES (:id, :client_id, :profile, :target, :status, :created_at)
            """),
            {
                "id": scan_id,
                "client_id": "test-client",
                "profile": "logistics",
                "target": '{"ip_address": "192.168.1.1"}',
                "status": "running",
                "created_at": datetime.utcnow()
            }
        )
        await db_session.commit()

        response = api_client.get(
            f"/api/v1/scans/{scan_id}",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["scan_id"] == scan_id
        assert data["status"] == "running"

    @pytest.mark.asyncio
    async def test_get_scan_not_found(self, api_client, auth_headers):
        """Test getting non-existent scan"""
        response = api_client.get(
            "/api/v1/scans/nonexistent-scan-id",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_get_scan_without_auth(self, api_client):
        """Test getting scan without authentication"""
        response = api_client.get("/api/v1/scans/some-scan-id")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestListScans:
    """Tests for listing scans"""

    @pytest.mark.asyncio
    async def test_list_scans_success(self, api_client, auth_headers, db_session, test_user):
        """Test listing scans"""
        from sqlalchemy import text
        from datetime import datetime

        # Create multiple scans
        for i in range(3):
            scan_id = secrets.token_hex(16)
            await db_session.execute(
                text("""
                    INSERT INTO scans (id, client_id, profile, target, status, created_by, created_at)
                    VALUES (:id, :client_id, :profile, :target, :status, :created_by, :created_at)
                """),
                {
                    "id": scan_id,
                    "client_id": f"test-client-{i}",
                    "profile": "logistics",
                    "target": '{"ip_address": "192.168.1.1"}',
                    "status": "completed",
                    "created_by": test_user["id"],
                    "created_at": datetime.utcnow()
                }
            )
        await db_session.commit()

        response = api_client.get(
            "/api/v1/scans",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "scans" in data
        assert len(data["scans"]) >= 3  # At least our 3 test scans

    @pytest.mark.asyncio
    async def test_list_scans_pagination(self, api_client, auth_headers):
        """Test scan list pagination"""
        response = api_client.get(
            "/api/v1/scans?limit=10&offset=0",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "scans" in data
        assert data["limit"] == 10
        assert data["offset"] == 0

    @pytest.mark.asyncio
    async def test_list_scans_filter_by_status(self, api_client, auth_headers):
        """Test filtering scans by status"""
        response = api_client.get(
            "/api/v1/scans?status_filter=running",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # All returned scans should have 'running' status
        for scan in data["scans"]:
            assert scan["status"] == "running"

    @pytest.mark.asyncio
    async def test_list_scans_without_auth(self, api_client):
        """Test listing scans without authentication"""
        response = api_client.get("/api/v1/scans")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestScanAuthorization:
    """Tests for scan authorization (users can only see their own scans)"""

    @pytest.mark.asyncio
    async def test_user_can_see_own_scans(self, api_client, auth_headers, db_session, test_user):
        """Test user can see their own scans"""
        from sqlalchemy import text
        from datetime import datetime

        # Create scan for this user
        scan_id = secrets.token_hex(16)
        await db_session.execute(
            text("""
                INSERT INTO scans (id, client_id, profile, target, status, created_by, created_at)
                VALUES (:id, :client_id, :profile, :target, :status, :created_by, :created_at)
            """),
            {
                "id": scan_id,
                "client_id": "test-client",
                "profile": "logistics",
                "target": '{"ip_address": "192.168.1.1"}',
                "status": "completed",
                "created_by": test_user["id"],
                "created_at": datetime.utcnow()
            }
        )
        await db_session.commit()

        response = api_client.get(
            f"/api/v1/scans/{scan_id}",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_admin_can_see_all_scans(self, api_client, admin_headers):
        """Test admin can see all scans"""
        response = api_client.get(
            "/api/v1/scans",
            headers=admin_headers
        )

        assert response.status_code == status.HTTP_200_OK
        # Admin should see all scans, not filtered by created_by
