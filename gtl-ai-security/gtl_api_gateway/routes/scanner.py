"""
Scanner API Routes

RESTful API endpoints for security scanning operations.
Provides access to the GTL Security Scanner module.
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, Field, validator

from gtl_api_gateway.security import require_role, audit_log, get_current_user
from gtl_security_scanner.scanner import (
    SecurityScanner,
    ScanTarget,
    ScanType,
    ScanStatus,
)
from gtl_security_scanner.scheduler import ScanScheduler, run_scheduled_scan_task
from gtl_security_scanner.reporters.report_generator import (
    ReportGenerator,
    ReportConfig,
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    prefix="/api/v1/scanner",
    tags=["scanner"],
)

# Initialize scanner components
scanner = SecurityScanner()
scheduler = ScanScheduler()
report_generator = ReportGenerator()


# ============================================
# REQUEST/RESPONSE MODELS
# ============================================


class ScanRequest(BaseModel):
    """Security scan request"""

    target_url: Optional[str] = Field(None, description="Target URL for web/API scanning")
    network_range: Optional[str] = Field(None, description="Network range in CIDR notation")
    scan_type: str = Field("full", description="Scan type: network, webapp, api, full")
    priority: str = Field("normal", description="Scan priority: low, normal, high, urgent")
    client_id: Optional[str] = Field(None, description="Client identifier")
    callback_url: Optional[str] = Field(None, description="Webhook callback URL for results")

    @validator("scan_type")
    def validate_scan_type(cls, v):
        allowed_types = ["network", "webapp", "api", "full"]
        if v not in allowed_types:
            raise ValueError(f"Invalid scan type. Must be one of: {allowed_types}")
        return v

    @validator("priority")
    def validate_priority(cls, v):
        allowed_priorities = ["low", "normal", "high", "urgent"]
        if v not in allowed_priorities:
            raise ValueError(f"Invalid priority. Must be one of: {allowed_priorities}")
        return v


class ScanResponse(BaseModel):
    """Scan operation response"""

    scan_id: str
    status: str
    message: str
    started_at: datetime
    estimated_duration_seconds: Optional[int] = None


class ScanStatusResponse(BaseModel):
    """Scan status response"""

    scan_id: str
    status: str
    progress: int = Field(..., ge=0, le=100, description="Progress percentage")
    current_stage: Optional[str] = None
    vulnerabilities_found: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class ScanResultsResponse(BaseModel):
    """Scan results response"""

    scan_id: str
    status: str
    risk_score: float = Field(..., ge=0, le=100)
    total_vulnerabilities: int
    severity_breakdown: Dict[str, int]
    vulnerabilities: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    started_at: datetime
    completed_at: datetime
    duration_seconds: float


class ReportRequest(BaseModel):
    """Report generation request"""

    scan_id: str
    report_type: str = Field("technical", description="Report type: executive, technical, both")
    format: str = Field("pdf", description="Format: pdf, html, json")
    language: str = Field("es", description="Language: es, en")
    include_remediation: bool = True

    @validator("report_type")
    def validate_report_type(cls, v):
        allowed_types = ["executive", "technical", "both"]
        if v not in allowed_types:
            raise ValueError(f"Invalid report type. Must be one of: {allowed_types}")
        return v

    @validator("format")
    def validate_format(cls, v):
        allowed_formats = ["pdf", "html", "json"]
        if v not in allowed_formats:
            raise ValueError(f"Invalid format. Must be one of: {allowed_formats}")
        return v


class ScheduleScanRequest(BaseModel):
    """Scheduled scan request"""

    client_id: str
    target_url: Optional[str] = None
    network_range: Optional[str] = None
    scan_type: str = "full"
    schedule: str = Field(..., description="Schedule type: daily, weekly, monthly")
    day_of_week: Optional[int] = Field(None, ge=0, le=6, description="0=Monday, 6=Sunday")
    day_of_month: Optional[int] = Field(None, ge=1, le=31)
    time: str = Field("02:00", description="Time in HH:MM format")

    @validator("schedule")
    def validate_schedule(cls, v):
        allowed_schedules = ["daily", "weekly", "monthly"]
        if v not in allowed_schedules:
            raise ValueError(f"Invalid schedule. Must be one of: {allowed_schedules}")
        return v


# ============================================
# API ENDPOINTS
# ============================================


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
@audit_log("scan_initiated")
async def initiate_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(require_role(["admin", "scanner", "analyst"]))
):
    """
    Initiate a security scan.

    Starts an asynchronous security scan of the specified target.
    Returns immediately with scan ID for status tracking.

    Required roles: admin, scanner, analyst

    Returns:
        Scan ID and status information
    """
    logger.info(f"Initiating scan requested by user: {current_user.get('username')}")

    try:
        # Generate scan ID
        scan_id = str(uuid4())

        # Build scan target
        scan_type_enum = ScanType[request.scan_type.upper()]

        target = ScanTarget(
            url=request.target_url,
            network_range=request.network_range,
            scan_type=scan_type_enum,
        )

        # Determine estimated duration
        estimated_duration = {
            "network": 600,   # 10 minutes
            "webapp": 1800,   # 30 minutes
            "api": 900,       # 15 minutes
            "full": 3600,     # 60 minutes
        }.get(request.scan_type, 1800)

        # Submit scan to Celery background task
        task = run_scheduled_scan_task.delay(
            client_id=request.client_id or current_user.get("client_id", "default"),
            profile="default",
            target_dict=target.__dict__,
            scan_id=scan_id,
        )

        logger.info(f"Scan initiated: {scan_id}, Task ID: {task.id}")

        return ScanResponse(
            scan_id=scan_id,
            status="queued",
            message="Scan has been queued and will start shortly",
            started_at=datetime.utcnow(),
            estimated_duration_seconds=estimated_duration,
        )

    except Exception as e:
        logger.error(f"Failed to initiate scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate scan: {str(e)}"
        )


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
@audit_log("scan_status_checked")
async def get_scan_status(
    scan_id: str,
    current_user: Dict = Depends(require_role(["admin", "scanner", "analyst", "viewer"]))
):
    """
    Get scan status and progress.

    Check the current status and progress of a running or completed scan.

    Required roles: admin, scanner, analyst, viewer

    Returns:
        Scan status and progress information
    """
    logger.info(f"Scan status requested for: {scan_id}")

    try:
        # Get task status from Celery
        task_status = scheduler.get_task_status(scan_id)

        # Map Celery state to our status
        status_map = {
            "PENDING": "queued",
            "STARTED": "running",
            "SUCCESS": "completed",
            "FAILURE": "failed",
            "RETRY": "retrying",
        }

        scan_status = status_map.get(task_status["status"], "unknown")

        # Extract progress from task result if available
        progress = 0
        current_stage = None
        vulnerabilities_found = 0

        if task_status.get("info"):
            info = task_status["info"]
            progress = info.get("progress", 0)
            current_stage = info.get("current_stage")
            vulnerabilities_found = info.get("vulnerabilities_found", 0)

        return ScanStatusResponse(
            scan_id=scan_id,
            status=scan_status,
            progress=progress,
            current_stage=current_stage,
            vulnerabilities_found=vulnerabilities_found,
        )

    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan status: {str(e)}"
        )


@router.get("/scan/{scan_id}/results", response_model=ScanResultsResponse)
@audit_log("scan_results_retrieved")
async def get_scan_results(
    scan_id: str,
    current_user: Dict = Depends(require_role(["admin", "scanner", "analyst", "viewer"]))
):
    """
    Get detailed scan results.

    Retrieve complete results of a completed scan including all
    vulnerabilities, services discovered, and risk assessment.

    Required roles: admin, scanner, analyst, viewer

    Returns:
        Complete scan results
    """
    logger.info(f"Scan results requested for: {scan_id}")

    try:
        # Get task result from Celery
        task_status = scheduler.get_task_status(scan_id)

        if task_status["status"] != "SUCCESS":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan not completed yet. Current status: {task_status['status']}"
            )

        # Extract scan result
        result = task_status.get("result", {})

        # Calculate severity breakdown
        severity_breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        vulnerabilities = result.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_breakdown:
                severity_breakdown[severity] += 1

        return ScanResultsResponse(
            scan_id=scan_id,
            status="completed",
            risk_score=result.get("risk_score", 0.0),
            total_vulnerabilities=len(vulnerabilities),
            severity_breakdown=severity_breakdown,
            vulnerabilities=vulnerabilities,
            services=result.get("services", []),
            started_at=datetime.fromisoformat(result.get("started_at")),
            completed_at=datetime.fromisoformat(result.get("completed_at")),
            duration_seconds=result.get("duration_seconds", 0.0),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan results: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan results: {str(e)}"
        )


@router.post("/scan/{scan_id}/report")
@audit_log("report_generated")
async def generate_report(
    scan_id: str,
    request: ReportRequest,
    current_user: Dict = Depends(require_role(["admin", "analyst"]))
):
    """
    Generate scan report.

    Generate executive or technical report from scan results
    in PDF, HTML, or JSON format.

    Required roles: admin, analyst

    Returns:
        Report download URL or report content
    """
    logger.info(f"Report generation requested for scan: {scan_id}")

    try:
        # Get scan results
        task_status = scheduler.get_task_status(scan_id)

        if task_status["status"] != "SUCCESS":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan must be completed before generating report"
            )

        scan_result = task_status.get("result")

        # Build report config
        config = ReportConfig(
            format=request.format,
            language=request.language,
            include_remediation=request.include_remediation,
        )

        # Generate report based on type
        if request.report_type == "executive":
            report_content = report_generator.generate_executive_report(
                scan_result, config
            )
        elif request.report_type == "technical":
            report_content = report_generator.generate_technical_report(
                scan_result, config
            )
        else:  # both
            # Generate both reports
            exec_report = report_generator.generate_executive_report(
                scan_result, config
            )
            tech_report = report_generator.generate_technical_report(
                scan_result, config
            )
            # TODO: Combine or return both
            report_content = tech_report

        # Return report based on format
        if request.format == "json":
            report_data = report_generator.generate_json_export(scan_result, config)
            return JSONResponse(content=report_data.decode('utf-8'))

        # For PDF/HTML, return base64 encoded content
        import base64
        encoded_report = base64.b64encode(report_content).decode('utf-8')

        return {
            "scan_id": scan_id,
            "report_type": request.report_type,
            "format": request.format,
            "content": encoded_report,
            "generated_at": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )


@router.post("/scan/schedule", status_code=status.HTTP_201_CREATED)
@audit_log("scan_scheduled")
async def schedule_scan(
    request: ScheduleScanRequest,
    current_user: Dict = Depends(require_role(["admin"]))
):
    """
    Schedule recurring scan.

    Create a recurring scan schedule (daily, weekly, or monthly).

    Required roles: admin

    Returns:
        Schedule confirmation
    """
    logger.info(f"Scan schedule requested by: {current_user.get('username')}")

    try:
        # Build scan target
        scan_type_enum = ScanType[request.scan_type.upper()]
        target = ScanTarget(
            url=request.target_url,
            network_range=request.network_range,
            scan_type=scan_type_enum,
        )

        # Add scheduled job
        job_id = scheduler.add_job(
            client_id=request.client_id,
            target=target,
            schedule=request.schedule,
            day_of_week=request.day_of_week,
            day_of_month=request.day_of_month,
            time=request.time,
        )

        logger.info(f"Scan scheduled: {job_id}")

        return {
            "job_id": job_id,
            "client_id": request.client_id,
            "schedule": request.schedule,
            "time": request.time,
            "status": "scheduled",
            "message": "Scan has been successfully scheduled",
        }

    except Exception as e:
        logger.error(f"Failed to schedule scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to schedule scan: {str(e)}"
        )


@router.get("/scan/schedule/list")
@audit_log("scheduled_scans_listed")
async def list_scheduled_scans(
    current_user: Dict = Depends(require_role(["admin", "analyst"]))
):
    """
    List all scheduled scans.

    Get list of all configured recurring scan schedules.

    Required roles: admin, analyst

    Returns:
        List of scheduled scans
    """
    try:
        jobs = scheduler.list_jobs()

        return {
            "total_schedules": len(jobs),
            "schedules": jobs,
        }

    except Exception as e:
        logger.error(f"Failed to list scheduled scans: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list scheduled scans: {str(e)}"
        )


@router.delete("/scan/schedule/{job_id}")
@audit_log("scan_schedule_deleted")
async def delete_scheduled_scan(
    job_id: str,
    current_user: Dict = Depends(require_role(["admin"]))
):
    """
    Delete scheduled scan.

    Remove a recurring scan schedule.

    Required roles: admin

    Returns:
        Deletion confirmation
    """
    try:
        success = scheduler.remove_job(job_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scheduled scan not found: {job_id}"
            )

        return {
            "job_id": job_id,
            "status": "deleted",
            "message": "Scheduled scan has been removed",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scheduled scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete scheduled scan: {str(e)}"
        )


# Add import for JSONResponse
from fastapi.responses import JSONResponse
