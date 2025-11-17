"""
GTL Scan Scheduler

Automated scheduling for security scans using Celery Beat.
Supports daily, weekly, and monthly schedules per client.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from celery import Celery
from celery.schedules import crontab
from pydantic import BaseModel

from .scanner import ScanConfig, ScanTarget, SecurityScanner

# Configure logging
logger = logging.getLogger(__name__)

# Initialize Celery
celery_app = Celery(
    "gtl_scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
)


# ===========================================
# DATA MODELS
# ===========================================


class ScheduledScan(BaseModel):
    """Scheduled scan configuration"""

    client_id: str
    profile: str
    target: ScanTarget
    schedule: str  # daily, weekly, monthly
    day_of_week: Optional[int] = None  # 0=Monday, 6=Sunday (for weekly)
    day_of_month: Optional[int] = None  # 1-31 (for monthly)
    time: str = "02:00"  # HH:MM format
    timezone: str = "America/Lima"
    enabled: bool = True


# ===========================================
# CELERY TASKS
# ===========================================


@celery_app.task(name="run_scheduled_scan")
def run_scheduled_scan_task(
    client_id: str,
    profile: str,
    target_dict: Dict,
    scan_id: Optional[str] = None,
) -> Dict:
    """
    Celery task to run a scheduled scan.

    Args:
        client_id: Client identifier
        profile: Scanner profile name
        target_dict: Target configuration as dict
        scan_id: Optional scan ID

    Returns:
        Scan result as dict
    """
    import asyncio

    logger.info(f"Running scheduled scan for client {client_id}")

    try:
        # Initialize scanner
        scanner = SecurityScanner()

        # Build scan config
        target = ScanTarget(**target_dict)
        config = ScanConfig(
            client_id=client_id,
            profile=profile,
            target=target,
        )
        if scan_id:
            config.scan_id = scan_id

        # Run scan (synchronously in Celery context)
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(scanner.run_scan(config))

        logger.info(f"Scheduled scan completed: {result.scan_id}")
        return result.model_dump()

    except Exception as e:
        logger.error(f"Scheduled scan failed for client {client_id}: {e}")
        return {"error": str(e), "client_id": client_id}


# ===========================================
# SCAN SCHEDULER
# ===========================================


class ScanScheduler:
    """
    Manages automated scan scheduling using Celery Beat.

    Example:
        >>> scheduler = ScanScheduler()
        >>> scheduler.add_job(
        ...     client_id="logistics_company_1",
        ...     target=ScanTarget(network_range="192.168.1.0/24"),
        ...     schedule="weekly",
        ...     day_of_week=6,  # Sunday
        ...     profile="logistics"
        ... )
    """

    def __init__(self):
        """Initialize scan scheduler"""
        self.celery = celery_app
        logger.info("ScanScheduler initialized")

    def add_job(
        self,
        client_id: str,
        target: ScanTarget,
        schedule: str = "weekly",
        profile: str = "default",
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
        time: str = "02:00",
    ) -> str:
        """
        Add a new scheduled scan job.

        Args:
            client_id: Client identifier
            target: Scan target
            schedule: Schedule type (daily, weekly, monthly)
            profile: Scanner profile name
            day_of_week: Day of week for weekly scans (0=Monday, 6=Sunday)
            day_of_month: Day of month for monthly scans (1-31)
            time: Time to run scan in HH:MM format

        Returns:
            Job ID

        Raises:
            ValueError: If schedule parameters are invalid
        """
        # Parse time
        hour, minute = map(int, time.split(":"))

        # Build crontab schedule
        if schedule == "daily":
            cron_schedule = crontab(hour=hour, minute=minute)
        elif schedule == "weekly":
            if day_of_week is None:
                day_of_week = 6  # Default to Sunday
            cron_schedule = crontab(
                hour=hour, minute=minute, day_of_week=day_of_week
            )
        elif schedule == "monthly":
            if day_of_month is None:
                day_of_month = 1  # Default to first day of month
            cron_schedule = crontab(
                hour=hour, minute=minute, day_of_month=day_of_month
            )
        else:
            raise ValueError(f"Invalid schedule: {schedule}")

        # Generate job ID
        job_id = f"scan_{client_id}_{schedule}"

        # Register periodic task
        self.celery.conf.beat_schedule[job_id] = {
            "task": "run_scheduled_scan",
            "schedule": cron_schedule,
            "args": (client_id, profile, target.model_dump()),
        }

        logger.info(f"Added scheduled scan: {job_id}")
        return job_id

    def remove_job(self, job_id: str) -> bool:
        """
        Remove a scheduled scan job.

        Args:
            job_id: Job ID to remove

        Returns:
            True if job was removed, False if not found
        """
        if job_id in self.celery.conf.beat_schedule:
            del self.celery.conf.beat_schedule[job_id]
            logger.info(f"Removed scheduled scan: {job_id}")
            return True
        return False

    def list_jobs(self) -> List[Dict]:
        """
        List all scheduled scan jobs.

        Returns:
            List of job configurations
        """
        jobs = []
        for job_id, config in self.celery.conf.beat_schedule.items():
            if job_id.startswith("scan_"):
                jobs.append(
                    {
                        "job_id": job_id,
                        "task": config["task"],
                        "schedule": str(config["schedule"]),
                        "args": config["args"],
                    }
                )
        return jobs

    def run_now(
        self, client_id: str, target: ScanTarget, profile: str = "default"
    ) -> str:
        """
        Run a scan immediately (bypass schedule).

        Args:
            client_id: Client identifier
            target: Scan target
            profile: Scanner profile

        Returns:
            Task ID
        """
        task = run_scheduled_scan_task.delay(
            client_id=client_id,
            profile=profile,
            target_dict=target.model_dump(),
        )

        logger.info(f"Triggered immediate scan: {task.id}")
        return task.id

    def get_task_status(self, task_id: str) -> Dict:
        """
        Get status of a running task.

        Args:
            task_id: Celery task ID

        Returns:
            Task status information
        """
        task = self.celery.AsyncResult(task_id)

        return {
            "task_id": task_id,
            "status": task.state,  # PENDING, STARTED, SUCCESS, FAILURE
            "result": task.result if task.ready() else None,
            "info": task.info,
        }


# ===========================================
# CELERY CONFIGURATION
# ===========================================

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="America/Lima",
    enable_utc=True,
    # Task result expires after 24 hours
    result_expires=86400,
    # Beat schedule (can be populated dynamically)
    beat_schedule={
        # Example: Daily scan for all clients
        # This would typically be loaded from database
    },
)


# ===========================================
# EXAMPLE USAGE
# ===========================================

if __name__ == "__main__":
    # Initialize scheduler
    scheduler = ScanScheduler()

    # Add weekly scan
    job_id = scheduler.add_job(
        client_id="logistics_company_1",
        target=ScanTarget(network_range="192.168.1.0/24"),
        schedule="weekly",
        day_of_week=6,  # Sunday
        time="02:00",
        profile="logistics",
    )

    print(f"Added job: {job_id}")

    # Run scan immediately
    task_id = scheduler.run_now(
        client_id="logistics_company_1",
        target=ScanTarget(network_range="192.168.1.0/24"),
        profile="quick_scan",
    )

    print(f"Started task: {task_id}")

    # Check status
    import time

    time.sleep(2)
    status = scheduler.get_task_status(task_id)
    print(f"Task status: {status['status']}")

    # List all jobs
    jobs = scheduler.list_jobs()
    print(f"\nScheduled jobs ({len(jobs)}):")
    for job in jobs:
        print(f"  - {job['job_id']}: {job['schedule']}")
