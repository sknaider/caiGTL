"""
System Monitoring and Metrics

Tracks uptime, performance metrics, and system health.
Provides Prometheus-compatible metrics.
"""

from typing import Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import time
import psutil
import logging

logger = logging.getLogger(__name__)


@dataclass
class UptimeTracker:
    """
    Tracks system uptime and availability

    Calculates uptime percentage based on start time and downtime events.
    """

    start_time: datetime = field(default_factory=datetime.utcnow)
    downtime_periods: list = field(default_factory=list)
    _last_heartbeat: datetime = field(default_factory=datetime.utcnow)

    def record_downtime(self, start: datetime, end: datetime):
        """Record a downtime period"""
        duration = (end - start).total_seconds()
        self.downtime_periods.append({
            "start": start,
            "end": end,
            "duration_seconds": duration
        })
        logger.warning(f"Downtime recorded: {duration}s from {start} to {end}")

    def get_uptime_percentage(self) -> float:
        """
        Calculate uptime percentage

        Returns:
            Uptime as percentage (0-100)
        """
        now = datetime.utcnow()
        total_time = (now - self.start_time).total_seconds()

        if total_time == 0:
            return 100.0

        total_downtime = sum(
            period["duration_seconds"]
            for period in self.downtime_periods
        )

        uptime_seconds = total_time - total_downtime
        uptime_percentage = (uptime_seconds / total_time) * 100

        return round(uptime_percentage, 2)

    def get_uptime_duration(self) -> timedelta:
        """Get total uptime duration"""
        now = datetime.utcnow()
        return now - self.start_time

    def get_formatted_uptime(self) -> str:
        """
        Get human-readable uptime

        Returns:
            Formatted string like "5d 3h 25m 10s"
        """
        duration = self.get_uptime_duration()

        days = duration.days
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")

        return " ".join(parts)

    def heartbeat(self):
        """Record a heartbeat (system is alive)"""
        self._last_heartbeat = datetime.utcnow()

    def is_healthy(self, timeout_seconds: int = 60) -> bool:
        """
        Check if system is healthy based on heartbeat

        Args:
            timeout_seconds: Seconds since last heartbeat to consider unhealthy

        Returns:
            True if healthy
        """
        now = datetime.utcnow()
        time_since_heartbeat = (now - self._last_heartbeat).total_seconds()
        return time_since_heartbeat < timeout_seconds


@dataclass
class PerformanceMetrics:
    """
    Tracks performance metrics for monitoring

    Stores request latencies, error rates, and throughput.
    """

    # Counters
    total_requests: int = 0
    total_errors: int = 0
    total_auth_successes: int = 0
    total_auth_failures: int = 0
    total_scans_created: int = 0
    total_scans_completed: int = 0

    # Latency tracking (in milliseconds)
    request_latencies: list = field(default_factory=list)
    _latency_limit: int = 1000  # Keep last 1000 measurements

    # Rate limiting
    rate_limit_hits: int = 0

    # Start time for rate calculations
    start_time: datetime = field(default_factory=datetime.utcnow)

    def record_request(self, latency_ms: float, error: bool = False):
        """Record a request"""
        self.total_requests += 1

        if error:
            self.total_errors += 1

        # Store latency (with limit)
        self.request_latencies.append(latency_ms)
        if len(self.request_latencies) > self._latency_limit:
            self.request_latencies.pop(0)

    def record_auth_attempt(self, success: bool):
        """Record authentication attempt"""
        if success:
            self.total_auth_successes += 1
        else:
            self.total_auth_failures += 1

    def record_scan_created(self):
        """Record scan creation"""
        self.total_scans_created += 1

    def record_scan_completed(self):
        """Record scan completion"""
        self.total_scans_completed += 1

    def record_rate_limit_hit(self):
        """Record rate limit hit"""
        self.rate_limit_hits += 1

    def get_error_rate(self) -> float:
        """
        Get error rate percentage

        Returns:
            Error rate as percentage
        """
        if self.total_requests == 0:
            return 0.0

        return round((self.total_errors / self.total_requests) * 100, 2)

    def get_average_latency(self) -> float:
        """
        Get average request latency

        Returns:
            Average latency in milliseconds
        """
        if not self.request_latencies:
            return 0.0

        return round(sum(self.request_latencies) / len(self.request_latencies), 2)

    def get_p95_latency(self) -> float:
        """
        Get 95th percentile latency

        Returns:
            P95 latency in milliseconds
        """
        if not self.request_latencies:
            return 0.0

        sorted_latencies = sorted(self.request_latencies)
        index = int(len(sorted_latencies) * 0.95)
        return round(sorted_latencies[index], 2)

    def get_p99_latency(self) -> float:
        """
        Get 99th percentile latency

        Returns:
            P99 latency in milliseconds
        """
        if not self.request_latencies:
            return 0.0

        sorted_latencies = sorted(self.request_latencies)
        index = int(len(sorted_latencies) * 0.99)
        return round(sorted_latencies[index], 2)

    def get_requests_per_second(self) -> float:
        """
        Get current requests per second

        Returns:
            Requests per second
        """
        now = datetime.utcnow()
        duration = (now - self.start_time).total_seconds()

        if duration == 0:
            return 0.0

        return round(self.total_requests / duration, 2)

    def get_summary(self) -> Dict:
        """
        Get metrics summary

        Returns:
            Dictionary with all metrics
        """
        return {
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "error_rate_percent": self.get_error_rate(),
            "average_latency_ms": self.get_average_latency(),
            "p95_latency_ms": self.get_p95_latency(),
            "p99_latency_ms": self.get_p99_latency(),
            "requests_per_second": self.get_requests_per_second(),
            "auth_successes": self.total_auth_successes,
            "auth_failures": self.total_auth_failures,
            "scans_created": self.total_scans_created,
            "scans_completed": self.total_scans_completed,
            "rate_limit_hits": self.rate_limit_hits
        }


class SystemMonitor:
    """
    Complete system monitoring

    Combines uptime tracking, performance metrics, and system resources.
    """

    def __init__(self):
        self.uptime = UptimeTracker()
        self.metrics = PerformanceMetrics()

    def get_system_resources(self) -> Dict:
        """
        Get current system resource usage

        Returns:
            Dictionary with CPU, memory, disk usage
        """
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
                "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "disk_percent": psutil.disk_usage('/').percent,
                "disk_used_gb": round(psutil.disk_usage('/').used / (1024**3), 2),
                "disk_total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
            }
        except Exception as e:
            logger.error(f"Failed to get system resources: {e}")
            return {}

    def get_health_status(self) -> Dict:
        """
        Get overall health status

        Returns:
            Dictionary with health status
        """
        resources = self.get_system_resources()

        # Determine health based on metrics
        is_healthy = (
            self.uptime.is_healthy() and
            self.metrics.get_error_rate() < 5.0 and  # Less than 5% errors
            resources.get("cpu_percent", 0) < 90 and  # CPU below 90%
            resources.get("memory_percent", 0) < 90  # Memory below 90%
        )

        return {
            "status": "healthy" if is_healthy else "degraded",
            "uptime_percentage": self.uptime.get_uptime_percentage(),
            "uptime_duration": self.uptime.get_formatted_uptime(),
            "error_rate_percent": self.metrics.get_error_rate(),
            "requests_per_second": self.metrics.get_requests_per_second(),
            "resources": resources
        }

    def get_complete_status(self) -> Dict:
        """
        Get complete system status

        Returns:
            Dictionary with all status information
        """
        return {
            "health": self.get_health_status(),
            "uptime": {
                "percentage": self.uptime.get_uptime_percentage(),
                "duration": self.uptime.get_formatted_uptime(),
                "start_time": self.uptime.start_time.isoformat(),
            },
            "performance": self.metrics.get_summary(),
            "resources": self.get_system_resources()
        }


# Global monitor instance
_monitor_instance: Optional[SystemMonitor] = None


def get_system_monitor() -> SystemMonitor:
    """
    Get global system monitor instance (singleton)

    Returns:
        SystemMonitor instance
    """
    global _monitor_instance

    if _monitor_instance is None:
        _monitor_instance = SystemMonitor()
        logger.info("System monitor initialized")

    return _monitor_instance
