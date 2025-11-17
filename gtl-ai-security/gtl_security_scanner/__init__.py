"""
GTL Security Scanner Module
Automated penetration testing and vulnerability scanning engine.
"""

from gtl_security_scanner.scanner import (
    SecurityScanner,
    ScanTarget,
    ScanResult,
    Vulnerability,
    Service,
    ScanType,
    ScanStatus,
    ScanError,
)

__version__ = "1.0.0"

__all__ = [
    'SecurityScanner',
    'ScanTarget',
    'ScanResult',
    'Vulnerability',
    'Service',
    'ScanType',
    'ScanStatus',
    'ScanError',
]
