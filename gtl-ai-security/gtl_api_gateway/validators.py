"""
Input validation and sanitization for GTL API Gateway
Prevents SSRF, injection attacks, XSS, and other input-based vulnerabilities
"""

import re
import ipaddress
from typing import Optional, Any
from urllib.parse import urlparse
import html
import logging

from gtl_api_gateway.config import settings

logger = logging.getLogger(__name__)


def validate_ip_address(ip: str) -> str:
    """
    Validate and normalize IP address

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        Normalized IP address

    Raises:
        ValueError: If IP is invalid or in blocked range
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Check if IP is in blocked ranges
        for blocked_range in settings.BLOCKED_IP_RANGES:
            network = ipaddress.ip_network(blocked_range)
            if ip_obj in network:
                raise ValueError(f"IP address {ip} is in blocked range {blocked_range}")

        # Block private IPs in production
        if settings.ENVIRONMENT == "production":
            if ip_obj.is_private:
                raise ValueError(f"Private IP addresses are not allowed: {ip}")

            if ip_obj.is_loopback:
                raise ValueError(f"Loopback addresses are not allowed: {ip}")

            if ip_obj.is_link_local:
                raise ValueError(f"Link-local addresses are not allowed: {ip}")

        return str(ip_obj)

    except ValueError as e:
        logger.warning(f"Invalid IP address: {ip} - {e}")
        raise ValueError(f"Invalid IP address: {e}")


def prevent_ssrf(target: str) -> bool:
    """
    Check if target could be used for SSRF attack

    Args:
        target: URL, domain, or IP address

    Returns:
        True if target is suspicious/blocked, False if allowed
    """
    target_lower = target.lower()

    # Check blocked domains
    for blocked_domain in settings.BLOCKED_DOMAINS:
        if blocked_domain in target_lower:
            logger.warning(f"Blocked domain detected in target: {target}")
            return True

    # Check for cloud metadata endpoints
    metadata_endpoints = [
        "169.254.169.254",  # AWS/Azure/GCP metadata
        "metadata.google.internal",
        "169.254.170.2",  # AWS ECS metadata
        "fd00:ec2::254",  # AWS IMDSv2
    ]

    for endpoint in metadata_endpoints:
        if endpoint in target_lower:
            logger.warning(f"Cloud metadata endpoint detected: {target}")
            return True

    # Check for internal IP ranges
    try:
        # Try to extract IP from URL
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.hostname

        if hostname:
            # Try to parse as IP
            try:
                ip_obj = ipaddress.ip_address(hostname)

                # Check if private/internal
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    logger.warning(f"Internal IP address detected: {hostname}")
                    return True

            except ValueError:
                # Not an IP, check as domain
                # Check for localhost variants
                localhost_variants = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
                if hostname in localhost_variants:
                    logger.warning(f"Localhost variant detected: {hostname}")
                    return True

    except Exception as e:
        logger.error(f"Error parsing target for SSRF check: {e}")
        # Err on the side of caution
        return True

    return False


def sanitize_input(value: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks

    Args:
        value: Input string
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not value:
        return ""

    # Limit length
    value = value[:max_length]

    # Remove null bytes
    value = value.replace('\0', '')

    # Remove control characters except newline and tab
    value = ''.join(char for char in value if char.isprintable() or char in ['\n', '\t'])

    # HTML escape (prevents XSS)
    value = html.escape(value)

    return value.strip()


def validate_scan_target(target: Any) -> Any:
    """
    Validate scan target object

    Args:
        target: ScanTarget object with ip_address, domain, or url

    Returns:
        Validated target object

    Raises:
        ValueError: If target is invalid
    """
    # Check that at least one target is provided
    if not any([target.ip_address, target.domain, target.url]):
        raise ValueError("At least one target (ip_address, domain, or url) must be provided")

    # Validate IP if provided
    if target.ip_address:
        try:
            validate_ip_address(target.ip_address)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {e}")

    # Validate domain if provided
    if target.domain:
        if prevent_ssrf(target.domain):
            raise ValueError("Target domain is not allowed (internal/private)")

    # Validate URL if provided
    if target.url:
        if prevent_ssrf(target.url):
            raise ValueError("Target URL is not allowed (internal/private)")

        # Additional URL validation
        try:
            parsed = urlparse(target.url)

            # Require http/https
            if parsed.scheme not in ['http', 'https']:
                raise ValueError("URL must use http or https protocol")

            # Check for username/password in URL (security risk)
            if parsed.username or parsed.password:
                raise ValueError("URLs with embedded credentials are not allowed")

        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")

    return target


def validate_email(email: str) -> str:
    """
    Validate email address

    Args:
        email: Email address

    Returns:
        Normalized email (lowercase)

    Raises:
        ValueError: If email is invalid
    """
    # Basic email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_pattern, email):
        raise ValueError("Invalid email format")

    # Normalize to lowercase
    email = email.lower().strip()

    # Check length
    if len(email) > 255:
        raise ValueError("Email too long (max 255 characters)")

    # Block disposable email domains (optional)
    disposable_domains = [
        'tempmail.com', 'throwaway.email', 'guerrillamail.com',
        '10minutemail.com', 'mailinator.com'
    ]

    domain = email.split('@')[1]
    if domain in disposable_domains:
        raise ValueError("Disposable email addresses are not allowed")

    return email


def validate_client_id(client_id: str) -> str:
    """
    Validate client ID format

    Args:
        client_id: Client identifier

    Returns:
        Validated client ID

    Raises:
        ValueError: If client ID is invalid
    """
    # Sanitize
    client_id = sanitize_input(client_id, max_length=100)

    # Check format (alphanumeric, underscore, hyphen only)
    if not re.match(r'^[a-zA-Z0-9_-]+$', client_id):
        raise ValueError("Client ID must contain only alphanumeric characters, underscores, and hyphens")

    # Check length
    if len(client_id) < 3 or len(client_id) > 100:
        raise ValueError("Client ID must be between 3 and 100 characters")

    return client_id


def validate_sql_injection(value: str) -> bool:
    """
    Check for SQL injection patterns

    Args:
        value: Input string to check

    Returns:
        True if suspicious patterns found, False otherwise
    """
    # Common SQL injection patterns
    sql_patterns = [
        r"(\bOR\b|\bAND\b).*[=<>]",  # OR 1=1, AND 1=1
        r"';.*--",                    # '; DROP TABLE--
        r"\bUNION\b.*\bSELECT\b",    # UNION SELECT
        r"<script",                   # XSS
        r"javascript:",               # XSS
        r"\bEXEC\b|\bEXECUTE\b",     # EXEC command
        r"\bDELETE\b.*\bFROM\b",     # DELETE FROM
        r"\bDROP\b.*\bTABLE\b",      # DROP TABLE
        r"\bINSERT\b.*\bINTO\b",     # INSERT INTO
        r"xp_cmdshell",               # SQL Server command execution
    ]

    value_upper = value.upper()

    for pattern in sql_patterns:
        if re.search(pattern, value_upper, re.IGNORECASE):
            logger.warning(f"Potential SQL injection detected: {pattern}")
            return True

    return False


def validate_command_injection(value: str) -> bool:
    """
    Check for command injection patterns

    Args:
        value: Input string to check

    Returns:
        True if suspicious patterns found, False otherwise
    """
    # Command injection patterns
    cmd_patterns = [
        r'[;&|`$]',           # Shell metacharacters
        r'\$\(',              # Command substitution
        r'>\s*/dev/null',     # Redirect to /dev/null
        r'\|\s*sh',           # Pipe to shell
        r'&&|\|\|',           # Command chaining
    ]

    for pattern in cmd_patterns:
        if re.search(pattern, value):
            logger.warning(f"Potential command injection detected: {pattern}")
            return True

    return False


def validate_path_traversal(path: str) -> bool:
    """
    Check for path traversal patterns

    Args:
        path: File path to check

    Returns:
        True if suspicious patterns found, False otherwise
    """
    # Path traversal patterns
    traversal_patterns = [
        r'\.\.',              # Parent directory
        r'%2e%2e',           # URL encoded ..
        r'%252e',            # Double URL encoded .
        r'\.\./',            # ../
        r'\.\.\\',           # ..\
    ]

    for pattern in traversal_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            logger.warning(f"Potential path traversal detected: {pattern}")
            return True

    return False


def validate_xss(value: str) -> bool:
    """
    Check for XSS patterns

    Args:
        value: Input string to check

    Returns:
        True if suspicious patterns found, False otherwise
    """
    # XSS patterns
    xss_patterns = [
        r'<script',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'<iframe',
        r'<object',
        r'<embed',
        r'eval\(',
    ]

    value_lower = value.lower()

    for pattern in xss_patterns:
        if re.search(pattern, value_lower, re.IGNORECASE):
            logger.warning(f"Potential XSS detected: {pattern}")
            return True

    return False


def comprehensive_input_validation(value: str, field_name: str = "input") -> str:
    """
    Run all validation checks on input

    Args:
        value: Input string
        field_name: Name of field for error messages

    Returns:
        Sanitized value

    Raises:
        ValueError: If dangerous patterns detected
    """
    # Sanitize first
    sanitized = sanitize_input(value)

    # Run all checks
    if validate_sql_injection(sanitized):
        raise ValueError(f"{field_name} contains suspicious SQL patterns")

    if validate_command_injection(sanitized):
        raise ValueError(f"{field_name} contains suspicious command injection patterns")

    if validate_path_traversal(sanitized):
        raise ValueError(f"{field_name} contains path traversal patterns")

    if validate_xss(sanitized):
        raise ValueError(f"{field_name} contains XSS patterns")

    return sanitized


def validate_cron_expression(cron: str) -> bool:
    """
    Validate cron expression format

    Args:
        cron: Cron expression (e.g., "0 2 * * *")

    Returns:
        True if valid, False otherwise
    """
    # Basic cron validation (5 or 6 fields)
    parts = cron.split()

    if len(parts) not in [5, 6]:
        return False

    # Check each field
    for i, part in enumerate(parts):
        if part == '*':
            continue

        # Check for ranges (e.g., "1-5")
        if '-' in part:
            try:
                start, end = part.split('-')
                int(start)
                int(end)
                continue
            except:
                return False

        # Check for lists (e.g., "1,3,5")
        if ',' in part:
            try:
                for num in part.split(','):
                    int(num)
                continue
            except:
                return False

        # Check for step values (e.g., "*/5")
        if '/' in part:
            try:
                base, step = part.split('/')
                int(step)
                continue
            except:
                return False

        # Must be a number
        try:
            int(part)
        except:
            return False

    return True


# Content Security Policy helpers
def generate_nonce() -> str:
    """Generate random nonce for CSP"""
    import secrets
    return secrets.token_urlsafe(16)


def build_csp_header(nonce: Optional[str] = None) -> str:
    """
    Build Content Security Policy header

    Args:
        nonce: Optional nonce for inline scripts

    Returns:
        CSP header string
    """
    directives = [
        "default-src 'self'",
        "script-src 'self'" + (f" 'nonce-{nonce}'" if nonce else ""),
        "style-src 'self' 'unsafe-inline'",  # Allow inline styles (needed for many frameworks)
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]

    return "; ".join(directives)
