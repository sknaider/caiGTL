"""
Database models for GTL API Gateway
SQLAlchemy models for users, API keys, audit logs, scans, etc.
"""

from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON, Text, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import secrets

Base = declarative_base()


class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = "users"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    organization = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # admin, analyst, user, readonly
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32), nullable=True)

    # Relationships
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="creator", foreign_keys="Scan.created_by")

    def __repr__(self):
        return f"<User(email='{self.email}', role='{self.role}')>"


class APIKey(Base):
    """API keys for programmatic access"""
    __tablename__ = "api_keys"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash
    name = Column(String(100), nullable=False)  # Friendly name for the key
    scopes = Column(JSON, nullable=False, default=list)  # List of allowed scopes
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<APIKey(name='{self.name}', user_id='{self.user_id}')>"


class AuditLog(Base):
    """Audit log for security and compliance"""
    __tablename__ = "audit_logs"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    user_id = Column(String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False, index=True)  # e.g., "auth.login.success", "scan.create"
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    user_agent = Column(Text, nullable=True)
    metadata = Column(JSON, nullable=True)  # Additional context
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<AuditLog(action='{self.action}', timestamp='{self.timestamp}')>"


class Scan(Base):
    """Security scan records"""
    __tablename__ = "scans"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    client_id = Column(String(100), nullable=False, index=True)
    profile = Column(String(50), nullable=False)  # logistics, medical_ai, etc.
    target = Column(JSON, nullable=False)  # IP, domain, or URL
    tools_enabled = Column(JSON, nullable=False)  # {"nmap": true, "nuclei": true, ...}
    status = Column(String(20), nullable=False, default="queued", index=True)  # queued, running, completed, failed
    created_by = Column(String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)

    # Scan results summary
    vulnerabilities_found = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Relationships
    creator = relationship("User", back_populates="scans", foreign_keys=[created_by])
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id='{self.id}', status='{self.status}', client_id='{self.client_id}')>"


class Vulnerability(Base):
    """Individual vulnerabilities found in scans"""
    __tablename__ = "vulnerabilities"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    scan_id = Column(String(32), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool = Column(String(50), nullable=False)  # nmap, nuclei, nikto, sqlmap
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(20), nullable=True, index=True)  # CVE identifier
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    affected_url = Column(String(500), nullable=True)
    affected_parameter = Column(String(100), nullable=True)
    proof_of_concept = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)  # List of reference URLs
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default="open", nullable=False)  # open, fixed, accepted_risk, false_positive
    fixed_at = Column(DateTime, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(severity='{self.severity}', cve_id='{self.cve_id}')>"


class ComplianceCheck(Base):
    """Compliance audit results"""
    __tablename__ = "compliance_checks"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    client_id = Column(String(100), nullable=False, index=True)
    framework = Column(String(50), nullable=False, index=True)  # HIPAA, ISO27001, SUNAT, etc.
    control_id = Column(String(50), nullable=False)  # e.g., "HIPAA-164.312(a)(1)"
    control_name = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False)  # compliant, non_compliant, partial, not_applicable
    evidence = Column(JSON, nullable=True)  # Supporting evidence
    findings = Column(Text, nullable=True)
    remediation_required = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    checked_by = Column(String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    def __repr__(self):
        return f"<ComplianceCheck(framework='{self.framework}', control_id='{self.control_id}', status='{self.status}')>"


class ThreatDetection(Base):
    """Real-time threat detection events"""
    __tablename__ = "threat_detections"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    client_id = Column(String(100), nullable=False, index=True)
    threat_type = Column(String(50), nullable=False, index=True)  # malware, intrusion, anomaly, etc.
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low
    confidence_score = Column(Float, nullable=False)  # 0.0 - 1.0
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    description = Column(Text, nullable=False)
    indicators = Column(JSON, nullable=True)  # IOCs (Indicators of Compromise)
    mitre_tactics = Column(JSON, nullable=True)  # MITRE ATT&CK tactics
    mitre_techniques = Column(JSON, nullable=True)  # MITRE ATT&CK techniques
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = Column(String(20), default="new", nullable=False)  # new, investigating, contained, resolved, false_positive
    assigned_to = Column(String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<ThreatDetection(threat_type='{self.threat_type}', severity='{self.severity}')>"


class IncidentResponse(Base):
    """Incident response records"""
    __tablename__ = "incident_responses"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    threat_detection_id = Column(String(32), ForeignKey("threat_detections.id", ondelete="CASCADE"), nullable=True)
    incident_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(20), default="open", nullable=False)  # open, investigating, contained, resolved, closed
    playbook_id = Column(String(50), nullable=True)  # Reference to automated playbook
    actions_taken = Column(JSON, nullable=True)  # List of actions
    timeline = Column(JSON, nullable=True)  # Event timeline
    affected_systems = Column(JSON, nullable=True)  # List of affected systems
    assigned_to = Column(String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    resolved_at = Column(DateTime, nullable=True)
    post_mortem = Column(Text, nullable=True)

    def __repr__(self):
        return f"<IncidentResponse(incident_type='{self.incident_type}', status='{self.status}')>"


class RateLimitRule(Base):
    """Custom rate limit rules per user/client"""
    __tablename__ = "rate_limit_rules"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    client_id = Column(String(100), nullable=True)
    endpoint_pattern = Column(String(255), nullable=False)  # e.g., "/api/v1/scans/*"
    max_requests = Column(Integer, nullable=False)  # Maximum requests
    window_seconds = Column(Integer, nullable=False, default=60)  # Time window
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<RateLimitRule(endpoint='{self.endpoint_pattern}', max={self.max_requests})>"


class Notification(Base):
    """Notification/alert records"""
    __tablename__ = "notifications"

    id = Column(String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    type = Column(String(50), nullable=False)  # email, slack, webhook, sms
    priority = Column(String(20), nullable=False)  # critical, high, normal, low
    subject = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    metadata = Column(JSON, nullable=True)
    status = Column(String(20), default="pending", nullable=False)  # pending, sent, failed
    sent_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<Notification(type='{self.type}', status='{self.status}')>"


# Database initialization script
def init_database(engine):
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)


def create_admin_user(session, email: str, password: str, full_name: str):
    """Create initial admin user"""
    from gtl_api_gateway.security import get_password_hash

    admin = User(
        email=email,
        password_hash=get_password_hash(password),
        full_name=full_name,
        organization="GTL Security",
        role="admin",
        is_active=True,
        is_verified=True
    )

    session.add(admin)
    session.commit()

    return admin
