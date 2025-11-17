export enum ScanStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

export enum ScanProfile {
  DEFAULT = 'default',
  LOGISTICS = 'logistics',
  MEDICAL_AI = 'medical_ai',
  CUSTOMS = 'customs',
  FULL = 'full',
}

export enum VulnerabilitySeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export enum UserRole {
  ADMIN = 'admin',
  ANALYST = 'analyst',
  VIEWER = 'viewer',
}

export enum ComplianceFramework {
  HIPAA = 'hipaa',
  GDPR = 'gdpr',
  PCI_DSS = 'pci_dss',
  ISO_27001 = 'iso_27001',
  SOC2 = 'soc2',
  NIST = 'nist',
  SUNAT = 'sunat',
  LEY_29733 = 'ley_29733',
  C_TPAT = 'c_tpat',
}

export enum ReportFormat {
  PDF = 'pdf',
  JSON = 'json',
  HTML = 'html',
  CSV = 'csv',
}
