import { ScanStatus, ScanProfile, VulnerabilitySeverity, UserRole, ComplianceFramework } from './enums';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  full_name?: string;
  created_at: string;
  last_login?: string;
  is_active: boolean;
}

export interface Scan {
  id: string;
  target_url: string;
  scan_profile: ScanProfile;
  status: ScanStatus;
  progress: number;
  risk_score?: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  created_by: string;
  duration?: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  title: string;
  severity: VulnerabilitySeverity;
  category: string;
  description: string;
  cvss_score?: number;
  cwe_id?: string;
  affected_url: string;
  evidence?: string;
  remediation: string;
  references?: string[];
  discovered_at: string;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
}

export interface AgentFinding {
  id: string;
  scan_id: string;
  agent_type: string;
  title: string;
  severity: VulnerabilitySeverity;
  category: string;
  description: string;
  business_impact: string;
  financial_impact?: string;
  affected_component: string;
  remediation: string;
  remediation_priority: 'immediate' | 'high' | 'medium' | 'low';
  remediation_effort: string;
  compliance_violations: string[];
  regulatory_risk?: string;
  evidence: Record<string, any>;
  discovered_at: string;
}

export interface ComplianceControl {
  id: string;
  framework: ComplianceFramework;
  control_id: string;
  control_name: string;
  description: string;
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable';
  related_vulnerabilities: string[];
  last_assessed: string;
}

export interface ComplianceScore {
  framework: ComplianceFramework;
  score: number;
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  partial_controls: number;
  not_applicable: number;
  last_updated: string;
}

export interface ScanStatistics {
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  failed_scans: number;
  average_risk_score: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  risk_trend: Array<{
    date: string;
    risk_score: number;
  }>;
}

export interface VulnerabilityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  by_category: Record<string, number>;
  by_status: Record<string, number>;
}

export interface ScanProgress {
  scan_id: string;
  progress: number;
  message: string;
  status: ScanStatus;
  current_stage?: string;
  eta?: number;
}

export interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
}
