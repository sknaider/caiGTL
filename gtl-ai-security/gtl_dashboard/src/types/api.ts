import { Scan, User, Vulnerability, AgentFinding, ComplianceControl, ScanProfile } from './models';

// Auth API
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: User;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface RefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

// Scan API
export interface CreateScanRequest {
  target_url: string;
  scan_profile: ScanProfile;
  description?: string;
  tags?: string[];
  options?: Record<string, any>;
}

export interface UpdateScanRequest {
  status?: string;
  notes?: string;
  tags?: string[];
}

export interface ScanListParams {
  limit?: number;
  offset?: number;
  status?: string;
  profile?: string;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

// Vulnerability API
export interface VulnerabilityListParams {
  scan_id?: string;
  severity?: string;
  category?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export interface UpdateVulnerabilityRequest {
  status?: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  notes?: string;
  assigned_to?: string;
}

// Compliance API
export interface ComplianceReportParams {
  scan_id?: string;
  framework?: string;
  start_date?: string;
  end_date?: string;
}

// Report API
export interface GenerateReportRequest {
  scan_id: string;
  format: 'pdf' | 'json' | 'html' | 'csv';
  include_sections?: string[];
  custom_logo?: string;
}

// Pagination
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// API Error
export interface ApiError {
  detail: string;
  status_code: number;
  error_code?: string;
}
