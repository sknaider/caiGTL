import apiClient from './client';
import {
  Vulnerability,
  VulnerabilityListParams,
  UpdateVulnerabilityRequest,
  VulnerabilityStats,
  PaginatedResponse,
} from '@/types';

export const getVulnerabilities = async (
  params?: VulnerabilityListParams
): Promise<PaginatedResponse<Vulnerability>> => {
  const response = await apiClient.get<PaginatedResponse<Vulnerability>>('/vulnerabilities', {
    params,
  });
  return response.data;
};

export const getVulnerability = async (vulnId: string): Promise<Vulnerability> => {
  const response = await apiClient.get<Vulnerability>(`/vulnerabilities/${vulnId}`);
  return response.data;
};

export const updateVulnerability = async (
  vulnId: string,
  data: UpdateVulnerabilityRequest
): Promise<Vulnerability> => {
  const response = await apiClient.patch<Vulnerability>(`/vulnerabilities/${vulnId}`, data);
  return response.data;
};

export const getVulnerabilityStats = async (scanId?: string): Promise<VulnerabilityStats> => {
  const response = await apiClient.get<VulnerabilityStats>('/vulnerabilities/statistics', {
    params: { scan_id: scanId },
  });
  return response.data;
};

export const exportVulnerabilities = async (
  params: VulnerabilityListParams,
  format: 'csv' | 'json'
): Promise<Blob> => {
  const response = await apiClient.get('/vulnerabilities/export', {
    params: { ...params, format },
    responseType: 'blob',
  });
  return response.data;
};
