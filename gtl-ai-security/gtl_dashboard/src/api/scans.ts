import apiClient from './client';
import {
  Scan,
  CreateScanRequest,
  UpdateScanRequest,
  ScanListParams,
  ScanStatistics,
  PaginatedResponse,
} from '@/types';

export const getScans = async (params?: ScanListParams): Promise<PaginatedResponse<Scan>> => {
  const response = await apiClient.get<PaginatedResponse<Scan>>('/scans', { params });
  return response.data;
};

export const getScan = async (scanId: string): Promise<Scan> => {
  const response = await apiClient.get<Scan>(`/scans/${scanId}`);
  return response.data;
};

export const createScan = async (data: CreateScanRequest): Promise<Scan> => {
  const response = await apiClient.post<Scan>('/scans', data);
  return response.data;
};

export const updateScan = async (scanId: string, data: UpdateScanRequest): Promise<Scan> => {
  const response = await apiClient.patch<Scan>(`/scans/${scanId}`, data);
  return response.data;
};

export const deleteScan = async (scanId: string): Promise<void> => {
  await apiClient.delete(`/scans/${scanId}`);
};

export const cancelScan = async (scanId: string): Promise<Scan> => {
  const response = await apiClient.post<Scan>(`/scans/${scanId}/cancel`);
  return response.data;
};

export const getScanStatistics = async (): Promise<ScanStatistics> => {
  const response = await apiClient.get<ScanStatistics>('/scans/statistics');
  return response.data;
};

export const downloadReport = async (
  scanId: string,
  format: 'pdf' | 'json' | 'html' | 'csv'
): Promise<Blob> => {
  const response = await apiClient.get(`/scans/${scanId}/report`, {
    params: { format },
    responseType: 'blob',
  });
  return response.data;
};

export const retryFailedScan = async (scanId: string): Promise<Scan> => {
  const response = await apiClient.post<Scan>(`/scans/${scanId}/retry`);
  return response.data;
};
