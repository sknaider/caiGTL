import apiClient from './client';
import { ComplianceScore, ComplianceControl, ComplianceReportParams } from '@/types';

export const getComplianceScores = async (scanId?: string): Promise<ComplianceScore[]> => {
  const response = await apiClient.get<ComplianceScore[]>('/compliance/scores', {
    params: { scan_id: scanId },
  });
  return response.data;
};

export const getComplianceControls = async (
  framework: string,
  scanId?: string
): Promise<ComplianceControl[]> => {
  const response = await apiClient.get<ComplianceControl[]>('/compliance/controls', {
    params: { framework, scan_id: scanId },
  });
  return response.data;
};

export const generateComplianceReport = async (
  params: ComplianceReportParams
): Promise<Blob> => {
  const response = await apiClient.post(
    '/compliance/reports',
    params,
    { responseType: 'blob' }
  );
  return response.data;
};

export const updateControlStatus = async (
  controlId: string,
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable',
  notes?: string
): Promise<ComplianceControl> => {
  const response = await apiClient.patch<ComplianceControl>(`/compliance/controls/${controlId}`, {
    status,
    notes,
  });
  return response.data;
};
