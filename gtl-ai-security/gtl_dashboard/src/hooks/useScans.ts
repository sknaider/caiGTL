import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getScans, getScan, createScan, deleteScan, cancelScan } from '@/api/scans';
import { CreateScanRequest, ScanListParams } from '@/types';

export const useScans = (params?: ScanListParams) => {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => getScans(params),
  });
};

export const useScan = (scanId: string) => {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId),
    enabled: !!scanId,
  });
};

export const useCreateScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateScanRequest) => createScan(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
};

export const useDeleteScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (scanId: string) => deleteScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
};

export const useCancelScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (scanId: string) => cancelScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
};
