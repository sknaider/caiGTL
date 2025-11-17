import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScans, useCreateScan } from '@/hooks/useScans';
import { ScanList, CreateScanModal } from '@/components/Scans';
import { LoadingSpinner, Card, EmptyState } from '@/components/Common';
import { CreateScanRequest } from '@/types';

const ScansPage: React.FC = () => {
  const navigate = useNavigate();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const { data, isLoading } = useScans({ limit: 50 });
  const createScanMutation = useCreateScan();

  const handleCreateScan = async (scanData: CreateScanRequest) => {
    try {
      const scan = await createScanMutation.mutateAsync(scanData);
      setIsCreateModalOpen(false);
      navigate(`/scans/${scan.id}`);
    } catch (error) {
      console.error('Failed to create scan:', error);
    }
  };

  if (isLoading) {
    return <LoadingSpinner fullScreen message="Loading scans..." />;
  }

  const scans = data?.items || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Scans</h1>
        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700"
        >
          <svg className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Scan
        </button>
      </div>

      {/* Scans Table */}
      <Card padding="none">
        {scans.length > 0 ? (
          <ScanList scans={scans} />
        ) : (
          <EmptyState
            icon={
              <svg className="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
            }
            title="No scans found"
            description="Get started by creating your first security scan"
            action={{
              label: 'Create Scan',
              onClick: () => setIsCreateModalOpen(true),
            }}
          />
        )}
      </Card>

      {/* Create Scan Modal */}
      <CreateScanModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={handleCreateScan}
        isLoading={createScanMutation.isPending}
      />
    </div>
  );
};

export default ScansPage;
