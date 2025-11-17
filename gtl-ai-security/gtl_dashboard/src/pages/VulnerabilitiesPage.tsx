import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { getVulnerabilities } from '@/api/vulnerabilities';
import { VulnerabilityTable } from '@/components/Vulnerabilities';
import { LoadingSpinner, Card, EmptyState } from '@/components/Common';

const VulnerabilitiesPage: React.FC = () => {
  const { data, isLoading } = useQuery({
    queryKey: ['vulnerabilities', { limit: 100 }],
    queryFn: () => getVulnerabilities({ limit: 100 }),
  });

  if (isLoading) {
    return <LoadingSpinner fullScreen message="Loading vulnerabilities..." />;
  }

  const vulnerabilities = data?.items || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Vulnerabilities</h1>
      </div>

      {/* Vulnerabilities Table */}
      <Card padding="none">
        {vulnerabilities.length > 0 ? (
          <VulnerabilityTable vulnerabilities={vulnerabilities} />
        ) : (
          <EmptyState
            icon={
              <svg className="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            }
            title="No vulnerabilities found"
            description="Run a scan to discover security vulnerabilities"
          />
        )}
      </Card>
    </div>
  );
};

export default VulnerabilitiesPage;
