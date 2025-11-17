import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getScans, getScanStatistics } from '@/api/scans';
import { getVulnerabilityStats } from '@/api/vulnerabilities';
import { ScanList } from '@/components/Scans';
import { RiskTrendChart, VulnerabilityPieChart } from '@/components/Charts';
import { CreateScanModal } from '@/components/Scans';
import { LoadingSpinner, Card } from '@/components/Common';
import { useCreateScan } from '@/hooks/useScans';
import { CreateScanRequest } from '@/types';

const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ['scans', { limit: 5 }],
    queryFn: () => getScans({ limit: 5 }),
  });

  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ['scan-statistics'],
    queryFn: getScanStatistics,
  });

  const { data: vulnStatsData, isLoading: vulnStatsLoading } = useQuery({
    queryKey: ['vulnerability-statistics'],
    queryFn: () => getVulnerabilityStats(),
  });

  const createScanMutation = useCreateScan();

  const handleCreateScan = async (data: CreateScanRequest) => {
    try {
      const scan = await createScanMutation.mutateAsync(data);
      setIsCreateModalOpen(false);
      navigate(`/scans/${scan.id}`);
    } catch (error) {
      console.error('Failed to create scan:', error);
    }
  };

  if (scansLoading || statsLoading || vulnStatsLoading) {
    return <LoadingSpinner fullScreen message="Loading dashboard..." />;
  }

  const scans = scansData?.items || [];
  const stats = statsData;
  const vulnStats = vulnStatsData;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
        >
          <svg
            className="h-5 w-5 mr-2"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 4v16m8-8H4"
            />
          </svg>
          New Scan
        </button>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Total Scans"
          value={stats?.total_scans || 0}
          icon="📊"
          trend={stats?.active_scans ? `${stats.active_scans} active` : undefined}
        />
        <MetricCard
          title="Critical Vulnerabilities"
          value={vulnStats?.critical || 0}
          icon="🚨"
          danger={vulnStats && vulnStats.critical > 0}
        />
        <MetricCard
          title="Avg Risk Score"
          value={stats?.average_risk_score?.toFixed(1) || '0'}
          icon="📈"
        />
        <MetricCard
          title="Total Vulnerabilities"
          value={vulnStats?.total || 0}
          icon="🔍"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <h2 className="text-xl font-semibold text-gray-900 mb-4">
            Risk Trend (30 days)
          </h2>
          <RiskTrendChart data={stats?.risk_trend || []} />
        </Card>
        <Card>
          <h2 className="text-xl font-semibold text-gray-900 mb-4">
            Vulnerabilities by Severity
          </h2>
          {vulnStats ? (
            <VulnerabilityPieChart data={vulnStats} />
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-500">
              No data available
            </div>
          )}
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Recent Scans</h2>
          <button
            onClick={() => navigate('/scans')}
            className="text-sm text-primary-600 hover:text-primary-700 font-medium"
          >
            View all →
          </button>
        </div>
        {scans.length > 0 ? (
          <ScanList scans={scans} />
        ) : (
          <div className="text-center py-12">
            <p className="text-gray-500">No scans yet</p>
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="mt-4 text-primary-600 hover:text-primary-700 font-medium"
            >
              Create your first scan
            </button>
          </div>
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

interface MetricCardProps {
  title: string;
  value: number | string;
  icon: string;
  trend?: string;
  danger?: boolean;
}

const MetricCard: React.FC<MetricCardProps> = ({ title, value, icon, trend, danger }) => (
  <Card>
    <div className="flex items-center justify-between mb-2">
      <span className="text-sm font-medium text-gray-600">{title}</span>
      <span className="text-2xl">{icon}</span>
    </div>
    <div className="text-3xl font-bold mb-1">{value}</div>
    {trend && (
      <div className={`text-sm ${danger ? 'text-red-600' : 'text-gray-600'}`}>
        {trend}
      </div>
    )}
  </Card>
);

export default DashboardPage;
