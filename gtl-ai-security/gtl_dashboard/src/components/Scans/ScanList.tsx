import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Scan } from '@/types';
import { formatDateTime, formatRelativeTime } from '@/utils/formatters';
import SeverityBadge from '../Common/SeverityBadge';
import clsx from 'clsx';

interface ScanListProps {
  scans: Scan[];
  onScanClick?: (scan: Scan) => void;
}

const ScanList: React.FC<ScanListProps> = ({ scans, onScanClick }) => {
  const navigate = useNavigate();

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-700 bg-green-100';
      case 'running':
        return 'text-blue-700 bg-blue-100';
      case 'failed':
        return 'text-red-700 bg-red-100';
      case 'pending':
        return 'text-yellow-700 bg-yellow-100';
      case 'cancelled':
        return 'text-gray-700 bg-gray-100';
      default:
        return 'text-gray-700 bg-gray-100';
    }
  };

  const handleClick = (scan: Scan) => {
    if (onScanClick) {
      onScanClick(scan);
    } else {
      navigate(`/scans/${scan.id}`);
    }
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Target
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Profile
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Status
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Vulnerabilities
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Risk Score
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Created
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {scans.map((scan) => (
            <tr
              key={scan.id}
              onClick={() => handleClick(scan)}
              className="hover:bg-gray-50 cursor-pointer transition-colors"
            >
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm font-medium text-gray-900">
                  {scan.target_url}
                </div>
                <div className="text-sm text-gray-500">ID: {scan.id.slice(0, 8)}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
                  {scan.scan_profile}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span
                  className={clsx(
                    'px-2 inline-flex text-xs leading-5 font-semibold rounded-full',
                    getStatusColor(scan.status)
                  )}
                >
                  {scan.status}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex items-center space-x-2">
                  {scan.critical_count > 0 && (
                    <span className="text-xs text-red-600 font-medium">
                      {scan.critical_count} Critical
                    </span>
                  )}
                  {scan.high_count > 0 && (
                    <span className="text-xs text-orange-600 font-medium">
                      {scan.high_count} High
                    </span>
                  )}
                  {scan.total_vulnerabilities === 0 && (
                    <span className="text-xs text-gray-500">No issues</span>
                  )}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                {scan.risk_score !== undefined ? (
                  <div className="flex items-center">
                    <div className="text-sm font-medium text-gray-900">
                      {scan.risk_score.toFixed(1)}
                    </div>
                    <div className="ml-2 w-16 bg-gray-200 rounded-full h-2">
                      <div
                        className={clsx(
                          'h-2 rounded-full',
                          scan.risk_score >= 80
                            ? 'bg-red-600'
                            : scan.risk_score >= 60
                            ? 'bg-orange-500'
                            : scan.risk_score >= 40
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                        )}
                        style={{ width: `${scan.risk_score}%` }}
                      />
                    </div>
                  </div>
                ) : (
                  <span className="text-sm text-gray-400">N/A</span>
                )}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                <div title={formatDateTime(scan.created_at)}>
                  {formatRelativeTime(scan.created_at)}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ScanList;
