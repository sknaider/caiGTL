import React from 'react';
import { ComplianceScore as ComplianceScoreType } from '@/types';
import clsx from 'clsx';

interface ComplianceScoreProps {
  score: ComplianceScoreType;
}

const ComplianceScore: React.FC<ComplianceScoreProps> = ({ score }) => {
  const percentage = score.total_controls > 0
    ? (score.compliant_controls / score.total_controls) * 100
    : 0;

  const getScoreColor = (pct: number) => {
    if (pct >= 90) return 'text-green-600';
    if (pct >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getProgressColor = (pct: number) => {
    if (pct >= 90) return 'bg-green-500';
    if (pct >= 70) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">
          {score.framework.toUpperCase()}
        </h3>
        <span className={clsx('text-2xl font-bold', getScoreColor(percentage))}>
          {percentage.toFixed(1)}%
        </span>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-gray-200 rounded-full h-3 mb-4">
        <div
          className={clsx('h-3 rounded-full transition-all', getProgressColor(percentage))}
          style={{ width: `${percentage}%` }}
        />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-gray-500">Compliant</div>
          <div className="text-lg font-semibold text-green-600">
            {score.compliant_controls}
          </div>
        </div>
        <div>
          <div className="text-gray-500">Non-Compliant</div>
          <div className="text-lg font-semibold text-red-600">
            {score.non_compliant_controls}
          </div>
        </div>
        <div>
          <div className="text-gray-500">Partial</div>
          <div className="text-lg font-semibold text-yellow-600">
            {score.partial_controls}
          </div>
        </div>
        <div>
          <div className="text-gray-500">Total Controls</div>
          <div className="text-lg font-semibold text-gray-900">
            {score.total_controls}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ComplianceScore;
