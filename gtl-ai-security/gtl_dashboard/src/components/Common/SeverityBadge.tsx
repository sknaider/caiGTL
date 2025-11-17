import React from 'react';
import { VulnerabilitySeverity } from '@/types';
import clsx from 'clsx';

interface SeverityBadgeProps {
  severity: VulnerabilitySeverity;
  size?: 'sm' | 'md' | 'lg';
}

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
    lg: 'px-3 py-1.5 text-base',
  };

  const colorClasses = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-800 border-gray-200',
  };

  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full font-medium border',
        sizeClasses[size],
        colorClasses[severity]
      )}
    >
      {severity.toUpperCase()}
    </span>
  );
};

export default SeverityBadge;
