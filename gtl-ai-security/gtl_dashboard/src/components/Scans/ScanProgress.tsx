import React, { useEffect } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { ScanStatus } from '@/types';
import clsx from 'clsx';

interface ScanProgressProps {
  scanId: string;
  onComplete?: () => void;
  onError?: () => void;
}

const ScanProgress: React.FC<ScanProgressProps> = ({ scanId, onComplete, onError }) => {
  const { progress, connected, error } = useWebSocket(scanId);

  useEffect(() => {
    if (progress?.status === ScanStatus.COMPLETED && onComplete) {
      onComplete();
    }
    if (progress?.status === ScanStatus.FAILED && onError) {
      onError();
    }
  }, [progress?.status, onComplete, onError]);

  if (!progress && !error) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin h-8 w-8 border-4 border-primary-600 border-t-transparent rounded-full" />
        <span className="ml-3 text-gray-600">Connecting to scan...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <p className="text-red-800">Failed to connect to scan: {error}</p>
      </div>
    );
  }

  const getStatusColor = (status: ScanStatus) => {
    switch (status) {
      case ScanStatus.COMPLETED:
        return 'bg-green-500';
      case ScanStatus.FAILED:
        return 'bg-red-500';
      case ScanStatus.RUNNING:
        return 'bg-blue-500';
      case ScanStatus.PENDING:
        return 'bg-yellow-500';
      default:
        return 'bg-gray-500';
    }
  };

  const stages = [
    { name: 'Initializing', threshold: 10 },
    { name: 'Network Discovery', threshold: 30 },
    { name: 'Vulnerability Scanning', threshold: 70 },
    { name: 'Risk Assessment', threshold: 90 },
    { name: 'Generating Report', threshold: 100 },
  ];

  const currentStage = stages.find(
    (s, i) => progress && progress.progress <= s.threshold && (i === 0 || progress.progress > stages[i - 1].threshold)
  );

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">
          Scan Progress
        </h3>
        <span
          className={clsx(
            'px-3 py-1 rounded-full text-sm font-medium',
            progress?.status === ScanStatus.COMPLETED
              ? 'bg-green-100 text-green-800'
              : progress?.status === ScanStatus.FAILED
              ? 'bg-red-100 text-red-800'
              : progress?.status === ScanStatus.RUNNING
              ? 'bg-blue-100 text-blue-800'
              : 'bg-gray-100 text-gray-800'
          )}
        >
          {progress?.status.toUpperCase()}
        </span>
      </div>

      {/* Progress Bar */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700">
            {currentStage?.name || 'Processing...'}
          </span>
          <span className="text-sm font-medium text-gray-900">
            {progress?.progress}%
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3">
          <div
            className={clsx(
              'h-3 rounded-full transition-all duration-500',
              getStatusColor(progress?.status || ScanStatus.PENDING)
            )}
            style={{ width: `${progress?.progress || 0}%` }}
          />
        </div>
      </div>

      {/* Status Message */}
      <p className="text-sm text-gray-600 mb-6">
        {progress?.message || 'Waiting for scan to start...'}
      </p>

      {/* Stages */}
      <div className="space-y-3">
        {stages.map((stage, index) => {
          const isCompleted = progress && progress.progress > stage.threshold;
          const isActive =
            progress &&
            progress.progress <= stage.threshold &&
            (index === 0 || progress.progress > stages[index - 1].threshold);

          return (
            <div key={stage.name} className="flex items-center">
              <div
                className={clsx(
                  'flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center',
                  isCompleted
                    ? 'bg-green-500 text-white'
                    : isActive
                    ? 'bg-blue-500 text-white animate-pulse'
                    : 'bg-gray-300 text-gray-500'
                )}
              >
                {isCompleted ? (
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path
                      fillRule="evenodd"
                      d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                      clipRule="evenodd"
                    />
                  </svg>
                ) : (
                  <span className="text-sm">{index + 1}</span>
                )}
              </div>
              <span
                className={clsx(
                  'ml-3 text-sm',
                  isCompleted || isActive ? 'text-gray-900 font-medium' : 'text-gray-500'
                )}
              >
                {stage.name}
              </span>
            </div>
          );
        })}
      </div>

      {/* Connection Status */}
      <div className="mt-6 pt-4 border-t border-gray-200">
        <div className="flex items-center text-xs text-gray-500">
          <div
            className={clsx(
              'w-2 h-2 rounded-full mr-2',
              connected ? 'bg-green-500' : 'bg-red-500'
            )}
          />
          {connected ? 'Connected' : 'Disconnected'}
        </div>
      </div>
    </div>
  );
};

export default ScanProgress;
