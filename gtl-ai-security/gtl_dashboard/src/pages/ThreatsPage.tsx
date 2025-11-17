import React from 'react';
import { Card, EmptyState } from '@/components/Common';

const ThreatsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Threat Intelligence</h1>

      <Card>
        <EmptyState
          icon={
            <svg className="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          }
          title="Threat Intelligence Coming Soon"
          description="Real-time threat intelligence and attack patterns will be available here"
        />
      </Card>
    </div>
  );
};

export default ThreatsPage;
