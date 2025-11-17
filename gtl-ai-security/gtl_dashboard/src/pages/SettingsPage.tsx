import React from 'react';
import { useAuthStore } from '@/stores/authStore';
import { Card } from '@/components/Common';

const SettingsPage: React.FC = () => {
  const { user } = useAuthStore();

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Settings</h1>

      <Card>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Account Information</h2>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-700">Username</label>
            <div className="mt-1 text-sm text-gray-900">{user?.username}</div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Email</label>
            <div className="mt-1 text-sm text-gray-900">{user?.email}</div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Role</label>
            <div className="mt-1 text-sm text-gray-900">{user?.role}</div>
          </div>
        </div>
      </Card>

      <Card>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Preferences</h2>
        <p className="text-sm text-gray-600">
          Additional settings will be available soon
        </p>
      </Card>
    </div>
  );
};

export default SettingsPage;
