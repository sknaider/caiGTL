import React, { useState } from 'react';
import { ScanProfile } from '@/types';
import { isValidUrl } from '@/utils/validators';

interface CreateScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: { target_url: string; scan_profile: ScanProfile }) => void;
  isLoading?: boolean;
}

const CreateScanModal: React.FC<CreateScanModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  isLoading = false,
}) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanProfile, setScanProfile] = useState<ScanProfile>(ScanProfile.DEFAULT);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!targetUrl.trim()) {
      setError('Please enter a target URL');
      return;
    }

    if (!isValidUrl(targetUrl)) {
      setError('Please enter a valid URL');
      return;
    }

    onSubmit({ target_url: targetUrl, scan_profile: scanProfile });
  };

  const handleClose = () => {
    setTargetUrl('');
    setScanProfile(ScanProfile.DEFAULT);
    setError('');
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        {/* Backdrop */}
        <div
          className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75"
          onClick={handleClose}
        />

        {/* Modal */}
        <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
          <form onSubmit={handleSubmit}>
            <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
              <h3 className="text-lg font-medium leading-6 text-gray-900 mb-4">
                Create New Scan
              </h3>

              {error && (
                <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
                  {error}
                </div>
              )}

              <div className="space-y-4">
                <div>
                  <label htmlFor="target_url" className="block text-sm font-medium text-gray-700">
                    Target URL
                  </label>
                  <input
                    type="text"
                    id="target_url"
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    placeholder="https://example.com"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label htmlFor="scan_profile" className="block text-sm font-medium text-gray-700">
                    Scan Profile
                  </label>
                  <select
                    id="scan_profile"
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    value={scanProfile}
                    onChange={(e) => setScanProfile(e.target.value as ScanProfile)}
                    disabled={isLoading}
                  >
                    <option value={ScanProfile.DEFAULT}>Default Security Scan</option>
                    <option value={ScanProfile.LOGISTICS}>Logistics Security Agent</option>
                    <option value={ScanProfile.MEDICAL_AI}>Medical AI Compliance Agent</option>
                    <option value={ScanProfile.CUSTOMS}>Customs Data Protection Agent</option>
                    <option value={ScanProfile.FULL}>Full Scan (All Agents)</option>
                  </select>
                  <p className="mt-2 text-sm text-gray-500">
                    {scanProfile === ScanProfile.DEFAULT &&
                      'Standard vulnerability scan with basic security checks'}
                    {scanProfile === ScanProfile.LOGISTICS &&
                      'EDI, customs data, and supply chain security'}
                    {scanProfile === ScanProfile.MEDICAL_AI &&
                      'HIPAA compliance, PHI exposure, and medical AI security'}
                    {scanProfile === ScanProfile.CUSTOMS &&
                      'SUNAT integration and Peru customs compliance'}
                    {scanProfile === ScanProfile.FULL &&
                      'Comprehensive scan with all specialized agents'}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
              <button
                type="submit"
                disabled={isLoading}
                className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary-600 text-base font-medium text-white hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Creating...' : 'Start Scan'}
              </button>
              <button
                type="button"
                onClick={handleClose}
                disabled={isLoading}
                className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:w-auto sm:text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default CreateScanModal;
