import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import duration from 'dayjs/plugin/duration';

dayjs.extend(relativeTime);
dayjs.extend(duration);

export const formatDate = (date: string | Date, format = 'MMM D, YYYY'): string => {
  return dayjs(date).format(format);
};

export const formatDateTime = (date: string | Date): string => {
  return dayjs(date).format('MMM D, YYYY h:mm A');
};

export const formatRelativeTime = (date: string | Date): string => {
  return dayjs(date).fromNow();
};

export const formatDuration = (seconds: number): string => {
  const d = dayjs.duration(seconds, 'seconds');
  const hours = Math.floor(d.asHours());
  const minutes = d.minutes();
  const secs = d.seconds();

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
};

export const formatNumber = (num: number, decimals = 0): string => {
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  }).format(num);
};

export const formatPercentage = (value: number, total: number): string => {
  if (total === 0) return '0%';
  const percentage = (value / total) * 100;
  return `${percentage.toFixed(1)}%`;
};

export const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

export const truncateText = (text: string, maxLength: number): string => {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
};

export const formatUrl = (url: string): string => {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname + urlObj.pathname;
  } catch {
    return url;
  }
};

export const formatRiskScore = (score: number): {
  label: string;
  color: string;
  bgColor: string;
} => {
  if (score >= 80) {
    return {
      label: 'Critical',
      color: 'text-red-700',
      bgColor: 'bg-red-100',
    };
  }
  if (score >= 60) {
    return {
      label: 'High',
      color: 'text-orange-700',
      bgColor: 'bg-orange-100',
    };
  }
  if (score >= 40) {
    return {
      label: 'Medium',
      color: 'text-yellow-700',
      bgColor: 'bg-yellow-100',
    };
  }
  if (score >= 20) {
    return {
      label: 'Low',
      color: 'text-blue-700',
      bgColor: 'bg-blue-100',
    };
  }
  return {
    label: 'Info',
    color: 'text-gray-700',
    bgColor: 'bg-gray-100',
  };
};
