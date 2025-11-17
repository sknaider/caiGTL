import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { formatDate } from '@/utils/formatters';

interface RiskTrendChartProps {
  data: Array<{ date: string; risk_score: number }>;
}

const RiskTrendChart: React.FC<RiskTrendChartProps> = ({ data }) => {
  const chartData = data.map((item) => ({
    date: formatDate(item.date, 'MMM D'),
    score: item.risk_score,
  }));

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500">
        No data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
        <XAxis dataKey="date" stroke="#6b7280" fontSize={12} />
        <YAxis stroke="#6b7280" fontSize={12} domain={[0, 100]} />
        <Tooltip
          contentStyle={{
            backgroundColor: '#fff',
            border: '1px solid #e5e7eb',
            borderRadius: '0.375rem',
          }}
        />
        <Legend />
        <Line
          type="monotone"
          dataKey="score"
          name="Risk Score"
          stroke="#2563eb"
          strokeWidth={2}
          dot={{ fill: '#2563eb', r: 4 }}
          activeDot={{ r: 6 }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
};

export default RiskTrendChart;
