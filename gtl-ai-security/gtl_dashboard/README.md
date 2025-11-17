# GTL Security Platform - Dashboard

React-based security dashboard for the GTL AI Security Platform.

## Features

- **Authentication**: JWT-based authentication with automatic token refresh
- **Real-time Scan Monitoring**: WebSocket integration for live scan progress
- **Vulnerability Management**: View and manage security vulnerabilities
- **Compliance Dashboards**: HIPAA, GDPR, ISO 27001, and more
- **Interactive Charts**: Visualize security trends and metrics
- **Responsive Design**: Mobile-friendly interface

## Tech Stack

- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **TailwindCSS** - Styling
- **React Query** - Data fetching
- **Zustand** - State management
- **Recharts** - Data visualization
- **React Router** - Navigation
- **Axios** - HTTP client

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Update .env with your API endpoint
VITE_API_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000
```

### Development

```bash
# Start development server
npm run dev

# Server will run on http://localhost:3000
```

### Build

```bash
# Build for production
npm run build

# Preview production build
npm run preview
```

## Project Structure

```
src/
├── api/              # API client and endpoints
├── components/       # React components
│   ├── Auth/         # Authentication components
│   ├── Charts/       # Data visualization
│   ├── Common/       # Shared components
│   ├── Compliance/   # Compliance components
│   ├── Layout/       # Layout components
│   ├── Scans/        # Scan management
│   └── Vulnerabilities/
├── hooks/            # Custom React hooks
├── pages/            # Page components
├── stores/           # Zustand stores
├── styles/           # Global styles
├── types/            # TypeScript types
└── utils/            # Utility functions
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | `http://localhost:8000/api/v1` |
| `VITE_WS_URL` | WebSocket URL | `ws://localhost:8000` |
| `VITE_APP_NAME` | Application name | `GTL Security Platform` |
| `VITE_APP_VERSION` | Application version | `1.0.0` |

## Features in Detail

### Authentication

- Login/logout with JWT tokens
- Automatic token refresh
- Protected routes
- Role-based access control

### Scan Management

- Create new scans with different profiles (Default, Logistics, Medical AI, Customs)
- Real-time progress monitoring via WebSocket
- View scan results and vulnerabilities
- Download reports in multiple formats (PDF, JSON, HTML, CSV)

### Vulnerability Management

- View all vulnerabilities with severity filtering
- Detailed vulnerability information
- Update vulnerability status
- Export vulnerabilities

### Compliance Dashboard

- View compliance scores for multiple frameworks
- Track compliance controls
- Generate compliance reports

### Charts & Visualizations

- Risk trend over time
- Vulnerability distribution by severity
- Compliance score gauges

## API Integration

The dashboard integrates with the GTL Security Platform backend API:

- Authentication: `/api/v1/auth/*`
- Scans: `/api/v1/scans/*`
- Vulnerabilities: `/api/v1/vulnerabilities/*`
- Compliance: `/api/v1/compliance/*`

## Development Notes

- All API calls use the centralized `apiClient` with automatic authentication
- WebSocket connections auto-reconnect on failure
- React Query handles caching and revalidation
- Zustand provides lightweight state management
- TailwindCSS utility classes for styling

## Contributing

1. Follow the existing code structure
2. Use TypeScript for type safety
3. Add proper error handling
4. Update tests when adding features
5. Follow the component naming conventions

## License

Proprietary - GTL Security Platform
