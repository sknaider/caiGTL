# GTL Dashboard - Quick Start Guide

## Installation

```bash
# Navigate to dashboard directory
cd gtl_dashboard

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Edit .env file with your API endpoint
# VITE_API_URL=http://localhost:8000/api/v1
# VITE_WS_URL=ws://localhost:8000
```

## Development

```bash
# Start development server
npm run dev

# Application will run on http://localhost:3000
```

## Build for Production

```bash
# Type check
npm run type-check

# Build optimized bundle
npm run build

# Preview production build
npm run preview
```

## Code Quality

```bash
# Run linter
npm run lint

# Auto-fix linting issues
npm run lint:fix

# Format code with Prettier
npm run format
```

## Default Login Credentials

Check with your backend administrator for login credentials.

## Common Issues

### Port 3000 already in use

```bash
# Change port in vite.config.ts
server: { port: 3001 }
```

### API Connection Failed

1. Verify backend is running on `http://localhost:8000`
2. Check `.env` file has correct API URL
3. Check CORS settings on backend

### WebSocket Connection Failed

1. Verify WebSocket endpoint in `.env`
2. Check backend WebSocket server is running
3. Verify firewall settings

## Project Structure

- `src/api/` - API client and endpoints
- `src/components/` - React components
- `src/pages/` - Page components
- `src/hooks/` - Custom hooks
- `src/stores/` - Zustand state management
- `src/types/` - TypeScript types
- `src/utils/` - Utility functions

## Technologies Used

- React 18 + TypeScript
- Vite (build tool)
- TailwindCSS (styling)
- React Query (data fetching)
- Zustand (state management)
- Recharts (charts)
- Axios (HTTP client)

## Support

For issues or questions, please check the main README.md or contact the development team.
