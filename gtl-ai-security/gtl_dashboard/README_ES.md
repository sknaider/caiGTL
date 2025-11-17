# GTL Security Platform - Dashboard

Dashboard basado en React para la Plataforma de Seguridad GTL AI.

## Características

- **Autenticación**: Autenticación basada en JWT con refresh automático de tokens
- **Monitoreo de Escaneos en Tiempo Real**: Integración WebSocket para progreso de escaneos en vivo
- **Gestión de Vulnerabilidades**: Ver y gestionar vulnerabilidades de seguridad
- **Dashboards de Compliance**: HIPAA, GDPR, ISO 27001, y más
- **Gráficos Interactivos**: Visualiza tendencias de seguridad y métricas
- **Diseño Responsive**: Interfaz amigable para móviles

## Stack Tecnológico

- **React 18** - Biblioteca de UI
- **TypeScript** - Seguridad de tipos
- **Vite** - Herramienta de build
- **TailwindCSS** - Estilos
- **React Query** - Obtención de datos
- **Zustand** - Gestión de estado
- **Recharts** - Visualización de datos
- **React Router** - Navegación
- **Axios** - Cliente HTTP

## Primeros Pasos

### Prerequisitos

- Node.js 18+
- npm o yarn

### Instalación

```bash
# Instalar dependencias
npm install

# Copiar archivo de entorno
cp .env.example .env

# Actualizar .env con tu endpoint de API
VITE_API_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000
```

### Desarrollo

```bash
# Iniciar servidor de desarrollo
npm run dev

# El servidor se ejecutará en http://localhost:3000
```

### Build

```bash
# Build para producción
npm run build

# Preview del build de producción
npm run preview
```

## Estructura del Proyecto

```
src/
├── api/              # Cliente API y endpoints
├── components/       # Componentes React
│   ├── Auth/         # Componentes de autenticación
│   ├── Charts/       # Visualización de datos
│   ├── Common/       # Componentes compartidos
│   ├── Compliance/   # Componentes de compliance
│   ├── Layout/       # Componentes de layout
│   ├── Scans/        # Gestión de escaneos
│   └── Vulnerabilities/
├── hooks/            # Hooks personalizados de React
├── pages/            # Componentes de página
├── stores/           # Stores de Zustand
├── styles/           # Estilos globales
├── types/            # Tipos TypeScript
└── utils/            # Funciones utilitarias
```

## Variables de Entorno

| Variable | Descripción | Por Defecto |
|----------|-------------|-------------|
| `VITE_API_URL` | URL del API backend | `http://localhost:8000/api/v1` |
| `VITE_WS_URL` | URL WebSocket | `ws://localhost:8000` |
| `VITE_APP_NAME` | Nombre de la aplicación | `GTL Security Platform` |
| `VITE_APP_VERSION` | Versión de la aplicación | `1.0.0` |

## Características en Detalle

### Autenticación

- Login/logout con tokens JWT
- Refresh automático de tokens
- Rutas protegidas
- Control de acceso basado en roles

### Gestión de Escaneos

- Crear nuevos escaneos con diferentes perfiles (Default, Logistics, Medical AI, Customs)
- Monitoreo de progreso en tiempo real vía WebSocket
- Ver resultados de escaneos y vulnerabilidades
- Descargar reportes en múltiples formatos (PDF, JSON, HTML, CSV)

### Gestión de Vulnerabilidades

- Ver todas las vulnerabilidades con filtrado por severidad
- Información detallada de vulnerabilidades
- Actualizar estado de vulnerabilidades
- Exportar vulnerabilidades

### Dashboard de Compliance

- Ver scores de compliance para múltiples frameworks
- Rastrear controles de compliance
- Generar reportes de compliance

### Gráficos y Visualizaciones

- Tendencia de riesgo a través del tiempo
- Distribución de vulnerabilidades por severidad
- Medidores de score de compliance

## Integración con API

El dashboard se integra con el API backend de la Plataforma de Seguridad GTL:

- Autenticación: `/api/v1/auth/*`
- Escaneos: `/api/v1/scans/*`
- Vulnerabilidades: `/api/v1/vulnerabilities/*`
- Compliance: `/api/v1/compliance/*`

## Notas de Desarrollo

- Todas las llamadas al API usan el `apiClient` centralizado con autenticación automática
- Las conexiones WebSocket se reconectan automáticamente en caso de fallo
- React Query maneja el caché y la revalidación
- Zustand proporciona gestión de estado ligera
- Clases utilitarias de TailwindCSS para estilos

## Licencia

Propietario - GTL Security Platform
