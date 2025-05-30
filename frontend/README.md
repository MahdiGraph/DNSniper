# DNSniper Frontend

React frontend for the DNSniper application with modern UI/UX.

## Setup

1. Install Node.js dependencies:
```bash
npm install
```

2. For development:
```bash
npm start
```
This runs the frontend in development mode on port 3000 with proxy to backend.

3. For production build:
```bash
npm run build
```
This creates a `build` folder that the FastAPI backend will serve.

## Features

- ✅ Modern, responsive UI with glassmorphism design
- ✅ Gradient backgrounds and smooth animations
- ✅ API integration with axios
- ✅ Real-time status checking
- ✅ Mobile-friendly responsive design
- ✅ Proxy configuration for backend API

## API Integration

The frontend uses relative paths for API calls:
- `/api/health` - Health check
- `/api/test` - Test endpoint

No domain needed - works with the FastAPI backend proxy setup.

## Build Process

The build process creates static files that are served by the FastAPI backend at the root path `/`. 