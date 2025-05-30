# DNSniper Backend

FastAPI backend that serves both the API and React frontend build from a single port.

## Setup

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
python main.py
```

The server will run on the port specified in `.env` (default: 8000)

## API Endpoints

- `GET /api/` - API root
- `GET /api/health` - Health check
- `GET /api/test` - Test endpoint
- `GET /docs` - Interactive API documentation
- `GET /` - Serves React frontend (when built)

## Features

- ✅ CORS enabled for all origins
- ✅ Serves React build from root `/`
- ✅ API endpoints under `/api`
- ✅ Hot reload in development
- ✅ Single port for frontend + backend

## Environment Variables

- `PORT` - Server port (default: 8000) 