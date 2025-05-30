# DNSniper Full-Stack Application

A modern full-stack application with FastAPI backend and React frontend served from a single port.

## Project Structure

```
DNSniper/
├── backend/                 # Python FastAPI backend
│   ├── main.py             # Main FastAPI application
│   ├── requirements.txt    # Python dependencies  
│   ├── .env               # Environment variables (PORT=8000)
│   └── README.md          # Backend documentation
├── frontend/               # React frontend
│   ├── src/               # React source code
│   ├── public/            # Static assets
│   ├── package.json       # Node.js dependencies
│   └── README.md          # Frontend documentation
└── README-fullstack.md    # This file
```

## Quick Start

### Option 1: Development Mode (Separate Ports)

1. **Start Backend** (Terminal 1):
```bash
cd backend
pip install -r requirements.txt
python main.py
```
Backend runs on: http://localhost:8000

2. **Start Frontend** (Terminal 2):
```bash
cd frontend
npm install
npm start
```
Frontend runs on: http://localhost:3000 (with proxy to backend)

### Option 2: Production Mode (Single Port)

1. **Build Frontend**:
```bash
cd frontend
npm install
npm run build
```

2. **Start Backend** (serves both frontend and API):
```bash
cd backend
pip install -r requirements.txt
python main.py
```

Everything runs on: http://localhost:8000
- Frontend: http://localhost:8000/
- API: http://localhost:8000/api/
- API Docs: http://localhost:8000/docs

## Features

### Backend (FastAPI)
- ✅ RESTful API with automatic documentation
- ✅ CORS enabled for all origins
- ✅ Serves React build from root path
- ✅ Environment-based configuration
- ✅ Hot reload in development

### Frontend (React)
- ✅ Modern glassmorphism UI design
- ✅ Responsive design for all devices
- ✅ Real-time API status monitoring
- ✅ Smooth animations and transitions
- ✅ Relative API paths (no domain needed)

## API Endpoints

- `GET /` - React frontend (production)
- `GET /api/` - API root
- `GET /api/health` - Health check
- `GET /api/test` - Test endpoint
- `GET /docs` - Interactive API documentation
- `GET /redoc` - Alternative API documentation

## Configuration

### Backend (.env)
```
PORT=8000
```

### Frontend (package.json)
```json
{
  "proxy": "http://localhost:8000"
}
```

## Development Tips

1. **For API development**: Use http://localhost:8000/docs for interactive testing
2. **For frontend development**: Use `npm start` for hot reload
3. **For production testing**: Build frontend first, then run backend
4. **CORS**: All origins are allowed for maximum compatibility

## Troubleshooting

1. **PowerShell execution policy**: If npx fails, the React structure is manually created
2. **Port conflicts**: Change PORT in backend/.env file
3. **Build issues**: Make sure to run `npm run build` in frontend before production mode
4. **API not found**: Check that backend is running and CORS is enabled

## Next Steps

- Add more API endpoints in `backend/main.py`
- Enhance frontend components in `frontend/src/`
- Add database integration
- Implement authentication
- Add DNS analysis features 