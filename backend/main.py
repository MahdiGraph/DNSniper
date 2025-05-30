import os
from pathlib import Path
from fastapi import FastAPI, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn

# Load environment variables
load_dotenv()

app = FastAPI(title="DNSniper API", version="1.0.0")

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# API Router
api_router = APIRouter(prefix="/api")

@api_router.get("/")
async def api_root():
    return {"message": "DNSniper API is running!", "status": "success"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

# Sample API endpoints
@api_router.get("/test")
async def test_endpoint():
    return {"message": "Test endpoint working!", "data": [1, 2, 3]}

# Include API router
app.include_router(api_router)

# Get the directory paths
current_dir = Path(__file__).parent
frontend_build_dir = current_dir.parent / "frontend" / "build"

# Mount static files for React build
if frontend_build_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_build_dir / "static")), name="static")
    
    # Serve index.html for any non-API routes (React Router support)
    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        # If path starts with 'api', let FastAPI handle it
        if full_path.startswith("api"):
            return {"error": "API endpoint not found"}
        
        # For all other paths, serve index.html (React Router will handle routing)
        index_file = frontend_build_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        else:
            return {"message": "Frontend not built yet. Run 'npm run build' in frontend directory."}
else:
    @app.get("/")
    async def root():
        return {
            "message": "DNSniper Backend is running!", 
            "frontend_status": "Frontend not built yet. Run 'npm run build' in frontend directory.",
            "api_docs": "/docs"
        }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=port, 
        reload=True,
        log_level="info"
    ) 