import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import engine, get_db, Base, SessionLocal
from models import Domain, IP, IPRange, AutoUpdateSource, Setting, Log, User, APIToken
from routers import domains, ips, ip_ranges, settings, logs, auto_update_sources, auth
from services.firewall_service import FirewallService
from services.auto_update_service import AutoUpdateService
import asyncio
import schedule
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global scheduler control
auto_update_thread = None
auto_update_stop_event = threading.Event()
auto_update_paused = False

def auto_update_scheduler():
    """Background scheduler for auto-update cycles"""
    global auto_update_paused
    logger.info("Auto-update scheduler started")
    
    while not auto_update_stop_event.is_set():
        try:
            # Create database session for this thread
            db = SessionLocal()
            try:
                # Check if auto-update is enabled
                enabled = Setting.get_setting(db, "auto_update_enabled", True)
                interval = Setting.get_setting(db, "auto_update_interval", 3600)  # Default 1 hour
                
                if enabled and not auto_update_paused:
                    logger.info("Running scheduled auto-update cycle")
                    auto_update_service = AutoUpdateService(db)
                    
                    # Run async function in thread context
                    import asyncio
                    try:
                        # Create new event loop for this thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(auto_update_service.run_auto_update_cycle())
                    finally:
                        loop.close()
                else:
                    logger.debug(f"Auto-update skipped - enabled: {enabled}, paused: {auto_update_paused}")
                
            finally:
                db.close()
            
            # Wait for the interval or until stop event
            auto_update_stop_event.wait(interval)
            
        except Exception as e:
            logger.error(f"Auto-update scheduler error: {e}")
            # Wait 60 seconds before retrying on error
            auto_update_stop_event.wait(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting DNSniper application...")
    
    try:
        # Create database tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created/verified")
        
        # Initialize default settings
        from database import SessionLocal
        db = SessionLocal()
        
        try:
            # Set default settings if they don't exist
            default_settings = {
                "auto_update_enabled": True,
                "auto_update_interval": 3600,  # 1 hour in seconds
                "rule_expiration": 86400,  # 24 hours in seconds
                "max_ips_per_domain": 5,
                "dns_resolver_primary": "1.1.1.1",
                "dns_resolver_secondary": "8.8.8.8",
                "manual_domain_resolution": True,
                "rate_limit_delay": 1.0,
                "logging_enabled": False,
                "max_log_entries": 10000,
                "log_retention_days": 7,
                # SSL configuration
                "enable_ssl": False,  # Enable SSL/HTTPS support (master switch)
                "force_https": False,  # Force HTTP to HTTPS redirection (requires SSL configuration)
                "ssl_domain": "",    # Domain name for SSL certificate (required for HTTPS)
                "ssl_certfile": "",  # Path to SSL certificate file (PEM) (required for HTTPS)
                "ssl_keyfile": ""    # Path to SSL private key file (PEM) (required for HTTPS)
            }
            
            # MIGRATION: Remove old dns_resolver_ipv4/ipv6, migrate to new fields
            v4 = db.query(Setting).filter(Setting.key == "dns_resolver_ipv4").first()
            v6 = db.query(Setting).filter(Setting.key == "dns_resolver_ipv6").first()
            if v4:
                Setting.set_setting(db, "dns_resolver_primary", v4.value, "Primary DNS resolver")
                db.delete(v4)
            if v6:
                Setting.set_setting(db, "dns_resolver_secondary", v6.value, "Secondary DNS resolver")
                db.delete(v6)
            db.commit()
            
            for key, value in default_settings.items():
                setting = db.query(Setting).filter(Setting.key == key).first()
                if not setting:
                    setting = Setting(key=key, value=str(value))
                    db.add(setting)
            db.commit()
            logger.info("Default settings initialized and DNS resolver fields migrated/normalized")
            
            # Create default admin user
            User.create_default_admin(db)
            logger.info("Default admin user initialized")
            
        finally:
            db.close()
        
        # Initialize firewall
        try:
            firewall = FirewallService()
            firewall.initialize_firewall()
            logger.info("Firewall initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize firewall: {e}")
        
        # Start auto-update scheduler in background
        global auto_update_thread
        auto_update_thread = threading.Thread(target=auto_update_scheduler, daemon=True)
        auto_update_thread.start()
        logger.info("Auto-update scheduler started in background")
        
        yield
        
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        raise
    
    # Cleanup
    logger.info("Shutting down DNSniper application...")
    auto_update_stop_event.set()
    if auto_update_thread:
        auto_update_thread.join(timeout=10)
    logger.info("Auto-update scheduler stopped")


# Create FastAPI app
app = FastAPI(
    title="DNSniper API",
    description="""
## DNSniper - Firewall Management API

A comprehensive API for managing firewall rules, domain blacklists/whitelists, IP addresses, and automated threat intelligence updates.

### Features

* **Domain Management** - Add/remove domains from blacklists and whitelists
* **IP Address Management** - Manage individual IP addresses and ranges (CIDR blocks)
* **Auto-Update Sources** - Configure external threat feeds for automatic updates
* **Authentication** - Secure API token and session-based authentication
* **Firewall Integration** - Direct integration with iptables/ipset for real-time rule updates
* **Activity Logging** - Comprehensive audit trail of all configuration changes
* **Dashboard Statistics** - Real-time metrics and system status

### Authentication

Most endpoints require authentication using Bearer tokens. Get your API token from the DNSniper web interface:

1. Navigate to **API Tokens** page
2. Click **Create Token**
3. Copy the generated token
4. Include it in the `Authorization` header: `Bearer your_token_here`

### Rate Limiting

The API implements rate limiting to prevent abuse. If you exceed rate limits, you'll receive a `429` status code.

### Support

For additional support, visit the built-in API documentation at `/api-documentation` or contact your system administrator.
    """,
    version="1.0.0",
    contact={
        "name": "DNSniper API Support",
        "url": "/api-documentation",
    },
    license_info={
        "name": "MIT License",
    },
    servers=[
        {
            "url": "http://localhost:8000",
            "description": "Development server"
        }
    ],
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add SSL/HTTPS middleware for redirect and HSTS
@app.middleware("http")
async def ssl_enforcement_middleware(request: Request, call_next):
    # Import settings dynamically to avoid circular import
    from models import Setting
    db = SessionLocal()
    settings = Setting.get_all_settings(db)
    enable_ssl = settings.get('enable_ssl', False)
    force_https = settings.get('force_https', False)
    db.close()

    # Redirect HTTP to HTTPS if force_https is enabled
    if force_https and request.url.scheme == "http":
        url = request.url.replace(scheme="https")
        return RedirectResponse(url)

    response = await call_next(request)
    # Set HSTS header if SSL is enabled and request is HTTPS
    if enable_ssl and request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response

# Authentication middleware to protect API routes
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Skip auth for certain routes
    excluded_paths = [
        "/api/auth/login",
        "/api/health",
        "/docs",
        "/openapi.json",
        "/redoc"
    ]
    
    # Skip auth for static files and frontend routes
    if (request.url.path.startswith("/static/") or 
        not request.url.path.startswith("/api/") or
        request.url.path in excluded_paths):
        return await call_next(request)
    
    # Check for valid token (session or API token)
    from models.users import UserSession, APIToken
    authorization = request.headers.get("Authorization")
    
    if not authorization or not authorization.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"}
        )
    
    token = authorization.split(" ")[1]
    
    db = SessionLocal()
    try:
        user = None
        
        # First, try to validate as session token
        session = UserSession.get_valid_session(db, token)
        if session:
            user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
        
        # If no session found, try API token
        if not user and token.startswith("dnsniper_"):
            api_token = APIToken.get_valid_token(db, token)
            if api_token:
                user = db.query(User).filter(User.id == api_token.user_id, User.is_active == True).first()
                if user:
                    # Update last used timestamp for API tokens
                    api_token.update_last_used(db)
        
        if not user:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"}
            )
        
        # Add user info to request state for use in endpoints
        request.state.user = user
        
    finally:
        db.close()
    
    return await call_next(request)

# Health check endpoint - placed BEFORE API routers (no auth required)
@app.get("/api/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint"""
    try:
        # Test database connection
        db.execute(text("SELECT 1"))
        
        # Get basic stats
        domain_count = db.query(Domain).count()
        ip_count = db.query(IP).count()
        ip_range_count = db.query(IPRange).count()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "stats": {
                "domains": domain_count,
                "ips": ip_count,
                "ip_ranges": ip_range_count
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")


# Dashboard API endpoint
@app.get("/api/dashboard")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    try:
        # Basic counts
        total_domains = db.query(Domain).count()
        total_ips = db.query(IP).count()
        total_ip_ranges = db.query(IPRange).count()
        
        # Blacklist vs whitelist counts
        blacklist_domains = db.query(Domain).filter(Domain.list_type == "blacklist").count()
        whitelist_domains = db.query(Domain).filter(Domain.list_type == "whitelist").count()
        blacklist_ips = db.query(IP).filter(IP.list_type == "blacklist").count()
        whitelist_ips = db.query(IP).filter(IP.list_type == "whitelist").count()
        blacklist_ranges = db.query(IPRange).filter(IPRange.list_type == "blacklist").count()
        whitelist_ranges = db.query(IPRange).filter(IPRange.list_type == "whitelist").count()
        
        # Manual vs auto-update counts
        manual_domains = db.query(Domain).filter(Domain.source_type == "manual").count()
        auto_domains = db.query(Domain).filter(Domain.source_type == "auto_update").count()
        manual_ips = db.query(IP).filter(IP.source_type == "manual").count()
        auto_ips = db.query(IP).filter(IP.source_type == "auto_update").count()
        manual_ranges = db.query(IPRange).filter(IPRange.source_type == "manual").count()
        auto_ranges = db.query(IPRange).filter(IPRange.source_type == "auto_update").count()
        
        # Auto-update sources
        total_sources = db.query(AutoUpdateSource).count()
        active_sources = db.query(AutoUpdateSource).filter(AutoUpdateSource.is_active == True).count()
        
        # Get firewall status
        firewall = FirewallService()
        firewall_status = firewall.get_status()
        
        # Recent activity (last 24 hours)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        recent_logs = db.query(Log).filter(Log.created_at >= yesterday).count()
        
        return {
            "totals": {
                "domains": total_domains,
                "ips": total_ips,
                "ip_ranges": total_ip_ranges,
                "auto_update_sources": total_sources
            },
            "lists": {
                "blacklist": {
                    "domains": blacklist_domains,
                    "ips": blacklist_ips,
                    "ip_ranges": blacklist_ranges
                },
                "whitelist": {
                    "domains": whitelist_domains,
                    "ips": whitelist_ips,
                    "ip_ranges": whitelist_ranges
                }
            },
            "sources": {
                "manual": {
                    "domains": manual_domains,
                    "ips": manual_ips,
                    "ip_ranges": manual_ranges
                },
                "auto_update": {
                    "domains": auto_domains,
                    "ips": auto_ips,
                    "ip_ranges": auto_ranges
                }
            },
            "auto_update": {
                "total_sources": total_sources,
                "active_sources": active_sources,
                "is_running": auto_update_thread.is_alive(),
                "enabled": Setting.get_setting(db, "auto_update_enabled", True)
            },
            "firewall": firewall_status,
            "activity": {
                "recent_logs_24h": recent_logs
            }
        }
    except Exception as e:
        logger.error(f"Dashboard stats failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard stats")


# Include API routers
app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(domains.router, prefix="/api/domains", tags=["domains"])
app.include_router(ips.router, prefix="/api/ips", tags=["ips"])
app.include_router(ip_ranges.router, prefix="/api/ip-ranges", tags=["ip-ranges"])
app.include_router(auto_update_sources.router, prefix="/api/auto-update-sources", tags=["auto-update-sources"])
app.include_router(settings.router, prefix="/api/settings", tags=["settings"])
app.include_router(logs.router, prefix="/api/logs", tags=["logs"])

# Serve React frontend static files
frontend_build_path = Path(__file__).parent.parent / "frontend" / "build"

if frontend_build_path.exists():
    # Mount static files
    app.mount("/static", StaticFiles(directory=frontend_build_path / "static"), name="static")
    
    # Serve React app for all non-API routes (moved AFTER all API routes)
    @app.get("/{full_path:path}")
    async def serve_react_app(request: Request, full_path: str):
        """Serve React app for all non-API routes"""
        # Don't serve React for API routes or docs
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            raise HTTPException(status_code=404, detail="Not found")
        
        # Handle root path and empty paths
        if not full_path or full_path == "":
            index_path = frontend_build_path / "index.html"
            if index_path.exists():
                return FileResponse(index_path)
            else:
                raise HTTPException(status_code=404, detail="Frontend not built")
        
        # Serve specific files if they exist
        file_path = frontend_build_path / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        
        # Default to index.html for React routing
        index_path = frontend_build_path / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        
        raise HTTPException(status_code=404, detail="Frontend not built")
else:
    logger.warning("Frontend build directory not found. Make sure to build the React app.")
    
    @app.get("/")
    async def frontend_not_built():
        return {
            "message": "DNSniper API is running",
            "docs": "/docs", 
            "health": "/api/health",
            "note": "Frontend not built. Run 'npm run build' in the frontend directory."
        }

# Add security schemes to OpenAPI spec
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    from fastapi.openapi.utils import get_openapi
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        servers=app.servers
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "Token",
            "description": "DNSniper API Token or Session Token. Get your API token from the DNSniper web interface."
        }
    }
    
    # Add example schemas
    openapi_schema["components"]["examples"] = {
        "DomainCreateExample": {
            "summary": "Create a malware domain",
            "value": {
                "domain_name": "malware.example.com",
                "list_type": "blacklist",
                "notes": "Known malware domain from threat intelligence"
            }
        },
        "IPCreateExample": {
            "summary": "Add malicious IP",
            "value": {
                "ip_address": "192.0.2.100",
                "list_type": "blacklist",
                "notes": "Known command and control server"
            }
        },
        "IPRangeCreateExample": {
            "summary": "Block IP range",
            "value": {
                "ip_range": "198.51.100.0/24",
                "list_type": "blacklist",
                "notes": "Malicious IP range"
            }
        },
        "AutoUpdateSourceExample": {
            "summary": "Configure threat feed",
            "value": {
                "name": "Malware Domain List",
                "url": "https://example.com/threat-feed.txt",
                "is_active": True,
                "list_type": "blacklist"
            }
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port) 