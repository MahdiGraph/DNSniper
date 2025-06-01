import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
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
from services.firewall_log_monitor import firewall_log_monitor
from services.live_events import live_events
import asyncio
import schedule
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json
from models.logs import ActionType
from typing import Set
from fastapi.concurrency import run_in_threadpool

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

# Global set of connected WebSocket clients - DEPRECATED (replaced by live_events)
# agent_ws_clients: Set[WebSocket] = set()

def auto_update_scheduler():
    """Background scheduler for auto-update cycles"""
    global auto_update_paused
    
    # Create database session for startup logging
    db = SessionLocal()
    try:
        Log.create_rule_log(db, ActionType.update, None, "Auto-update scheduler started", mode="auto_update")
        Log.cleanup_old_logs(db)
        db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()
    
    while not auto_update_stop_event.is_set():
        db = None
        try:
            # Create database session for this thread
            db = SessionLocal()
            
            # Check if auto-update is enabled
            enabled = Setting.get_setting(db, "auto_update_enabled", True)
            interval = Setting.get_setting(db, "auto_update_interval", 3600)  # Default 1 hour
            
            if enabled and not auto_update_paused:
                # Log the start of auto-update cycle
                Log.create_rule_log(db, ActionType.update, None, "Running scheduled auto-update cycle", mode="auto_update")
                Log.cleanup_old_logs(db)
                db.commit()
                
                # Close the session before starting auto-update service to avoid conflicts
                db.close()
                db = None
                
                # Don't pass the existing db session to AutoUpdateService, it will create its own
                auto_update_service = AutoUpdateService(None)  # Will create its own sessions
                
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
                # Log that auto-update was skipped
                Log.create_rule_log(db, ActionType.update, None, f"Auto-update skipped - enabled: {enabled}, paused: {auto_update_paused}", mode="auto_update")
                Log.cleanup_old_logs(db)
                db.commit()
            
            # Wait for the interval or until stop event
            auto_update_stop_event.wait(interval)
            
        except Exception as e:
            # Handle session rollback if needed
            if db:
                try:
                    db.rollback()
                except:
                    pass
                finally:
                    db.close()
                    db = None
            
            # Use new database session for error logging
            error_db = SessionLocal()
            try:
                Log.create_error_log(error_db, f"Auto-update scheduler error: {e}", context="auto_update_scheduler", mode="auto_update")
                Log.cleanup_old_logs(error_db)
                error_db.commit()
            except Exception:
                error_db.rollback()
            finally:
                error_db.close()
            
            # Wait 60 seconds before retrying on error
            auto_update_stop_event.wait(60)
        finally:
            # Ensure session is closed
            if db:
                try:
                    db.close()
                except:
                    pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    try:
        # Create database tables
        Base.metadata.create_all(bind=engine)
        # Initialize default settings
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
                "automatic_domain_resolution": True,
                "rate_limit_delay": 1.0,
                "logging_enabled": False,
                "max_log_entries": 10000,
                "log_retention_days": 7,
                # Critical IPs configuration for auto-update protection (IPv4 and IPv6 separated)
                # NOTE: Dynamic detection (local network, DNS resolvers, public IP) happens automatically at runtime
                "critical_ipv4_ips_ranges": [
                    # Loopback and null addresses
                    "0.0.0.0",
                    "127.0.0.1",
                    "127.0.0.0/8",          # Entire loopback range
                    
                    # RFC 1918 Private Networks (ALL private ranges)
                    "10.0.0.0/8",           # Class A private (10.0.0.0 - 10.255.255.255)
                    "172.16.0.0/12",        # Class B private (172.16.0.0 - 172.31.255.255)
                    "192.168.0.0/16",       # Class C private (192.168.0.0 - 192.168.255.255)
                    
                    # Special Use Networks (RFC 3927, RFC 5735, RFC 6598)
                    "169.254.0.0/16",       # Link-Local (APIPA)
                    "100.64.0.0/10",        # Carrier Grade NAT (RFC 6598)
                    
                    # Multicast and Reserved
                    "224.0.0.0/4",          # Multicast (224.0.0.0 - 239.255.255.255)
                    "240.0.0.0/4",          # Reserved (240.0.0.0 - 255.255.255.255)
                    
                    # Special Documentation/Testing (RFC 5737)
                    "192.0.2.0/24",         # TEST-NET-1 (documentation)
                    "198.51.100.0/24",      # TEST-NET-2 (documentation)
                    "203.0.113.0/24",       # TEST-NET-3 (documentation)
                    
                    # Benchmarking (RFC 2544)
                    "198.18.0.0/15",        # Network benchmark tests
                    
                    # Common DNS servers (to prevent accidental blocking)
                    "1.1.1.1",              # Cloudflare
                    "1.0.0.1",              # Cloudflare
                    "8.8.8.8",              # Google
                    "8.8.4.4",              # Google
                    "9.9.9.9",              # Quad9
                    "208.67.222.222",       # OpenDNS
                    "208.67.220.220",       # OpenDNS
                ],  # List of static critical IPv4 addresses and ranges that should never be auto-blocked
                "critical_ipv6_ips_ranges": [
                    # Loopback and null addresses
                    "::",                   # Unspecified address
                    "::1",                  # Loopback
                    
                    # Private/Local Networks (RFC 4193)
                    "fc00::/7",             # Unique Local Addresses (fc00:: - fdff::)
                    "fe80::/10",            # Link-Local Addresses
                    
                    # Special Networks
                    "ff00::/8",             # Multicast
                    "::/128",               # Unspecified
                    "::1/128",              # Loopback
                    
                    # Documentation/Testing (RFC 3849)
                    "2001:db8::/32",        # Documentation prefix
                    
                    # 6to4 and Teredo
                    "2002::/16",            # 6to4 addressing
                    "2001::/32",            # Teredo tunneling
                    
                    # Common IPv6 DNS servers
                    "2606:4700:4700::1111", # Cloudflare
                    "2606:4700:4700::1001", # Cloudflare
                    "2001:4860:4860::8888", # Google
                    "2001:4860:4860::8844", # Google
                    "2620:fe::fe",          # Quad9
                    "2620:0:ccc::2",        # OpenDNS
                    "2620:0:ccd::2",        # OpenDNS
                ],  # List of static critical IPv6 addresses and ranges that should never be auto-blocked
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
            
            # MIGRATION: Rename confusing "manual_domain_resolution" to "automatic_domain_resolution"
            old_setting = db.query(Setting).filter(Setting.key == "manual_domain_resolution").first()
            if old_setting:
                Setting.set_setting(db, "automatic_domain_resolution", old_setting.get_value(), 
                                  "Automatically resolve manually-added domains to IPs during auto-update cycles")
                db.delete(old_setting)
                logger.info("Migrated manual_domain_resolution to automatic_domain_resolution")
            
            db.commit()
            
            for key, value in default_settings.items():
                setting = db.query(Setting).filter(Setting.key == key).first()
                if not setting:
                    Setting.set_setting(db, key, value)
            db.commit()
            # Create default admin user
            User.create_default_admin(db)
        except Exception as e:
            logger.error(f"Application startup failed: {e}")
            db = SessionLocal()
            Log.create_error_log(db, f"Application startup failed: {e}", context="lifespan", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
            raise
        db.close()
        # Now log that the app is starting, after tables and settings are ready
        db = SessionLocal()
        Log.create_rule_log(db, ActionType.update, None, "Starting DNSniper application...", mode="manual")
        Log.create_rule_log(db, ActionType.update, None, "Database tables created/verified", mode="manual")
        Log.cleanup_old_logs(db)
        db.close()
        # Initialize firewall
        try:
            firewall = FirewallService()
            firewall.initialize_firewall()
            db = SessionLocal()
            Log.create_rule_log(db, ActionType.update, None, "Firewall initialized successfully", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
        except Exception as e:
            logger.error(f"Failed to initialize firewall: {e}")
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to initialize firewall: {e}", context="lifespan", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
        # Start auto-update scheduler in background
        global auto_update_thread
        auto_update_thread = threading.Thread(target=auto_update_scheduler, daemon=True)
        auto_update_thread.start()
        db = SessionLocal()
        Log.create_rule_log(db, ActionType.update, None, "Auto-update scheduler started in background", mode="manual")
        Log.cleanup_old_logs(db)
        db.close()
        
        # Start firewall log monitoring if logging is enabled
        db = SessionLocal()
        logging_enabled = Setting.get_setting(db, "logging_enabled", False)
        if logging_enabled:
            firewall_log_monitor.start_monitoring()
            Log.create_rule_log(db, ActionType.update, None, "Firewall log monitoring enabled and started", mode="manual")
        else:
            Log.create_rule_log(db, ActionType.update, None, "Firewall log monitoring disabled (logging_enabled=False)", mode="manual")
        Log.cleanup_old_logs(db)
        db.close()
        
        yield
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        db = SessionLocal()
        Log.create_error_log(db, f"Application startup failed: {e}", context="lifespan", mode="manual")
        Log.cleanup_old_logs(db)
        db.close()
        raise
    # Cleanup
    db = SessionLocal()
    Log.create_rule_log(db, ActionType.update, None, "Shutting down DNSniper application...", mode="manual")
    Log.cleanup_old_logs(db)
    db.close()
    
    # Stop firewall log monitoring
    firewall_log_monitor.stop_monitoring()
    
    auto_update_stop_event.set()
    if auto_update_thread:
        auto_update_thread.join(timeout=10)
    db = SessionLocal()
    Log.create_rule_log(db, ActionType.update, None, "Auto-update scheduler stopped", mode="manual")
    Log.cleanup_old_logs(db)
    db.close()


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

# Helper: Authenticate WebSocket connection via query parameters
async def authenticate_websocket_query(token: str) -> bool:
    """Authenticate WebSocket connection using token from query parameters"""
    if not token:
        return False
    
    db = SessionLocal()
    try:
        from models.users import UserSession, APIToken, User
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
        
        return user is not None
    finally:
        db.close()

# WebSocket endpoint for live events (replaces agent-logs)
@app.websocket("/ws/live-events")
async def live_events_ws(websocket: WebSocket, token: str = None):
    """WebSocket endpoint for live system events"""
    await websocket.accept()
    
    # Authenticate via query parameter
    if not token or not await authenticate_websocket_query(token):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    
    # Add client to live events broadcaster
    await live_events.add_client(websocket)
    
    try:
        # Send initial status
        await live_events.broadcast_system_event("client_connected", {
            "message": "Live events connection established",
            "client_count": live_events.get_client_count()
        })
        
        # Keep connection alive and listen for client messages
        while True:
            try:
                # Wait for client ping or close
                data = await websocket.receive_text()
                # Handle any client messages if needed (e.g., ping/pong)
                if data == "ping":
                    await websocket.send_text("pong")
            except Exception:
                break
    except Exception:
        pass
    finally:
        live_events.remove_client(websocket)
        await live_events.broadcast_system_event("client_disconnected", {
            "message": "Live events client disconnected",
            "client_count": live_events.get_client_count()
        })

# DEPRECATED: Old WebSocket endpoint (kept for backward compatibility)
@app.websocket("/ws/agent-logs")
async def agent_logs_ws_deprecated(websocket: WebSocket, token: str = None):
    """DEPRECATED: Use /ws/live-events instead"""
    await websocket.accept()
    await websocket.close(code=4004, reason="Endpoint deprecated. Use /ws/live-events with ?token=your_token")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port) 