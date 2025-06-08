import os
import logging
import json
import time
import argparse
from pathlib import Path
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
from services.scheduler_manager import scheduler_manager
from version import VERSION, APP_NAME
import asyncio
import threading
from datetime import datetime, timezone, timedelta
from models.logs import ActionType
from fastapi.concurrency import run_in_threadpool

# Parse command line arguments only when run directly
def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description=f'{APP_NAME} - Advanced Firewall Management Application')
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Run in quiet mode (suppress console logs)'
    )
    return parser.parse_args()

# Only parse arguments if running directly (not when imported by uvicorn)
args = None
if __name__ == "__main__":
    args = parse_arguments()
else:
    # Default args when imported by uvicorn
    class DefaultArgs:
        def __init__(self):
            self.quiet = False
    args = DefaultArgs()

# Load configuration from JSON file
def load_config():
    """Load configuration from config.json with defaults"""
    
    def get_base_directory():
        """Get the correct base directory for both development and packaged environments"""
        import sys
        import os
        
        # Check if we're running from a PyInstaller bundle
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # We're running from a PyInstaller bundle - use the actual binary's directory
            return Path(os.path.dirname(os.path.abspath(sys.argv[0])))
        else:
            # We're running from source - use the current file's directory
            return Path(__file__).parent
    
    def get_smart_static_path():
        """Intelligently determine the correct static path default"""
        base_dir = get_base_directory()
        
        # Look for packaged structure (static/ directory next to binary/script)
        if (base_dir / "static").exists():
            return "static/"
        
        # Look for development structure (frontend/build relative to backend)
        elif (base_dir / "../frontend/build").exists():
            return "../frontend/build"
        
        # Default to development path as fallback
        else:
            return "../frontend/build"
    
    config_path = get_base_directory() / "config.json"
    
    # Default configuration with smart static path detection
    default_config = {
        "web_server": {
            "host": "0.0.0.0",
            "port": 8000
        },
        "frontend": {
            "static_path": get_smart_static_path()
        }
    }
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                
                # Deep merge with defaults to ensure all required keys exist
                config = default_config.copy()
                if "web_server" in user_config:
                    config["web_server"].update(user_config["web_server"])
                if "frontend" in user_config:
                    config["frontend"].update(user_config["frontend"])
                
                return config
        except (json.JSONDecodeError, Exception) as e:
            print(f"⚠️  Error reading config.json: {e}")
            print("🔧 Using default configuration")
            return default_config
    else:
        print("📝 No config.json found, using defaults (host: 0.0.0.0, port: 8000)")
        return default_config

config = load_config()

# Configure logging
if args.quiet:
    # In quiet mode, only log ERROR and CRITICAL messages to console
    logging.basicConfig(
        level=logging.ERROR,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    # Suppress uvicorn access logs completely in quiet mode
    logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)
    logging.getLogger("uvicorn").setLevel(logging.ERROR)
else:
    # Normal logging configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
logger = logging.getLogger(__name__)

# Initialize SchedulerManager 
from services.scheduler_manager import scheduler_manager

def get_scheduler_status():
    """Get the current scheduler status."""
    return scheduler_manager.get_status()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager"""
    # Startup
    logger.info("🚀 Starting DNSniper application...")
    
    # Create database tables
    Base.metadata.create_all(bind=engine)
    
    # Apply security migrations for enhanced login tracking
    try:
        from routers.auth import migrate_login_attempts_table
        db = SessionLocal()
        migrate_login_attempts_table(db)
        db.close()
    except Exception as e:
        logger.warning(f"Security migration warning: {e}")
    
    # Initialize database with default admin user
    db = SessionLocal()
    try:
        User.create_default_admin(db)
        logger.info("✅ Default admin user initialized")
        
        # Initialize default settings with comprehensive configuration
        default_settings = {
            "auto_update_enabled": True,
            "auto_update_interval": 21600,  # 6 hours in seconds
            "rule_expiration": 86400,  # 24 hours in seconds
            "max_ips_per_domain": 10,
            "dns_resolver_primary": "1.1.1.1",
            "dns_resolver_secondary": "8.8.8.8",
            "automatic_domain_resolution": True,
            "rate_limit_delay": 1.0,
            "logging_enabled": True,
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
            "ssl_keyfile": "",    # Path to SSL private key file (PEM) (required for HTTPS)
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
        
        # Set default settings if they don't exist
        for key, value in default_settings.items():
            setting = db.query(Setting).filter(Setting.key == key).first()
            if not setting:
                Setting.set_setting(db, key, value)
        db.commit()
        
        # Initialize default auto-update sources if they don't exist
        default_sources = [
            {
                "url": "https://raw.githubusercontent.com/MahdiGraph/DNSniper/refs/heads/main/blacklist-default.txt",
                "name": "DNSniper Default Blacklist",
                "list_type": "blacklist"
            }
        ]
        
        for source_config in default_sources:
            existing_source = db.query(AutoUpdateSource).filter(AutoUpdateSource.url == source_config["url"]).first()
            if not existing_source:
                default_source = AutoUpdateSource(
                    url=source_config["url"],
                    name=source_config["name"],
                    is_active=True,
                    list_type=source_config["list_type"]
                )
                db.add(default_source)
                logger.info(f"✅ Default auto-update source initialized: {source_config['name']}")
        db.commit()
        
        logger.info("✅ Default settings initialized")
    except Exception as e:
        logger.error(f"Failed to create default admin and settings: {e}")
    finally:
        db.close()
    
    # Clean up old temporary SQLite files
    temp_files = ["dnsniper.db-wal", "dnsniper.db-shm"]
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
                logger.info(f"🧹 Removed SQLite temporary file: {temp_file}")
            except Exception as e:
                logger.warning(f"Could not remove temporary file {temp_file}: {e}")
    
    # Start the auto-update scheduler
    try:
        if scheduler_manager.start_scheduler():
            logger.info("🔄 Auto-update scheduler started successfully")
        else:
            logger.warning("⚠️ Auto-update scheduler was already running")
    except Exception as e:
        logger.error(f"❌ Failed to start auto-update scheduler: {e}")
    
    # Initialize firewall system
    try:
        from services.firewall_service import FirewallService
        firewall = FirewallService()
        firewall.initialize_firewall()
        logger.info("🔥 Firewall system initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize firewall system: {e}")
    
    # Application is ready
    logger.info("✅ DNSniper application startup completed")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down DNSniper application...")
    
    # Stop the auto-update scheduler
    try:
        if scheduler_manager.stop_scheduler(timeout=10):
            logger.info("🔄 Auto-update scheduler stopped successfully")
        else:
            logger.warning("⚠️ Auto-update scheduler was not running or failed to stop")
    except Exception as e:
        logger.error(f"❌ Failed to stop auto-update scheduler: {e}")
    
    logger.info("✅ DNSniper application shutdown completed")


# Create FastAPI app
app = FastAPI(
    title=f"{APP_NAME} API",
    description=f"""
## {APP_NAME} - Firewall Management API

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

Most endpoints require authentication using Bearer tokens. Get your API token from the {APP_NAME} web interface:

1. Navigate to **API Tokens** page
2. Click **Create Token**
3. Copy the generated token
4. Include it in the `Authorization` header: `Bearer your_token_here`

### Rate Limiting

The API implements rate limiting to prevent abuse. If you exceed rate limits, you'll receive a `429` status code.

### Support

For additional support, visit the built-in API documentation at `/api-documentation` or contact your system administrator.
    """,
    version=VERSION,
    contact={
        "name": f"{APP_NAME} API Support",
        "url": "/api-documentation",
    },
    license_info={
        "name": "MIT License",
    },
    servers=[
        {
            "url": f"http://{config['web_server']['host']}:{config['web_server']['port']}",
            "description": "Development server"
        },
        {
            "url": "http://localhost:8000",
            "description": "Local server (default)"
        }
    ],
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS configuration - Allow all origins for open source project
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Open source project - allow access from anywhere
    allow_credentials=False,  # Must be False when allow_origins=["*"]
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Requested-With",
        "Accept",
        "Origin",
        "User-Agent",
        "DNT",
        "Cache-Control",
        "X-Forwarded-For",
        "X-Real-IP"
    ],
    expose_headers=["X-Total-Count", "X-Content-Range"],
    max_age=86400,  # 24 hours
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
@app.get("/api/health",
    summary="Health Check",
    description="Check basic service availability. This endpoint does not require authentication and provides minimal status information.",
    tags=["System Health"],
    responses={
        200: {
            "description": "Service is available and operational",
            "content": {
                "application/json": {
                    "example": {
                        "status": "healthy",
                        "timestamp": "2024-01-01T12:00:00Z",
                        "service": "DNSniper API"
                    }
                }
            }
        },
        503: {
            "description": "Service unavailable",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Service unavailable"
                    }
                }
            }
        }
    }
)
async def health_check():
    """Minimal health check endpoint - no sensitive information exposed"""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "DNSniper API"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

# Dashboard API endpoint
@app.get("/api/dashboard",
    summary="Dashboard Statistics",
    description="Get comprehensive system statistics including counts of domains, IPs, IP ranges, and system status. Requires authentication.",
    tags=["Dashboard"],
    responses={
        200: {
            "description": "Dashboard statistics retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "totals": {
                            "domains": 1250,
                            "ips": 2340,
                            "ip_ranges": 45,
                            "auto_update_sources": 3
                        },
                        "lists": {
                            "blacklist": {
                                "domains": 1200,
                                "ips": 2200,
                                "ip_ranges": 40
                            },
                            "whitelist": {
                                "domains": 50,
                                "ips": 140,
                                "ip_ranges": 5
                            }
                        },
                        "sources": {
                            "manual": {
                                "domains": 250,
                                "ips": 340,
                                "ip_ranges": 15
                            },
                            "auto_update": {
                                "domains": 1000,
                                "ips": 2000,
                                "ip_ranges": 30
                            }
                        },
                        "auto_update": {
                            "total_sources": 3,
                            "active_sources": 2,
                            "is_running": True,
                            "enabled": True
                        },
                        "firewall": {
                            "chains_exist": {
                                "ipv4": True,
                                "ipv6": True
                            }
                        },
                        "activity": {
                            "recent_logs_24h": 156
                        }
                    }
                }
            }
        },
        401: {
            "description": "Authentication required",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Authentication required"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to get dashboard stats"
                    }
                }
            }
        }
    }
)
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
                "is_running": AutoUpdateService.is_auto_update_running(),
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


# Clear all database data endpoint
@app.delete("/api/clear-all-data")
async def clear_all_database_data(db: Session = Depends(get_db)):
    """Clear all domains, IPs, and IP ranges from the database"""
    try:
        # Get counts before deletion for logging
        domain_count = db.query(Domain).count()
        ip_count = db.query(IP).count()
        ip_range_count = db.query(IPRange).count()
        
        # Delete all records
        db.query(Domain).delete()
        db.query(IP).delete()
        db.query(IPRange).delete()
        
        # Commit the transaction
        db.commit()
        
        # Log the action
        Log.create_rule_log(
            db, 
            ActionType.remove_rule, 
            None, 
            f"Cleared all database data: {domain_count} domains, {ip_count} IPs, {ip_range_count} IP ranges", 
            mode="manual"
        )
        Log.cleanup_old_logs(db)
        db.commit()
        
        # Clear firewall rules after database cleanup
        try:
            firewall = FirewallService()
            firewall.clear_all_rules()
            Log.create_rule_log(db, ActionType.remove_rule, None, "Firewall rules cleared after database cleanup", mode="manual")
            Log.cleanup_old_logs(db)
            db.commit()
        except Exception as fw_error:
            logger.error(f"Failed to clear firewall rules after database cleanup: {fw_error}")
            Log.create_error_log(db, f"Failed to clear firewall rules after database cleanup: {fw_error}", context="clear_all_data", mode="manual")
            Log.cleanup_old_logs(db)
            db.commit()
        
        return {
            "message": "All database data cleared successfully",
            "cleared": {
                "domains": domain_count,
                "ips": ip_count,
                "ip_ranges": ip_range_count,
                "total": domain_count + ip_count + ip_range_count
            },
            "firewall_cleared": True
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to clear database data: {e}")
        
        # Log the error
        try:
            Log.create_error_log(db, f"Failed to clear all database data: {e}", context="clear_all_data", mode="manual")
            Log.cleanup_old_logs(db)
            db.commit()
        except:
            pass
        
        raise HTTPException(status_code=500, detail=f"Failed to clear database data: {str(e)}")


# Include API routers
app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(domains.router, prefix="/api/domains", tags=["domains"])
app.include_router(ips.router, prefix="/api/ips", tags=["ips"])
app.include_router(ip_ranges.router, prefix="/api/ip-ranges", tags=["ip-ranges"])
app.include_router(auto_update_sources.router, prefix="/api/auto-update-sources", tags=["auto-update-sources"])
app.include_router(settings.router, prefix="/api/settings", tags=["settings"])
app.include_router(logs.router, prefix="/api/logs", tags=["logs"])

# Serve React frontend static files
def get_app_base_directory():
    """Get the correct base directory for both development and packaged environments"""
    import sys
    import os
    
    # Check if we're running from a PyInstaller bundle
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # We're running from a PyInstaller bundle - use the actual binary's directory
        return Path(os.path.dirname(os.path.abspath(sys.argv[0])))
    else:
        # We're running from source - use the current file's directory
        return Path(__file__).parent

frontend_build_path = get_app_base_directory() / config['frontend']['static_path']

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
    logger.warning(f"Frontend build directory not found at: {frontend_build_path}")
    
    @app.get("/")
    async def frontend_not_built():
        return {
            "message": "DNSniper API is running",
            "docs": "/docs", 
            "health": "/api/health",
            "note": f"Frontend not built. Expected at: {frontend_build_path}"
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
            "description": "DNSniper API Token or Session Token. Get your API token from the DNSniper web interface at /api-tokens."
        }
    }
    
    # Add comprehensive example schemas
    openapi_schema["components"]["examples"] = {
        "DomainCreateExample": {
            "summary": "Create a malware domain",
            "description": "Example of adding a known malware domain to the blacklist",
            "value": {
                "domain_name": "malware.example.com",
                "list_type": "blacklist",
                "notes": "Known malware domain from threat intelligence feed"
            }
        },
        "DomainWhitelistExample": {
            "summary": "Whitelist a trusted domain",
            "description": "Example of adding a trusted domain to the whitelist",
            "value": {
                "domain_name": "cdn.trusted-site.com",
                "list_type": "whitelist",
                "notes": "Trusted CDN domain - never block"
            }
        },
        "IPCreateExample": {
            "summary": "Block malicious IP",
            "description": "Example of adding a malicious IP address to the blacklist",
            "value": {
                "ip_address": "203.0.113.100",
                "list_type": "blacklist",
                "notes": "Known command and control server"
            }
        },
        "IPWhitelistExample": {
            "summary": "Whitelist trusted IP",
            "description": "Example of adding a trusted IP to the whitelist",
            "value": {
                "ip_address": "8.8.8.8",
                "list_type": "whitelist",
                "notes": "Google DNS server - always allow"
            }
        },
        "IPRangeCreateExample": {
            "summary": "Block IP range",
            "description": "Example of blocking an entire IP range (CIDR block)",
            "value": {
                "ip_range": "1.2.3.0/24",
                "list_type": "blacklist",
                "notes": "Malicious IP range from threat intelligence"
            }
        },
        "IPRangeIPv6Example": {
            "summary": "Block IPv6 range",
            "description": "Example of blocking an IPv6 range",
            "value": {
                "ip_range": "2600:1900::/32",
                "list_type": "blacklist",
                "notes": "Suspicious IPv6 range"
            }
        },
        "AutoUpdateSourceExample": {
            "summary": "Configure threat feed",
            "description": "Example of setting up an external threat intelligence feed",
            "value": {
                "name": "Malware Domain List",
                "url": "https://example.com/threat-feed.txt",
                "is_active": True,
                "list_type": "blacklist",
                "notes": "Daily updated malware domain feed"
            }
        },
        "SettingsUpdateExample": {
            "summary": "Update rule expiration",
            "description": "Example of updating the rule expiration setting",
            "value": {
                "value": 86400
            }
        }
    }
    
    # Add common response schemas
    openapi_schema["components"]["schemas"].update({
        "ErrorResponse": {
            "type": "object",
            "properties": {
                "detail": {
                    "type": "string",
                    "description": "Error message describing what went wrong"
                }
            },
            "example": {
                "detail": "Domain already exists"
            }
        },
        "SuccessMessage": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Success message"
                }
            },
            "example": {
                "message": "Operation completed successfully"
            }
        },
        "HealthCheck": {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "timestamp": {"type": "string", "format": "date-time"},
                "service": {"type": "string"}
            },
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-01T12:00:00Z",
                "service": "DNSniper API"
            }
        }
    })
    
    # Add security requirement to all endpoints except excluded ones
    excluded_paths = ["/api/auth/login", "/api/health", "/docs", "/openapi.json", "/redoc"]
    
    for path, path_item in openapi_schema["paths"].items():
        if not any(path.startswith(excluded) for excluded in excluded_paths):
            for method in path_item:
                if method in ["get", "post", "put", "delete", "patch"]:
                    path_item[method]["security"] = [{"BearerAuth": []}]
    
    # Add tags with descriptions
    openapi_schema["tags"] = [
        {
            "name": "authentication",
            "description": "Authentication and API token management endpoints"
        },
        {
            "name": "domains",
            "description": "Domain blacklist/whitelist management"
        },
        {
            "name": "ips",
            "description": "IP address blacklist/whitelist management"
        },
        {
            "name": "ip-ranges",
            "description": "IP range (CIDR block) blacklist/whitelist management"
        },
        {
            "name": "auto-update-sources",
            "description": "External threat intelligence feed configuration"
        },
        {
            "name": "settings",
            "description": "System configuration and settings management"
        },
        {
            "name": "logs",
            "description": "Activity logs and audit trail"
        }
    ]
    
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

if __name__ == "__main__":
    import uvicorn
    
    # Get host and port from config
    host = config['web_server']['host']
    port = config['web_server']['port']
    
    # Check for SSL configuration in database
    ssl_config = None
    db_path = get_app_base_directory() / "dnsniper.db"
    
    if db_path.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Get SSL settings from database
            ssl_settings = {}
            cursor.execute('SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?, ?)', 
                          ('enable_ssl', 'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'))
            
            for row in cursor.fetchall():
                key, value = row
                # Parse boolean values
                if value.lower() == 'true':
                    ssl_settings[key] = True
                elif value.lower() == 'false':
                    ssl_settings[key] = False
                else:
                    ssl_settings[key] = value.strip()
            
            conn.close()
            
            # Check if SSL is properly configured
            enable_ssl = ssl_settings.get('enable_ssl', False)
            force_https = ssl_settings.get('force_https', False)
            ssl_domain = ssl_settings.get('ssl_domain', '')
            ssl_certfile = ssl_settings.get('ssl_certfile', '')
            ssl_keyfile = ssl_settings.get('ssl_keyfile', '')
            
            # SSL is enabled if either enable_ssl or force_https is true AND all files exist
            if (enable_ssl or force_https) and ssl_domain and ssl_certfile and ssl_keyfile:
                if os.path.isfile(ssl_certfile) and os.path.isfile(ssl_keyfile):
                    ssl_config = {
                        'ssl_certfile': ssl_certfile,
                        'ssl_keyfile': ssl_keyfile,
                        'ssl_domain': ssl_domain
                    }
                    print(f"🔒 SSL/HTTPS enabled for domain: {ssl_domain}")
                else:
                    print(f"⚠️  SSL configured but certificate files not found")
            
        except Exception as e:
            print(f"⚠️  Could not read SSL settings from database: {e}")
    
    # Determine log level for uvicorn based on quiet flag
    uvicorn_log_level = "error" if args.quiet else "info"
    
    # Start server
    if not args.quiet:
        print(f"🚀 Starting DNSniper on {host}:{port}")
    
    if ssl_config:
        if not args.quiet:
            print(f"🔒 Starting with SSL/HTTPS support")
        uvicorn.run(
            app, 
            host=host, 
            port=port,
            ssl_certfile=ssl_config['ssl_certfile'],
            ssl_keyfile=ssl_config['ssl_keyfile'],
            log_level=uvicorn_log_level
        )
    else:
        if not args.quiet:
            print(f"🌐 Starting without SSL (HTTP only)")
        uvicorn.run(app, host=host, port=port, log_level=uvicorn_log_level) 