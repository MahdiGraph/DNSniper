from .domains import router as domains_router
from .ips import router as ips_router
from .ip_ranges import router as ip_ranges_router
from .auto_update_sources import router as auto_update_sources_router
from .logs import router as logs_router
from .settings import router as settings_router

__all__ = [
    "domains_router",
    "ips_router", 
    "ip_ranges_router",
    "auto_update_sources_router",
    "logs_router",
    "settings_router"
] 