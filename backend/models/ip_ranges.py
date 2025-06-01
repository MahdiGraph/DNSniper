from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, event
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from database import Base
from .domains import ListType, SourceType
from datetime import datetime
import ipaddress
import logging


class IPRange(Base):
    __tablename__ = "ip_ranges"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_range = Column(String, nullable=False, index=True)
    ip_version = Column(Integer, nullable=False, index=True)
    list_type = Column(Enum(ListType), nullable=False, index=True)
    source_type = Column(Enum(SourceType), nullable=False, index=True)
    source_url = Column(String, nullable=True)
    expired_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    notes = Column(Text, nullable=True)

    def __repr__(self):
        return f"<IPRange(id={self.id}, ip_range='{self.ip_range}', list_type='{self.list_type}')>"

    def is_expired(self) -> bool:
        """Check if this IP range entry is expired"""
        if self.expired_at is None:
            return False  # Manual entries never expire
        return self.expired_at < datetime.utcnow()

    def is_manual(self) -> bool:
        """Check if this is a manual entry"""
        return self.source_type == SourceType.manual

    def is_auto_update(self) -> bool:
        """Check if this is an auto-update entry"""
        return self.source_type == SourceType.auto_update

    def is_ipv4(self) -> bool:
        """Check if this is IPv4"""
        return self.ip_version == 4

    def is_ipv6(self) -> bool:
        """Check if this is IPv6"""
        return self.ip_version == 6

    @staticmethod
    def validate_ip_range(ip_range_str: str) -> tuple[bool, int]:
        """Validate IP range (CIDR notation) and return (is_valid, version)"""
        try:
            network = ipaddress.ip_network(ip_range_str, strict=False)
            return True, network.version
        except ValueError:
            return False, 0

    @staticmethod
    def is_safe_ip_range(ip_range_str: str) -> bool:
        """Check if IP range is safe to block (not private, localhost, etc.)"""
        try:
            network = ipaddress.ip_network(ip_range_str, strict=False)
            
            # Skip private networks
            if network.is_private:
                return False
            
            # Skip loopback
            if network.is_loopback:
                return False
            
            # Skip multicast and reserved
            if hasattr(network, 'is_multicast') and network.is_multicast:
                return False
            
            if hasattr(network, 'is_reserved') and network.is_reserved:
                return False
            
            # Skip very large ranges (e.g., /8 or smaller) to prevent blocking too much
            if network.version == 4 and network.prefixlen < 16:
                return False
            
            if network.version == 6 and network.prefixlen < 32:
                return False
            
            return True
        except ValueError:
            return False

    @classmethod
    def get_expired_auto_updates(cls, db: Session):
        """Get all expired auto-update entries"""
        return db.query(cls).filter(
            cls.source_type == SourceType.auto_update,
            cls.expired_at.isnot(None),
            cls.expired_at < func.now()
        ).all()

    @staticmethod
    def normalize_cidr(ip_range_str: str) -> str:
        """Normalize CIDR notation (e.g., remove host bits)"""
        try:
            network = ipaddress.ip_network(ip_range_str, strict=False)
            return str(network)
        except ValueError:
            return ip_range_str


# SQLAlchemy event hooks for firewall rule management
@event.listens_for(IPRange, 'after_insert')
def iprange_after_insert(mapper, connection, target):
    from services.firewall_service import FirewallService
    logger = logging.getLogger(__name__)
    if not target.is_expired():
        try:
            firewall = FirewallService()
            firewall.add_ip_range_to_ipset(target.ip_range, target.list_type.value, target.ip_version)
            logger.info(f"[HOOK] Added IP range {target.ip_range} to ipset ({target.list_type.value}, v{target.ip_version}) after insert.")
        except Exception as e:
            logger.error(f"[HOOK] Failed to add IP range {target.ip_range} to ipset: {e}")

@event.listens_for(IPRange, 'after_delete')
def iprange_after_delete(mapper, connection, target):
    from services.firewall_service import FirewallService
    logger = logging.getLogger(__name__)
    try:
        firewall = FirewallService()
        firewall.remove_ip_range_from_ipset(target.ip_range, target.list_type.value, target.ip_version)
        logger.info(f"[HOOK] Removed IP range {target.ip_range} from ipset ({target.list_type.value}, v{target.ip_version}) after delete.")
    except Exception as e:
        logger.error(f"[HOOK] Failed to remove IP range {target.ip_range} from ipset: {e}")

@event.listens_for(IPRange, 'after_update')
def iprange_after_update(mapper, connection, target):
    from services.firewall_service import FirewallService
    logger = logging.getLogger(__name__)
    try:
        firewall = FirewallService()
        firewall.remove_ip_range_from_ipset(target.ip_range, target.list_type.value, target.ip_version)
        if not target.is_expired():
            firewall.add_ip_range_to_ipset(target.ip_range, target.list_type.value, target.ip_version)
            logger.info(f"[HOOK] Updated IP range {target.ip_range} in ipset ({target.list_type.value}, v{target.ip_version}) after update.")
        else:
            logger.info(f"[HOOK] Removed expired IP range {target.ip_range} from ipset after update.")
    except Exception as e:
        logger.error(f"[HOOK] Failed to update IP range {target.ip_range} in ipset: {e}") 