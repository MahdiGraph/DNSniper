from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, ForeignKey, event
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func
from database import Base
from .domains import ListType, SourceType
from datetime import datetime
import ipaddress
import logging


class IP(Base):
    __tablename__ = "ips"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_address = Column(String, nullable=False, index=True)
    ip_version = Column(Integer, nullable=False, index=True)
    list_type = Column(Enum(ListType), nullable=False, index=True)
    source_type = Column(Enum(SourceType), nullable=False, index=True)
    source_url = Column(String, nullable=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True, index=True)
    expired_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    notes = Column(Text, nullable=True)

    # Relationships
    domain = relationship("Domain", back_populates="ips")

    def __repr__(self):
        return f"<IP(id={self.id}, ip_address='{self.ip_address}', list_type='{self.list_type}')>"

    def is_expired(self) -> bool:
        """Check if this IP entry is expired"""
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
    def validate_ip_address(ip_str: str) -> tuple[bool, int]:
        """Validate IP address and return (is_valid, version)"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return True, ip_obj.version
        except ValueError:
            return False, 0

    @staticmethod
    def is_safe_ip(ip_str: str) -> bool:
        """Check if IP is safe to block (not private, localhost, etc.)"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            
            # Skip private networks
            if ip_obj.is_private:
                return False
            
            # Skip localhost
            if ip_obj.is_loopback:
                return False
            
            # Skip null route
            if str(ip_obj) == "0.0.0.0" or str(ip_obj) == "::":
                return False
            
            # Skip multicast and reserved
            if hasattr(ip_obj, 'is_multicast') and ip_obj.is_multicast:
                return False
            
            if hasattr(ip_obj, 'is_reserved') and ip_obj.is_reserved:
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

    @classmethod
    def get_ips_for_domain(cls, db: Session, domain_id: int):
        """Get all IPs for a specific domain"""
        return db.query(cls).filter(cls.domain_id == domain_id).all()

    @classmethod
    def cleanup_old_ips_for_domain(cls, db: Session, domain_id: int, max_ips: int = 5):
        """Remove oldest IPs for domain when limit exceeded (FIFO)"""
        ips = db.query(cls).filter(
            cls.domain_id == domain_id
        ).order_by(cls.created_at.asc()).all()
        
        if len(ips) > max_ips:
            ips_to_remove = ips[:-max_ips]  # Keep the newest max_ips
            for ip in ips_to_remove:
                db.delete(ip)
            db.commit()


# SQLAlchemy event hooks for firewall rule management
@event.listens_for(IP, 'after_insert')
def ip_after_insert(mapper, connection, target):
    from services.firewall_service import FirewallService
    logger = logging.getLogger(__name__)
    if not target.is_expired():
        try:
            firewall = FirewallService()
            firewall.add_ip_to_ipset(target.ip_address, target.list_type.value, target.ip_version)
            logger.info(f"[HOOK] Added IP {target.ip_address} to ipset ({target.list_type.value}, v{target.ip_version}) after insert.")
        except Exception as e:
            logger.error(f"[HOOK] Failed to add IP {target.ip_address} to ipset: {e}")

@event.listens_for(IP, 'after_delete')
def ip_after_delete(mapper, connection, target):
    from services.firewall_service import FirewallService
    logger = logging.getLogger(__name__)
    try:
        firewall = FirewallService()
        firewall.remove_ip_from_ipset(target.ip_address, target.list_type.value, target.ip_version)
        logger.info(f"[HOOK] Removed IP {target.ip_address} from ipset ({target.list_type.value}, v{target.ip_version}) after delete.")
    except Exception as e:
        logger.error(f"[HOOK] Failed to remove IP {target.ip_address} from ipset: {e}")

@event.listens_for(IP, 'after_update')
def ip_after_update(mapper, connection, target):
    from services.firewall_service import FirewallService
    logger = logging.getLogger(__name__)
    # On update, always remove and re-add if not expired
    try:
        firewall = FirewallService()
        firewall.remove_ip_from_ipset(target.ip_address, target.list_type.value, target.ip_version)
        if not target.is_expired():
            firewall.add_ip_to_ipset(target.ip_address, target.list_type.value, target.ip_version)
            logger.info(f"[HOOK] Updated IP {target.ip_address} in ipset ({target.list_type.value}, v{target.ip_version}) after update.")
        else:
            logger.info(f"[HOOK] Removed expired IP {target.ip_address} from ipset after update.")
    except Exception as e:
        logger.error(f"[HOOK] Failed to update IP {target.ip_address} in ipset: {e}") 