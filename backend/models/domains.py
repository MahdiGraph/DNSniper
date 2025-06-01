from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum, event
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func
from database import Base
import enum
from datetime import datetime


class ListType(enum.Enum):
    blacklist = "blacklist"
    whitelist = "whitelist"


class SourceType(enum.Enum):
    manual = "manual"
    auto_update = "auto_update"


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    domain_name = Column(String, unique=True, nullable=False, index=True)
    list_type = Column(Enum(ListType), nullable=False, index=True)
    source_type = Column(Enum(SourceType), nullable=False, index=True)
    source_url = Column(String, nullable=True)
    is_cdn = Column(Boolean, default=False, nullable=False)
    expired_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    notes = Column(Text, nullable=True)

    # Relationships
    ips = relationship("IP", back_populates="domain", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Domain(id={self.id}, domain_name='{self.domain_name}', list_type='{self.list_type}')>"

    def is_expired(self) -> bool:
        """Check if this domain entry is expired"""
        if self.expired_at is None:
            return False  # Manual entries never expire
        return self.expired_at < datetime.utcnow()

    def is_manual(self) -> bool:
        """Check if this is a manual entry"""
        return self.source_type == SourceType.manual

    def is_auto_update(self) -> bool:
        """Check if this is an auto-update entry"""
        return self.source_type == SourceType.auto_update

    def update_cdn_status(self, db: Session):
        """Update CDN status based on number of resolved IPs"""
        from models import IP
        ip_count = db.query(IP).filter(IP.domain_id == self.id).count()
        
        # Flag as CDN if more than 3 IPs
        self.is_cdn = ip_count > 3
        db.commit()

    @classmethod
    def get_expired_auto_updates(cls, db: Session):
        """Get all expired auto-update entries"""
        return db.query(cls).filter(
            cls.source_type == SourceType.auto_update,
            cls.expired_at.isnot(None),
            cls.expired_at < func.now()
        ).all()

    @classmethod
    def get_manual_domains(cls, db: Session):
        """Get all manual domains for resolution during auto-update"""
        return db.query(cls).filter(
            cls.source_type == SourceType.manual
        ).all()


# SQLAlchemy event hooks for firewall rule management
@event.listens_for(Domain, "after_insert")
def domain_after_insert(mapper, connection, target):
    """Add firewall rules when domain is added"""
    from services.firewall_service import FirewallService
    firewall = FirewallService()
    # Domain rules are managed through IP resolution
    pass


@event.listens_for(Domain, "after_update") 
def domain_after_update(mapper, connection, target):
    """Update firewall rules when domain is updated"""
    from services.firewall_service import FirewallService
    firewall = FirewallService()
    # Domain rules are managed through IP resolution
    pass


@event.listens_for(Domain, "before_delete")
def domain_before_delete(mapper, connection, target):
    """Remove firewall rules when domain is deleted"""
    from services.firewall_service import FirewallService
    firewall = FirewallService()
    # Remove associated IP rules when domain is deleted
    # This is handled by cascade deletion of IPs 