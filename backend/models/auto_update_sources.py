from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func
from database import Base
from datetime import datetime


class AutoUpdateSource(Base):
    __tablename__ = "auto_update_sources"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    list_type = Column(String, default='blacklist', nullable=False, index=True)  # 'blacklist' or 'whitelist'
    last_update = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    update_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<AutoUpdateSource(id={self.id}, name='{self.name}', url='{self.url}')>"

    def is_active_source(self) -> bool:
        """Check if this source is active"""
        return self.is_active

    def mark_successful_update(self):
        """Mark a successful update"""
        self.last_update = datetime.utcnow()
        self.last_error = None
        self.update_count += 1

    def mark_failed_update(self, error_message: str):
        """Mark a failed update with error message"""
        self.last_error = error_message

    def get_last_update_ago(self) -> str:
        """Get human-readable time since last update"""
        if not self.last_update:
            return "Never"
        
        diff = datetime.utcnow() - self.last_update
        days = diff.days
        hours = diff.seconds // 3600
        minutes = (diff.seconds % 3600) // 60
        
        if days > 0:
            return f"{days} day{'s' if days != 1 else ''} ago"
        elif hours > 0:
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif minutes > 0:
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"

    @classmethod
    def get_active_sources(cls, db):
        """Get all active auto-update sources"""
        return db.query(cls).filter(cls.is_active == True).all()

    @classmethod
    def get_all_sources(cls, db):
        """Get all auto-update sources"""
        return db.query(cls).all() 