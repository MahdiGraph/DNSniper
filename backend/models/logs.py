from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import Session
from database import Base
import enum
from datetime import datetime, timedelta


class ActionType(enum.Enum):
    block = "block"
    allow = "allow"
    add_rule = "add_rule"
    remove_rule = "remove_rule"
    update = "update"
    error = "error"


class RuleType(enum.Enum):
    domain = "domain"
    ip = "ip"
    ip_range = "ip_range"


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action = Column(Enum(ActionType), nullable=False, index=True)
    ip_address = Column(String, nullable=True, index=True)
    domain_name = Column(String, nullable=True, index=True)
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True, index=True)
    rule_type = Column(Enum(RuleType), nullable=True, index=True)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.now(), index=True)
    mode = Column(String, nullable=True, index=True)  # 'manual', 'auto_update', etc.

    def __repr__(self):
        return f"<Log(id={self.id}, action='{self.action}', message='{self.message[:50]}...')>"

    def is_firewall_log(self) -> bool:
        """Check if this is a firewall block/allow log"""
        return self.action in [ActionType.block, ActionType.allow]

    def is_rule_management_log(self) -> bool:
        """Check if this is a rule management log"""
        return self.action in [ActionType.add_rule, ActionType.remove_rule, ActionType.update]

    def is_error_log(self) -> bool:
        """Check if this is an error log"""
        return self.action == ActionType.error

    @classmethod
    def _is_logging_enabled(cls, db: Session) -> bool:
        """Check if logging is enabled in settings"""
        try:
            # Import here to avoid circular import
            from models.settings import Setting
            return Setting.get_setting(db, "logging_enabled", False)
        except Exception:
            # If there's any error checking the setting, default to enabled
            return True

    @classmethod
    def create_firewall_log(cls, db: Session, action: ActionType, message: str, 
                           source_ip: str = None, destination_ip: str = None, 
                           ip_address: str = None, domain_name: str = None, mode: str = None):
        """Create a firewall activity log entry"""
        if not cls._is_logging_enabled(db):
            return None
            
        log = cls(
            action=action,
            message=message,
            source_ip=source_ip,
            destination_ip=destination_ip,
            ip_address=ip_address,
            domain_name=domain_name,
            mode=mode
        )
        db.add(log)
        db.commit()
        return log

    @classmethod
    def create_rule_log(cls, db: Session, action: ActionType, rule_type: RuleType, 
                       message: str, ip_address: str = None, domain_name: str = None, mode: str = None):
        """Create a rule management log entry"""
        if not cls._is_logging_enabled(db):
            return None
            
        log = cls(
            action=action,
            rule_type=rule_type,
            message=message,
            ip_address=ip_address,
            domain_name=domain_name,
            mode=mode
        )
        db.add(log)
        db.commit()
        return log

    @classmethod
    def create_error_log(cls, db: Session, message: str, context: str = None, mode: str = None):
        """Create an error log entry"""
        if not cls._is_logging_enabled(db):
            return None
            
        full_message = f"{context}: {message}" if context else message
        log = cls(
            action=ActionType.error,
            message=full_message,
            mode=mode
        )
        db.add(log)
        db.commit()
        return log

    @classmethod
    def cleanup_old_logs(cls, db: Session, max_entries: int = None, max_days: int = None):
        """Clean up old log entries (FIFO mechanism)"""
        
        # Get settings if not provided
        if max_entries is None or max_days is None:
            try:
                from models.settings import Setting
                if max_entries is None:
                    max_entries = Setting.get_setting(db, "max_log_entries", 10000)
                if max_days is None:
                    max_days = Setting.get_setting(db, "log_retention_days", 7)
            except Exception:
                # Default values if settings can't be retrieved
                max_entries = max_entries or 10000
                max_days = max_days or 7
        
        deleted_count = 0
        
        # Clean by count (keep newest max_entries)
        total_count = db.query(cls).count()
        if total_count > max_entries:
            entries_to_delete = total_count - max_entries
            oldest_logs = db.query(cls).order_by(cls.created_at.asc()).limit(entries_to_delete)
            for log in oldest_logs:
                db.delete(log)
                deleted_count += 1
        
        # Clean by age (remove entries older than max_days)
        cutoff_date = datetime.utcnow() - timedelta(days=max_days)
        old_logs = db.query(cls).filter(cls.created_at < cutoff_date)
        for log in old_logs:
            db.delete(log)
            deleted_count += 1
        
        db.commit()
        return deleted_count

    @classmethod
    def get_recent_logs(cls, db: Session, limit: int = 100, action_filter: ActionType = None):
        """Get recent logs with optional action filter"""
        query = db.query(cls).order_by(cls.created_at.desc())
        
        if action_filter:
            query = query.filter(cls.action == action_filter)
        
        return query.limit(limit).all()

    @classmethod
    def get_logs_by_date_range(cls, db: Session, start_date: datetime, end_date: datetime):
        """Get logs within a date range"""
        return db.query(cls).filter(
            cls.created_at >= start_date,
            cls.created_at <= end_date
        ).order_by(cls.created_at.desc()).all()

    @classmethod
    def get_logs_by_ip(cls, db: Session, ip_address: str):
        """Get all logs related to a specific IP address"""
        return db.query(cls).filter(
            (cls.ip_address == ip_address) |
            (cls.source_ip == ip_address) |
            (cls.destination_ip == ip_address)
        ).order_by(cls.created_at.desc()).all()

    @classmethod
    def get_logs_by_domain(cls, db: Session, domain_name: str):
        """Get all logs related to a specific domain"""
        return db.query(cls).filter(
            cls.domain_name == domain_name
        ).order_by(cls.created_at.desc()).all()

    @classmethod
    def get_statistics(cls, db: Session, hours: int = 24):
        """Get log statistics for the last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        stats = {}
        for action in ActionType:
            count = db.query(cls).filter(
                cls.action == action,
                cls.created_at >= cutoff_time
            ).count()
            stats[action.value] = count
        
        return stats 