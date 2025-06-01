from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import Session
from database import Base
import json


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    key = Column(String, unique=True, nullable=False, index=True)
    value = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<Setting(id={self.id}, key='{self.key}', value='{self.value[:50]}...')>"

    def get_value(self):
        """Get parsed value (handles JSON and simple strings)"""
        try:
            # Try JSON parsing first
            return json.loads(self.value)
        except (json.JSONDecodeError, TypeError):
            # Handle special string cases
            if self.value.lower() == 'true':
                return True
            elif self.value.lower() == 'false':
                return False
            elif self.value.lower() == 'null' or self.value.lower() == 'none':
                return None
            
            # Try to parse as number
            try:
                if '.' in self.value:
                    return float(self.value)
                else:
                    return int(self.value)
            except ValueError:
                pass
            
            # Return as string
            return self.value

    def set_value(self, value):
        """Set value (automatically converts complex types to JSON)"""
        if isinstance(value, (dict, list, tuple)):
            self.value = json.dumps(value)
        elif isinstance(value, bool):
            # Store booleans as JSON to ensure proper parsing
            self.value = json.dumps(value)
        else:
            self.value = str(value)

    @classmethod
    def get_setting(cls, db: Session, key: str, default=None):
        """Get a setting value by key"""
        setting = db.query(cls).filter(cls.key == key).first()
        if setting:
            return setting.get_value()
        return default

    @classmethod
    def set_setting(cls, db: Session, key: str, value, description: str = None):
        """Set a setting value by key"""
        setting = db.query(cls).filter(cls.key == key).first()
        if setting:
            setting.set_value(value)
            if description:
                setting.description = description
        else:
            setting = cls(key=key, description=description)
            setting.set_value(value)
            db.add(setting)
        db.commit()
        return setting

    @classmethod
    def get_all_settings(cls, db: Session):
        """Get all settings as a dictionary"""
        settings = db.query(cls).all()
        return {setting.key: setting.get_value() for setting in settings}

    @classmethod
    def initialize_default_settings(cls, db: Session):
        """Initialize default settings if they don't exist"""
        defaults = {
            "auto_update_interval": {
                "value": 3600,  # 1 hour in seconds
                "description": "Auto-update interval in seconds"
            },
            "rule_expiration": {
                "value": 86400,  # 24 hours in seconds
                "description": "Rule expiration time in seconds"
            },
            "max_ips_per_domain": {
                "value": 5,
                "description": "Maximum IPs to store per domain"
            },
            "dns_resolver_primary": {
                "value": "1.1.1.1",
                "description": "Primary DNS server for resolution"
            },
            "dns_resolver_secondary": {
                "value": "8.8.8.8",
                "description": "Secondary DNS server for resolution"
            },
            "logging_enabled": {
                "value": False,
                "description": "Enable/disable firewall logging"
            },
            "manual_domain_resolution": {
                "value": True,
                "description": "Resolve manual domains during auto-update cycles"
            },
            "rate_limit_delay": {
                "value": 1.0,
                "description": "Delay between auto-update requests in seconds"
            },
            "auto_update_enabled": {
                "value": True,
                "description": "Enable/disable auto-update agent"
            },
            "log_retention_days": {
                "value": 7,
                "description": "Number of days to keep logs"
            },
            "max_log_entries": {
                "value": 10000,
                "description": "Maximum number of log entries to keep"
            },
            # SSL configuration
            "force_https": {
                "value": False,
                "description": "Force HTTP to HTTPS redirection (requires SSL configuration)"
            },
            "enable_ssl": {
                "value": False,
                "description": "Enable SSL/HTTPS support (master switch)"
            },
            "ssl_domain": {
                "value": "",
                "description": "Domain name for SSL certificate (required for HTTPS)"
            },
            "ssl_certfile": {
                "value": "",
                "description": "Path to SSL certificate file (PEM) (required for HTTPS)"
            },
            "ssl_keyfile": {
                "value": "",
                "description": "Path to SSL private key file (PEM) (required for HTTPS)"
            }
        }

        for key, config in defaults.items():
            existing = db.query(cls).filter(cls.key == key).first()
            if not existing:
                cls.set_setting(db, key, config["value"], config["description"]) 