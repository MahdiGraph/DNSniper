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
            "automatic_domain_resolution": {
                "value": True,
                "description": "Automatically resolve manually-added domains to IPs during auto-update cycles"
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
            # Critical IPs configuration for auto-update protection (IPv4 and IPv6 separated)
            # NOTE: Dynamic detection (local network, DNS resolvers, public IP) happens automatically at runtime
            "critical_ipv4_ips_ranges": {
                "value": [
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
                ],
                "description": "List of static critical IPv4 addresses and ranges that should never be auto-blocked (dynamic detection happens automatically at runtime)"
            },
            "critical_ipv6_ips_ranges": {
                "value": [
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
                ],
                "description": "List of static critical IPv6 addresses and ranges that should never be auto-blocked (dynamic detection happens automatically at runtime)"
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