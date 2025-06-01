import asyncio
import aiohttp
import logging
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import List, Set, Optional
from sqlalchemy.orm import Session
from models import Domain, IP, IPRange, AutoUpdateSource, Setting, Log
from models.domains import ListType, SourceType
from models.logs import ActionType, RuleType
from services.dns_service import DNSService
from services.firewall_service import FirewallService
import time


class AutoUpdateService:
    """Service for handling auto-update functionality"""
    
    def __init__(self, db: Session):
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.dns_service = DNSService()
        self.firewall_service = FirewallService()
        self.is_running = False

    async def run_auto_update_cycle(self):
        """Run a complete auto-update cycle"""
        if self.is_running:
            self.logger.warning("Auto-update cycle already running, skipping")
            return
        
        self.is_running = True
        start_time = datetime.now(timezone.utc)
        
        try:
            self.logger.info("Starting auto-update cycle")
            
            # Step 1: Cleanup expired entries (PRIORITY)
            await self.cleanup_expired_entries()
            
            # Step 2: Resolve manual domains (if enabled)
            if Setting.get_setting(self.db, "manual_domain_resolution", True):
                await self.resolve_manual_domains()
            
            # Step 3: Process auto-update sources
            await self.process_auto_update_sources()
            
            # Step 4: Cleanup logs
            await self.cleanup_old_logs()
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.logger.info(f"Auto-update cycle completed in {duration:.2f} seconds")
            
            Log.create_rule_log(
                self.db, ActionType.update, None,
                f"Auto-update cycle completed successfully in {duration:.2f}s"
            )
            
        except Exception as e:
            self.logger.error(f"Auto-update cycle failed: {e}")
            Log.create_error_log(self.db, str(e), "Auto-update cycle")
            
        finally:
            self.is_running = False

    async def cleanup_expired_entries(self):
        """Clean up expired auto-update entries (PRIORITY TASK)"""
        self.logger.info("Cleaning up expired entries...")
        
        try:
            # Find expired domains
            expired_domains = Domain.get_expired_auto_updates(self.db)
            
            # Find expired IPs
            expired_ips = IP.get_expired_auto_updates(self.db)
            
            # Find expired IP ranges
            expired_ip_ranges = IPRange.get_expired_auto_updates(self.db)
            
            cleanup_count = len(expired_domains) + len(expired_ips) + len(expired_ip_ranges)
            
            if cleanup_count > 0:
                self.logger.info(f"Found {cleanup_count} expired entries to clean up")
                
                # Delete from database
                for domain in expired_domains:
                    self.db.delete(domain)
                for ip in expired_ips:
                    self.db.delete(ip)
                for ip_range in expired_ip_ranges:
                    self.db.delete(ip_range)
                
                self.db.commit()
                
                self.logger.info(f"Cleaned up {cleanup_count} expired entries")
                Log.create_rule_log(
                    self.db, ActionType.remove_rule, None,
                    f"Cleaned up {cleanup_count} expired auto-update entries"
                )
            else:
                self.logger.info("No expired entries found")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired entries: {e}")
            self.db.rollback()
            raise

    async def resolve_manual_domains(self):
        """Resolve manual domains to keep IP mappings current"""
        self.logger.info("Resolving manual domains...")
        
        try:
            manual_domains = Domain.get_manual_domains(self.db)
            max_ips_per_domain = Setting.get_setting(self.db, "max_ips_per_domain", 5)
            dns_resolver_primary = Setting.get_setting(self.db, "dns_resolver_primary", "1.1.1.1")
            dns_resolver_secondary = Setting.get_setting(self.db, "dns_resolver_secondary", "8.8.8.8")
            dns_service = DNSService(dns_resolver_primary, dns_resolver_secondary)
            self.logger.info(f"Found {len(manual_domains)} manual domains to resolve.")
            
            for domain in manual_domains:
                try:
                    self.logger.info(f"Resolving domain: {domain.domain_name} (list_type={domain.list_type}, id={domain.id})")
                    # Resolve domain
                    resolution = dns_service.resolve_domain(domain.domain_name)
                    self.logger.info(f"Resolution result for {domain.domain_name}: IPv4={resolution['ipv4']}, IPv6={resolution['ipv6']}, errors={resolution['errors']}")
                    
                    # Process IPv4 addresses
                    for ip_str in resolution['ipv4']:
                        self.logger.info(f"Attempting to add IPv4 {ip_str} for domain {domain.domain_name}")
                        await self._add_or_update_domain_ip(
                            domain, ip_str, 4, max_ips_per_domain
                        )
                    
                    # Process IPv6 addresses
                    for ip_str in resolution['ipv6']:
                        self.logger.info(f"Attempting to add IPv6 {ip_str} for domain {domain.domain_name}")
                        await self._add_or_update_domain_ip(
                            domain, ip_str, 6, max_ips_per_domain
                        )
                    
                    # Update CDN status
                    domain.update_cdn_status(self.db)
                    
                except Exception as e:
                    self.logger.error(f"Failed to resolve manual domain {domain.domain_name}: {e}")
                    continue
            
            self.db.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to resolve manual domains: {e}")
            self.db.rollback()
            raise

    async def process_auto_update_sources(self):
        """Process all active auto-update sources"""
        self.logger.info("Processing auto-update sources...")
        
        try:
            active_sources = AutoUpdateSource.get_active_sources(self.db)
            
            if not active_sources:
                self.logger.info("No active auto-update sources configured")
                return
            
            rate_limit_delay = Setting.get_setting(self.db, "rate_limit_delay", 1.0)
            
            for source in active_sources:
                try:
                    self.logger.info(f"Processing source: {source.name}")
                    
                    # Fetch content
                    content = await self._fetch_url_content(source.url)
                    
                    if content:
                        # Process content
                        await self._process_list_content(content, source)
                        
                        # Mark successful update
                        source.mark_successful_update()
                        self.logger.info(f"Successfully processed source: {source.name}")
                    else:
                        source.mark_failed_update("Failed to fetch content")
                        self.logger.warning(f"Failed to fetch content from: {source.name}")
                    
                    # Rate limiting
                    await asyncio.sleep(rate_limit_delay)
                    
                except Exception as e:
                    source.mark_failed_update(str(e))
                    self.logger.error(f"Failed to process source {source.name}: {e}")
                    continue
            
            self.db.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to process auto-update sources: {e}")
            self.db.rollback()
            raise

    async def _fetch_url_content(self, url: str) -> Optional[str]:
        """Fetch content from URL"""
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        self.logger.warning(f"HTTP {response.status} for URL: {url}")
                        return None
        except Exception as e:
            self.logger.error(f"Failed to fetch URL {url}: {e}")
            return None

    async def _process_list_content(self, content: str, source: AutoUpdateSource):
        """Process blacklist/whitelist content"""
        lines = content.strip().split('\n')
        processed_count = 0
        rule_expiration = Setting.get_setting(self.db, "rule_expiration", 86400)
        max_ips_per_domain = Setting.get_setting(self.db, "max_ips_per_domain", 5)
        expiration_time = datetime.now(timezone.utc) + timedelta(seconds=rule_expiration)
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            try:
                await self._process_list_entry(
                    line, source, expiration_time, max_ips_per_domain
                )
                processed_count += 1
                
            except Exception as e:
                self.logger.debug(f"Failed to process entry '{line}': {e}")
                continue
        
        self.logger.info(f"Processed {processed_count} entries from {source.name}")

    async def _process_list_entry(self, entry: str, source: AutoUpdateSource, 
                                 expiration_time: datetime, max_ips_per_domain: int):
        """Process a single entry from auto-update list"""
        # Determine list type from source
        list_type = ListType[source.list_type] if hasattr(source, 'list_type') else ListType.blacklist
        # Try to parse as IP address
        try:
            ip_obj = ipaddress.ip_address(entry)
            if IP.is_safe_ip(entry):
                await self._add_or_update_ip(
                    entry, ip_obj.version, list_type, 
                    SourceType.auto_update, source.url, expiration_time
                )
            return
        except ValueError:
            pass
        # Try to parse as IP range
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if IPRange.is_safe_ip_range(entry):
                await self._add_or_update_ip_range(
                    str(network), network.version, list_type,
                    SourceType.auto_update, source.url, expiration_time
                )
            return
        except ValueError:
            pass
        # Treat as domain
        if self._is_valid_domain(entry):
            domain = await self._add_or_update_domain(
                entry, list_type, SourceType.auto_update, 
                source.url, expiration_time
            )
            if domain:
                # Resolve domain to IPs
                dns_resolver_primary = Setting.get_setting(self.db, "dns_resolver_primary", "1.1.1.1")
                dns_resolver_secondary = Setting.get_setting(self.db, "dns_resolver_secondary", "8.8.8.8")
                dns_service = DNSService(dns_resolver_primary, dns_resolver_secondary)
                resolution = dns_service.resolve_domain(entry)
                # Process IPv4 addresses
                for ip_str in resolution['ipv4']:
                    await self._add_or_update_domain_ip(
                        domain, ip_str, 4, max_ips_per_domain, expiration_time
                    )
                # Process IPv6 addresses
                for ip_str in resolution['ipv6']:
                    await self._add_or_update_domain_ip(
                        domain, ip_str, 6, max_ips_per_domain, expiration_time
                    )

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        if not domain or len(domain) > 255:
            return False
        
        # Remove wildcard prefix
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Basic domain regex
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain))

    async def _add_or_update_domain(self, domain_name: str, list_type: ListType, 
                                   source_type: SourceType, source_url: str = None, 
                                   expiration_time: datetime = None) -> Optional[Domain]:
        """Add or update domain entry"""
        try:
            # Check if domain exists
            existing = self.db.query(Domain).filter(
                Domain.domain_name == domain_name
            ).first()
            
            if existing:
                # Update expiration if it's an auto-update entry
                if existing.source_type == SourceType.auto_update and expiration_time:
                    existing.expired_at = expiration_time
                    existing.updated_at = datetime.now(timezone.utc)
                return existing
            else:
                # Create new domain
                domain = Domain(
                    domain_name=domain_name,
                    list_type=list_type,
                    source_type=source_type,
                    source_url=source_url,
                    expired_at=expiration_time
                )
                self.db.add(domain)
                self.db.flush()  # Get ID
                return domain
                
        except Exception as e:
            self.logger.error(f"Failed to add/update domain {domain_name}: {e}")
            return None

    async def _add_or_update_ip(self, ip_address: str, ip_version: int, 
                               list_type: ListType, source_type: SourceType,
                               source_url: str = None, expiration_time: datetime = None):
        """Add or update IP entry"""
        try:
            # Check if IP exists
            existing = self.db.query(IP).filter(
                IP.ip_address == ip_address
            ).first()
            
            if existing:
                # Update expiration if it's an auto-update entry
                if existing.source_type == SourceType.auto_update and expiration_time:
                    existing.expired_at = expiration_time
                    existing.updated_at = datetime.now(timezone.utc)
            else:
                # Create new IP
                ip = IP(
                    ip_address=ip_address,
                    ip_version=ip_version,
                    list_type=list_type,
                    source_type=source_type,
                    source_url=source_url,
                    expired_at=expiration_time
                )
                self.db.add(ip)
                
        except Exception as e:
            self.logger.error(f"Failed to add/update IP {ip_address}: {e}")

    async def _add_or_update_ip_range(self, ip_range: str, ip_version: int,
                                     list_type: ListType, source_type: SourceType,
                                     source_url: str = None, expiration_time: datetime = None):
        """Add or update IP range entry"""
        try:
            # Normalize CIDR
            normalized_range = IPRange.normalize_cidr(ip_range)
            
            # Check if IP range exists
            existing = self.db.query(IPRange).filter(
                IPRange.ip_range == normalized_range
            ).first()
            
            if existing:
                # Update expiration if it's an auto-update entry
                if existing.source_type == SourceType.auto_update and expiration_time:
                    existing.expired_at = expiration_time
                    existing.updated_at = datetime.now(timezone.utc)
            else:
                # Create new IP range
                ip_range_obj = IPRange(
                    ip_range=normalized_range,
                    ip_version=ip_version,
                    list_type=list_type,
                    source_type=source_type,
                    source_url=source_url,
                    expired_at=expiration_time
                )
                self.db.add(ip_range_obj)
                
        except Exception as e:
            self.logger.error(f"Failed to add/update IP range {ip_range}: {e}")

    async def _add_or_update_domain_ip(self, domain: Domain, ip_address: str, 
                                      ip_version: int, max_ips_per_domain: int,
                                      expiration_time: datetime = None):
        """Add or update IP for a domain with FIFO management"""
        try:
            self.logger.info(f"_add_or_update_domain_ip: domain={domain.domain_name}, ip={ip_address}, version={ip_version}, list_type={domain.list_type}, source_type={domain.source_type}")
            # Check if this IP already exists for this domain
            existing = self.db.query(IP).filter(
                IP.domain_id == domain.id,
                IP.ip_address == ip_address
            ).first()
            
            if existing:
                self.logger.info(f"IP {ip_address} already exists for domain {domain.domain_name}, updating timestamps if needed.")
                # Update existing IP
                if domain.source_type == SourceType.auto_update and expiration_time:
                    existing.expired_at = expiration_time
                existing.updated_at = datetime.now(timezone.utc)
            else:
                self.logger.info(f"Adding new IP {ip_address} for domain {domain.domain_name} to DB.")
                # Create new IP
                ip = IP(
                    ip_address=ip_address,
                    ip_version=ip_version,
                    list_type=domain.list_type,
                    source_type=domain.source_type,
                    source_url=domain.source_url,
                    domain_id=domain.id,
                    expired_at=expiration_time if domain.source_type == SourceType.auto_update else None
                )
                self.db.add(ip)
                self.db.flush()
                self.logger.info(f"Added IP {ip_address} to DB for domain {domain.domain_name}.")
                
                # Apply FIFO limit
                IP.cleanup_old_ips_for_domain(self.db, domain.id, max_ips_per_domain)
                self.logger.info(f"Applied FIFO limit for domain {domain.domain_name} (max {max_ips_per_domain} IPs).")
                
        except Exception as e:
            self.logger.error(f"Failed to add/update domain IP {ip_address} for {domain.domain_name}: {e}")

    async def cleanup_old_logs(self):
        """Clean up old log entries"""
        try:
            max_entries = Setting.get_setting(self.db, "max_log_entries", 10000)
            max_days = Setting.get_setting(self.db, "log_retention_days", 7)
            
            Log.cleanup_old_logs(self.db, max_entries, max_days)
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")

    def get_status(self) -> dict:
        """Get auto-update service status"""
        return {
            "is_running": self.is_running,
            "enabled": Setting.get_setting(self.db, "auto_update_enabled", True),
            "active_sources": len(AutoUpdateSource.get_active_sources(self.db)),
            "last_update": "Not implemented",  # Would need to track this
            "next_update": "Not implemented"   # Would need scheduler integration
        } 