import asyncio
import aiohttp
import re
import ipaddress
import threading
from datetime import datetime, timedelta, timezone
from typing import List, Set, Optional
from sqlalchemy.orm import Session
from models import Domain, IP, IPRange, AutoUpdateSource, Setting, Log
from models.domains import ListType, SourceType
from models.logs import ActionType, RuleType
from services.dns_service import DNSService
from services.firewall_service import FirewallService
from services.live_events import live_events
import time
from database import SessionLocal

# Global lock and state management for auto-update operations
_auto_update_lock = threading.Lock()
_auto_update_running = False
_current_auto_update_thread = None
_auto_update_start_time = None

class AutoUpdateService:
    """Service for handling auto-update functionality"""
    
    def __init__(self, db: Session = None):
        self.db = db  # Can be None, will create sessions as needed
        self.dns_service = DNSService()
        self.firewall_service = FirewallService()

    @classmethod
    def is_auto_update_running(cls) -> bool:
        """Check if auto-update is currently running (thread-safe)"""
        global _auto_update_running
        with _auto_update_lock:
            return _auto_update_running

    @classmethod
    def get_auto_update_status(cls) -> dict:
        """Get current auto-update status (thread-safe)"""
        global _auto_update_running, _current_auto_update_thread, _auto_update_start_time
        with _auto_update_lock:
            return {
                "is_running": _auto_update_running,
                "thread_alive": _current_auto_update_thread is not None and _current_auto_update_thread.is_alive(),
                "start_time": _auto_update_start_time.isoformat() if _auto_update_start_time else None,
                "thread_id": _current_auto_update_thread.ident if _current_auto_update_thread else None
            }

    @classmethod
    def start_auto_update_cycle_thread(cls) -> dict:
        """Start auto-update cycle in a new thread with proper lock management"""
        global _auto_update_lock, _auto_update_running, _current_auto_update_thread, _auto_update_start_time
        
        with _auto_update_lock:
            # Check if already running
            if _auto_update_running:
                if _current_auto_update_thread and _current_auto_update_thread.is_alive():
                    return {
                        "status": "already_running",
                        "message": "Auto-update cycle is already running",
                        "thread_id": _current_auto_update_thread.ident,
                        "start_time": _auto_update_start_time.isoformat() if _auto_update_start_time else None
                    }
                else:
                    # Thread died but flag still set - reset state
                    _auto_update_running = False
                    _current_auto_update_thread = None
                    _auto_update_start_time = None
            
            # Clean up any dead threads
            if _current_auto_update_thread and not _current_auto_update_thread.is_alive():
                _current_auto_update_thread = None
                _auto_update_running = False
                _auto_update_start_time = None
            
            # Set start time and running state BEFORE starting thread
            _auto_update_start_time = datetime.now(timezone.utc)
            _auto_update_running = True
            
            # Start new thread
            def run_auto_update_wrapper():
                """Wrapper function to run auto-update with proper state management"""
                loop = None
                try:
                    # Create service instance and run cycle
                    service = AutoUpdateService()
                    import asyncio
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(service.run_auto_update_cycle())
                    
                except Exception as e:
                    # Log error
                    db = SessionLocal()
                    try:
                        Log.create_error_log(db, f"Auto-update thread failed: {e}", context="AutoUpdateService.start_auto_update_cycle_thread", mode="auto_update")
                        Log.cleanup_old_logs(db)
                        db.commit()
                    finally:
                        db.close()
                    
                finally:
                    # Always reset state and clean up event loop when thread finishes
                    if loop and not loop.is_closed():
                        try:
                            loop.close()
                        except Exception as e:
                            # Log cleanup error but don't raise
                            db = SessionLocal()
                            try:
                                Log.create_error_log(db, f"Failed to close event loop: {e}", context="AutoUpdateService.run_auto_update_wrapper", mode="auto_update")
                                Log.cleanup_old_logs(db)
                                db.commit()
                            finally:
                                db.close()
                    
                    with _auto_update_lock:
                        global _auto_update_running, _auto_update_start_time
                        _auto_update_running = False
                        _auto_update_start_time = None
            
            # Create and start thread
            _current_auto_update_thread = threading.Thread(
                target=run_auto_update_wrapper,
                name="AutoUpdateCycle",
                daemon=True
            )
            _current_auto_update_thread.start()
            
            return {
                "status": "started",
                "message": "Auto-update cycle started successfully",
                "thread_id": _current_auto_update_thread.ident,
                "start_time": _auto_update_start_time.isoformat()
            }

    @classmethod 
    def stop_auto_update_cycle(cls, timeout: int = 30) -> dict:
        """Stop the current auto-update cycle (if running)"""
        global _auto_update_lock, _auto_update_running, _current_auto_update_thread
        
        with _auto_update_lock:
            if not _auto_update_running or not _current_auto_update_thread:
                return {
                    "status": "not_running",
                    "message": "No auto-update cycle is currently running"
                }
            
            if not _current_auto_update_thread.is_alive():
                return {
                    "status": "already_stopped", 
                    "message": "Auto-update thread is not alive"
                }
            
            thread_to_stop = _current_auto_update_thread
        
        # Wait for thread to finish (outside of lock to prevent deadlock)
        thread_to_stop.join(timeout=timeout)
        
        with _auto_update_lock:
            if thread_to_stop.is_alive():
                return {
                    "status": "timeout",
                    "message": f"Auto-update thread did not stop within {timeout} seconds"
                }
            else:
                # Reset state
                _auto_update_running = False
                _current_auto_update_thread = None
                return {
                    "status": "stopped",
                    "message": "Auto-update cycle stopped successfully"
                }

    def _get_db_session(self):
        """Get database session - use provided one or create new"""
        if self.db:
            return self.db
        return SessionLocal()

    def _close_db_if_needed(self, db):
        """Close database session if we created it"""
        if not self.db:  # Only close if we created it
            db.close()

    async def run_auto_update_cycle(self):
        """Run a complete auto-update cycle"""
        cycle_start_time = datetime.now(timezone.utc)
        
        # Broadcast cycle start event
        await live_events.broadcast_auto_update_cycle_event("started", {
            "message": "Auto-update cycle started",
            "start_time": cycle_start_time.isoformat(),
            "sources_count": 0
        })
        
        db = self._get_db_session()
        try:
            # Log cycle start
            Log.create_rule_log(db, ActionType.update, None, "Starting auto-update cycle", mode="auto_update")
            Log.cleanup_old_logs(db)
            
            # Get active sources count for progress tracking
            active_sources = AutoUpdateSource.get_active_sources(db)
            sources_count = len(active_sources)
            
            # Update cycle start with source count
            await live_events.broadcast_auto_update_cycle_event("progress", {
                "message": f"Found {sources_count} active auto-update sources",
                "sources_count": sources_count,
                "processed_sources": 0
            })
            
            # Clean up expired entries first
            await self.cleanup_expired_entries()
            
            # Broadcast progress
            await live_events.broadcast_auto_update_cycle_event("progress", {
                "message": "Cleaned up expired entries",
                "phase": "cleanup"
            })
            
            # Resolve manual domains if enabled
            if Setting.get_setting(db, "automatic_domain_resolution", True):
                await live_events.broadcast_auto_update_cycle_event("progress", {
                    "message": "Resolving manual domains",
                    "phase": "domain_resolution"
                })
                await self.resolve_manual_domains()
            
            # Process auto-update sources
            await live_events.broadcast_auto_update_cycle_event("progress", {
                "message": "Processing auto-update sources",
                "phase": "auto_update_processing"
            })
            await self.process_auto_update_sources()
            
            # Final cleanup
            await live_events.broadcast_auto_update_cycle_event("progress", {
                "message": "Final cleanup and optimization",
                "phase": "final_cleanup"
            })
            await self.cleanup_expired_entries()
            
            cycle_end_time = datetime.now(timezone.utc)
            cycle_duration = (cycle_end_time - cycle_start_time).total_seconds()
            
            # Log completion
            Log.create_rule_log(db, ActionType.update, None, f"Auto-update cycle completed in {cycle_duration:.2f} seconds", mode="auto_update")
            Log.cleanup_old_logs(db)
            
            # Broadcast completion event
            await live_events.broadcast_auto_update_cycle_event("completed", {
                "message": "Auto-update cycle completed successfully",
                "start_time": cycle_start_time.isoformat(),
                "end_time": cycle_end_time.isoformat(),
                "duration_seconds": cycle_duration,
                "sources_processed": sources_count
            })
            
        except Exception as e:
            cycle_end_time = datetime.now(timezone.utc)
            cycle_duration = (cycle_end_time - cycle_start_time).total_seconds()
            
            # Log error
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Auto-update cycle failed: {e}", context="AutoUpdateService.run_auto_update_cycle", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close()
            
            # Broadcast failure event
            await live_events.broadcast_auto_update_cycle_event("failed", {
                "message": "Auto-update cycle failed",
                "error": str(e),
                "start_time": cycle_start_time.isoformat(),
                "end_time": cycle_end_time.isoformat(),
                "duration_seconds": cycle_duration
            })
            
            raise
        finally:
            self._close_db_if_needed(db)

    async def cleanup_expired_entries(self):
        """Clean up expired auto-update entries (PRIORITY TASK)"""
        db = SessionLocal()
        Log.create_rule_log(db, ActionType.update, None, "Cleaning up expired entries...", mode="auto_update")
        Log.cleanup_old_logs(db)
        db.close()
        
        try:
            db = self._get_db_session()
            try:
                # Find expired domains
                expired_domains = Domain.get_expired_auto_updates(db)
                
                # Find expired IPs
                expired_ips = IP.get_expired_auto_updates(db)
                
                # Find expired IP ranges
                expired_ip_ranges = IPRange.get_expired_auto_updates(db)
                
                cleanup_count = len(expired_domains) + len(expired_ips) + len(expired_ip_ranges)
                
                if cleanup_count > 0:
                    # Delete from database
                    for domain in expired_domains:
                        db.delete(domain)
                    for ip in expired_ips:
                        db.delete(ip)
                    for ip_range in expired_ip_ranges:
                        db.delete(ip_range)
                    
                    db.commit()
                    
                    # Log the cleanup
                    log_db = SessionLocal()
                    Log.create_rule_log(
                        log_db, ActionType.remove_rule, None,
                        f"Cleaned up {cleanup_count} expired auto-update entries",
                        mode='auto_update'
                    )
                    Log.cleanup_old_logs(log_db)
                    log_db.close()
                else:
                    # Log that no entries were found
                    log_db = SessionLocal()
                    Log.create_rule_log(log_db, ActionType.update, None, "No expired entries found", mode="auto_update")
                    Log.cleanup_old_logs(log_db)
                    log_db.close()
                    
            finally:
                self._close_db_if_needed(db)
                
        except Exception as e:
            # Rollback and log error
            if not self.db:  # Only rollback if we created the session
                db.rollback()
            
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Failed to cleanup expired entries: {e}", context="AutoUpdateService.cleanup_expired_entries", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close()
            raise

    def get_status(self) -> dict:
        """Get auto-update service status"""
        db = SessionLocal()
        try:
            enabled = Setting.get_setting(db, "auto_update_enabled", True)
            active_sources = len(AutoUpdateSource.get_active_sources(db))
            
            # Get global status
            global_status = self.get_auto_update_status()
            
            return {
                "is_running": global_status["is_running"],
                "thread_alive": global_status["thread_alive"],
                "enabled": enabled,
                "active_sources": active_sources,
                "start_time": global_status["start_time"],
                "thread_id": global_status["thread_id"]
            }
        finally:
            db.close()

    async def resolve_manual_domains(self):
        """Resolve manual domains to keep IP mappings current"""
        db = SessionLocal()
        Log.create_rule_log(db, ActionType.update, None, "Resolving manual domains...", mode="auto_update")
        Log.cleanup_old_logs(db)
        db.close()
        
        try:
            db = self._get_db_session()
            try:
                manual_domains = Domain.get_manual_domains(db)
                max_ips_per_domain = Setting.get_setting(db, "max_ips_per_domain", 10)
                dns_resolver_primary = Setting.get_setting(db, "dns_resolver_primary", "1.1.1.1")
                dns_resolver_secondary = Setting.get_setting(db, "dns_resolver_secondary", "8.8.8.8")
                # Get critical IPs settings for protection during auto-update (separated by IP version)
                critical_ipv4_list = Setting.get_setting(db, "critical_ipv4_ips_ranges", [])
                critical_ipv6_list = Setting.get_setting(db, "critical_ipv6_ips_ranges", [])
                dns_service = DNSService(dns_resolver_primary, dns_resolver_secondary)
                
                for domain in manual_domains:
                    try:
                        # Resolve domain
                        resolution = dns_service.resolve_domain(domain.domain_name)
                        
                        # Collect all new IPs (both IPv4 and IPv6)
                        new_ips = []
                        
                        # Process IPv4 addresses with critical IP protection
                        for ip_str in resolution['ipv4']:
                            if dns_service.is_safe_ip_for_auto_update(ip_str, critical_ipv4_list, critical_ipv6_list, db):
                                new_ips.append({
                                    'ip_address': ip_str,
                                    'ip_version': 4
                                })
                        
                        # Process IPv6 addresses with critical IP protection
                        for ip_str in resolution['ipv6']:
                            if dns_service.is_safe_ip_for_auto_update(ip_str, critical_ipv4_list, critical_ipv6_list, db):
                                new_ips.append({
                                    'ip_address': ip_str,
                                    'ip_version': 6
                                })
                        
                        # Process all IPs as a batch with proper FIFO and CDN logic
                        if new_ips:
                            await self._process_domain_ips_batch(
                                domain, new_ips, max_ips_per_domain, db
                            )
                        else:
                            # No new IPs, just update timestamp and CDN status if needed
                            current_ips = db.query(IP).filter(IP.domain_id == domain.id).all()
                            existing_ip_addresses = {ip.ip_address for ip in current_ips}
                            
                            # Create set of all IPs (stored + resolved) to get true total count
                            all_ips = set(existing_ip_addresses)
                            all_ips.update(resolution['ipv4'])
                            all_ips.update(resolution['ipv6'])
                            total_unique_ips = len(all_ips)
                            
                            # CDN flagging based on total unique IPs
                            domain.is_cdn = total_unique_ips > max_ips_per_domain
                            domain.updated_at = datetime.now(timezone.utc)
                        
                    except Exception as e:
                        # Log error but continue with other domains
                        log_db = SessionLocal()
                        Log.create_error_log(log_db, f"Failed to resolve manual domain {domain.domain_name}: {e}", context="AutoUpdateService.resolve_manual_domains", mode="auto_update")
                        Log.cleanup_old_logs(log_db)
                        log_db.close()
                        continue
                
                db.commit()
                
            finally:
                self._close_db_if_needed(db)
            
        except Exception as e:
            # Rollback and log error
            if not self.db:  # Only rollback if we created the session
                db.rollback()
            
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Failed to resolve manual domains: {e}", context="AutoUpdateService.resolve_manual_domains", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close()
            raise

    async def process_auto_update_sources(self):
        """Process all active auto-update sources"""
        db = self._get_db_session()
        try:
            active_sources = AutoUpdateSource.get_active_sources(db)
            
            if not active_sources:
                log_db = SessionLocal()
                Log.create_rule_log(log_db, ActionType.update, None, "No active auto-update sources configured", mode="auto_update")
                Log.cleanup_old_logs(log_db)
                log_db.close()
                return
            
            rate_limit_delay = Setting.get_setting(db, "rate_limit_delay", 1.0)
            processed_count = 0
            
            for source in active_sources:
                try:
                    # Broadcast progress for each source
                    await live_events.broadcast_auto_update_cycle_event("progress", {
                        "message": f"Processing source: {source.name}",
                        "source_name": source.name,
                        "source_url": source.url,
                        "processed_sources": processed_count,
                        "total_sources": len(active_sources),
                        "phase": "source_processing"
                    })
                    
                    # Fetch content
                    content = await self._fetch_url_content(source.url)
                    
                    if content:
                        # Process content
                        await self._process_list_content(content, source, db)
                        
                        # Mark successful update
                        source.mark_successful_update()
                        
                        # Broadcast success for this source
                        await live_events.broadcast_auto_update_cycle_event("progress", {
                            "message": f"Successfully processed source: {source.name}",
                            "source_name": source.name,
                            "status": "success"
                        })
                    else:
                        source.mark_failed_update("Failed to fetch content")
                        
                        # Broadcast failure for this source
                        await live_events.broadcast_auto_update_cycle_event("progress", {
                            "message": f"Failed to process source: {source.name}",
                            "source_name": source.name,
                            "status": "failed",
                            "error": "Failed to fetch content"
                        })
                    
                    processed_count += 1
                    
                    # Rate limiting
                    await asyncio.sleep(rate_limit_delay)
                    
                except Exception as e:
                    source.mark_failed_update(str(e))
                    log_db = SessionLocal()
                    Log.create_error_log(log_db, f"Failed to process source {source.name}: {e}", context="AutoUpdateService.process_auto_update_sources", mode="auto_update")
                    Log.cleanup_old_logs(log_db)
                    log_db.close()
                    
                    # Broadcast failure for this source
                    await live_events.broadcast_auto_update_cycle_event("progress", {
                        "message": f"Error processing source: {source.name}",
                        "source_name": source.name,
                        "status": "error",
                        "error": str(e)
                    })
                    
                    processed_count += 1
                    continue
            
            db.commit()
            
        finally:
            self._close_db_if_needed(db)

    async def _fetch_url_content(self, url: str) -> Optional[str]:
        """Fetch content from URL"""
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        db = SessionLocal()
                        Log.create_error_log(db, f"HTTP {response.status} for URL: {url}", context="AutoUpdateService._fetch_url_content", mode="auto_update")
                        Log.cleanup_old_logs(db)
                        db.close()
                        return None
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to fetch URL {url}: {e}", context="AutoUpdateService._fetch_url_content", mode="auto_update")
            Log.cleanup_old_logs(db)
            db.close()
            return None

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

    async def _process_list_content(self, content: str, source: AutoUpdateSource, db: Session):
        """Process blacklist/whitelist content"""
        lines = content.strip().split('\n')
        processed_count = 0
        rule_expiration = Setting.get_setting(db, "rule_expiration", 86400)
        max_ips_per_domain = Setting.get_setting(db, "max_ips_per_domain", 10)
        expiration_time = datetime.now(timezone.utc) + timedelta(seconds=rule_expiration)
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            try:
                await self._process_list_entry(
                    line, source, expiration_time, max_ips_per_domain, db
                )
                processed_count += 1
                
            except Exception as e:
                db = SessionLocal()
                Log.create_error_log(db, f"Failed to process entry '{line}': {e}", context="AutoUpdateService._process_list_content", mode="auto_update")
                Log.cleanup_old_logs(db)
                db.close()
                continue
        
        # Log the processing result
        log_db = SessionLocal()
        Log.create_rule_log(log_db, ActionType.update, None, f"Processed {processed_count} entries from {source.name}", mode="auto_update")
        Log.cleanup_old_logs(log_db)
        log_db.close()

    async def _process_list_entry(self, entry: str, source: AutoUpdateSource, 
                                 expiration_time: datetime, max_ips_per_domain: int, db: Session):
        """Process a single entry from auto-update list"""
        
        # Strip port numbers from entries (e.g., "malware.example.com:3953" -> "malware.example.com")
        # Handle both IPv4:port and domain:port formats
        if ':' in entry:
            # Check if it might be IPv6 (has multiple colons)
            if entry.count(':') > 1:
                # Likely IPv6 - only strip port if it's at the end in brackets or after last colon
                # Examples: [2001:db8::1]:80 or 2001:db8::1
                if entry.startswith('[') and ']:' in entry:
                    # Format: [IPv6]:port
                    entry = entry.split(']:')[0][1:]  # Remove [brackets] and port
                # If no brackets, assume it's pure IPv6 without port
            else:
                # IPv4:port or domain:port format
                parts = entry.split(':')
                if len(parts) == 2:
                    # Check if the second part is a valid port number
                    try:
                        port = int(parts[1])
                        if 1 <= port <= 65535:
                            # Valid port, strip it
                            entry = parts[0]
                    except ValueError:
                        # Not a valid port number, keep original entry
                        pass
        
        # Continue with original processing logic
        # Determine list type from source
        list_type = ListType[source.list_type] if hasattr(source, 'list_type') else ListType.blacklist
        
        # Get critical IPs settings for protection during auto-update
        critical_ipv4_list = Setting.get_setting(db, "critical_ipv4_ips_ranges", [])
        critical_ipv6_list = Setting.get_setting(db, "critical_ipv6_ips_ranges", [])
        dns_service = DNSService()
        
        # Try to parse as IP address
        try:
            ip_obj = ipaddress.ip_address(entry)
            # Check if IP is safe and not in critical IPs list
            if IP.is_safe_ip(entry) and not dns_service.is_critical_ip(entry, critical_ipv4_list, critical_ipv6_list, db):
                await self._add_or_update_ip(
                    entry, ip_obj.version, list_type, 
                    SourceType.auto_update, db, source.url, expiration_time
                )
            return
        except ValueError:
            pass
        
        # Try to parse as IP range
        try:
            network = ipaddress.ip_network(entry, strict=False)
            # Check if IP range is safe and not overlapping with critical IP ranges
            if IPRange.is_safe_ip_range(entry) and not self._is_critical_ip_range(entry, critical_ipv4_list, critical_ipv6_list):
                await self._add_or_update_ip_range(
                    str(network), network.version, list_type,
                    SourceType.auto_update, db, source.url, expiration_time
                )
            return
        except ValueError:
            pass
        
        # Treat as domain
        if self._is_valid_domain(entry):
            domain = await self._add_or_update_domain(
                entry, list_type, SourceType.auto_update, db, source.url, expiration_time
            )
            if domain:
                # Resolve domain to IPs with critical IP protection
                dns_resolver_primary = Setting.get_setting(db, "dns_resolver_primary", "1.1.1.1")
                dns_resolver_secondary = Setting.get_setting(db, "dns_resolver_secondary", "8.8.8.8")
                dns_service = DNSService(dns_resolver_primary, dns_resolver_secondary)
                resolution = dns_service.resolve_domain(entry)
                
                # Collect all new IPs (both IPv4 and IPv6) for batch processing
                new_ips = []
                
                # Process IPv4 addresses with critical IP protection
                for ip_str in resolution['ipv4']:
                    if dns_service.is_safe_ip_for_auto_update(ip_str, critical_ipv4_list, critical_ipv6_list, db):
                        new_ips.append({
                            'ip_address': ip_str,
                            'ip_version': 4
                        })
                
                # Process IPv6 addresses with critical IP protection
                for ip_str in resolution['ipv6']:
                    if dns_service.is_safe_ip_for_auto_update(ip_str, critical_ipv4_list, critical_ipv6_list, db):
                        new_ips.append({
                            'ip_address': ip_str,
                            'ip_version': 6
                        })
                
                # Process all IPs as a batch with proper FIFO and CDN logic
                if new_ips:
                    await self._process_domain_ips_batch(
                        domain, new_ips, max_ips_per_domain, db, expiration_time
                    )

    def _is_critical_ip_range(self, ip_range_str: str, critical_ipv4_list: List[str], critical_ipv6_list: List[str]) -> bool:
        """Check if IP range overlaps with critical IPs or critical IP ranges"""
        try:
            network = ipaddress.ip_network(ip_range_str, strict=False)
            
            # Get dynamic critical IPs at runtime
            dns_service = DNSService()
            
            # Create a temporary session for this check
            temp_db = SessionLocal()
            try:
                dynamic_critical = dns_service._get_dynamic_critical_ips(temp_db)
            finally:
                temp_db.close()
            
            # Ensure critical IP lists are actually lists
            if critical_ipv4_list is None:
                critical_ipv4_list = []
            elif isinstance(critical_ipv4_list, str):
                try:
                    import json
                    critical_ipv4_list = json.loads(critical_ipv4_list)
                except:
                    critical_ipv4_list = []
            
            if critical_ipv6_list is None:
                critical_ipv6_list = []
            elif isinstance(critical_ipv6_list, str):
                try:
                    import json
                    critical_ipv6_list = json.loads(critical_ipv6_list)
                except:
                    critical_ipv6_list = []
            
            # Combine static (from database) with dynamic (runtime detection)
            if network.version == 4:
                combined_critical_list = list(critical_ipv4_list) + list(dynamic_critical['ipv4'])
            elif network.version == 6:
                combined_critical_list = list(critical_ipv6_list) + list(dynamic_critical['ipv6'])
            else:
                return False
            
            # Check if any critical IPs or ranges are in this range or overlap
            for item in combined_critical_list:
                try:
                    # Try as IP address first
                    critical_ip_obj = ipaddress.ip_address(item)
                    if critical_ip_obj in network:
                        return True
                except ValueError:
                    try:
                        # Try as network/CIDR range
                        critical_network = ipaddress.ip_network(item, strict=False)
                        if network.overlaps(critical_network):
                            return True
                    except ValueError:
                        continue
            
            return False
        except ValueError:
            return False

    async def _add_or_update_domain(self, domain_name: str, list_type: ListType, 
                                   source_type: SourceType, db: Session, source_url: str = None, 
                                   expiration_time: datetime = None) -> Optional[Domain]:
        """Add or update domain entry"""
        try:
            # Check if domain exists
            existing = db.query(Domain).filter(
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
                db.add(domain)
                db.flush()  # Get ID
                return domain
                
        except Exception as e:
            # Log error via database
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Failed to add/update domain {domain_name}: {e}", context="AutoUpdateService._add_or_update_domain", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close()
            return None

    async def _add_or_update_ip(self, ip_address: str, ip_version: int, 
                               list_type: ListType, source_type: SourceType, db: Session,
                               source_url: str = None, expiration_time: datetime = None):
        """Add or update IP entry"""
        try:
            # Check if IP exists
            existing = db.query(IP).filter(
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
                db.add(ip)
                
        except Exception as e:
            # Log error via database
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Failed to add/update IP {ip_address}: {e}", context="AutoUpdateService._add_or_update_ip", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close()

    async def _add_or_update_ip_range(self, ip_range: str, ip_version: int,
                                     list_type: ListType, source_type: SourceType, db: Session,
                                     source_url: str = None, expiration_time: datetime = None):
        """Add or update IP range entry"""
        try:
            # Normalize CIDR
            normalized_range = IPRange.normalize_cidr(ip_range)
            
            # Check if IP range exists
            existing = db.query(IPRange).filter(
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
                db.add(ip_range_obj)
                
        except Exception as e:
            # Log error via database
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Failed to add/update IP range {ip_range}: {e}", context="AutoUpdateService._add_or_update_ip_range", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close()

    async def _process_domain_ips_batch(self, domain: Domain, new_ips: list, max_ips_per_domain: int, 
                                       db: Session, expiration_time: datetime = None):
        """Process a batch of new IPs for a domain with proper FIFO management"""
        try:
            # Get current IPs for this domain
            current_ips = db.query(IP).filter(
                IP.domain_id == domain.id
            ).order_by(IP.created_at.asc()).all()
            
            current_count = len(current_ips)
            
            # Filter out IPs that already exist
            existing_ip_addresses = {ip.ip_address for ip in current_ips}
            truly_new_ips = [ip_data for ip_data in new_ips if ip_data['ip_address'] not in existing_ip_addresses]
            
            # Create set of all IPs (stored + new) to get true total count
            all_ips = set(existing_ip_addresses)
            for ip_data in new_ips:
                all_ips.add(ip_data['ip_address'])
            total_unique_ips = len(all_ips)
            
            # CDN flagging based on total unique IPs
            domain.is_cdn = total_unique_ips > max_ips_per_domain
            
            if not truly_new_ips:
                # No new IPs to add, just update CDN status and timestamp
                domain.updated_at = datetime.now(timezone.utc)
                return
            
            new_count = len(truly_new_ips)
            total_after_adding = current_count + new_count
            
            if total_after_adding <= max_ips_per_domain:
                # We can add all new IPs without exceeding the limit
                for ip_data in truly_new_ips:
                    ip = IP(
                        ip_address=ip_data['ip_address'],
                        ip_version=ip_data['ip_version'],
                        list_type=domain.list_type,
                        source_type=domain.source_type,
                        source_url=domain.source_url,
                        domain_id=domain.id,
                        expired_at=expiration_time if domain.source_type == SourceType.auto_update else None
                    )
                    db.add(ip)
                
                db.flush()
                
            else:
                # We exceed the limit - apply FIFO removal and add what we can
                if current_count == 0:
                    # New domain - just take the first max_ips_per_domain IPs
                    ips_to_add = truly_new_ips[:max_ips_per_domain]
                    
                    for ip_data in ips_to_add:
                        ip = IP(
                            ip_address=ip_data['ip_address'],
                            ip_version=ip_data['ip_version'],
                            list_type=domain.list_type,
                            source_type=domain.source_type,
                            source_url=domain.source_url,
                            domain_id=domain.id,
                            expired_at=expiration_time if domain.source_type == SourceType.auto_update else None
                        )
                        db.add(ip)
                    
                    db.flush()
                    
                else:
                    # Existing domain - apply FIFO removal
                    ips_to_remove_count = total_after_adding - max_ips_per_domain
                    
                    # Remove the oldest IPs (FIFO)
                    ips_to_remove = current_ips[:ips_to_remove_count]
                    
                    for ip in ips_to_remove:
                        db.delete(ip)  # This will trigger the firewall hooks
                    
                    # Calculate how many new IPs we can actually add
                    remaining_capacity = max_ips_per_domain - (current_count - len(ips_to_remove))
                    ips_to_add = truly_new_ips[:remaining_capacity]
                    
                    # Add only the IPs that fit within the limit
                    for ip_data in ips_to_add:
                        ip = IP(
                            ip_address=ip_data['ip_address'],
                            ip_version=ip_data['ip_version'],
                            list_type=domain.list_type,
                            source_type=domain.source_type,
                            source_url=domain.source_url,
                            domain_id=domain.id,
                            expired_at=expiration_time if domain.source_type == SourceType.auto_update else None
                        )
                        db.add(ip)
                    
                    db.flush()
            
            # Update domain's updated_at timestamp
            domain.updated_at = datetime.now(timezone.utc)
            
        except Exception as e:
            # Log error via database
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Failed to process domain IPs batch for {domain.domain_name}: {e}", context="AutoUpdateService._process_domain_ips_batch", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close()
            raise

    async def cleanup_old_logs(self):
        """Clean up old log entries"""
        try:
            db = self._get_db_session()
            try:
                max_entries = Setting.get_setting(db, "max_log_entries", 10000)
                max_days = Setting.get_setting(db, "log_retention_days", 7)
                
                deleted_count = Log.cleanup_old_logs(db, max_entries, max_days)
                
                # Log the cleanup if any entries were deleted
                if deleted_count > 0:
                    log_db = SessionLocal()
                    Log.create_rule_log(log_db, ActionType.update, None, f"Cleaned up {deleted_count} old log entries during auto-update", mode="auto_update")
                    Log.cleanup_old_logs(log_db)
                    log_db.close()
                
            finally:
                self._close_db_if_needed(db)
            
        except Exception as e:
            log_db = SessionLocal()
            Log.create_error_log(log_db, f"Failed to cleanup old logs: {e}", context="AutoUpdateService.cleanup_old_logs", mode="auto_update")
            Log.cleanup_old_logs(log_db)
            log_db.close() 