"""
DNSniper Controller - Business Logic Layer

This module contains all business logic extracted from the router files.
Each function corresponds to an endpoint and handles data processing,
database operations, validation, and transformations.
"""

import os
import logging
import json
import time
import asyncio
import signal
import ipaddress
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, text, func

from database import SessionLocal
from models import Domain, IP, IPRange, AutoUpdateSource, Setting, Log, User, APIToken
from models.domains import ListType, SourceType
from models.logs import ActionType, RuleType
from models.users import UserSession, LoginAttempt
from services.firewall_service import FirewallService
from services.dns_service import DNSService
from services.auto_update_service import AutoUpdateService
from services.live_events import live_events
from services.firewall_log_monitor import firewall_log_monitor
from services.scheduler_manager import scheduler_manager

logger = logging.getLogger(__name__)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def calculate_time_remaining(expired_at: Optional[datetime]) -> Optional[str]:
    """Calculate time remaining until expiration in a human-readable format"""
    if not expired_at:
        return None
    
    # Ensure we're working with timezone-aware datetime
    now = datetime.now(timezone.utc)
    if expired_at.tzinfo is None:
        expired_at = expired_at.replace(tzinfo=timezone.utc)
    
    # If already expired
    if expired_at <= now:
        return "Expired"
    
    # Calculate the difference
    diff = expired_at - now
    total_seconds = int(diff.total_seconds())
    
    # Convert to appropriate time unit
    if total_seconds < 3600:  # Less than 1 hour
        minutes = total_seconds // 60
        if minutes == 0:
            return "in less than 1 minute"
        elif minutes == 1:
            return "in 1 minute"
        else:
            return f"in {minutes} minutes"
    elif total_seconds < 86400:  # Less than 1 day
        hours = total_seconds // 3600
        if hours == 1:
            return "in 1 hour"
        else:
            return f"in {hours} hours"
    else:  # 1 day or more
        days = total_seconds // 86400
        if days == 1:
            return "in 1 day"
        else:
            return f"in {days} days"

# =============================================================================
# HEALTH CHECK CONTROLLER
# =============================================================================

async def get_health_check(db: Session) -> dict:
    """Health check endpoint controller"""
    try:
        # Test database connection
        db.execute(text("SELECT 1"))
        
        # Get basic stats
        domain_count = db.query(Domain).count()
        ip_count = db.query(IP).count()
        ip_range_count = db.query(IPRange).count()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "stats": {
                "domains": domain_count,
                "ips": ip_count,
                "ip_ranges": ip_range_count
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise Exception("Service unavailable")

# =============================================================================
# DASHBOARD CONTROLLER
# =============================================================================

async def get_dashboard_statistics(db: Session) -> dict:
    """Get comprehensive dashboard statistics"""
    try:
        # Basic counts
        total_domains = db.query(Domain).count()
        total_ips = db.query(IP).count()
        total_ip_ranges = db.query(IPRange).count()
        
        # Blacklist vs whitelist counts
        blacklist_domains = db.query(Domain).filter(Domain.list_type == "blacklist").count()
        whitelist_domains = db.query(Domain).filter(Domain.list_type == "whitelist").count()
        blacklist_ips = db.query(IP).filter(IP.list_type == "blacklist").count()
        whitelist_ips = db.query(IP).filter(IP.list_type == "whitelist").count()
        blacklist_ranges = db.query(IPRange).filter(IPRange.list_type == "blacklist").count()
        whitelist_ranges = db.query(IPRange).filter(IPRange.list_type == "whitelist").count()
        
        # Manual vs auto-update counts
        manual_domains = db.query(Domain).filter(Domain.source_type == "manual").count()
        auto_domains = db.query(Domain).filter(Domain.source_type == "auto_update").count()
        manual_ips = db.query(IP).filter(IP.source_type == "manual").count()
        auto_ips = db.query(IP).filter(IP.source_type == "auto_update").count()
        manual_ranges = db.query(IPRange).filter(IPRange.source_type == "manual").count()
        auto_ranges = db.query(IPRange).filter(IPRange.source_type == "auto_update").count()
        
        # Auto-update sources
        total_sources = db.query(AutoUpdateSource).count()
        active_sources = db.query(AutoUpdateSource).filter(AutoUpdateSource.is_active == True).count()
        
        # Get firewall status
        firewall = FirewallService()
        firewall_status = firewall.get_status()
        
        # Recent activity (last 24 hours)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        recent_logs = db.query(Log).filter(Log.created_at >= yesterday).count()
        
        return {
            "totals": {
                "domains": total_domains,
                "ips": total_ips,
                "ip_ranges": total_ip_ranges,
                "auto_update_sources": total_sources
            },
            "lists": {
                "blacklist": {
                    "domains": blacklist_domains,
                    "ips": blacklist_ips,
                    "ip_ranges": blacklist_ranges
                },
                "whitelist": {
                    "domains": whitelist_domains,
                    "ips": whitelist_ips,
                    "ip_ranges": whitelist_ranges
                }
            },
            "sources": {
                "manual": {
                    "domains": manual_domains,
                    "ips": manual_ips,
                    "ip_ranges": manual_ranges
                },
                "auto_update": {
                    "domains": auto_domains,
                    "ips": auto_ips,
                    "ip_ranges": auto_ranges
                }
            },
            "auto_update": {
                "total_sources": total_sources,
                "active_sources": active_sources,
                "is_running": AutoUpdateService.is_auto_update_running(),
                "enabled": Setting.get_setting(db, "auto_update_enabled", True)
            },
            "firewall": firewall_status,
            "activity": {
                "recent_logs_24h": recent_logs
            }
        }
    except Exception as e:
        logger.error(f"Dashboard stats failed: {e}")
        raise Exception("Failed to get dashboard stats")

# =============================================================================
# CLEAR DATA CONTROLLER
# =============================================================================

async def clear_all_database_data(db: Session) -> dict:
    """Clear all domains, IPs, and IP ranges from the database"""
    try:
        # Get counts before deletion for logging
        domain_count = db.query(Domain).count()
        ip_count = db.query(IP).count()
        ip_range_count = db.query(IPRange).count()
        
        # Delete all records
        db.query(Domain).delete()
        db.query(IP).delete()
        db.query(IPRange).delete()
        
        # Commit the transaction
        db.commit()
        
        # Log the action
        Log.create_rule_log(
            db, 
            ActionType.remove_rule, 
            None, 
            f"Cleared all database data: {domain_count} domains, {ip_count} IPs, {ip_range_count} IP ranges", 
            mode="manual"
        )
        Log.cleanup_old_logs(db)
        db.commit()
        
        # Clear firewall rules after database cleanup
        try:
            firewall = FirewallService()
            firewall.clear_all_rules()
            Log.create_rule_log(db, ActionType.remove_rule, None, "Firewall rules cleared after database cleanup", mode="manual")
            Log.cleanup_old_logs(db)
            db.commit()
        except Exception as fw_error:
            logger.error(f"Failed to clear firewall rules after database cleanup: {fw_error}")
            Log.create_error_log(db, f"Failed to clear firewall rules after database cleanup: {fw_error}", context="clear_all_data", mode="manual")
            Log.cleanup_old_logs(db)
            db.commit()
        
        return {
            "message": "All database data cleared successfully",
            "cleared": {
                "domains": domain_count,
                "ips": ip_count,
                "ip_ranges": ip_range_count,
                "total": domain_count + ip_count + ip_range_count
            },
            "firewall_cleared": True
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to clear database data: {e}")
        
        # Log the error
        try:
            Log.create_error_log(db, f"Failed to clear all database data: {e}", context="clear_all_data", mode="manual")
            Log.cleanup_old_logs(db)
            db.commit()
        except:
            pass
        
        raise Exception(f"Failed to clear database data: {str(e)}") 

# =============================================================================
# DOMAIN CONTROLLERS
# =============================================================================

async def get_domains_list(
    db: Session,
    list_type: Optional[str] = None,
    source_type: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
) -> dict:
    """Get domains with optional filtering and pagination"""
    # Get max_ips_per_domain setting for CDN calculation
    max_ips_per_domain = Setting.get_setting(db, "max_ips_per_domain", 10)
    
    # Build query with IP count using subquery to avoid N+1 problem
    ip_count_subquery = db.query(
        IP.domain_id,
        func.count(IP.id).label('ip_count')
    ).group_by(IP.domain_id).subquery()
    
    query = db.query(
        Domain,
        func.coalesce(ip_count_subquery.c.ip_count, 0).label('ip_count')
    ).outerjoin(ip_count_subquery, Domain.id == ip_count_subquery.c.domain_id)
    
    # Apply filters
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            query = query.filter(Domain.list_type == list_type_enum)
        except ValueError:
            raise ValueError("Invalid list_type")
    
    if source_type:
        try:
            source_type_enum = SourceType(source_type)
            query = query.filter(Domain.source_type == source_type_enum)
        except ValueError:
            raise ValueError("Invalid source_type")
    
    if search:
        query = query.filter(Domain.domain_name.contains(search.lower()))
    
    # Get total count before pagination
    total = query.count()
    
    # Calculate pagination
    offset = (page - 1) * per_page
    pages = (total + per_page - 1) // per_page  # Ceiling division
    
    # Get domains with pagination and IP counts
    domain_results = query.offset(offset).limit(per_page).all()
    
    # Build result with calculated CDN status
    result = []
    for domain, ip_count in domain_results:
        domain_dict = {
            "id": domain.id,
            "domain_name": domain.domain_name,
            "list_type": domain.list_type.value,
            "source_type": domain.source_type.value,
            "source_url": domain.source_url,
            "is_cdn": domain.is_cdn,  # Use stored value set during resolution
            "expired_at": domain.expired_at,
            "expires_in": calculate_time_remaining(domain.expired_at),
            "created_at": domain.created_at,
            "updated_at": domain.updated_at,
            "notes": domain.notes,
            "ip_count": ip_count
        }
        result.append(domain_dict)
    
    return {
        "domains": result,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages
    }

async def get_domain_by_id(db: Session, domain_id: int) -> dict:
    """Get a specific domain by ID"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise ValueError("Domain not found")
    
    # Get current IP count for display
    ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
    
    return {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "source_url": domain.source_url,
        "is_cdn": domain.is_cdn,  # Use stored value set during resolution
        "expired_at": domain.expired_at,
        "expires_in": calculate_time_remaining(domain.expired_at),
        "created_at": domain.created_at,
        "updated_at": domain.updated_at,
        "notes": domain.notes,
        "ip_count": ip_count
    }

async def create_domain(db: Session, domain_name: str, list_type: str, notes: Optional[str] = None) -> dict:
    """Create a new manual domain entry"""
    # Validate list_type
    try:
        list_type_enum = ListType(list_type)
    except ValueError:
        raise ValueError("Invalid list_type")
    
    # Clean domain name
    domain_name = domain_name.strip().lower()
    
    # Check if domain already exists
    existing = db.query(Domain).filter(Domain.domain_name == domain_name).first()
    if existing:
        raise ValueError("Domain already exists")
    
    # Create domain (without immediate resolution)
    domain = Domain(
        domain_name=domain_name,
        list_type=list_type_enum,
        source_type=SourceType.manual,  # Manual entries only
        notes=notes,
        expired_at=None  # Manual entries never expire
    )
    
    db.add(domain)
    db.commit()
    db.refresh(domain)
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.add_rule, RuleType.domain,
        f"Added manual domain: {domain_name} to {list_type_enum.value} (will be resolved in next auto-update cycle)",
        domain_name=domain_name,
        mode='manual'
    )
    
    ip_count = 0  # No IPs resolved yet
    
    # Calculate CDN status (will be False for new domains with 0 IPs)
    max_ips_per_domain = Setting.get_setting(db, "max_ips_per_domain", 10)
    is_cdn = ip_count > max_ips_per_domain  # False for new domains
    
    # Prepare response data
    response_data = {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "source_url": domain.source_url,
        "is_cdn": is_cdn,  # Use calculated value
        "expired_at": domain.expired_at,
        "expires_in": calculate_time_remaining(domain.expired_at),
        "created_at": domain.created_at,
        "updated_at": domain.updated_at,
        "notes": domain.notes,
        "ip_count": ip_count
    }
    
    # Broadcast live event
    await live_events.broadcast_domain_event("created", response_data)
    
    return response_data

async def update_domain(db: Session, domain_id: int, list_type: Optional[str] = None, notes: Optional[str] = None) -> dict:
    """Update a domain (manual entries only)"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise ValueError("Domain not found")
    
    if domain.source_type != SourceType.manual:
        raise ValueError("Can only update manual domains")
    
    # Update list_type if provided
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            old_list_type = domain.list_type
            domain.list_type = list_type_enum
            
            # Update all associated IPs
            ips = db.query(IP).filter(IP.domain_id == domain.id).all()
            for ip in ips:
                ip.list_type = list_type_enum
            
        except ValueError:
            raise ValueError("Invalid list_type")
    
    # Update notes if provided
    if notes is not None:
        domain.notes = notes
    
    domain.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.update, RuleType.domain,
        f"Updated manual domain: {domain.domain_name}",
        domain_name=domain.domain_name,
        mode='manual'
    )
    
    # Get current IP count for display
    ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
    
    # Prepare response data
    response_data = {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "source_url": domain.source_url,
        "is_cdn": domain.is_cdn,  # Use stored value set during resolution
        "expired_at": domain.expired_at,
        "expires_in": calculate_time_remaining(domain.expired_at),
        "created_at": domain.created_at,
        "updated_at": domain.updated_at,
        "notes": domain.notes,
        "ip_count": ip_count
    }
    
    # Broadcast live event
    await live_events.broadcast_domain_event("updated", response_data)
    
    return response_data

async def delete_domain(db: Session, domain_id: int) -> dict:
    """Delete a domain (allows deletion of both manual and auto-update entries)"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise ValueError("Domain not found")
    
    domain_name = domain.domain_name
    source_type = domain.source_type.value
    
    # Prepare event data before deletion
    event_data = {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "notes": domain.notes
    }
    
    db.delete(domain)
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.remove_rule, RuleType.domain,
        f"Deleted {source_type} domain: {domain_name}",
        domain_name=domain_name,
        mode='manual' if source_type == 'manual' else 'auto'
    )
    
    # Broadcast live event
    await live_events.broadcast_domain_event("deleted", event_data)
    
    return {"message": f"Domain {domain_name} deleted successfully"}

async def get_domain_ips(db: Session, domain_id: int) -> list:
    """Get all IPs associated with a domain"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise ValueError("Domain not found")
    
    ips = db.query(IP).filter(IP.domain_id == domain.id).all()
    
    result = []
    for ip in ips:
        result.append({
            "id": ip.id,
            "ip_address": ip.ip_address,
            "ip_version": ip.ip_version,
            "list_type": ip.list_type.value,
            "source_type": ip.source_type.value,
            "expired_at": ip.expired_at,
            "created_at": ip.created_at,
            "updated_at": ip.updated_at
        })
    
    return result

async def resolve_domain_manually(db: Session, domain_id: int) -> dict:
    """Manually resolve domain to update IP mappings"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise ValueError("Domain not found")
    
    if domain.source_type != SourceType.manual:
        raise ValueError("Can only resolve manual domains")
    
    # Resolve domain
    dns_service = DNSService()
    resolution = dns_service.resolve_domain(domain.domain_name)
    
    # Get settings and current state
    max_ips_per_domain = Setting.get_setting(db, "max_ips_per_domain", 10)
    
    # Get existing IPs for this domain
    existing_ips = db.query(IP).filter(IP.domain_id == domain.id).all()
    existing_ip_addresses = {ip.ip_address for ip in existing_ips}
    
    # Create set of all IPs (stored + resolved) to get true total count
    all_ips = set(existing_ip_addresses)
    all_ips.update(resolution['ipv4'])
    all_ips.update(resolution['ipv6'])
    total_unique_ips = len(all_ips)
    
    # CDN flagging based on total unique IPs
    domain.is_cdn = total_unique_ips > max_ips_per_domain
    
    # Collect new IPs that don't already exist
    new_ips = []
    
    # Add new IPv4 addresses
    for ip_str in resolution['ipv4']:
        if ip_str not in existing_ip_addresses:
            new_ips.append({
                'ip_address': ip_str,
                'ip_version': 4
            })
    
    # Add new IPv6 addresses
    for ip_str in resolution['ipv6']:
        if ip_str not in existing_ip_addresses:
            new_ips.append({
                'ip_address': ip_str,
                'ip_version': 6
            })
    
    if new_ips:
        current_count = len(existing_ips)
        new_count = len(new_ips)
        total_after_adding = current_count + new_count
        
        if total_after_adding <= max_ips_per_domain:
            # We can add all new IPs without exceeding the limit
            for ip_data in new_ips:
                ip = IP(
                    ip_address=ip_data['ip_address'],
                    ip_version=ip_data['ip_version'],
                    list_type=domain.list_type,
                    source_type=SourceType.manual,
                    domain_id=domain.id,
                    expired_at=None
                )
                db.add(ip)
        else:
            # We exceed the limit - apply FIFO removal and add what we can
            if current_count == 0:
                # New domain - just take the first max_ips_per_domain IPs
                ips_to_add = new_ips[:max_ips_per_domain]
                
                for ip_data in ips_to_add:
                    ip = IP(
                        ip_address=ip_data['ip_address'],
                        ip_version=ip_data['ip_version'],
                        list_type=domain.list_type,
                        source_type=SourceType.manual,
                        domain_id=domain.id,
                        expired_at=None
                    )
                    db.add(ip)
            else:
                # Existing domain - apply FIFO removal
                ips_to_remove_count = total_after_adding - max_ips_per_domain
                
                # Remove the oldest existing IPs (FIFO)
                oldest_ips = sorted(existing_ips, key=lambda x: x.created_at)[:ips_to_remove_count]
                for ip in oldest_ips:
                    db.delete(ip)  # This will trigger firewall hooks
                
                # Calculate remaining capacity after removal
                remaining_capacity = max_ips_per_domain - (current_count - len(oldest_ips))
                ips_to_add = new_ips[:remaining_capacity]
                
                for ip_data in ips_to_add:
                    ip = IP(
                        ip_address=ip_data['ip_address'],
                        ip_version=ip_data['ip_version'],
                        list_type=domain.list_type,
                        source_type=SourceType.manual,
                        domain_id=domain.id,
                        expired_at=None
                    )
                    db.add(ip)
        
        domain.updated_at = datetime.now(timezone.utc)
        db.commit()
        
        # Log the action
        final_ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
        Log.create_rule_log(
            db, ActionType.update, RuleType.domain,
            f"Manually resolved domain: {domain.domain_name} (total unique IPs: {total_unique_ips}, stored: {final_ip_count}, CDN: {domain.is_cdn})",
            domain_name=domain.domain_name,
            mode='manual'
        )
        
        # Broadcast live event for domain resolution
        event_data = {
            "id": domain.id,
            "domain_name": domain.domain_name,
            "list_type": domain.list_type.value,
            "source_type": domain.source_type.value,
            "ip_count": final_ip_count,
            "is_cdn": domain.is_cdn,
            "resolution": resolution
        }
        await live_events.broadcast_domain_event("resolved", event_data)
    
    else:
        # No new IPs but still update CDN status and timestamp
        domain.updated_at = datetime.now(timezone.utc)
        db.commit()
        
        # Log when no new IPs are found
        current_count = len(existing_ips)
        Log.create_rule_log(
            db, ActionType.update, RuleType.domain,
            f"Manual resolution of domain {domain.domain_name}: no new IPs found (total unique IPs: {total_unique_ips}, stored: {current_count}, CDN: {domain.is_cdn})",
            domain_name=domain.domain_name,
            mode='manual'
        )
    
    return {
        "message": f"Domain {domain.domain_name} resolved successfully",
        "resolution": resolution,
        "ip_count": db.query(IP).filter(IP.domain_id == domain.id).count(),
        "is_cdn": domain.is_cdn
    } 

# =============================================================================
# IP CONTROLLERS
# =============================================================================

async def get_ips_list(
    db: Session,
    list_type: Optional[str] = None,
    source_type: Optional[str] = None,
    ip_version: Optional[int] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
) -> dict:
    """Get IPs with optional filtering and search"""
    # Join with domains table to get domain names
    query = db.query(IP, Domain.domain_name).outerjoin(Domain, IP.domain_id == Domain.id)
    
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            query = query.filter(IP.list_type == list_type_enum)
        except ValueError:
            raise ValueError("Invalid list_type")
    
    if source_type:
        try:
            source_type_enum = SourceType(source_type)
            query = query.filter(IP.source_type == source_type_enum)
        except ValueError:
            raise ValueError("Invalid source_type")
    
    if ip_version:
        query = query.filter(IP.ip_version == ip_version)
    
    if search:
        query = query.filter(IP.ip_address.contains(search))
    
    # Get total count before pagination
    total = query.count()
    
    # Calculate pagination
    offset = (page - 1) * per_page
    pages = (total + per_page - 1) // per_page  # Ceiling division
    
    ip_results = query.offset(offset).limit(per_page).all()
    
    result = []
    for ip, domain_name in ip_results:
        result.append({
            "id": ip.id,
            "ip_address": ip.ip_address,
            "ip_version": ip.ip_version,
            "list_type": ip.list_type.value,
            "source_type": ip.source_type.value,
            "source_url": ip.source_url,
            "domain_id": ip.domain_id,
            "domain_name": domain_name,
            "expired_at": ip.expired_at,
            "expires_in": calculate_time_remaining(ip.expired_at),
            "created_at": ip.created_at,
            "updated_at": ip.updated_at,
            "notes": ip.notes
        })
    
    return {
        "ips": result,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages
    }

async def create_ip(db: Session, ip_address: str, list_type: str, notes: Optional[str] = None) -> dict:
    """Create a new manual IP entry"""
    # Validate IP address
    is_valid, ip_version = IP.validate_ip_address(ip_address)
    if not is_valid:
        raise ValueError("Invalid IP address")
    
    # Validate list_type
    try:
        list_type_enum = ListType(list_type)
    except ValueError:
        raise ValueError("Invalid list_type")
    
    # Check if IP already exists
    existing = db.query(IP).filter(IP.ip_address == ip_address).first()
    if existing:
        raise ValueError("IP already exists")
    
    # Create IP
    ip = IP(
        ip_address=ip_address,
        ip_version=ip_version,
        list_type=list_type_enum,
        source_type=SourceType.manual,
        notes=notes,
        expired_at=None  # Manual entries never expire
    )
    
    db.add(ip)
    db.commit()
    db.refresh(ip)
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.add_rule, RuleType.ip,
        f"Added manual IP: {ip_address} to {list_type_enum.value}",
        ip_address=ip_address,
        mode='manual'
    )
    
    # Prepare response data
    response_data = {
        "id": ip.id,
        "ip_address": ip.ip_address,
        "ip_version": ip.ip_version,
        "list_type": ip.list_type.value,
        "source_type": ip.source_type.value,
        "source_url": ip.source_url,
        "domain_id": ip.domain_id,
        "domain_name": None,  # Manual IPs typically don't have domain associations
        "expired_at": ip.expired_at,
        "expires_in": calculate_time_remaining(ip.expired_at),
        "created_at": ip.created_at,
        "updated_at": ip.updated_at,
        "notes": ip.notes
    }
    
    # Broadcast live event
    await live_events.broadcast_ip_event("created", response_data)
    
    return response_data

async def update_ip(db: Session, ip_id: int, list_type: Optional[str] = None, notes: Optional[str] = None) -> dict:
    """Update an IP (manual entries only)"""
    ip = db.query(IP).filter(IP.id == ip_id).first()
    if not ip:
        raise ValueError("IP not found")
    
    if ip.source_type != SourceType.manual:
        raise ValueError("Can only update manual IPs")
    
    # Update list_type if provided
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            ip.list_type = list_type_enum
        except ValueError:
            raise ValueError("Invalid list_type")
    
    # Update notes if provided
    if notes is not None:
        ip.notes = notes
    
    ip.updated_at = datetime.utcnow()
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.update, RuleType.ip,
        f"Updated manual IP: {ip.ip_address}",
        ip_address=ip.ip_address,
        mode='manual'
    )
    
    # Prepare response data
    response_data = {
        "id": ip.id,
        "ip_address": ip.ip_address,
        "ip_version": ip.ip_version,
        "list_type": ip.list_type.value,
        "source_type": ip.source_type.value,
        "source_url": ip.source_url,
        "domain_id": ip.domain_id,
        "domain_name": None,  # Manual IPs typically don't have domain associations
        "expired_at": ip.expired_at,
        "expires_in": calculate_time_remaining(ip.expired_at),
        "created_at": ip.created_at,
        "updated_at": ip.updated_at,
        "notes": ip.notes
    }
    
    # Broadcast live event
    await live_events.broadcast_ip_event("updated", response_data)
    
    return response_data

async def delete_ip(db: Session, ip_id: int) -> dict:
    """Delete an IP (allows deletion of both manual and auto-update entries)"""
    ip = db.query(IP).filter(IP.id == ip_id).first()
    if not ip:
        raise ValueError("IP not found")
    
    ip_address = ip.ip_address
    source_type = ip.source_type.value
    
    # Get domain name if IP has a domain association
    domain_name = None
    if ip.domain_id:
        domain = db.query(Domain).filter(Domain.id == ip.domain_id).first()
        if domain:
            domain_name = domain.domain_name
    
    # Prepare event data before deletion
    event_data = {
        "id": ip.id,
        "ip_address": ip.ip_address,
        "ip_version": ip.ip_version,
        "list_type": ip.list_type.value,
        "source_type": ip.source_type.value,
        "domain_name": domain_name,
        "notes": ip.notes
    }
    
    db.delete(ip)
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.remove_rule, RuleType.ip,
        f"Deleted {source_type} IP: {ip_address}",
        ip_address=ip_address,
        mode='manual' if source_type == 'manual' else 'auto'
    )
    
    # Broadcast live event
    await live_events.broadcast_ip_event("deleted", event_data)
    
    return {"message": f"IP {ip_address} deleted successfully"}

# =============================================================================
# IP RANGE CONTROLLERS
# =============================================================================

async def get_ip_ranges_list(
    db: Session,
    list_type: Optional[str] = None,
    source_type: Optional[str] = None,
    ip_version: Optional[int] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
) -> dict:
    """Get IP ranges with optional filtering and pagination"""
    query = db.query(IPRange)
    
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            query = query.filter(IPRange.list_type == list_type_enum)
        except ValueError:
            raise ValueError("Invalid list_type")
    
    if source_type:
        try:
            source_type_enum = SourceType(source_type)
            query = query.filter(IPRange.source_type == source_type_enum)
        except ValueError:
            raise ValueError("Invalid source_type")
    
    if ip_version:
        query = query.filter(IPRange.ip_version == ip_version)
    
    if search:
        query = query.filter(IPRange.ip_range.contains(search))
    
    # Get total count before pagination
    total = query.count()
    
    # Calculate pagination
    offset = (page - 1) * per_page
    pages = (total + per_page - 1) // per_page  # Ceiling division
    
    ip_ranges = query.offset(offset).limit(per_page).all()
    
    result = []
    for ip_range in ip_ranges:
        result.append({
            "id": ip_range.id,
            "ip_range": ip_range.ip_range,
            "ip_version": ip_range.ip_version,
            "list_type": ip_range.list_type.value,
            "source_type": ip_range.source_type.value,
            "source_url": ip_range.source_url,
            "expired_at": ip_range.expired_at,
            "expires_in": calculate_time_remaining(ip_range.expired_at),
            "created_at": ip_range.created_at,
            "updated_at": ip_range.updated_at,
            "notes": ip_range.notes
        })
    
    return {
        "ip_ranges": result,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages
    }

async def get_ip_range_by_id(db: Session, ip_range_id: int) -> dict:
    """Get a specific IP range by ID"""
    ip_range = db.query(IPRange).filter(IPRange.id == ip_range_id).first()
    if not ip_range:
        raise ValueError("IP range not found")
    
    return {
        "id": ip_range.id,
        "ip_range": ip_range.ip_range,
        "ip_version": ip_range.ip_version,
        "list_type": ip_range.list_type.value,
        "source_type": ip_range.source_type.value,
        "source_url": ip_range.source_url,
        "expired_at": ip_range.expired_at,
        "expires_in": calculate_time_remaining(ip_range.expired_at),
        "created_at": ip_range.created_at,
        "updated_at": ip_range.updated_at,
        "notes": ip_range.notes
    }

async def create_ip_range(db: Session, ip_range_str: str, list_type: str, notes: Optional[str] = None) -> dict:
    """Create a new manual IP range entry"""
    # Validate IP range
    is_valid, ip_version = IPRange.validate_ip_range(ip_range_str)
    if not is_valid:
        raise ValueError("Invalid IP range format")
    
    # Check if it's safe to block
    if not IPRange.is_safe_ip_range(ip_range_str):
        raise ValueError("IP range is not safe to block (private, loopback, or too broad)")
    
    # Validate list_type
    try:
        list_type_enum = ListType(list_type)
    except ValueError:
        raise ValueError("Invalid list_type")
    
    # Normalize CIDR
    normalized_range = IPRange.normalize_cidr(ip_range_str)
    
    # Check if IP range already exists
    existing = db.query(IPRange).filter(IPRange.ip_range == normalized_range).first()
    if existing:
        raise ValueError("IP range already exists")
    
    # Create IP range
    ip_range = IPRange(
        ip_range=normalized_range,
        ip_version=ip_version,
        list_type=list_type_enum,
        source_type=SourceType.manual,
        notes=notes,
        expired_at=None  # Manual entries never expire
    )
    
    db.add(ip_range)
    db.commit()
    db.refresh(ip_range)
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.add_rule, RuleType.ip_range,
        f"Added manual IP range: {normalized_range} to {list_type_enum.value}",
        mode='manual'
    )
    
    # Prepare response data
    response_data = {
        "id": ip_range.id,
        "ip_range": ip_range.ip_range,
        "ip_version": ip_range.ip_version,
        "list_type": ip_range.list_type.value,
        "source_type": ip_range.source_type.value,
        "source_url": ip_range.source_url,
        "expired_at": ip_range.expired_at,
        "expires_in": calculate_time_remaining(ip_range.expired_at),
        "created_at": ip_range.created_at,
        "updated_at": ip_range.updated_at,
        "notes": ip_range.notes
    }
    
    # Broadcast live event
    await live_events.broadcast_ip_range_event("created", response_data)
    
    return response_data

async def update_ip_range(db: Session, ip_range_id: int, list_type: Optional[str] = None, notes: Optional[str] = None) -> dict:
    """Update an IP range (manual entries only)"""
    ip_range = db.query(IPRange).filter(IPRange.id == ip_range_id).first()
    if not ip_range:
        raise ValueError("IP range not found")
    
    if ip_range.source_type != SourceType.manual:
        raise ValueError("Can only update manual IP ranges")
    
    # Update list_type if provided
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            ip_range.list_type = list_type_enum
        except ValueError:
            raise ValueError("Invalid list_type")
    
    # Update notes if provided
    if notes is not None:
        ip_range.notes = notes
    
    ip_range.updated_at = datetime.utcnow()
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.update, RuleType.ip_range,
        f"Updated manual IP range: {ip_range.ip_range}",
        mode='manual'
    )
    
    # Prepare response data
    response_data = {
        "id": ip_range.id,
        "ip_range": ip_range.ip_range,
        "ip_version": ip_range.ip_version,
        "list_type": ip_range.list_type.value,
        "source_type": ip_range.source_type.value,
        "source_url": ip_range.source_url,
        "expired_at": ip_range.expired_at,
        "expires_in": calculate_time_remaining(ip_range.expired_at),
        "created_at": ip_range.created_at,
        "updated_at": ip_range.updated_at,
        "notes": ip_range.notes
    }
    
    # Broadcast live event
    await live_events.broadcast_ip_range_event("updated", response_data)
    
    return response_data

async def delete_ip_range(db: Session, ip_range_id: int) -> dict:
    """Delete an IP range (allows deletion of both manual and auto-update entries)"""
    ip_range = db.query(IPRange).filter(IPRange.id == ip_range_id).first()
    if not ip_range:
        raise ValueError("IP range not found")
    
    ip_range_str = ip_range.ip_range
    source_type = ip_range.source_type.value
    
    # Prepare event data before deletion
    event_data = {
        "id": ip_range.id,
        "ip_range": ip_range.ip_range,
        "ip_version": ip_range.ip_version,
        "list_type": ip_range.list_type.value,
        "source_type": ip_range.source_type.value,
        "notes": ip_range.notes
    }
    
    db.delete(ip_range)
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.remove_rule, RuleType.ip_range,
        f"Deleted {source_type} IP range: {ip_range_str}",
        mode='manual' if source_type == 'manual' else 'auto'
    )
    
    # Broadcast live event
    await live_events.broadcast_ip_range_event("deleted", event_data)
    
    return {"message": f"IP range {ip_range_str} deleted successfully"}

# =============================================================================
# SETTINGS CONTROLLERS
# =============================================================================

def validate_setting_value(key: str, value):
    """Validate setting values according to constraints"""
    
    # Type conversion and validation
    def convert_to_number(val, setting_name):
        """Convert value to number (int or float)"""
        if isinstance(val, (int, float)):
            return val
        if isinstance(val, str):
            val = val.strip()
            # Try int first, then float
            try:
                if '.' in val:
                    return float(val)
                else:
                    return int(val)
            except ValueError:
                raise ValueError(f"Value for {setting_name} must be a valid number")
        raise ValueError(f"Value for {setting_name} must be a number")
    
    def convert_to_boolean(val, setting_name):
        """Convert value to boolean"""
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            val = val.lower().strip()
            if val in ('true', '1', 'yes', 'on'):
                return True
            elif val in ('false', '0', 'no', 'off'):
                return False
            else:
                raise ValueError(f"Value for {setting_name} must be a boolean (true/false)")
        if isinstance(val, (int, float)):
            return bool(val)
        raise ValueError(f"Value for {setting_name} must be a boolean")
    
    # Numeric validation rules
    numeric_constraints = {
        'auto_update_interval': {'min': 300, 'max': 86400},
        'rule_expiration': {'min': 600, 'max': 604800},
        'max_ips_per_domain': {'min': 1, 'max': 50},
        'rate_limit_delay': {'min': 0.1, 'max': 10.0},
        'log_retention_days': {'min': 1, 'max': 365},
        'max_log_entries': {'min': 1000, 'max': 100000}
    }
    
    if key in numeric_constraints:
        converted_value = convert_to_number(value, key)
        constraints = numeric_constraints[key]
        if converted_value < constraints['min'] or converted_value > constraints['max']:
            raise ValueError(
                f"Value for {key} must be between {constraints['min']} and {constraints['max']}"
            )
        return converted_value  # Return the converted value
    
    # DNS resolver validation
    if key in ['dns_resolver_primary', 'dns_resolver_secondary']:
        import re
        if not isinstance(value, str):
            value = str(value)
        value = value.strip()
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if not re.match(ipv4_pattern, value):
            raise ValueError(f"{key.replace('_', ' ').title()} must be a valid IPv4 address string")
        return value
    
    # Boolean validation with conversion
    boolean_settings = ['logging_enabled', 'automatic_domain_resolution', 'auto_update_enabled']
    if key in boolean_settings:
        converted_value = convert_to_boolean(value, key)
        return converted_value  # Return the converted value
    
    # Critical IPs validation
    if key == 'critical_ipv4_ips_ranges':
        if not isinstance(value, list):
            raise ValueError("Critical IPv4 IPs/Ranges must be a list of IPv4 addresses and CIDR ranges")
        
        for item in value:
            if not isinstance(item, str):
                raise ValueError("Each critical IPv4 item must be a string")
            try:
                # Try as IP address first
                ipaddress.IPv4Address(item)
            except ValueError:
                try:
                    # Try as network/CIDR range
                    ipaddress.IPv4Network(item, strict=False)
                except ValueError:
                    raise ValueError(f"Invalid IPv4 address or CIDR range in critical IPv4 list: {item}")
        return value
    
    if key == 'critical_ipv6_ips_ranges':
        if not isinstance(value, list):
            raise ValueError("Critical IPv6 IPs/Ranges must be a list of IPv6 addresses and CIDR ranges")
        
        for item in value:
            if not isinstance(item, str):
                raise ValueError("Each critical IPv6 item must be a string")
            try:
                # Try as IP address first
                ipaddress.IPv6Address(item)
            except ValueError:
                try:
                    # Try as network/CIDR range
                    ipaddress.IPv6Network(item, strict=False)
                except ValueError:
                    raise ValueError(f"Invalid IPv6 address or CIDR range in critical IPv6 list: {item}")
        return value
    
    # SSL settings validation
    if key == 'force_https':
        converted_value = convert_to_boolean(value, key)
        return converted_value
    
    if key in ['ssl_domain', 'ssl_certfile', 'ssl_keyfile']:
        if not isinstance(value, str):
            value = str(value)
        value = value.strip()
        return value
    
    # SSL file validation
    if key == 'ssl_certfile' and value:
        value = value.strip()
        if not os.path.isfile(value):
            raise ValueError(f"SSL certificate file does not exist: {value}")
        if not value.endswith(('.pem', '.crt', '.cert')):
            raise ValueError("SSL certificate file must be a .pem, .crt, or .cert file")
        return value
    
    if key == 'ssl_keyfile' and value:
        value = value.strip()
        if not os.path.isfile(value):
            raise ValueError(f"SSL private key file does not exist: {value}")
        if not value.endswith(('.pem', '.key')):
            raise ValueError("SSL private key file must be a .pem or .key file")
        return value
    
    # Return the original value if no specific validation is needed
    return value

def validate_ssl_configuration(db: Session, new_settings: dict = None):
    """Validate SSL configuration when SSL is enabled."""
    current_settings = Setting.get_all_settings(db)
    if new_settings:
        current_settings.update(new_settings)
    
    enable_ssl = current_settings.get('enable_ssl', False)
    force_https = current_settings.get('force_https', False)
    ssl_domain = current_settings.get('ssl_domain', '').strip()
    ssl_certfile = current_settings.get('ssl_certfile', '').strip()
    ssl_keyfile = current_settings.get('ssl_keyfile', '').strip()

    # Only validate if SSL is enabled OR if force_https is enabled
    if enable_ssl or force_https:
        # If either is enabled, all SSL fields must be present and valid
        if not ssl_domain:
            raise ValueError("SSL domain name is required when SSL is enabled.")
        if not ssl_certfile:
            raise ValueError("SSL certificate file path is required when SSL is enabled.")
        if not ssl_keyfile:
            raise ValueError("SSL private key file path is required when SSL is enabled.")
        
        # Validate domain format
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, ssl_domain):
            raise ValueError("SSL domain name must be a valid domain format")
        
        # Validate certificate and key files exist
        if not os.path.isfile(ssl_certfile):
            raise ValueError(f"SSL certificate file does not exist: {ssl_certfile}")
        if not os.path.isfile(ssl_keyfile):
            raise ValueError(f"SSL private key file does not exist: {ssl_keyfile}")
        
        # Try to validate certificate/key pair
        try:
            import ssl
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(ssl_certfile, ssl_keyfile)
        except Exception as e:
            raise ValueError(f"Invalid SSL certificate/key pair: {str(e)}")
    
    return True

async def get_all_settings(db: Session) -> dict:
    """Get all application settings"""
    settings = Setting.get_all_settings(db)
    # Ensure both fields are present for the frontend
    if "dns_resolver_primary" not in settings:
        settings["dns_resolver_primary"] = "1.1.1.1"
    if "dns_resolver_secondary" not in settings:
        settings["dns_resolver_secondary"] = "8.8.8.8"
    # Remove legacy fields if present
    for legacy in ["dns_resolvers", "dns_resolver_ipv4", "dns_resolver_ipv6"]:
        if legacy in settings:
            del settings[legacy]
    return settings

async def get_setting_by_key(db: Session, key: str) -> dict:
    """Get a specific setting by key"""
    setting = db.query(Setting).filter(Setting.key == key).first()
    if not setting:
        raise ValueError("Setting not found")
    
    return {
        "key": setting.key,
        "value": setting.get_value(),
        "description": setting.description
    }

async def update_setting(db: Session, key: str, value: Any) -> dict:
    """Update a specific setting"""
    try:
        # Validate and convert the setting value
        converted_value = validate_setting_value(key, value)
        
        # Check if this is an SSL setting
        ssl_keys = {'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'}
        is_ssl_setting = key in ssl_keys
        
        # Check if this is a scheduler-related setting
        is_scheduler_setting = key in ["auto_update_enabled", "auto_update_interval"]
        
        # If updating SSL setting, validate complete SSL configuration
        if is_ssl_setting:
            validate_ssl_configuration(db, {key: converted_value})
        
        # Update the setting with the converted value
        Setting.set_setting(db, key, converted_value)
        
        # Log the action
        logger.info(f"Setting {key} updated to: {converted_value}")
        
        # Restart firewall log monitoring if logging_enabled was changed
        logging_restarted = False
        if key == "logging_enabled":
            firewall_log_monitor.restart_if_needed()
            logging_restarted = True
        
        # Notify scheduler if auto-update settings changed
        scheduler_notified = False
        if is_scheduler_setting:
            scheduler_manager.notify_settings_changed()
            scheduler_notified = True
            logger.info(f"Notified scheduler of {key} change to: {converted_value}")
        
        response_data = {
            "message": f"Setting {key} updated successfully", 
            "value": converted_value,
            "scheduler_notified": scheduler_notified
        }
        
        # If SSL setting changed, trigger server restart
        ssl_restart_required = False
        if is_ssl_setting:
            response_data["ssl_restart_required"] = True
            ssl_restart_required = True
            logger.info("SSL setting changed, server restart will be triggered")
        
        # Broadcast live event for individual setting update
        await live_events.broadcast_settings_event("updated", {
            "category": "individual",
            "key": key,
            "value": converted_value,
            "is_ssl_setting": is_ssl_setting,
            "is_scheduler_setting": is_scheduler_setting,
            "ssl_restart_required": ssl_restart_required,
            "logging_restarted": logging_restarted,
            "scheduler_notified": scheduler_notified
        })
        
        return response_data
        
    except ValueError as e:
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"Failed to update setting {key}: {e}")
        raise Exception(f"Failed to update setting: {str(e)}")

async def update_settings_bulk(db: Session, settings: Dict[str, Any]) -> dict:
    """Update multiple settings at once (excluding SSL settings)"""
    try:
        updated_settings = {}
        validation_errors = {}
        logging_enabled_changed = False
        scheduler_settings_changed = False
        
        # Only update non-SSL settings
        ssl_keys = {'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'}
        for key, value in settings.items():
            if key in ssl_keys:
                continue
            try:
                # Validate and convert the value
                converted_value = validate_setting_value(key, value)
                Setting.set_setting(db, key, converted_value)
                updated_settings[key] = converted_value
                logger.info(f"Setting {key} updated to: {converted_value}")
                
                # Track if logging_enabled was changed
                if key == "logging_enabled":
                    logging_enabled_changed = True
                
                # Track if scheduler-related settings were changed
                if key in ["auto_update_enabled", "auto_update_interval"]:
                    scheduler_settings_changed = True
                    
            except ValueError as e:
                validation_errors[key] = str(e)
                
        if validation_errors:
            raise ValueError(f"Validation failed: {validation_errors}")
        
        # Restart firewall log monitoring if logging_enabled was changed
        if logging_enabled_changed:
            firewall_log_monitor.restart_if_needed()
        
        # Notify scheduler if auto-update settings changed
        if scheduler_settings_changed:
            scheduler_manager.notify_settings_changed()
            logger.info("Notified scheduler of settings changes")
            
        # Broadcast live event for bulk settings update
        if updated_settings:
            await live_events.broadcast_settings_event("updated", {
                "category": "bulk",
                "updated_settings": updated_settings,
                "count": len(updated_settings),
                "logging_restarted": logging_enabled_changed,
                "scheduler_notified": scheduler_settings_changed
            })
            
        return {
            "message": f"Successfully updated {len(updated_settings)} settings",
            "updated_settings": updated_settings,
            "scheduler_notified": scheduler_settings_changed
        }
    except Exception as e:
        logger.error(f"Failed to update settings: {e}")
        raise Exception(f"Failed to update settings: {str(e)}")

async def update_ssl_settings(db: Session, ssl_update: dict) -> dict:
    """Update SSL settings. Restart if enable_ssl or force_https changes."""
    ssl_keys = {'enable_ssl', 'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'}
    current_settings = Setting.get_all_settings(db)
    
    changed = False
    updated_settings = {}
    validation_errors = {}
    
    # Track critical settings that require restart
    prev_enable_ssl = current_settings.get('enable_ssl', False)
    prev_force_https = current_settings.get('force_https', False)
    new_enable_ssl = ssl_update.get('enable_ssl', prev_enable_ssl)
    new_force_https = ssl_update.get('force_https', prev_force_https)
    
    # Update settings
    for key in ssl_keys:
        if key in ssl_update and ssl_update[key] != current_settings.get(key):
            try:
                converted_value = validate_setting_value(key, ssl_update[key])
                Setting.set_setting(db, key, converted_value)
                updated_settings[key] = converted_value
                changed = True
            except ValueError as e:
                validation_errors[key] = str(e)
    
    if validation_errors:
        raise ValueError(f"Validation failed: {validation_errors}")
    
    # Validate complete SSL configuration if any SSL is enabled
    if changed:
        try:
            validate_ssl_configuration(db, ssl_update)
        except ValueError as e:
            raise ValueError(str(e))
        
        # Check if restart is needed (SSL enable/disable or force_https change)
        restart_required = (
            prev_enable_ssl != new_enable_ssl or 
            prev_force_https != new_force_https or
            (new_enable_ssl and any(key in ssl_update for key in ['ssl_domain', 'ssl_certfile', 'ssl_keyfile']))
        )
        
        # Broadcast live event for SSL settings update
        await live_events.broadcast_settings_event("updated", {
            "category": "ssl",
            "updated_settings": updated_settings,
            "restart_required": restart_required
        })
        
        if restart_required:
            logger.info("SSL configuration changed, server restart will be triggered")
            return {
                "message": "SSL settings updated", 
                "ssl_restart_required": True, 
                "updated_settings": updated_settings
            }
    
    return {
        "message": "SSL settings updated", 
        "ssl_restart_required": False, 
        "updated_settings": updated_settings
    }

async def clear_firewall_rules() -> dict:
    """Clear all DNSniper firewall rules"""
    try:
        firewall = FirewallService()
        firewall.clear_all_rules()
        return {"message": "All firewall rules cleared successfully"}
    except Exception as e:
        raise Exception(f"Failed to clear firewall rules: {str(e)}")

async def rebuild_firewall_rules(db: Session) -> dict:
    """Rebuild firewall rules from database"""
    try:
        firewall = FirewallService()
        firewall.rebuild_rules_from_database(db)
        
        # Broadcast live event for firewall rebuild
        await live_events.broadcast_firewall_event("rules_rebuilt", {
            "message": "Firewall rules rebuilt from database",
            "action": "rebuild"
        })
        
        return {"message": "Firewall rules rebuilt successfully"}
    except Exception as e:
        raise Exception(f"Failed to rebuild firewall rules: {str(e)}")

async def get_firewall_status() -> dict:
    """Get firewall status"""
    try:
        firewall = FirewallService()
        status = firewall.get_status()
        return status
    except Exception as e:
        raise Exception(f"Failed to get firewall status: {str(e)}")

async def get_ssl_status(db: Session) -> dict:
    """Get SSL configuration status and validation"""
    try:
        settings = Setting.get_all_settings(db)
        enable_ssl = settings.get('enable_ssl', False)
        force_https = settings.get('force_https', False)
        ssl_domain = settings.get('ssl_domain', '').strip()
        ssl_certfile = settings.get('ssl_certfile', '').strip()
        ssl_keyfile = settings.get('ssl_keyfile', '').strip()
        
        status = {
            "enable_ssl": enable_ssl,
            "force_https": force_https,
            "ssl_domain": ssl_domain,
            "ssl_certfile": ssl_certfile,
            "ssl_keyfile": ssl_keyfile,
            "configuration_complete": bool(ssl_domain and ssl_certfile and ssl_keyfile),
            "files_exist": {
                "certfile": bool(ssl_certfile and os.path.isfile(ssl_certfile)),
                "keyfile": bool(ssl_keyfile and os.path.isfile(ssl_keyfile))
            },
            "ssl_enabled": False,
            "validation_errors": [],
            "warnings": []
        }
        
        # Warn if any SSL field is filled but not all are present
        ssl_fields = [ssl_domain, ssl_certfile, ssl_keyfile]
        if any(ssl_fields) and not all(ssl_fields):
            status["warnings"].append("All SSL fields (domain, cert, key) are required for SSL to work.")
        
        # Validate SSL configuration if SSL is enabled
        if enable_ssl or force_https:
            try:
                validate_ssl_configuration(db)
                status["ssl_enabled"] = True
                status["status"] = "SSL properly configured and enabled"
            except ValueError as e:
                status["validation_errors"].append(str(e))
                status["status"] = f"SSL configuration error: {str(e)}"
        else:
            status["status"] = "SSL disabled"
        
        # Additional file validation details
        if ssl_certfile:
            if os.path.isfile(ssl_certfile):
                try:
                    with open(ssl_certfile, 'r') as f:
                        cert_data = f.read()
                    if 'BEGIN CERTIFICATE' in cert_data:
                        status["certfile_info"] = {"valid_format": True, "readable": True}
                    else:
                        status["certfile_info"] = {"valid_format": False, "readable": True}
                        status["validation_errors"].append("Certificate file does not appear to be in PEM format")
                except Exception as e:
                    status["certfile_info"] = {"valid_format": False, "readable": False, "error": str(e)}
                    status["validation_errors"].append(f"Certificate file read error: {str(e)}")
            else:
                status["validation_errors"].append(f"Certificate file not found: {ssl_certfile}")
        
        return status
    except Exception as e:
        logger.error(f"Failed to get SSL status: {e}")
        raise Exception(f"Failed to get SSL status: {str(e)}")

async def get_web_server_config() -> dict:
    """Get current web server configuration"""
    def load_config():
        """Load configuration from config.json with defaults"""
        config_path = Path(__file__).parent.parent / "config.json"
        
        # Default configuration
        default_config = {
            "web_server": {
                "host": "0.0.0.0",
                "port": 8000
            },
            "frontend": {
                "static_path": "../frontend/build"
            }
        }
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    
                    # Deep merge with defaults
                    config = default_config.copy()
                    if "web_server" in user_config:
                        config["web_server"].update(user_config["web_server"])
                    if "frontend" in user_config:
                        config["frontend"].update(user_config["frontend"])
                    
                    return config
            except Exception:
                return default_config
        else:
            return default_config
    
    config = load_config()
    return {
        "host": config["web_server"]["host"],
        "port": config["web_server"]["port"]
    }

async def update_web_server_config(db: Session, host: str, port: int) -> dict:
    """Update web server configuration and restart the application"""
    try:
        # Validate input
        if not host or not isinstance(host, str):
            raise ValueError("Invalid host address")
        
        # Validate port
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("Port out of range")
        except (ValueError, TypeError):
            raise ValueError("Port must be a valid integer between 1 and 65535")
        
        # Load current config
        def load_config():
            config_path = Path(__file__).parent.parent / "config.json"
            default_config = {
                "web_server": {"host": "0.0.0.0", "port": 8000},
                "frontend": {"static_path": "../frontend/build"}
            }
            
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        user_config = json.load(f)
                        config = default_config.copy()
                        if "web_server" in user_config:
                            config["web_server"].update(user_config["web_server"])
                        if "frontend" in user_config:
                            config["frontend"].update(user_config["frontend"])
                        return config
                except Exception:
                    return default_config
            else:
                return default_config
        
        config_path = Path(__file__).parent.parent / "config.json"
        current_config = load_config()
        
        # Update the configuration
        current_config["web_server"]["host"] = host
        current_config["web_server"]["port"] = port
        
        # Save to config.json
        try:
            with open(config_path, 'w') as f:
                json.dump(current_config, f, indent=2)
            
            # Log the configuration change
            Log.create_rule_log(
                db, 
                ActionType.update, 
                None, 
                f"Web server configuration updated: host={host}, port={port}", 
                mode="manual"
            )
            
            # Return success and trigger shutdown
            return {
                "message": "Web server configuration updated successfully. Server will restart.",
                "new_config": {
                    "host": host,
                    "port": port
                },
                "restart_required": True
            }
            
        except Exception as e:
            raise Exception(f"Failed to save configuration: {str(e)}")
        
    except Exception as e:
        Log.create_error_log(db, f"Failed to update web server config: {e}", context="web_server_config", mode="manual")
        raise Exception(f"Internal server error: {str(e)}")

async def test_critical_ip_detection(db: Session) -> dict:
    """Test critical IP detection system"""
    try:
        # Get current critical IP settings
        critical_ipv4_list = Setting.get_setting(db, "critical_ipv4_ips_ranges", [])
        critical_ipv6_list = Setting.get_setting(db, "critical_ipv6_ips_ranges", [])
        
        # Initialize DNS service
        dns_resolver_primary = Setting.get_setting(db, "dns_resolver_primary", "1.1.1.1")
        dns_resolver_secondary = Setting.get_setting(db, "dns_resolver_secondary", "8.8.8.8")
        dns_service = DNSService(dns_resolver_primary, dns_resolver_secondary)
        
        # Get dynamic critical IPs
        dynamic_critical = dns_service._get_dynamic_critical_ips(db)
        
        # Test some common IPs
        test_ips = [
            "127.0.0.1",        # Localhost
            "192.168.1.1",      # Private network
            "8.8.8.8",          # Google DNS
            "1.1.1.1",          # Cloudflare DNS
            "208.67.222.222",   # OpenDNS
            "192.0.2.1",        # Test network
            "10.0.0.1",         # Private network
        ]
        
        test_results = {}
        for ip in test_ips:
            is_critical = dns_service.is_critical_ip(ip, critical_ipv4_list, critical_ipv6_list, db)
            is_safe = dns_service.is_safe_ip(ip)
            is_safe_for_auto_update = dns_service.is_safe_ip_for_auto_update(ip, critical_ipv4_list, critical_ipv6_list, db)
            
            test_results[ip] = {
                "is_critical": is_critical,
                "is_safe": is_safe,
                "is_safe_for_auto_update": is_safe_for_auto_update
            }
        
        return {
            "static_critical_ipv4": critical_ipv4_list,
            "static_critical_ipv6": critical_ipv6_list,
            "dynamic_critical": dynamic_critical,
            "test_results": test_results,
            "summary": {
                "total_static_ipv4": len(critical_ipv4_list),
                "total_static_ipv6": len(critical_ipv6_list),
                "total_dynamic_ipv4": len(dynamic_critical['ipv4']),
                "total_dynamic_ipv6": len(dynamic_critical['ipv6']),
                "protected_count": sum(1 for result in test_results.values() if result["is_critical"])
            }
        }
    except Exception as e:
        raise Exception(f"Failed to test critical IP detection: {str(e)}")

async def validate_critical_ips(critical_ips: dict) -> dict:
    """Validate critical IP lists without saving them"""
    try:
        validation_results = {
            "ipv4": {"valid": [], "invalid": []},
            "ipv6": {"valid": [], "invalid": []},
            "errors": []
        }
        
        # Validate IPv4 list
        if 'ipv4' in critical_ips:
            if not isinstance(critical_ips['ipv4'], list):
                validation_results["errors"].append("IPv4 list must be an array")
            else:
                for item in critical_ips['ipv4']:
                    if not isinstance(item, str):
                        validation_results["ipv4"]["invalid"].append({"item": item, "error": "Must be a string"})
                        continue
                    
                    try:
                        # Try as IP address first
                        ipaddress.IPv4Address(item)
                        validation_results["ipv4"]["valid"].append({"item": item, "type": "ip"})
                    except ValueError:
                        try:
                            # Try as network/CIDR range
                            ipaddress.IPv4Network(item, strict=False)
                            validation_results["ipv4"]["valid"].append({"item": item, "type": "network"})
                        except ValueError:
                            validation_results["ipv4"]["invalid"].append({"item": item, "error": "Invalid IPv4 address or CIDR range"})
        
        # Validate IPv6 list
        if 'ipv6' in critical_ips:
            if not isinstance(critical_ips['ipv6'], list):
                validation_results["errors"].append("IPv6 list must be an array")
            else:
                for item in critical_ips['ipv6']:
                    if not isinstance(item, str):
                        validation_results["ipv6"]["invalid"].append({"item": item, "error": "Must be a string"})
                        continue
                    
                    try:
                        # Try as IP address first
                        ipaddress.IPv6Address(item)
                        validation_results["ipv6"]["valid"].append({"item": item, "type": "ip"})
                    except ValueError:
                        try:
                            # Try as network/CIDR range
                            ipaddress.IPv6Network(item, strict=False)
                            validation_results["ipv6"]["valid"].append({"item": item, "type": "network"})
                        except ValueError:
                            validation_results["ipv6"]["invalid"].append({"item": item, "error": "Invalid IPv6 address or CIDR range"})
        
        # Calculate summary
        total_valid = len(validation_results["ipv4"]["valid"]) + len(validation_results["ipv6"]["valid"])
        total_invalid = len(validation_results["ipv4"]["invalid"]) + len(validation_results["ipv6"]["invalid"])
        
        validation_results["summary"] = {
            "total_valid": total_valid,
            "total_invalid": total_invalid,
            "is_valid": total_invalid == 0 and len(validation_results["errors"]) == 0
        }
        
        return validation_results
    except Exception as e:
        raise Exception(f"Failed to validate critical IPs: {str(e)}")

# =============================================================================
# LOG CONTROLLERS
# =============================================================================

async def get_logs_list(
    db: Session,
    action: Optional[str] = None,
    rule_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    domain_name: Optional[str] = None,
    hours: Optional[int] = 24,
    page: int = 1,
    per_page: int = 50
) -> dict:
    """Get logs with filtering and pagination"""
    query = db.query(Log)
    
    # Time filter
    if hours:
        time_filter = datetime.utcnow() - timedelta(hours=hours)
        query = query.filter(Log.created_at >= time_filter)
    
    # Action filter
    if action:
        try:
            action_enum = ActionType(action)
            query = query.filter(Log.action == action_enum)
        except ValueError:
            raise ValueError("Invalid action type")
    
    # Rule type filter
    if rule_type:
        try:
            rule_type_enum = RuleType(rule_type)
            query = query.filter(Log.rule_type == rule_type_enum)
        except ValueError:
            raise ValueError("Invalid rule type")
    
    # IP address filter (search in any IP field)
    if ip_address:
        query = query.filter(
            (Log.ip_address == ip_address) |
            (Log.source_ip == ip_address) |
            (Log.destination_ip == ip_address)
        )
    
    # Domain name filter
    if domain_name:
        query = query.filter(Log.domain_name.contains(domain_name))
    
    # Order by newest first
    query = query.order_by(Log.created_at.desc())
    
    # Get total count before pagination
    total = query.count()
    
    # Calculate pagination
    offset = (page - 1) * per_page
    pages = (total + per_page - 1) // per_page  # Ceiling division
    
    # Apply pagination
    logs = query.offset(offset).limit(per_page).all()
    
    result = []
    for log in logs:
        result.append({
            "id": log.id,
            "action": log.action.value if log.action else None,
            "ip_address": log.ip_address,
            "domain_name": log.domain_name,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "rule_type": log.rule_type.value if log.rule_type else None,
            "message": log.message,
            "created_at": log.created_at,
            "mode": log.mode
        })
    
    return {
        "logs": result,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages
    }

async def get_log_statistics(db: Session, hours: int = 24) -> dict:
    """Get log statistics"""
    # Time filter for recent stats
    time_filter = datetime.utcnow() - timedelta(hours=hours)
    
    # Total logs
    total_logs = db.query(Log).count()
    
    # Recent logs
    recent_logs_24h = db.query(Log).filter(Log.created_at >= time_filter).count()
    
    # Logs by action
    logs_by_action = {}
    for action in ActionType:
        count = db.query(Log).filter(
            Log.action == action,
            Log.created_at >= time_filter
        ).count()
        logs_by_action[action.value] = count
    
    # Logs by rule type
    logs_by_rule_type = {}
    for rule_type in RuleType:
        count = db.query(Log).filter(
            Log.rule_type == rule_type,
            Log.created_at >= time_filter
        ).count()
        logs_by_rule_type[rule_type.value] = count
    
    # Recent blocks and allows
    recent_blocks = db.query(Log).filter(
        Log.action == ActionType.block,
        Log.created_at >= time_filter
    ).count()
    
    recent_allows = db.query(Log).filter(
        Log.action == ActionType.allow,
        Log.created_at >= time_filter
    ).count()
    
    return {
        "total_logs": total_logs,
        "logs_by_action": logs_by_action,
        "logs_by_rule_type": logs_by_rule_type,
        "recent_logs_24h": recent_logs_24h,
        "recent_blocks": recent_blocks,
        "recent_allows": recent_allows
    }

async def get_recent_logs(db: Session, limit: int = 50) -> list:
    """Get most recent logs (for real-time display)"""
    logs = db.query(Log).order_by(Log.created_at.desc()).limit(limit).all()
    
    result = []
    for log in logs:
        result.append({
            "id": log.id,
            "action": log.action.value if log.action else None,
            "ip_address": log.ip_address,
            "domain_name": log.domain_name,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "rule_type": log.rule_type.value if log.rule_type else None,
            "message": log.message,
            "created_at": log.created_at,
            "mode": log.mode
        })
    
    return result

async def cleanup_old_logs(db: Session, days: Optional[int] = None, keep_count: Optional[int] = None) -> dict:
    """Clean up old logs"""
    try:
        if days is not None:
            # Delete logs older than specified days
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            deleted_count = db.query(Log).filter(Log.created_at < cutoff_date).count()
            db.query(Log).filter(Log.created_at < cutoff_date).delete()
            
        elif keep_count is not None:
            # Keep only the most recent X logs
            total_logs = db.query(Log).count()
            if total_logs > keep_count:
                # Get the ID of the log at the keep_count position
                subquery = db.query(Log.id).order_by(Log.created_at.desc()).offset(keep_count).limit(1).subquery()
                cutoff_id = db.query(subquery.c.id).scalar()
                
                if cutoff_id:
                    deleted_count = db.query(Log).filter(Log.id < cutoff_id).count()
                    db.query(Log).filter(Log.id < cutoff_id).delete()
                else:
                    deleted_count = 0
            else:
                deleted_count = 0
        else:
            # Use default settings
            max_entries = Setting.get_setting(db, "max_log_entries", 10000)
            max_days = Setting.get_setting(db, "log_retention_days", 30)
            
            deleted_count = Log.cleanup_old_logs(db, max_entries, max_days)
        
        db.commit()
        
        # Log the cleanup action
        Log.create_rule_log(
            db, ActionType.update, None,
            f"Cleaned up {deleted_count} old log entries",
            mode='manual'
        )
        
        return {"message": f"Successfully deleted {deleted_count} old log entries"}
        
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to cleanup logs: {str(e)}")

# =============================================================================
# AUTO-UPDATE SOURCE CONTROLLERS
# =============================================================================

async def get_auto_update_sources_list(db: Session, skip: int = 0, limit: int = 100) -> list:
    """Get all auto-update sources with pagination"""
    sources = db.query(AutoUpdateSource).offset(skip).limit(limit).all()
    return sources

async def get_auto_update_status(db: Session) -> dict:
    """Get auto-update agent status"""
    try:
        auto_update_service = AutoUpdateService(db)
        # Get enhanced status with thread information
        status = auto_update_service.get_status()
        active_sources = AutoUpdateSource.get_active_sources(db)
        # Get scheduler status from the scheduler manager
        scheduler_info = scheduler_manager.get_status()
        return {
            "enabled": status["enabled"],
            "is_running": status["is_running"],
            "active_sources": status["active_sources"],
            "total_sources": db.query(AutoUpdateSource).count(),
            "interval": Setting.get_setting(db, "auto_update_interval", 3600),
            "start_time": status["start_time"],
            "thread_id": status["thread_id"],
            "can_trigger": not status["is_running"],  # Can only trigger if not already running
            "scheduler": scheduler_info
        }
    except Exception as e:
        logger.error(f"Failed to get auto-update status: {e}")
        raise Exception(str(e))

async def get_auto_update_source_by_id(db: Session, source_id: int) -> AutoUpdateSource:
    """Get a specific auto-update source"""
    source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
    if not source:
        raise ValueError("Auto-update source not found")
    return source

async def create_auto_update_source(db: Session, name: str, url: str, is_active: bool = True, list_type: str = 'blacklist') -> dict:
    """Create a new auto-update source"""
    try:
        # Check if URL already exists
        existing = db.query(AutoUpdateSource).filter(AutoUpdateSource.url == url).first()
        if existing:
            raise ValueError("URL already exists")
        
        # Create new source
        source = AutoUpdateSource(
            name=name,
            url=url,
            is_active=is_active,
            list_type=list_type or 'blacklist'
        )
        
        db.add(source)
        db.commit()
        db.refresh(source)
        
        # Log the action
        Log.create_rule_log(
            db, ActionType.add_rule, None,
            f"Added auto-update source: {source.name} ({source.url})",
            mode='auto_update'
        )
        
        # Prepare event data
        event_data = {
            "id": source.id,
            "name": source.name,
            "url": source.url,
            "is_active": source.is_active,
            "list_type": source.list_type,
            "last_update": source.last_update,
            "last_error": source.last_error,
            "update_count": source.update_count,
            "created_at": source.created_at,
            "updated_at": source.updated_at
        }
        
        # Broadcast live event
        await live_events.broadcast_auto_update_source_event("created", event_data)
        
        return source
        
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to create auto-update source: {str(e)}")

async def update_auto_update_source(db: Session, source_id: int, name: Optional[str] = None, url: Optional[str] = None, is_active: Optional[bool] = None, list_type: Optional[str] = None) -> AutoUpdateSource:
    """Update an existing auto-update source"""
    try:
        source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
        
        if not source:
            raise ValueError("Auto-update source not found")
        
        # Track changes for logging
        changes = []
        
        # Update fields if provided
        if name is not None:
            if source.name != name:
                changes.append(f"name: {source.name} -> {name}")
                source.name = name
        
        if url is not None:
            # Check if new URL already exists (excluding current source)
            existing = db.query(AutoUpdateSource).filter(
                AutoUpdateSource.url == url,
                AutoUpdateSource.id != source_id
            ).first()
            if existing:
                raise ValueError("URL already exists")
            
            if source.url != url:
                changes.append(f"url: {source.url} -> {url}")
                source.url = url
        
        if is_active is not None:
            if source.is_active != is_active:
                status = "active" if is_active else "inactive"
                changes.append(f"status: {status}")
                source.is_active = is_active
        
        if list_type is not None:
            if source.list_type != list_type:
                changes.append(f"list_type: {source.list_type} -> {list_type}")
                source.list_type = list_type
        
        if changes:
            source.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(source)
            
            # Log the action
            Log.create_rule_log(
                db, ActionType.update, None,
                f"Updated auto-update source {source.name}: {', '.join(changes)}",
                mode='auto_update'
            )
            
            # Prepare event data
            event_data = {
                "id": source.id,
                "name": source.name,
                "url": source.url,
                "is_active": source.is_active,
                "list_type": source.list_type,
                "last_update": source.last_update,
                "last_error": source.last_error,
                "update_count": source.update_count,
                "created_at": source.created_at,
                "updated_at": source.updated_at,
                "changes": changes
            }
            
            # Broadcast live event
            await live_events.broadcast_auto_update_source_event("updated", event_data)
        
        return source
        
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to update auto-update source: {str(e)}")

async def delete_auto_update_source(db: Session, source_id: int) -> dict:
    """Delete an auto-update source"""
    try:
        source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
        
        if not source:
            raise ValueError("Auto-update source not found")
        
        source_name = source.name
        source_url = source.url
        
        # Prepare event data before deletion
        event_data = {
            "id": source.id,
            "name": source.name,
            "url": source.url,
            "is_active": source.is_active,
            "list_type": source.list_type,
            "update_count": source.update_count
        }
        
        db.delete(source)
        db.commit()
        
        # Log the action
        Log.create_rule_log(
            db, ActionType.remove_rule, None,
            f"Deleted auto-update source: {source_name} ({source_url})",
            mode='auto_update'
        )
        
        # Broadcast live event
        await live_events.broadcast_auto_update_source_event("deleted", event_data)
        
        return {"message": "Auto-update source deleted successfully"}
        
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to delete auto-update source: {str(e)}")

async def trigger_auto_update(db: Session) -> dict:
    """Manually trigger an auto-update cycle"""
    try:
        # Use the new thread management system
        result = AutoUpdateService.start_auto_update_cycle_thread()
        
        # Log the trigger attempt
        if result["status"] == "started":
            Log.create_rule_log(
                db, ActionType.update, None, 
                "Auto-update cycle triggered manually", 
                mode="auto_update"
            )
            Log.cleanup_old_logs(db)
            db.commit()
            
            return {
                "message": result["message"],
                "status": result["status"],
                "thread_id": result["thread_id"],
                "start_time": result["start_time"]
            }
        elif result["status"] == "already_running":
            return {
                "message": result["message"],
                "status": result["status"],
                "thread_id": result["thread_id"],
                "start_time": result["start_time"]
            }
        else:
            raise Exception(result["message"])
            
    except Exception as e:
        logger.error(f"Failed to trigger auto-update: {e}")
        raise Exception(str(e))

async def stop_auto_update(db: Session) -> dict:
    """Stop the currently running auto-update cycle"""
    try:
        result = AutoUpdateService.stop_auto_update_cycle()
        
        # Log the stop attempt
        if result["status"] in ["stopped", "not_running", "already_stopped"]:
            Log.create_rule_log(
                db, ActionType.update, None, 
                f"Auto-update stop requested: {result['message']}", 
                mode="auto_update"
            )
            Log.cleanup_old_logs(db)
            db.commit()
        
        return {
            "message": result["message"],
            "status": result["status"]
        }
        
    except Exception as e:
        logger.error(f"Failed to stop auto-update: {e}")
        raise Exception(str(e))

# =============================================================================
# AUTHENTICATION CONTROLLERS
# =============================================================================

def get_client_ip(request) -> str:
    """Get client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

def check_rate_limit(ip_address: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """Check if IP address is rate limited"""
    # This is a simplified version - in production, you'd use Redis
    rate_limit_storage = {}
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)
    
    # Clean old entries
    if ip_address in rate_limit_storage:
        rate_limit_storage[ip_address] = [
            attempt_time for attempt_time in rate_limit_storage[ip_address]
            if attempt_time > window_start
        ]
    
    # Check current attempts
    attempts = len(rate_limit_storage.get(ip_address, []))
    return attempts < max_attempts

def record_rate_limit_attempt(ip_address: str):
    """Record a rate limit attempt"""
    # This is a simplified version - in production, you'd use Redis
    rate_limit_storage = {}
    now = datetime.utcnow()
    if ip_address not in rate_limit_storage:
        rate_limit_storage[ip_address] = []
    rate_limit_storage[ip_address].append(now)

async def authenticate_user(db: Session, username: str, password: str, client_ip: str, user_agent: str) -> dict:
    """Authenticate user and create session"""
    # Check rate limiting
    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for IP {client_ip}")
        raise ValueError("Too many login attempts. Please try again later.")
    
    # Check database rate limiting
    recent_failures = LoginAttempt.get_recent_failed_attempts(db, client_ip)
    if recent_failures >= 10:  # More strict database-based rate limiting
        logger.warning(f"Database rate limit exceeded for IP {client_ip}")
        raise ValueError("Too many failed login attempts. Please try again later.")
    
    # Authenticate user
    user = User.get_by_username(db, username)
    
    if not user or not user.verify_password(password):
        # Record failed attempt
        LoginAttempt.record_attempt(db, client_ip, username, success=False)
        record_rate_limit_attempt(client_ip)
        
        logger.warning(f"Failed login attempt for username '{username}' from IP {client_ip}")
        raise ValueError("Invalid username or password")
    
    # Create session
    session = UserSession.create_session(db, user.id, client_ip, user_agent)
    
    # Record successful attempt
    LoginAttempt.record_attempt(db, client_ip, username, success=True)
    user.update_last_login(db)
    
    logger.info(f"Successful login for user '{user.username}' from IP {client_ip}")
    
    return {
        "message": "Login successful",
        "token": session.session_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "is_default_password": user.is_default_password,
            "last_login": user.last_login,
            "created_at": user.created_at
        }
    }

async def logout_user(db: Session, token: str, client_ip: str) -> dict:
    """Logout user and invalidate session"""
    if token:
        UserSession.invalidate_session(db, token)
        logger.info(f"User logged out from IP {client_ip}")
    
    return {"message": "Logout successful"}

async def get_current_user_info(user: User) -> dict:
    """Get current user information"""
    return {
        "id": user.id,
        "username": user.username,
        "is_default_password": user.is_default_password,
        "last_login": user.last_login,
        "created_at": user.created_at
    }

async def change_user_password(db: Session, user: User, current_password: str, new_password: str, confirm_password: str) -> dict:
    """Change user password"""
    # Verify current password
    if not user.verify_password(current_password):
        raise ValueError("Current password is incorrect")
    
    # Validate new password
    if len(new_password) < 6:
        raise ValueError('Password must be at least 6 characters long')
    
    if new_password != confirm_password:
        raise ValueError('Passwords do not match')
    
    # Set new password
    user.set_password(new_password)
    db.commit()
    
    logger.info(f"Password changed for user '{user.username}'")
    
    return {
        "message": "Password changed successfully",
        "is_default_password": user.is_default_password
    }

async def change_user_username(db: Session, user: User, current_password: str, new_username: str) -> dict:
    """Change user username"""
    # Verify current password
    if not user.verify_password(current_password):
        raise ValueError("Current password is incorrect")
    
    # Validate new username
    if len(new_username) < 3:
        raise ValueError('Username must be at least 3 characters long')
    if not new_username.isalnum():
        raise ValueError('Username must contain only letters and numbers')
    
    # Check if username already exists
    existing_user = User.get_by_username(db, new_username)
    if existing_user and existing_user.id != user.id:
        raise ValueError("Username already exists")
    
    # Update username
    old_username = user.username
    user.username = new_username
    user.updated_at = func.now()
    db.commit()
    
    logger.info(f"Username changed from '{old_username}' to '{user.username}'")
    
    return {
        "message": "Username changed successfully",
        "new_username": user.username
    }

async def cleanup_expired_sessions(db: Session) -> dict:
    """Cleanup expired sessions"""
    cleaned_count = UserSession.cleanup_expired_sessions(db)
    logger.info(f"Cleaned up {cleaned_count} expired sessions")
    
    return {
        "message": f"Cleaned up {cleaned_count} expired sessions",
        "cleaned_count": cleaned_count
    }

async def get_user_api_tokens(db: Session, user_id: int) -> list:
    """Get all API tokens for the current user"""
    tokens = APIToken.get_user_tokens(db, user_id)
    result = []
    for token in tokens:
        result.append({
            "id": token.id,
            "name": token.name,
            "token": None,  # Never return the actual token in list
            "is_permanent": token.is_permanent,
            "expires_at": token.expires_at,
            "last_used": token.last_used,
            "created_at": token.created_at,
            "days_until_expiry": token.days_until_expiry()
        })
    return result

async def create_api_token(db: Session, user_id: int, name: str, is_permanent: bool = False, days: int = 30) -> dict:
    """Create a new API token"""
    # Validate token name
    if len(name.strip()) == 0:
        raise ValueError('Token name cannot be empty')
    if len(name) > 100:
        raise ValueError('Token name cannot be longer than 100 characters')
    name = name.strip()
    
    # Validate days
    if not is_permanent and (days < 1 or days > 365):
        raise ValueError('Days must be between 1 and 365')
    
    # Check if token name already exists for this user
    existing = db.query(APIToken).filter(
        APIToken.user_id == user_id,
        APIToken.name == name,
        APIToken.is_active == True
    ).first()
    
    if existing:
        raise ValueError("A token with this name already exists")
    
    # Create the token
    api_token = APIToken.create_token(db, user_id, name, is_permanent, days)
    
    user = db.query(User).filter(User.id == user_id).first()
    logger.info(f"API token '{name}' created for user '{user.username}'")
    
    return {
        "id": api_token.id,
        "name": api_token.name,
        "token": api_token.token,  # Include token only when creating
        "is_permanent": api_token.is_permanent,
        "expires_at": api_token.expires_at,
        "last_used": api_token.last_used,
        "created_at": api_token.created_at,
        "days_until_expiry": api_token.days_until_expiry()
    }

async def revoke_api_token(db: Session, token_id: int, user_id: int) -> dict:
    """Revoke an API token"""
    token = APIToken.revoke_token(db, token_id, user_id)
    
    if not token:
        raise ValueError("Token not found")
    
    user = db.query(User).filter(User.id == user_id).first()
    logger.info(f"API token '{token.name}' revoked for user '{user.username}'")
    
    return {"message": f"Token '{token.name}' has been revoked"}

async def cleanup_expired_tokens(db: Session) -> dict:
    """Cleanup expired API tokens"""
    cleaned_count = APIToken.cleanup_expired_tokens(db)
    logger.info(f"Cleaned up {cleaned_count} expired API tokens")
    
    return {
        "message": f"Cleaned up {cleaned_count} expired API tokens",
        "cleaned_count": cleaned_count
    } 