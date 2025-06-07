from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from sqlalchemy import desc, text, func
from typing import List, Optional
from pydantic import BaseModel, validator
from datetime import datetime, timezone

from database import get_db
from models import Domain, IP, Log
from models.domains import ListType, SourceType
from models.logs import ActionType, RuleType
from services.dns_service import DNSService
from services.firewall_service import FirewallService
from services.live_events import live_events

router = APIRouter()
security = HTTPBearer()

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

# Pydantic models
class DomainCreate(BaseModel):
    domain_name: str
    list_type: str  # "blacklist" or "whitelist"
    notes: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "domain_name": "malware.example.com",
                "list_type": "blacklist",
                "notes": "Known malware domain from threat intelligence"
            }
        }

class DomainUpdate(BaseModel):
    list_type: Optional[str] = None
    notes: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "list_type": "whitelist",
                "notes": "Updated notes for this domain"
            }
        }

class DomainResponse(BaseModel):
    id: int
    domain_name: str
    list_type: str
    source_type: str
    source_url: Optional[str]
    is_cdn: bool
    expired_at: Optional[datetime]
    expires_in: Optional[str]
    created_at: datetime
    updated_at: datetime
    notes: Optional[str]
    ip_count: int

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "domain_name": "malware.example.com",
                "list_type": "blacklist",
                "source_type": "manual",
                "source_url": None,
                "is_cdn": False,
                "expired_at": None,
                "expires_in": None,
                "created_at": "2024-01-01T12:00:00Z",
                "updated_at": "2024-01-01T12:00:00Z",
                "notes": "Known malware domain",
                "ip_count": 3
            }
        }

class PaginatedDomainsResponse(BaseModel):
    domains: List[DomainResponse]
    page: int
    per_page: int
    total: int
    pages: int

@router.get("/", 
    response_model=PaginatedDomainsResponse,
    summary="List domains",
    description="Get all domains with optional filtering by list type, source type, and search term. Supports pagination.",
    dependencies=[Depends(security)],
    responses={
        200: {
            "description": "Paginated list of domains matching the criteria",
            "content": {
                "application/json": {
                    "example": {
                        "domains": [
                            {
                                "id": 1,
                                "domain_name": "malware.example.com",
                                "list_type": "blacklist",
                                "source_type": "manual",
                                "source_url": None,
                                "is_cdn": False,
                                "expired_at": None,
                                "expires_in": None,
                                "created_at": "2024-01-01T12:00:00Z",
                                "updated_at": "2024-01-01T12:00:00Z",
                                "notes": "Known malware domain",
                                "ip_count": 3
                            }
                        ],
                        "page": 1,
                        "per_page": 50,
                        "total": 100,
                        "pages": 2
                    }
                }
            }
        },
        401: {"description": "Authentication required"},
        400: {"description": "Invalid filter parameters"}
    }
)
async def get_domains(
    db: Session = Depends(get_db),
    list_type: Optional[str] = Query(None, description="Filter by list type (blacklist or whitelist)"),
    source_type: Optional[str] = Query(None, description="Filter by source type (manual or auto_update)"),
    search: Optional[str] = Query(None, description="Search domain names (partial match)"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(50, ge=1, le=1000, description="Items per page")
):
    """Get domains with optional filtering and pagination"""
    from models import Setting
    
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
            raise HTTPException(status_code=400, detail="Invalid list_type")
    
    if source_type:
        try:
            source_type_enum = SourceType(source_type)
            query = query.filter(Domain.source_type == source_type_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid source_type")
    
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
        # Use stored CDN status (set correctly during resolution)
        # No longer auto-correct based on current IP count as this overrides
        # the correct CDN logic that considers total resolved IPs, not just stored IPs
        
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
    
    # No longer committing CDN status "corrections" that override correct values
    
    return {
        "domains": result,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages
    }

@router.get("/{domain_id}", response_model=DomainResponse)
async def get_domain(domain_id: int, db: Session = Depends(get_db)):
    """Get a specific domain by ID"""
    from models import Setting
    
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Get current IP count for display
    ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
    
    # Use stored CDN status (set correctly during resolution)
    # No longer auto-correct based on current IP count as this overrides
    # the correct CDN logic that considers total resolved IPs, not just stored IPs
    
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

@router.post("/", response_model=DomainResponse)
async def create_domain(domain_data: DomainCreate, db: Session = Depends(get_db)):
    """Create a new manual domain entry"""
    
    # Validate list_type
    try:
        list_type_enum = ListType(domain_data.list_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid list_type")
    
    # Clean domain name
    domain_name = domain_data.domain_name.strip().lower()
    
    # Check if domain already exists
    existing = db.query(Domain).filter(Domain.domain_name == domain_name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain already exists")
    
    # Create domain (without immediate resolution)
    domain = Domain(
        domain_name=domain_name,
        list_type=list_type_enum,
        source_type=SourceType.manual,  # Manual entries only
        notes=domain_data.notes,
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
    from models import Setting
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

@router.put("/{domain_id}", response_model=DomainResponse)
async def update_domain(domain_id: int, domain_data: DomainUpdate, db: Session = Depends(get_db)):
    """Update a domain (manual entries only)"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    if domain.source_type != SourceType.manual:
        raise HTTPException(status_code=400, detail="Can only update manual domains")
    
    # Update list_type if provided
    if domain_data.list_type:
        try:
            list_type_enum = ListType(domain_data.list_type)
            old_list_type = domain.list_type
            domain.list_type = list_type_enum
            
            # Update all associated IPs and firewall rules
            # firewall_service = FirewallService()
            ips = db.query(IP).filter(IP.domain_id == domain.id).all()
            for ip in ips:
                # Remove from old firewall list
                # firewall_service.remove_ip_from_ipset(ip.ip_address, old_list_type.value, ip.ip_version)
                # Add to new firewall list
                # firewall_service.add_ip_to_ipset(ip.ip_address, list_type_enum.value, ip.ip_version)
                # Update IP record
                ip.list_type = list_type_enum
            
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid list_type")
    
    # Update notes if provided
    if domain_data.notes is not None:
        domain.notes = domain_data.notes
    
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
    
    # Use stored CDN status (set correctly during resolution)
    # No longer auto-correct based on current IP count as this overrides
    # the correct CDN logic that considers total resolved IPs, not just stored IPs
    
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

@router.delete("/{domain_id}")
async def delete_domain(domain_id: int, db: Session = Depends(get_db)):
    """Delete a domain (allows deletion of both manual and auto-update entries)"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
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
    
    # Remove associated IPs from firewall - handled by hooks
    # firewall_service = FirewallService()
    # ips = db.query(IP).filter(IP.domain_id == domain.id).all()
    # for ip in ips:
    #     firewall_service.remove_ip_from_ipset(ip.ip_address, ip.list_type.value, ip.ip_version)
    
    # Delete domain (cascade will delete associated IPs)
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

@router.get("/{domain_id}/ips")
async def get_domain_ips(domain_id: int, db: Session = Depends(get_db)):
    """Get all IPs associated with a domain"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    ips = db.query(IP).filter(IP.domain_id == domain_id).all()
    
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

@router.post("/{domain_id}/resolve")
async def resolve_domain(domain_id: int, db: Session = Depends(get_db)):
    """Manually resolve domain to update IP mappings"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    if domain.source_type != SourceType.manual:
        raise HTTPException(status_code=400, detail="Can only resolve manual domains")
    
    # Resolve domain
    dns_service = DNSService()
    resolution = dns_service.resolve_domain(domain.domain_name)
    
    # Get settings and current state
    from models import Setting
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