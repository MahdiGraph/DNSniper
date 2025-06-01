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
                "created_at": "2024-01-01T12:00:00Z",
                "updated_at": "2024-01-01T12:00:00Z",
                "notes": "Known malware domain",
                "ip_count": 3
            }
        }

@router.get("/", 
    response_model=List[DomainResponse],
    summary="List domains",
    description="Get all domains with optional filtering by list type, source type, and search term. Supports pagination.",
    dependencies=[Depends(security)],
    responses={
        200: {
            "description": "List of domains matching the criteria",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 1,
                            "domain_name": "malware.example.com",
                            "list_type": "blacklist",
                            "source_type": "manual",
                            "source_url": None,
                            "is_cdn": False,
                            "expired_at": None,
                            "created_at": "2024-01-01T12:00:00Z",
                            "updated_at": "2024-01-01T12:00:00Z",
                            "notes": "Known malware domain",
                            "ip_count": 3
                        }
                    ]
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
    limit: int = Query(100, le=1000, description="Maximum number of results (max 1000)"),
    offset: int = Query(0, description="Number of results to skip for pagination")
):
    """Get domains with optional filtering and pagination"""
    query = db.query(Domain)
    
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
    
    # Get domains with pagination
    domains = query.offset(offset).limit(limit).all()
    
    # Add IP count for each domain
    result = []
    for domain in domains:
        ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
        domain_dict = {
            "id": domain.id,
            "domain_name": domain.domain_name,
            "list_type": domain.list_type.value,
            "source_type": domain.source_type.value,
            "source_url": domain.source_url,
            "is_cdn": domain.is_cdn,
            "expired_at": domain.expired_at,
            "created_at": domain.created_at,
            "updated_at": domain.updated_at,
            "notes": domain.notes,
            "ip_count": ip_count
        }
        result.append(domain_dict)
    
    return result

@router.get("/{domain_id}", response_model=DomainResponse)
async def get_domain(domain_id: int, db: Session = Depends(get_db)):
    """Get a specific domain by ID"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
    
    return {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "source_url": domain.source_url,
        "is_cdn": domain.is_cdn,
        "expired_at": domain.expired_at,
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
    
    # Prepare response data
    response_data = {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "source_url": domain.source_url,
        "is_cdn": domain.is_cdn,
        "expired_at": domain.expired_at,
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
    
    ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
    
    # Prepare response data
    response_data = {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "source_url": domain.source_url,
        "is_cdn": domain.is_cdn,
        "expired_at": domain.expired_at,
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
    """Delete a domain (manual entries only)"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    if domain.source_type != SourceType.manual:
        raise HTTPException(status_code=400, detail="Can only delete manual domains")
    
    domain_name = domain.domain_name
    
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
        f"Deleted manual domain: {domain_name}",
        domain_name=domain_name,
        mode='manual'
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
    
    # Update IP mappings with FIFO
    from models import Setting
    max_ips = Setting.get_setting(db, "max_ips_per_domain", 5)
    # firewall_service = FirewallService()
    
    # Add new IPv4 addresses
    for ip_str in resolution['ipv4']:
        # Check if IP already exists for this domain
        existing = db.query(IP).filter(
            IP.domain_id == domain.id,
            IP.ip_address == ip_str
        ).first()
        
        if not existing:
            ip = IP(
                ip_address=ip_str,
                ip_version=4,
                list_type=domain.list_type,
                source_type=SourceType.manual,
                domain_id=domain.id,
                expired_at=None
            )
            db.add(ip)
            # Firewall add handled by hook
            # firewall_service.add_ip_to_ipset(ip_str, domain.list_type.value, 4)
    
    # Add new IPv6 addresses  
    for ip_str in resolution['ipv6']:
        existing = db.query(IP).filter(
            IP.domain_id == domain.id,
            IP.ip_address == ip_str
        ).first()
        
        if not existing:
            ip = IP(
                ip_address=ip_str,
                ip_version=6,
                list_type=domain.list_type,
                source_type=SourceType.manual,
                domain_id=domain.id,
                expired_at=None
            )
            db.add(ip)
            # Firewall add handled by hook
            # firewall_service.add_ip_to_ipset(ip_str, domain.list_type.value, 6)
    
    db.commit()
    
    # Apply FIFO limit
    IP.cleanup_old_ips_for_domain(db, domain.id, max_ips)
    
    # Update CDN status
    domain.update_cdn_status(db)
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.update, RuleType.domain,
        f"Manually resolved domain: {domain.domain_name}",
        domain_name=domain.domain_name,
        mode='manual'
    )
    
    # Broadcast live event for domain resolution
    ip_count = db.query(IP).filter(IP.domain_id == domain.id).count()
    event_data = {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "list_type": domain.list_type.value,
        "source_type": domain.source_type.value,
        "ip_count": ip_count,
        "resolution": resolution
    }
    await live_events.broadcast_domain_event("resolved", event_data)
    
    return {
        "message": f"Domain {domain.domain_name} resolved successfully",
        "resolution": resolution
    } 