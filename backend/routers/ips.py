from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timezone

from database import get_db
from models import IP, Log, Domain
from models.domains import ListType, SourceType
from models.logs import ActionType, RuleType
from services.live_events import live_events

router = APIRouter()

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
class IPCreate(BaseModel):
    ip_address: str
    list_type: str  # "blacklist" or "whitelist"
    notes: Optional[str] = None

class IPUpdate(BaseModel):
    list_type: Optional[str] = None
    notes: Optional[str] = None

class IPResponse(BaseModel):
    id: int
    ip_address: str
    ip_version: int
    list_type: str
    source_type: str
    source_url: Optional[str]
    domain_id: Optional[int]
    domain_name: Optional[str]
    expired_at: Optional[datetime]
    expires_in: Optional[str]
    created_at: datetime
    updated_at: datetime
    notes: Optional[str]

    class Config:
        from_attributes = True

class PaginatedIPsResponse(BaseModel):
    ips: List[IPResponse]
    page: int
    per_page: int
    total: int
    pages: int

@router.get("/", response_model=PaginatedIPsResponse)
async def get_ips(
    db: Session = Depends(get_db),
    list_type: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    ip_version: Optional[int] = Query(None),
    search: Optional[str] = Query(None, description="Search IP addresses (partial match)"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(50, ge=1, le=1000, description="Items per page")
):
    """Get IPs with optional filtering and search"""
    # Join with domains table to get domain names
    query = db.query(IP, Domain.domain_name).outerjoin(Domain, IP.domain_id == Domain.id)
    
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            query = query.filter(IP.list_type == list_type_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid list_type")
    
    if source_type:
        try:
            source_type_enum = SourceType(source_type)
            query = query.filter(IP.source_type == source_type_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid source_type")
    
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

@router.post("/", response_model=IPResponse)
async def create_ip(ip_data: IPCreate, db: Session = Depends(get_db)):
    """Create a new manual IP entry"""
    
    # Validate IP address
    is_valid, ip_version = IP.validate_ip_address(ip_data.ip_address)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    # Validate list_type
    try:
        list_type_enum = ListType(ip_data.list_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid list_type")
    
    # Check if IP already exists
    existing = db.query(IP).filter(IP.ip_address == ip_data.ip_address).first()
    if existing:
        raise HTTPException(status_code=400, detail="IP already exists")
    
    # Create IP
    ip = IP(
        ip_address=ip_data.ip_address,
        ip_version=ip_version,
        list_type=list_type_enum,
        source_type=SourceType.manual,
        notes=ip_data.notes,
        expired_at=None  # Manual entries never expire
    )
    
    db.add(ip)
    db.commit()
    db.refresh(ip)
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.add_rule, RuleType.ip,
        f"Added manual IP: {ip_data.ip_address} to {list_type_enum.value}",
        ip_address=ip_data.ip_address,
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

@router.put("/{ip_id}", response_model=IPResponse)
async def update_ip(ip_id: int, ip_data: IPUpdate, db: Session = Depends(get_db)):
    """Update an IP (manual entries only)"""
    ip = db.query(IP).filter(IP.id == ip_id).first()
    if not ip:
        raise HTTPException(status_code=404, detail="IP not found")
    
    if ip.source_type != SourceType.manual:
        raise HTTPException(status_code=400, detail="Can only update manual IPs")
    
    # Update list_type if provided
    if ip_data.list_type:
        try:
            list_type_enum = ListType(ip_data.list_type)
            ip.list_type = list_type_enum
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid list_type")
    
    # Update notes if provided
    if ip_data.notes is not None:
        ip.notes = ip_data.notes
    
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

@router.delete("/{ip_id}")
async def delete_ip(ip_id: int, db: Session = Depends(get_db)):
    """Delete an IP (allows deletion of both manual and auto-update entries)"""
    ip = db.query(IP).filter(IP.id == ip_id).first()
    if not ip:
        raise HTTPException(status_code=404, detail="IP not found")
    
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