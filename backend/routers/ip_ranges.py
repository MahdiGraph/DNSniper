from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from pydantic import BaseModel, validator
from datetime import datetime
import ipaddress

from database import get_db
from models import IPRange, Log
from models.domains import ListType, SourceType
from models.logs import ActionType, RuleType

router = APIRouter()

# Pydantic models
class IPRangeCreate(BaseModel):
    ip_range: str
    list_type: str  # "blacklist" or "whitelist"
    notes: Optional[str] = None

class IPRangeUpdate(BaseModel):
    list_type: Optional[str] = None
    notes: Optional[str] = None

class IPRangeResponse(BaseModel):
    id: int
    ip_range: str
    ip_version: int
    list_type: str
    source_type: str
    source_url: Optional[str]
    expired_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    notes: Optional[str]

    class Config:
        from_attributes = True

@router.get("/", response_model=List[IPRangeResponse])
async def get_ip_ranges(
    db: Session = Depends(get_db),
    list_type: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    ip_version: Optional[int] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0)
):
    """Get IP ranges with optional filtering"""
    query = db.query(IPRange)
    
    if list_type:
        try:
            list_type_enum = ListType(list_type)
            query = query.filter(IPRange.list_type == list_type_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid list_type")
    
    if source_type:
        try:
            source_type_enum = SourceType(source_type)
            query = query.filter(IPRange.source_type == source_type_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid source_type")
    
    if ip_version:
        query = query.filter(IPRange.ip_version == ip_version)
    
    ip_ranges = query.offset(offset).limit(limit).all()
    
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
            "created_at": ip_range.created_at,
            "updated_at": ip_range.updated_at,
            "notes": ip_range.notes
        })
    
    return result

@router.get("/{ip_range_id}", response_model=IPRangeResponse)
async def get_ip_range(ip_range_id: int, db: Session = Depends(get_db)):
    """Get a specific IP range by ID"""
    ip_range = db.query(IPRange).filter(IPRange.id == ip_range_id).first()
    if not ip_range:
        raise HTTPException(status_code=404, detail="IP range not found")
    
    return {
        "id": ip_range.id,
        "ip_range": ip_range.ip_range,
        "ip_version": ip_range.ip_version,
        "list_type": ip_range.list_type.value,
        "source_type": ip_range.source_type.value,
        "source_url": ip_range.source_url,
        "expired_at": ip_range.expired_at,
        "created_at": ip_range.created_at,
        "updated_at": ip_range.updated_at,
        "notes": ip_range.notes
    }

@router.post("/", response_model=IPRangeResponse)
async def create_ip_range(ip_range_data: IPRangeCreate, db: Session = Depends(get_db)):
    """Create a new manual IP range entry"""
    
    # Validate IP range
    is_valid, ip_version = IPRange.validate_ip_range(ip_range_data.ip_range)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid IP range format")
    
    # Check if it's safe to block
    if not IPRange.is_safe_ip_range(ip_range_data.ip_range):
        raise HTTPException(status_code=400, detail="IP range is not safe to block (private, loopback, or too broad)")
    
    # Validate list_type
    try:
        list_type_enum = ListType(ip_range_data.list_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid list_type")
    
    # Normalize CIDR
    normalized_range = IPRange.normalize_cidr(ip_range_data.ip_range)
    
    # Check if IP range already exists
    existing = db.query(IPRange).filter(IPRange.ip_range == normalized_range).first()
    if existing:
        raise HTTPException(status_code=400, detail="IP range already exists")
    
    # Create IP range
    ip_range = IPRange(
        ip_range=normalized_range,
        ip_version=ip_version,
        list_type=list_type_enum,
        source_type=SourceType.manual,
        notes=ip_range_data.notes,
        expired_at=None  # Manual entries never expire
    )
    
    db.add(ip_range)
    db.commit()
    db.refresh(ip_range)
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.add_rule, RuleType.ip_range,
        f"Added manual IP range: {normalized_range} to {list_type_enum.value}"
    )
    
    return {
        "id": ip_range.id,
        "ip_range": ip_range.ip_range,
        "ip_version": ip_range.ip_version,
        "list_type": ip_range.list_type.value,
        "source_type": ip_range.source_type.value,
        "source_url": ip_range.source_url,
        "expired_at": ip_range.expired_at,
        "created_at": ip_range.created_at,
        "updated_at": ip_range.updated_at,
        "notes": ip_range.notes
    }

@router.put("/{ip_range_id}", response_model=IPRangeResponse)
async def update_ip_range(ip_range_id: int, ip_range_data: IPRangeUpdate, db: Session = Depends(get_db)):
    """Update an IP range (manual entries only)"""
    ip_range = db.query(IPRange).filter(IPRange.id == ip_range_id).first()
    if not ip_range:
        raise HTTPException(status_code=404, detail="IP range not found")
    
    if ip_range.source_type != SourceType.manual:
        raise HTTPException(status_code=400, detail="Can only update manual IP ranges")
    
    # Update list_type if provided
    if ip_range_data.list_type:
        try:
            list_type_enum = ListType(ip_range_data.list_type)
            ip_range.list_type = list_type_enum
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid list_type")
    
    # Update notes if provided
    if ip_range_data.notes is not None:
        ip_range.notes = ip_range_data.notes
    
    ip_range.updated_at = datetime.utcnow()
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.update, RuleType.ip_range,
        f"Updated manual IP range: {ip_range.ip_range}"
    )
    
    return {
        "id": ip_range.id,
        "ip_range": ip_range.ip_range,
        "ip_version": ip_range.ip_version,
        "list_type": ip_range.list_type.value,
        "source_type": ip_range.source_type.value,
        "source_url": ip_range.source_url,
        "expired_at": ip_range.expired_at,
        "created_at": ip_range.created_at,
        "updated_at": ip_range.updated_at,
        "notes": ip_range.notes
    }

@router.delete("/{ip_range_id}")
async def delete_ip_range(ip_range_id: int, db: Session = Depends(get_db)):
    """Delete an IP range (manual entries only)"""
    ip_range = db.query(IPRange).filter(IPRange.id == ip_range_id).first()
    if not ip_range:
        raise HTTPException(status_code=404, detail="IP range not found")
    
    if ip_range.source_type != SourceType.manual:
        raise HTTPException(status_code=400, detail="Can only delete manual IP ranges")
    
    ip_range_str = ip_range.ip_range
    db.delete(ip_range)
    db.commit()
    
    # Log the action
    Log.create_rule_log(
        db, ActionType.remove_rule, RuleType.ip_range,
        f"Deleted manual IP range: {ip_range_str}"
    )
    
    return {"message": f"IP range {ip_range_str} deleted successfully"} 