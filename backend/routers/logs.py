from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, text, func
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta

from database import get_db
from models import Log
from models.logs import ActionType, RuleType

router = APIRouter()

# Pydantic models
class LogResponse(BaseModel):
    id: int
    action: str
    ip_address: Optional[str]
    domain_name: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    rule_type: Optional[str]
    message: str
    created_at: datetime

    class Config:
        from_attributes = True

class LogStatsResponse(BaseModel):
    total_logs: int
    logs_by_action: dict
    logs_by_rule_type: dict
    recent_logs_24h: int
    recent_blocks: int
    recent_allows: int

@router.get("/", response_model=List[LogResponse])
async def get_logs(
    db: Session = Depends(get_db),
    action: Optional[str] = Query(None, description="Filter by action type"),
    rule_type: Optional[str] = Query(None, description="Filter by rule type"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address"),
    domain_name: Optional[str] = Query(None, description="Filter by domain name"),
    hours: Optional[int] = Query(24, description="Hours of history to fetch"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0)
):
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
            raise HTTPException(status_code=400, detail="Invalid action type")
    
    # Rule type filter
    if rule_type:
        try:
            rule_type_enum = RuleType(rule_type)
            query = query.filter(Log.rule_type == rule_type_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid rule type")
    
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
    
    # Apply pagination
    logs = query.offset(offset).limit(limit).all()
    
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
            "created_at": log.created_at
        })
    
    return result

@router.get("/stats", response_model=LogStatsResponse)
async def get_log_statistics(
    db: Session = Depends(get_db),
    hours: int = Query(24, description="Hours of statistics to calculate")
):
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

@router.get("/recent", response_model=List[LogResponse])
async def get_recent_logs(
    db: Session = Depends(get_db),
    limit: int = Query(50, le=200, description="Number of recent logs to fetch")
):
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
            "created_at": log.created_at
        })
    
    return result

@router.delete("/cleanup")
async def cleanup_old_logs(
    db: Session = Depends(get_db),
    days: Optional[int] = Query(None, description="Delete logs older than X days"),
    keep_count: Optional[int] = Query(None, description="Keep only X most recent logs")
):
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
            from models import Setting
            max_entries = Setting.get_setting(db, "max_log_entries", 10000)
            max_days = Setting.get_setting(db, "log_retention_days", 30)
            
            deleted_count = Log.cleanup_old_logs(db, max_entries, max_days)
        
        db.commit()
        
        # Log the cleanup action
        Log.create_rule_log(
            db, ActionType.update, None,
            f"Cleaned up {deleted_count} old log entries"
        )
        
        return {"message": f"Successfully deleted {deleted_count} old log entries"}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to cleanup logs: {str(e)}")

@router.get("/search")
async def search_logs(
    db: Session = Depends(get_db),
    query_text: str = Query(..., description="Text to search in log messages"),
    limit: int = Query(100, le=1000)
):
    """Search logs by message content"""
    logs = db.query(Log).filter(
        Log.message.contains(query_text)
    ).order_by(Log.created_at.desc()).limit(limit).all()
    
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
            "created_at": log.created_at
        })
    
    return result

@router.get("/export")
async def export_logs(
    db: Session = Depends(get_db),
    hours: int = Query(24, description="Hours of logs to export"),
    format: str = Query("json", description="Export format (json, csv)")
):
    """Export logs for download"""
    time_filter = datetime.utcnow() - timedelta(hours=hours)
    logs = db.query(Log).filter(Log.created_at >= time_filter).order_by(Log.created_at.desc()).all()
    
    if format.lower() == "csv":
        import io
        import csv
        from fastapi.responses import StreamingResponse
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow([
            "ID", "Action", "IP Address", "Domain Name", "Source IP", 
            "Destination IP", "Rule Type", "Message", "Created At"
        ])
        
        # Write data
        for log in logs:
            writer.writerow([
                log.id,
                log.action.value if log.action else "",
                log.ip_address or "",
                log.domain_name or "",
                log.source_ip or "",
                log.destination_ip or "",
                log.rule_type.value if log.rule_type else "",
                log.message,
                log.created_at.isoformat()
            ])
        
        output.seek(0)
        return StreamingResponse(
            io.StringIO(output.getvalue()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=dnsniper_logs_{hours}h.csv"}
        )
    
    else:  # JSON format
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
                "created_at": log.created_at.isoformat()
            })
        
        return {"logs": result, "total": len(result), "hours": hours} 