from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
from pydantic import BaseModel, HttpUrl, validator
from database import get_db
from models import AutoUpdateSource, Log, Setting
from models.logs import ActionType
from datetime import datetime, timezone
import asyncio
import logging
import threading
import functools
from services.live_events import live_events

router = APIRouter()
logger = logging.getLogger(__name__)


# Pydantic models for request/response
class AutoUpdateSourceBase(BaseModel):
    name: str
    url: str
    is_active: bool = True
    list_type: str = 'blacklist'  # 'blacklist' or 'whitelist'

    @validator('name')
    def validate_name(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Name cannot be empty')
        if len(v) > 100:
            raise ValueError('Name cannot be longer than 100 characters')
        return v.strip()

    @validator('url')
    def validate_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('URL cannot be empty')
        # Basic URL validation
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v.strip()

    @validator('list_type')
    def validate_list_type(cls, v):
        if v not in ('blacklist', 'whitelist'):
            raise ValueError("list_type must be 'blacklist' or 'whitelist'")
        return v


class AutoUpdateSourceCreate(AutoUpdateSourceBase):
    pass


class AutoUpdateSourceUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    is_active: Optional[bool] = None
    list_type: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        if v is not None:
            if len(v.strip()) == 0:
                raise ValueError('Name cannot be empty')
            if len(v) > 100:
                raise ValueError('Name cannot be longer than 100 characters')
            return v.strip()
        return v

    @validator('url')
    def validate_url(cls, v):
        if v is not None:
            if len(v.strip()) == 0:
                raise ValueError('URL cannot be empty')
            if not v.startswith(('http://', 'https://')):
                raise ValueError('URL must start with http:// or https://')
            return v.strip()
        return v

    @validator('list_type')
    def validate_list_type(cls, v):
        if v is not None and v not in ('blacklist', 'whitelist'):
            raise ValueError("list_type must be 'blacklist' or 'whitelist'")
        return v


class AutoUpdateSourceResponse(AutoUpdateSourceBase):
    id: int
    last_update: Optional[datetime]
    last_error: Optional[str]
    update_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AutoUpdateSourceListResponse(BaseModel):
    sources: List[AutoUpdateSourceResponse]
    total: int
    page: int
    per_page: int
    pages: int


@router.get("/")
async def get_auto_update_sources(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get all auto-update sources with pagination"""
    sources = db.query(AutoUpdateSource).offset(skip).limit(limit).all()
    return sources


@router.get("/status")
async def get_auto_update_status(
    db: Session = Depends(get_db)
):
    """Get auto-update agent status"""
    try:
        from services.auto_update_service import AutoUpdateService
        from services.scheduler_manager import scheduler_manager
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
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{source_id}")
async def get_auto_update_source(source_id: int, db: Session = Depends(get_db)):
    """Get a specific auto-update source"""
    source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Auto-update source not found")
    return source


@router.post("/", response_model=AutoUpdateSourceResponse)
async def create_auto_update_source(
    source_data: AutoUpdateSourceCreate,
    db: Session = Depends(get_db)
):
    """Create a new auto-update source"""
    try:
        # Check if URL already exists
        existing = db.query(AutoUpdateSource).filter(AutoUpdateSource.url == source_data.url).first()
        if existing:
            raise HTTPException(status_code=400, detail="URL already exists")
        
        # Create new source
        source = AutoUpdateSource(
            name=source_data.name,
            url=source_data.url,
            is_active=source_data.is_active,
            list_type=source_data.list_type or 'blacklist'
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
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create auto-update source: {str(e)}")


@router.put("/{source_id}", response_model=AutoUpdateSourceResponse)
async def update_auto_update_source(
    source_id: int,
    source_data: AutoUpdateSourceUpdate,
    db: Session = Depends(get_db)
):
    """Update an existing auto-update source"""
    try:
        source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
        
        if not source:
            raise HTTPException(status_code=404, detail="Auto-update source not found")
        
        # Track changes for logging
        changes = []
        
        # Update fields if provided
        if source_data.name is not None:
            if source.name != source_data.name:
                changes.append(f"name: {source.name} -> {source_data.name}")
                source.name = source_data.name
        
        if source_data.url is not None:
            # Check if new URL already exists (excluding current source)
            existing = db.query(AutoUpdateSource).filter(
                AutoUpdateSource.url == source_data.url,
                AutoUpdateSource.id != source_id
            ).first()
            if existing:
                raise HTTPException(status_code=400, detail="URL already exists")
            
            if source.url != source_data.url:
                changes.append(f"url: {source.url} -> {source_data.url}")
                source.url = source_data.url
        
        if source_data.is_active is not None:
            if source.is_active != source_data.is_active:
                status = "active" if source_data.is_active else "inactive"
                changes.append(f"status: {status}")
                source.is_active = source_data.is_active
        
        if source_data.list_type is not None:
            if source.list_type != source_data.list_type:
                changes.append(f"list_type: {source.list_type} -> {source_data.list_type}")
                source.list_type = source_data.list_type
        
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
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update auto-update source: {str(e)}")


@router.delete("/{source_id}")
async def delete_auto_update_source(source_id: int, db: Session = Depends(get_db)):
    """Delete an auto-update source"""
    try:
        source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
        
        if not source:
            raise HTTPException(status_code=404, detail="Auto-update source not found")
        
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
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete auto-update source: {str(e)}")


@router.post("/{source_id}/toggle")
async def toggle_auto_update_source(source_id: int, db: Session = Depends(get_db)):
    """Toggle the active status of an auto-update source"""
    try:
        source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
        
        if not source:
            raise HTTPException(status_code=404, detail="Auto-update source not found")
        
        # Toggle status
        source.is_active = not source.is_active
        source.updated_at = datetime.now(timezone.utc)
        
        db.commit()
        db.refresh(source)
        
        status = "activated" if source.is_active else "deactivated"
        
        # Log the action
        Log.create_rule_log(
            db, ActionType.update, None,
            f"Auto-update source {source.name} {status}",
            mode='auto_update'
        )
        
        # Prepare event data
        event_data = {
            "id": source.id,
            "name": source.name,
            "url": source.url,
            "is_active": source.is_active,
            "list_type": source.list_type,
            "status_change": status
        }
        
        # Broadcast live event
        await live_events.broadcast_auto_update_source_event("toggled", event_data)
        
        return {
            "message": f"Auto-update source {status} successfully",
            "is_active": source.is_active
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to toggle auto-update source: {str(e)}")


@router.post("/{source_id}/test")
async def test_auto_update_source(source_id: int, db: Session = Depends(get_db)):
    """Test connectivity to an auto-update source"""
    try:
        source = db.query(AutoUpdateSource).filter(AutoUpdateSource.id == source_id).first()
        
        if not source:
            raise HTTPException(status_code=404, detail="Auto-update source not found")
        
        import aiohttp
        import asyncio
        
        async def test_url():
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(source.url) as response:
                        content_length = len(await response.text())
                        
                        # Check if the HTTP status indicates success (2xx range)
                        if 200 <= response.status < 300:
                            return {
                                "status": "success",
                                "http_status": response.status,
                                "content_length": content_length,
                                "content_type": response.headers.get("content-type", "unknown")
                            }
                        else:
                            return {
                                "status": "failed",
                                "error": f"HTTP {response.status} - Server returned an error status",
                                "http_status": response.status,
                                "content_length": content_length,
                                "content_type": response.headers.get("content-type", "unknown")
                            }
            except asyncio.TimeoutError:
                return {"status": "timeout", "error": "Request timed out"}
            except Exception as e:
                return {"status": "error", "error": str(e)}
        
        result = await test_url()
        
        # Log the test with appropriate status
        status_msg = "successful" if result["status"] == "success" else f"failed ({result.get('error', 'unknown error')})"
        Log.create_rule_log(
            db, ActionType.update, None,
            f"Tested auto-update source {source.name}: {status_msg}",
            mode='auto_update'
        )
        
        # Prepare event data
        event_data = {
            "id": source.id,
            "name": source.name,
            "url": source.url,
            "test_result": result,
            "test_status": status_msg
        }
        
        # Broadcast live event
        await live_events.broadcast_auto_update_source_event("tested", event_data)
        
        return {
            "source": {
                "id": source.id,
                "name": source.name,
                "url": source.url
            },
            "test_result": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to test auto-update source: {str(e)}")


@router.post("/trigger-update")
async def trigger_auto_update(
    db: Session = Depends(get_db)
):
    """Manually trigger an auto-update cycle"""
    try:
        from services.auto_update_service import AutoUpdateService
        
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
            raise HTTPException(status_code=500, detail=result["message"])
            
    except Exception as e:
        logger.error(f"Failed to trigger auto-update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop-update")
async def stop_auto_update(
    db: Session = Depends(get_db)
):
    """Stop the currently running auto-update cycle"""
    try:
        from services.auto_update_service import AutoUpdateService
        
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
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pause")
async def pause_auto_update(
    db: Session = Depends(get_db)
):
    """Pause the auto-update agent"""
    try:
        Setting.set_setting(db, "auto_update_enabled", False, "Paused by user")
        return {"message": "Auto-update agent paused"}
    except Exception as e:
        logger.error(f"Failed to pause auto-update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start")
async def start_auto_update(
    db: Session = Depends(get_db)
):
    """Start/resume the auto-update agent"""
    try:
        Setting.set_setting(db, "auto_update_enabled", True, "Started by user")
        return {"message": "Auto-update agent started"}
    except Exception as e:
        logger.error(f"Failed to start auto-update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/summary")
async def get_auto_update_stats(db: Session = Depends(get_db)):
    """Get auto-update sources statistics"""
    try:
        total_sources = db.query(AutoUpdateSource).count()
        active_sources = db.query(AutoUpdateSource).filter(AutoUpdateSource.is_active == True).count()
        inactive_sources = total_sources - active_sources
        
        # Get sources with errors
        sources_with_errors = db.query(AutoUpdateSource).filter(
            AutoUpdateSource.last_error.isnot(None)
        ).count()
        
        # Get successful updates count
        total_updates = db.query(AutoUpdateSource).with_entities(
            func.sum(AutoUpdateSource.update_count)
        ).scalar() or 0
        
        return {
            "total_sources": total_sources,
            "active_sources": active_sources,
            "inactive_sources": inactive_sources,
            "sources_with_errors": sources_with_errors,
            "total_successful_updates": total_updates
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get auto-update stats: {str(e)}")


@router.get("/scheduler/debug")
async def get_scheduler_debug_info(
    db: Session = Depends(get_db)
):
    """Get detailed scheduler debug information"""
    try:
        from services.auto_update_service import AutoUpdateService
        from services.scheduler_manager import scheduler_manager
        
        # Get current settings
        enabled = Setting.get_setting(db, "auto_update_enabled", True)
        interval = Setting.get_setting(db, "auto_update_interval", 3600)
        
        # Get scheduler status
        scheduler_status = scheduler_manager.get_status()
        
        # Get auto-update service status
        auto_update_status = AutoUpdateService.get_auto_update_status()
        
        return {
            "scheduler": {
                "thread_alive": scheduler_status["thread_alive"],
                "thread_id": scheduler_manager.scheduler_thread.ident if scheduler_manager.scheduler_thread else None,
                "last_agent_run_time": scheduler_manager.last_agent_run_time,
                "type": "scheduler_manager_with_instant_updates",
                "features": ["instant_settings_updates", "live_events", "thread_safe"]
            },
            "settings": {
                "enabled": enabled,
                "interval_seconds": interval,
                "interval_human": f"{interval // 3600}h {(interval % 3600) // 60}m {interval % 60}s" if interval >= 3600 else f"{interval // 60}m {interval % 60}s" if interval >= 60 else f"{interval}s"
            },
            "auto_update_service": {
                "is_running": auto_update_status["is_running"],
                "start_time": auto_update_status["start_time"],
                "thread_id": auto_update_status["thread_id"]
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get scheduler debug info: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 