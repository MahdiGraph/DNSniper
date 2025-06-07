# Scheduler Manager Service
import threading
import time
import logging
import gc
from datetime import datetime, timezone
from database import SessionLocal
from models import Setting
from services.auto_update_service import AutoUpdateService

logger = logging.getLogger(__name__)

class SchedulerManager:
    """Manages the auto-update scheduler thread and provides status information"""
    
    def __init__(self):
        self.scheduler_thread = None
        self.scheduler_stop_event = threading.Event()
        self.settings_changed_event = threading.Event()  # New: for instant settings updates
        self.last_agent_run_time = 0
        self._lock = threading.Lock()
        self._event_loop = None  # Persistent event loop for broadcasting
        self._error_count = 0
        
    def start_scheduler(self):
        """Start the scheduler thread"""
        with self._lock:
            if self.scheduler_thread is not None and self.scheduler_thread.is_alive():
                logger.warning("[SchedulerManager] Scheduler already running")
                return False
                
            self.scheduler_stop_event.clear()
            self.settings_changed_event.clear()
            self._error_count = 0  # Reset error count
            self.scheduler_thread = threading.Thread(
                target=self._scheduler_loop, 
                daemon=True, 
                name="AutoUpdateScheduler"
            )
            self.scheduler_thread.start()
            logger.info("[SchedulerManager] Background scheduler started")
            return True
    
    def stop_scheduler(self, timeout=5):
        """Stop the scheduler thread"""
        with self._lock:
            if self.scheduler_thread is None or not self.scheduler_thread.is_alive():
                logger.warning("[SchedulerManager] Scheduler not running")
                return False
                
            logger.info("[SchedulerManager] Stopping background scheduler...")
            self.scheduler_stop_event.set()
            self.scheduler_thread.join(timeout=timeout)
            
            # Clean up event loop if it exists
            if self._event_loop and not self._event_loop.is_closed():
                try:
                    self._event_loop.close()
                    logger.info("[SchedulerManager] Event loop cleaned up")
                except Exception as e:
                    logger.error(f"[SchedulerManager] Error cleaning up event loop: {e}")
                finally:
                    self._event_loop = None
            
            if self.scheduler_thread.is_alive():
                logger.error(f"[SchedulerManager] Scheduler thread did not stop within {timeout} seconds")
                return False
            else:
                logger.info("[SchedulerManager] Background scheduler stopped")
                return True
    
    def notify_settings_changed(self):
        """Notify the scheduler that relevant settings have changed"""
        logger.info("[SchedulerManager] Settings change notification received")
        self.settings_changed_event.set()
    
    def get_status(self):
        """Get the current scheduler status"""
        with self._lock:
            is_running = self.scheduler_thread is not None and self.scheduler_thread.is_alive()
            
            if not is_running:
                return {
                    "thread_alive": False,
                    "next_run": None,
                    "debug_info": {
                        "scheduler_thread_exists": self.scheduler_thread is not None,
                        "scheduler_thread_alive": self.scheduler_thread.is_alive() if self.scheduler_thread else False,
                        "error_count": self._error_count
                    }
                }
            
            # Calculate next run time
            db = SessionLocal()
            try:
                enabled = Setting.get_setting(db, "auto_update_enabled", True)
                interval = Setting.get_setting(db, "auto_update_interval", 3600)
                
                if enabled:
                    current_time = time.time()
                    time_since_last_run = current_time - self.last_agent_run_time
                    time_until_next_run = max(0, interval - time_since_last_run)
                    
                    return {
                        "thread_alive": True,
                        "next_run": {
                            "interval_seconds": interval,
                            "interval_human": f"{interval // 3600}h {(interval % 3600) // 60}m {interval % 60}s" if interval >= 3600 else f"{interval // 60}m {interval % 60}s" if interval >= 60 else f"{interval}s",
                            "seconds_until_next": int(time_until_next_run)
                        },
                        "debug_info": {
                            "scheduler_thread_exists": True,
                            "scheduler_thread_alive": True,
                            "enabled": enabled,
                            "last_agent_run_time": self.last_agent_run_time,
                            "current_time": current_time,
                            "instant_updates": True,
                            "error_count": self._error_count
                        }
                    }
                else:
                    return {
                        "thread_alive": True,
                        "next_run": {
                            "interval_seconds": interval,
                            "interval_human": "Disabled",
                            "seconds_until_next": None
                        },
                        "debug_info": {
                            "scheduler_thread_exists": True,
                            "scheduler_thread_alive": True,
                            "enabled": False,
                            "instant_updates": True,
                            "error_count": self._error_count
                        }
                    }
            finally:
                db.close()

    def _scheduler_loop(self):
        """The main scheduler loop with improved resource management"""
        logger.info("[SchedulerManager] Background scheduler thread started")
        
        # Import here to avoid circular imports
        import asyncio
        from services.live_events import live_events
        
        # Helper function to safely broadcast events
        def broadcast_scheduler_event(action: str, data: dict):
            """Safely broadcast events with proper resource management"""
            try:
                # Create a new event loop only if we don't have one or it's closed
                if self._event_loop is None or self._event_loop.is_closed():
                    self._event_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self._event_loop)
                
                # Run the broadcast
                self._event_loop.run_until_complete(live_events.broadcast_scheduler_event(action, data))
                
            except Exception as e:
                logger.error(f"[SchedulerManager] Failed to broadcast event: {e}")
                self._error_count += 1
                
                # Clean up corrupted event loop
                if self._event_loop and not self._event_loop.is_closed():
                    try:
                        self._event_loop.close()
                    except:
                        pass
                    self._event_loop = None
        
        # Broadcast scheduler start event
        broadcast_scheduler_event("scheduler_started", {
            "message": "Auto-update scheduler started with memory leak fixes",
            "status": "running",
            "features": ["instant_settings_updates", "memory_leak_fixes"]
        })
        
        error_count = 0
        gc_counter = 0
        
        while not self.scheduler_stop_event.is_set():
            try:
                # Periodic garbage collection every 60 iterations (approximately 10 minutes)
                gc_counter += 1
                if gc_counter >= 60:
                    gc_counter = 0
                    collected = gc.collect()
                    logger.debug(f"[SchedulerManager] Garbage collection freed {collected} objects")
                
                # Wait for either 10 seconds OR a settings change notification
                wait_timeout = 10
                settings_changed = self.settings_changed_event.wait(timeout=wait_timeout)
                
                if settings_changed:
                    logger.info("[SchedulerManager] Settings change detected, checking immediately")
                    self.settings_changed_event.clear()  # Reset the event
                    
                    # Broadcast instant response event
                    broadcast_scheduler_event("settings_updated", {
                        "message": "Scheduler responding to settings change",
                        "response_time": "instant"
                    })
                
                db = SessionLocal()
                try:
                    # Get current settings
                    enabled = Setting.get_setting(db, "auto_update_enabled", True)
                    interval = Setting.get_setting(db, "auto_update_interval", 3600)
                    
                    current_time = time.time()
                    
                    # Check if it's time to run the agent
                    if enabled and (current_time - self.last_agent_run_time) >= interval:
                        # Only trigger if not already running
                        if not AutoUpdateService.is_auto_update_running():
                            logger.info(f"[SchedulerManager] Triggering auto-update agent (interval: {interval}s)")
                            
                            # Broadcast scheduler trigger event
                            broadcast_scheduler_event("agent_triggered", {
                                "message": f"Scheduler triggered auto-update agent",
                                "interval_seconds": interval,
                                "time_since_last_run": int(current_time - self.last_agent_run_time),
                                "trigger_reason": "settings_change" if settings_changed else "scheduled"
                            })
                            
                            AutoUpdateService.start_auto_update_cycle_thread()
                            self.last_agent_run_time = current_time
                        else:
                            logger.info(f"[SchedulerManager] Agent already running, skipping trigger")
                            
                            # Broadcast scheduler skip event
                            broadcast_scheduler_event("agent_skip", {
                                "message": "Scheduler skipped trigger - agent already running",
                                "reason": "agent_already_running"
                            })
                            
                            # Reset timer so we don't spam logs
                            self.last_agent_run_time = current_time
                    elif settings_changed:
                        # Settings changed but not time to run yet, just log it
                        time_remaining = interval - (current_time - self.last_agent_run_time)
                        logger.info(f"[SchedulerManager] Settings updated. Next run in {time_remaining:.0f}s (enabled: {enabled})")
                        
                        broadcast_scheduler_event("settings_acknowledged", {
                            "message": f"Settings update acknowledged",
                            "enabled": enabled,
                            "interval_seconds": interval,
                            "next_run_seconds": max(0, time_remaining) if enabled else None
                        })
                    
                finally:
                    db.close()
                
                # Reset error count on successful iteration
                error_count = 0
                    
            except Exception as e:
                error_count += 1
                logger.error(f"[SchedulerManager] Error in scheduler loop: {e}")
                
                # Broadcast scheduler error event
                broadcast_scheduler_event("scheduler_error", {
                    "message": f"Scheduler encountered an error",
                    "error": str(e),
                    "status": "error",
                    "error_count": error_count
                })
                
                # If too many consecutive errors, log and reset
                if error_count >= 10:
                    logger.critical(f"[SchedulerManager] Too many consecutive errors: {error_count}. Resetting error count.")
                    error_count = 0
        
        # Clean up event loop before exit
        if self._event_loop and not self._event_loop.is_closed():
            try:
                # Broadcast scheduler stop event
                self._event_loop.run_until_complete(live_events.broadcast_scheduler_event("scheduler_stopped", {
                    "message": "Auto-update scheduler stopped",
                    "status": "stopped"
                }))
                self._event_loop.close()
            except Exception as e:
                logger.error(f"[SchedulerManager] Error during cleanup: {e}")
            finally:
                self._event_loop = None
        
        logger.info("[SchedulerManager] Background scheduler thread stopped")

# Global scheduler manager instance
scheduler_manager = SchedulerManager() 