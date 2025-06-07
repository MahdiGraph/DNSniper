import asyncio
import json
import logging
import threading
import weakref
from datetime import datetime, timezone
from typing import Set, Dict, Any, Optional
from fastapi import WebSocket
from models.logs import ActionType, RuleType

logger = logging.getLogger(__name__)

class LiveEventsBroadcaster:
    """Service for broadcasting live events to WebSocket clients with improved resource management"""
    
    def __init__(self):
        self.connected_clients: Set[WebSocket] = set()
        self._client_lock = threading.Lock()
        self._cleanup_counter = 0
        self._max_cleanup_interval = 100  # Clean up every 100 broadcasts
    
    async def add_client(self, websocket: WebSocket):
        """Add a new WebSocket client with proper tracking"""
        try:
            with self._client_lock:
                self.connected_clients.add(websocket)
            
            logger.info(f"[LiveEvents] Client connected. Total clients: {len(self.connected_clients)}")
            
            await self.broadcast_event({
                'type': 'connection',
                'message': 'Connected to live events',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'client_count': len(self.connected_clients)
            })
        except Exception as e:
            logger.error(f"[LiveEvents] Error adding client: {e}")
    
    def remove_client(self, websocket: WebSocket):
        """Remove a WebSocket client with proper cleanup"""
        try:
            with self._client_lock:
                self.connected_clients.discard(websocket)
            
            logger.info(f"[LiveEvents] Client disconnected. Total clients: {len(self.connected_clients)}")
        except Exception as e:
            logger.error(f"[LiveEvents] Error removing client: {e}")
    
    def _cleanup_disconnected_clients(self):
        """Periodic cleanup of disconnected clients"""
        try:
            with self._client_lock:
                # Create a copy to avoid modification during iteration
                clients_to_check = list(self.connected_clients)
                initial_count = len(clients_to_check)
                
                for client in clients_to_check:
                    try:
                        # Try to check if the client is still connected
                        # This is a simple check - if the websocket is closed, accessing it will raise an exception
                        if hasattr(client, 'client_state') and client.client_state.name == 'DISCONNECTED':
                            self.connected_clients.discard(client)
                    except Exception:
                        # Client is likely disconnected, remove it
                        self.connected_clients.discard(client)
                
                cleaned_count = initial_count - len(self.connected_clients)
                if cleaned_count > 0:
                    logger.info(f"[LiveEvents] Cleaned up {cleaned_count} disconnected clients. Active clients: {len(self.connected_clients)}")
        
        except Exception as e:
            logger.error(f"[LiveEvents] Error during client cleanup: {e}")
    
    async def broadcast_event(self, event: Dict[str, Any]):
        """Broadcast an event to all connected clients with better error handling"""
        # Periodic cleanup
        self._cleanup_counter += 1
        if self._cleanup_counter >= self._max_cleanup_interval:
            self._cleanup_counter = 0
            self._cleanup_disconnected_clients()
        
        if not self.connected_clients:
            return
        
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # Create list of clients to avoid modification during iteration
        with self._client_lock:
            clients_to_broadcast = list(self.connected_clients)
        
        if not clients_to_broadcast:
            return
        
        # Track clients to remove
        clients_to_remove = []
        successful_broadcasts = 0
        
        for client in clients_to_broadcast:
            try:
                await client.send_json(event)
                successful_broadcasts += 1
            except Exception as e:
                # Client disconnected or error occurred, mark for removal
                logger.debug(f"[LiveEvents] Failed to send to client: {e}")
                clients_to_remove.append(client)
        
        # Remove disconnected clients
        if clients_to_remove:
            with self._client_lock:
                for client in clients_to_remove:
                    self.connected_clients.discard(client)
            
            logger.debug(f"[LiveEvents] Removed {len(clients_to_remove)} disconnected clients. "
                        f"Successful broadcasts: {successful_broadcasts}/{len(clients_to_broadcast)}")
    
    async def broadcast_domain_event(self, action: str, domain_data: Dict[str, Any], user_id: Optional[int] = None):
        """Broadcast domain-related events"""
        await self.broadcast_event({
            'type': 'domain',
            'action': action,  # 'created', 'updated', 'deleted', 'resolved'
            'data': domain_data,
            'user_id': user_id,
            'category': 'domains'
        })
    
    async def broadcast_ip_event(self, action: str, ip_data: Dict[str, Any], user_id: Optional[int] = None):
        """Broadcast IP-related events"""
        await self.broadcast_event({
            'type': 'ip',
            'action': action,  # 'created', 'updated', 'deleted'
            'data': ip_data,
            'user_id': user_id,
            'category': 'ips'
        })
    
    async def broadcast_ip_range_event(self, action: str, ip_range_data: Dict[str, Any], user_id: Optional[int] = None):
        """Broadcast IP range-related events"""
        await self.broadcast_event({
            'type': 'ip_range',
            'action': action,  # 'created', 'updated', 'deleted'
            'data': ip_range_data,
            'user_id': user_id,
            'category': 'ip_ranges'
        })
    
    async def broadcast_auto_update_source_event(self, action: str, source_data: Dict[str, Any], user_id: Optional[int] = None):
        """Broadcast auto-update source events"""
        await self.broadcast_event({
            'type': 'auto_update_source',
            'action': action,  # 'created', 'updated', 'deleted', 'tested'
            'data': source_data,
            'user_id': user_id,
            'category': 'auto_update_sources'
        })
    
    async def broadcast_settings_event(self, action: str, setting_data: Dict[str, Any], user_id: Optional[int] = None):
        """Broadcast settings change events"""
        await self.broadcast_event({
            'type': 'settings',
            'action': action,  # 'updated'
            'data': setting_data,
            'user_id': user_id,
            'category': 'settings'
        })
    
    async def broadcast_auto_update_cycle_event(self, action: str, cycle_data: Dict[str, Any]):
        """Broadcast auto-update cycle events"""
        await self.broadcast_event({
            'type': 'auto_update_cycle',
            'action': action,  # 'started', 'completed', 'failed', 'progress'
            'data': cycle_data,
            'category': 'auto_update'
        })
    
    async def broadcast_firewall_event(self, action: str, firewall_data: Dict[str, Any]):
        """Broadcast firewall status events"""
        await self.broadcast_event({
            'type': 'firewall',
            'action': action,  # 'rule_added', 'rule_removed', 'status_changed'
            'data': firewall_data,
            'category': 'firewall'
        })
    
    async def broadcast_auth_event(self, action: str, auth_data: Dict[str, Any]):
        """Broadcast authentication events"""
        await self.broadcast_event({
            'type': 'auth',
            'action': action,  # 'login', 'logout', 'token_created'
            'data': auth_data,
            'category': 'authentication'
        })
    
    async def broadcast_system_event(self, action: str, system_data: Dict[str, Any]):
        """Broadcast system events"""
        await self.broadcast_event({
            'type': 'system',
            'action': action,  # 'startup', 'shutdown', 'error'
            'data': system_data,
            'category': 'system'
        })
    
    async def broadcast_scheduler_event(self, action: str, scheduler_data: Dict[str, Any]):
        """Broadcast scheduler events"""
        await self.broadcast_event({
            'type': 'scheduler',
            'action': action,  # 'started', 'stopped', 'agent_triggered', 'agent_skip', 'error'
            'data': scheduler_data,
            'category': 'scheduler'
        })
    
    def get_client_count(self) -> int:
        """Get number of connected clients"""
        with self._client_lock:
            return len(self.connected_clients)
    
    def get_status(self) -> Dict[str, Any]:
        """Get broadcaster status and statistics"""
        with self._client_lock:
            return {
                "connected_clients": len(self.connected_clients),
                "cleanup_counter": self._cleanup_counter,
                "max_cleanup_interval": self._max_cleanup_interval,
                "status": "active" if self.connected_clients else "idle"
            }

# Global instance
live_events = LiveEventsBroadcaster() 