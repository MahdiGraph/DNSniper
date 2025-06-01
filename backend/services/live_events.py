import asyncio
import json
from datetime import datetime, timezone
from typing import Set, Dict, Any, Optional
from fastapi import WebSocket
from models.logs import ActionType, RuleType


class LiveEventsBroadcaster:
    """Service for broadcasting live events to WebSocket clients"""
    
    def __init__(self):
        self.connected_clients: Set[WebSocket] = set()
    
    async def add_client(self, websocket: WebSocket):
        """Add a new WebSocket client"""
        self.connected_clients.add(websocket)
        await self.broadcast_event({
            'type': 'connection',
            'message': 'Connected to live events',
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    
    def remove_client(self, websocket: WebSocket):
        """Remove a WebSocket client"""
        self.connected_clients.discard(websocket)
    
    async def broadcast_event(self, event: Dict[str, Any]):
        """Broadcast an event to all connected clients"""
        if not self.connected_clients:
            return
        
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # Create list of clients to avoid modification during iteration
        clients_to_remove = []
        for client in list(self.connected_clients):
            try:
                await client.send_json(event)
            except Exception:
                # Client disconnected, mark for removal
                clients_to_remove.append(client)
        
        # Remove disconnected clients
        for client in clients_to_remove:
            self.connected_clients.discard(client)
    
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
    
    def get_client_count(self) -> int:
        """Get number of connected clients"""
        return len(self.connected_clients)


# Global instance
live_events = LiveEventsBroadcaster() 