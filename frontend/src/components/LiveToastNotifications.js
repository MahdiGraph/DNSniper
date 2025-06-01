import React, { useState, useEffect, useRef } from 'react';
import { 
  Globe, 
  Network, 
  Activity, 
  Shield,
  CheckCircle,
  Clock,
  RefreshCw,
  Bell,
  Settings,
  Database,
  X,
  AlertCircle
} from 'lucide-react';

function LiveToastNotifications() {
  const [toastEvents, setToastEvents] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    connectToLiveEvents();
    
    // Cleanup on unmount
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectToLiveEvents = () => {
    const token = localStorage.getItem('authToken');
    if (!token) return;

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${protocol}://${window.location.host}/ws/live-events?token=${encodeURIComponent(token)}`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('🔴 Live Toast Notifications Connected');
        setWsConnected(true);
        // Send ping every 30 seconds to keep connection alive
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          } else {
            clearInterval(pingInterval);
          }
        }, 30000);
      };

      ws.onmessage = (event) => {
        try {
          const eventData = JSON.parse(event.data);
          
          // Skip connection and ping/pong events for toasts
          if (eventData.type === 'connection' || event.data === 'pong') {
            return;
          }
          
          // Add timestamp and unique ID for React keys
          const enrichedEvent = {
            ...eventData,
            id: Date.now() + Math.random(),
            timestamp: eventData.timestamp || new Date().toISOString()
          };
          
          // Add to toast notifications (keep only last 5)
          setToastEvents(prev => [enrichedEvent, ...prev].slice(0, 5));
          
          // Auto-remove toast after 6 seconds
          setTimeout(() => {
            setToastEvents(prev => prev.filter(toast => toast.id !== enrichedEvent.id));
          }, 6000);
          
        } catch (error) {
          console.error('Failed to parse WebSocket event:', error);
        }
      };

      ws.onclose = (event) => {
        console.log('🔴 Live Toast Notifications disconnected:', event.code, event.reason);
        setWsConnected(false);
        
        // Attempt to reconnect after 5 seconds if not a normal closure
        if (event.code !== 1000 && event.code !== 4004) {
          setTimeout(() => {
            if (!wsRef.current || wsRef.current.readyState === WebSocket.CLOSED) {
              connectToLiveEvents();
            }
          }, 5000);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setWsConnected(false);
      };
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      setWsConnected(false);
    }
  };

  const getToastIcon = (event) => {
    switch (event.type) {
      case 'domain': return <Globe size={16} />;
      case 'ip': return <Network size={16} />;
      case 'ip_range': return <Network size={16} />;
      case 'auto_update_source': return <Database size={16} />;
      case 'auto_update_cycle': return <RefreshCw size={16} />;
      case 'settings': return <Settings size={16} />;
      case 'firewall': return <Shield size={16} />;
      case 'auth': return <CheckCircle size={16} />;
      case 'system': return <Activity size={16} />;
      default: return <Bell size={16} />;
    }
  };

  const getToastClass = (event) => {
    switch (event.action) {
      case 'created': return 'hey-toast-success';
      case 'deleted': return 'hey-toast-danger';
      case 'updated': return 'hey-toast-info';
      case 'failed': return 'hey-toast-danger';
      case 'completed': return 'hey-toast-success';
      case 'started': return 'hey-toast-info';
      default: return 'hey-toast-default';
    }
  };

  const formatToastMessage = (event) => {
    if (event.type === 'auto_update_cycle') {
      return event.data?.message || 'Auto-update cycle event';
    }
    
    if (event.type === 'domain') {
      const domain = event.data?.domain_name || 'domain';
      return `${event.action} domain: ${domain}`;
    }
    
    if (event.type === 'ip') {
      const ip = event.data?.ip_address || 'IP';
      return `${event.action} IP: ${ip}`;
    }
    
    if (event.type === 'ip_range') {
      const range = event.data?.ip_range || 'IP range';
      return `${event.action} IP range: ${range}`;
    }
    
    if (event.type === 'auto_update_source') {
      const name = event.data?.name || 'auto-update source';
      return `${event.action} source: ${name}`;
    }
    
    if (event.type === 'settings') {
      if (event.data?.category === 'bulk') {
        return `Updated ${event.data?.count || 0} settings`;
      } else if (event.data?.key) {
        return `Updated setting: ${event.data.key}`;
      }
      return 'Settings updated';
    }
    
    if (event.type === 'firewall') {
      return event.data?.message || 'Firewall event';
    }
    
    if (event.type === 'system') {
      return event.data?.message || 'System event';
    }
    
    return event.message || `${event.type} ${event.action}`;
  };

  const removeToast = (toastId) => {
    setToastEvents(prev => prev.filter(toast => toast.id !== toastId));
  };

  // Don't render anything if not connected or no events
  if (!wsConnected && toastEvents.length === 0) {
    return null;
  }

  return (
    <div className="hey-toast-container">
      {/* Connection Status Indicator (only when disconnected and events exist) */}
      {!wsConnected && toastEvents.length > 0 && (
        <div className="hey-toast hey-toast-warning">
          <div className="hey-toast-icon">
            <AlertCircle size={16} />
          </div>
          <div className="hey-toast-content">
            <div className="hey-toast-message">
              Live events disconnected
            </div>
            <div className="hey-toast-time">
              Attempting to reconnect...
            </div>
          </div>
        </div>
      )}

      {/* Toast Events */}
      {toastEvents.map((event) => (
        <div key={event.id} className={`hey-toast ${getToastClass(event)}`}>
          <div className="hey-toast-icon">
            {getToastIcon(event)}
          </div>
          <div className="hey-toast-content">
            <div className="hey-toast-message">
              {formatToastMessage(event)}
            </div>
            <div className="hey-toast-time">
              <Clock size={10} />
              {new Date(event.timestamp).toLocaleTimeString()}
            </div>
          </div>
          <button 
            className="hey-toast-close"
            onClick={() => removeToast(event.id)}
          >
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

export default LiveToastNotifications; 