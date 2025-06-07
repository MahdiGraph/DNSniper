import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { 
  Shield, 
  Globe, 
  Network, 
  Activity, 
  TrendingUp, 
  AlertCircle,
  CheckCircle,
  Clock,
  RefreshCw,
  Square
} from 'lucide-react';
import { showSuccess, showError, showInfo } from '../utils/customAlert';

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [autoUpdateStatus, setAutoUpdateStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchDashboardStats = useCallback(async () => {
    const response = await axios.get('/api/dashboard');
    setStats(response.data);
  }, []);

  const fetchAutoUpdateStatus = useCallback(async () => {
    try {
      const response = await axios.get('/api/auto-update-sources/status');
      setAutoUpdateStatus(response.data);
    } catch (err) {
      console.error('Auto-update status fetch error:', err);
    }
  }, []);

  const fetchDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      await Promise.all([
        fetchDashboardStats(),
        fetchAutoUpdateStatus()
      ]);
      setError(null);
    } catch (err) {
      setError('Failed to fetch dashboard data');
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, [fetchDashboardStats, fetchAutoUpdateStatus]);

  useEffect(() => {
    fetchDashboardData();
    // Set up auto-refresh for auto-update status every 5 seconds
    const interval = setInterval(fetchAutoUpdateStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchDashboardData, fetchAutoUpdateStatus]);

  // Helper function to format seconds into human-readable time
  const formatTimeRemaining = (seconds) => {
    if (!seconds || seconds <= 0) return '0s';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    const parts = [];
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
    
    return parts.join('');
  };

  const handleAutoUpdateAction = async (action) => {
    if (actionLoading) return; // Prevent multiple concurrent actions
    
    try {
      setActionLoading(true);
      let endpoint;
      let message;

      switch (action) {
        case 'trigger':
          // For restart scenario, stop first then trigger
          if (autoUpdateStatus?.is_running) {
            // Stop current cycle first
            await axios.post('/api/auto-update-sources/stop-update');
            // Wait a moment for it to stop
            await new Promise(resolve => setTimeout(resolve, 1000));
            message = 'Auto-update cycle restarted successfully';
          } else {
            message = 'Auto-update cycle triggered successfully';
          }
          endpoint = '/api/auto-update-sources/trigger-update';
          break;
        case 'stop':
          endpoint = '/api/auto-update-sources/stop-update';
          message = 'Auto-update cycle stopped successfully';
          break;
        default:
          return;
      }

      const response = await axios.post(endpoint);
      
      // Handle different response statuses for trigger action
      if (action === 'trigger' && response.data.status === 'already_running') {
        await showInfo(
          'Already Running', 
          response.data.message + `\nThread ID: ${response.data.thread_id}\nStarted: ${new Date(response.data.start_time).toLocaleString()}`
        );
      } else {
        await showSuccess('Success', message);
      }
      
      // Refresh status immediately
      await fetchAutoUpdateStatus();
      await fetchDashboardStats();
      
    } catch (error) {
      await showError(
        'Operation Failed',
        `Failed to ${action === 'trigger' ? (autoUpdateStatus?.is_running ? 'restart' : 'trigger') : action} auto-update: ${error.response?.data?.detail || error.message}`
      );
    } finally {
      setActionLoading(false);
    }
  };

  const getAutoUpdateDisplayStatus = () => {
    if (!autoUpdateStatus) return 'inactive';
    
    if (autoUpdateStatus.is_running) {
      return 'running';
    } else {
      return 'active';  // Ready to run
    }
  };

  const getAutoUpdateDetails = () => {
    if (!autoUpdateStatus) return ['Status: Unknown'];
    
    const details = [];
    
    // Add running status first (most important)
    if (autoUpdateStatus.is_running) {
      details.push(`🔄 Currently running since ${new Date(autoUpdateStatus.start_time).toLocaleString()}`);
      if (autoUpdateStatus.thread_id) {
        details.push(`Thread ID: ${autoUpdateStatus.thread_id}`);
      }
    } else {
      details.push(`⏸️ Not running`);
    }
    
    // Add scheduler status
    if (autoUpdateStatus.enabled) {
      details.push(`📅 Scheduler: Enabled`);
    } else {
      details.push(`📅 Scheduler: Disabled`);
    }
    
    // Add sources info
    details.push(`📡 Active Sources: ${autoUpdateStatus.active_sources || 0}/${autoUpdateStatus.total_sources || 0}`);
    
    // Add update interval info if available
    if (autoUpdateStatus.scheduler?.next_run?.interval_human) {
      details.push(`⏰ Update Interval: ${autoUpdateStatus.scheduler.next_run.interval_human}`);
    }
    
    // Add scheduler health information (only if we have scheduler data)
    if (autoUpdateStatus.scheduler && typeof autoUpdateStatus.scheduler.thread_alive !== 'undefined') {
      if (autoUpdateStatus.scheduler.thread_alive) {
        // Scheduler is healthy
        let statusText = '✅ Healthy';
        
        // Add time remaining information
        if (autoUpdateStatus.enabled) {
          // Auto-update is enabled, show time until next run
          if (autoUpdateStatus.scheduler.next_run && 
              typeof autoUpdateStatus.scheduler.next_run.seconds_until_next === 'number') {
            const timeRemaining = formatTimeRemaining(autoUpdateStatus.scheduler.next_run.seconds_until_next);
            statusText += ` (${timeRemaining} until next run)`;
          } else {
            statusText += ' (Next run time calculating...)';
          }
        } else {
          // Auto-update is disabled
          statusText += ' (Disabled)';
        }
        
        details.push(`🔧 Scheduler Auto-Update Status: ${statusText}`);
      } else {
        // Scheduler is not running
        details.push(`🔧 Scheduler Auto-Update Status: ❌ Not Running`);
      }
    } else if (autoUpdateStatus.enabled) {
      // If scheduler is enabled but we don't have health data, show unknown
      details.push(`🔧 Scheduler Auto-Update Status: ❓ Unknown`);
    }
    
    return details;
  };

  const getAutoUpdateActions = () => {
    if (!autoUpdateStatus) return [];
    
    const actions = [];
    
    if (autoUpdateStatus.is_running) {
      // When auto-update is currently running, show stop button
      actions.push({
        label: 'Stop Update',
        action: 'stop',
        variant: 'danger',
        icon: Square
      });
      
      // Show trigger button as "restart" when running
      actions.push({
        label: 'Restart Update',
        action: 'trigger',
        variant: 'primary',
        icon: RefreshCw
      });
    } else {
      // When auto-update is not running, show trigger button as "start"
      actions.push({
        label: 'Trigger Update',
        action: 'trigger',
        variant: 'primary',
        icon: RefreshCw,
        disabled: !autoUpdateStatus.can_trigger
      });
    }
    
    return actions;
  };

  if (loading) {
    return (
      <div className="dashboard">
        <div className="dashboard-header">
          <h1>Dashboard</h1>
          <div className="loading">Loading...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard">
        <div className="dashboard-header">
          <h1>Dashboard</h1>
          <button className="refresh-button" onClick={fetchDashboardData}>
            <RefreshCw size={16} />
            Retry
          </button>
        </div>
        <div className="error-message">
          <AlertCircle size={20} />
          {error}
        </div>
      </div>
    );
  }

  // Match the actual API response structure
  const { totals, lists, sources, auto_update, firewall, activity } = stats || {};

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <button className="refresh-button" onClick={fetchDashboardData}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Summary Cards */}
      <div className="stats-grid">
        <StatsCard
          title="Total Domains"
          value={totals?.domains || 0}
          icon={Globe}
          subtitle={`${lists?.blacklist?.domains || 0} blacklisted, ${lists?.whitelist?.domains || 0} whitelisted`}
        />
        <StatsCard
          title="Total IPs"
          value={totals?.ips || 0}
          icon={Network}
          subtitle={`${lists?.blacklist?.ips || 0} blacklisted, ${lists?.whitelist?.ips || 0} whitelisted`}
        />
        <StatsCard
          title="IP Ranges"
          value={totals?.ip_ranges || 0}
          icon={Shield}
          subtitle={`${lists?.blacklist?.ip_ranges || 0} blacklisted, ${lists?.whitelist?.ip_ranges || 0} whitelisted`}
        />
        <StatsCard
          title="Auto-Update Sources"
          value={totals?.auto_update_sources || 0}
          icon={TrendingUp}
          subtitle={`${auto_update?.active_sources || 0} active`}
        />
      </div>

      {/* Detailed Statistics */}
      <div className="stats-grid">
        <StatsCard
          title="Manual Entries"
          value={(sources?.manual?.domains || 0) + (sources?.manual?.ips || 0) + (sources?.manual?.ip_ranges || 0)}
          icon={TrendingUp}
          subtitle={`Domains: ${sources?.manual?.domains || 0}, IPs: ${sources?.manual?.ips || 0}, Ranges: ${sources?.manual?.ip_ranges || 0}`}
        />
        <StatsCard
          title="Auto-Update Entries"
          value={(sources?.auto_update?.domains || 0) + (sources?.auto_update?.ips || 0) + (sources?.auto_update?.ip_ranges || 0)}
          icon={Clock}
          subtitle={`Domains: ${sources?.auto_update?.domains || 0}, IPs: ${sources?.auto_update?.ips || 0}, Ranges: ${sources?.auto_update?.ip_ranges || 0}`}
        />
        <StatsCard
          title="Blacklist Total"
          value={(lists?.blacklist?.domains || 0) + (lists?.blacklist?.ips || 0) + (lists?.blacklist?.ip_ranges || 0)}
          icon={AlertCircle}
          subtitle={`Domains: ${lists?.blacklist?.domains || 0}, IPs: ${lists?.blacklist?.ips || 0}, Ranges: ${lists?.blacklist?.ip_ranges || 0}`}
        />
        <StatsCard
          title="Whitelist Total"
          value={(lists?.whitelist?.domains || 0) + (lists?.whitelist?.ips || 0) + (lists?.whitelist?.ip_ranges || 0)}
          icon={CheckCircle}
          subtitle={`Domains: ${lists?.whitelist?.domains || 0}, IPs: ${lists?.whitelist?.ips || 0}, Ranges: ${lists?.whitelist?.ip_ranges || 0}`}
        />
      </div>

      {/* Status Cards */}
      <div className="status-grid">
        <StatusCard
          title="Auto-Update Agent"
          status={getAutoUpdateDisplayStatus()}
          details={getAutoUpdateDetails()}
          actions={getAutoUpdateActions()}
          onAction={handleAutoUpdateAction}
          actionLoading={actionLoading}
        />
        <StatusCard
          title="Firewall Status"
          status={firewall?.chains_exist?.ipv4 && firewall?.chains_exist?.ipv6 ? 'active' : 'inactive'}
          details={[
            `IPv4 Chain: ${firewall?.chains_exist?.ipv4 ? 'Active' : 'Inactive'}`,
            `IPv6 Chain: ${firewall?.chains_exist?.ipv6 ? 'Active' : 'Inactive'}`,
            `IPSets: ${
              firewall?.ipsets_exist?.ipv4 && firewall?.ipsets_exist?.ipv6 
                ? Object.values(firewall.ipsets_exist.ipv4).filter(Boolean).length + 
                  Object.values(firewall.ipsets_exist.ipv6).filter(Boolean).length
                : 0
            }/8`
          ]}
        />
      </div>

      {/* Recent Activity */}
      <div className="activity-section">
        <h2>Recent Activity (24h)</h2>
        <div className="activity-stats">
          <div className="activity-item">
            <span className="activity-label">Recent Logs</span>
            <span className="activity-count">{activity?.recent_logs_24h || 0}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatsCard({ title, value, icon: Icon, subtitle }) {
  return (
    <div className="stats-card">
      <div className="stats-header">
        <div className="stats-icon">
          <Icon size={24} />
        </div>
        <div className="stats-info">
          <h3>{title}</h3>
          <div className="stats-value">{value}</div>
        </div>
      </div>
      {subtitle && <div className="stats-subtitle">{subtitle}</div>}
    </div>
  );
}

function StatusCard({ title, status, details, actions = [], onAction, actionLoading }) {
  const getStatusIcon = () => {
    switch (status) {
      case 'active':
        return <CheckCircle size={16} className="status-active" />;
      case 'running':
        return <Activity size={16} className="status-running" />;
      case 'warning':
        return <AlertCircle size={16} className="status-warning" />;
      case 'inactive':
        return <AlertCircle size={16} className="status-inactive" />;
      default:
        return <Clock size={16} className="status-unknown" />;
    }
  };

  return (
    <div className="status-card">
      <div className="status-header">
        <h3>{title}</h3>
        <div className="status-indicator">
          {getStatusIcon()}
          <span className={`status-text status-${status}`}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </span>
        </div>
      </div>
      <div className="status-details">
        {details && details.map((detail, index) => (
          <div key={index} className="status-detail">{detail}</div>
        ))}
      </div>
      {actions && actions.length > 0 && (
        <div className="status-actions">
          {actions.map((action, index) => {
            const Icon = action.icon;
            return (
              <button
                key={index}
                className={`status-action status-${action.variant} ${action.disabled || actionLoading ? 'disabled' : ''}`}
                onClick={() => onAction && !action.disabled && !actionLoading && onAction(action.action)}
                disabled={action.disabled || actionLoading}
                title={action.disabled ? 'Action not available' : action.label}
              >
                {Icon && <Icon size={14} />}
                {actionLoading ? 'Loading...' : action.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default Dashboard;