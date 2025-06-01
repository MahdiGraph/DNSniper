import React, { useState, useEffect } from 'react';
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
  RefreshCw
} from 'lucide-react';

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardStats();
  }, []);

  const fetchDashboardStats = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/dashboard');
      setStats(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch dashboard data');
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleAutoUpdateAction = async (action) => {
    try {
      let endpoint;
      let message;

      switch (action) {
        case 'pause':
          endpoint = '/api/auto-update-sources/pause';
          message = 'Auto-update agent paused successfully';
          break;
        case 'start':
          endpoint = '/api/auto-update-sources/start';
          message = 'Auto-update agent started successfully';
          break;
        case 'trigger':
          endpoint = '/api/auto-update-sources/trigger-update';
          message = 'Auto-update cycle triggered successfully';
          break;
        default:
          return;
      }

      await axios.post(endpoint);
      alert(message);
      
      // Refresh dashboard data
      fetchDashboardStats();
    } catch (error) {
      alert(`Failed to ${action} auto-update agent: ` + (error.response?.data?.detail || error.message));
    }
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
          <button className="refresh-button" onClick={fetchDashboardStats}>
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
        <button className="refresh-button" onClick={fetchDashboardStats}>
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
          status={auto_update?.enabled && !auto_update?.is_running ? 'active' : auto_update?.is_running ? 'running' : 'inactive'}
          details={[
            `Sources: ${auto_update?.active_sources || 0}`,
            `Running: ${auto_update?.is_running ? 'Yes' : 'No'}`,
            `Enabled: ${auto_update?.enabled ? 'Yes' : 'No'}`
          ]}
          actions={[
            {
              label: auto_update?.enabled ? 'Pause' : 'Start',
              action: auto_update?.enabled ? 'pause' : 'start',
              variant: auto_update?.enabled ? 'warning' : 'success'
            },
            {
              label: 'Trigger Update',
              action: 'trigger',
              variant: 'primary'
            }
          ]}
          onAction={handleAutoUpdateAction}
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

function StatusCard({ title, status, details, actions = [], onAction }) {
  const getStatusIcon = () => {
    switch (status) {
      case 'active':
        return <CheckCircle size={16} className="status-active" />;
      case 'running':
        return <Activity size={16} className="status-running" />;
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
          {actions.map((action, index) => (
            <button
              key={index}
              className={`status-action status-${action.variant}`}
              onClick={() => onAction && onAction(action.action)}
            >
              {action.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default Dashboard;