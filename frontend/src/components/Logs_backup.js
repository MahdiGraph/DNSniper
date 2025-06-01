import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { FileText, Filter, Search, Download, RefreshCw, Trash2, Eye } from 'lucide-react';

function Logs() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    action: '',
    rule_type: '',
    ip_address: '',
    domain_name: '',
    hours: 24
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [showFilters, setShowFilters] = useState(false);

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      
      if (filters.action) params.append('action', filters.action);
      if (filters.rule_type) params.append('rule_type', filters.rule_type);
      if (filters.ip_address) params.append('ip_address', filters.ip_address);
      if (filters.domain_name) params.append('domain_name', filters.domain_name);
      if (filters.hours) params.append('hours', filters.hours);
      
      const response = await axios.get(`/api/logs/?${params}`);
      setLogs(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`/api/logs/stats?hours=${filters.hours}`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch log stats:', error);
      setStats(null);
    }
  }, [filters.hours]);

  const searchLogs = async () => {
    if (!searchQuery.trim()) {
      fetchLogs();
      return;
    }

    try {
      setLoading(true);
      const response = await axios.get(`/api/logs/search?query_text=${encodeURIComponent(searchQuery)}`);
      setLogs(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Failed to search logs:', error);
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  const exportLogs = async (format = 'json') => {
    try {
      const response = await axios.get(`/api/logs/export?hours=${filters.hours}&format=${format}`, {
        responseType: format === 'csv' ? 'blob' : 'json'
      });

      if (format === 'csv') {
        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `dnsniper_logs_${filters.hours}h.csv`);
        document.body.appendChild(link);
        link.click();
        link.remove();
      } else {
        const dataStr = JSON.stringify(response.data, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = window.URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `dnsniper_logs_${filters.hours}h.json`);
        document.body.appendChild(link);
        link.click();
        link.remove();
      }
    } catch (error) {
      alert('Failed to export logs: ' + (error.response?.data?.detail || error.message));
    }
  };

  const cleanupLogs = async () => {
    const days = prompt('Delete logs older than how many days? (Enter number):');
    if (!days || isNaN(days)) return;

    if (!window.confirm(`Are you sure you want to delete logs older than ${days} days?`)) return;

    try {
      await axios.delete(`/api/logs/cleanup?days=${days}`);
      alert('Logs cleaned up successfully');
      fetchLogs();
      fetchStats();
    } catch (error) {
      alert('Failed to cleanup logs: ' + (error.response?.data?.detail || error.message));
    }
  };

  useEffect(() => {
    fetchLogs();
    fetchStats();
  }, [fetchLogs, fetchStats]);

  // Auto-refresh functionality
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      fetchLogs();
      fetchStats();
    }, 5000); // Refresh every 5 seconds

    return () => clearInterval(interval);
  }, [autoRefresh, fetchLogs, fetchStats]);

  const getActionBadgeClass = (action) => {
    switch (action) {
      case 'block': return 'badge-danger';
      case 'allow': return 'badge-success';
      case 'add_rule': return 'badge-primary';
      case 'remove_rule': return 'badge-warning';
      case 'update': return 'badge-secondary';
      case 'error': return 'badge-danger';
      default: return 'badge-secondary';
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="logs">
      <div className="page-header">
        <h1>
          <FileText size={24} />
          System Logs
        </h1>
        <div className="header-actions">
          <button 
            className={`btn ${autoRefresh ? 'btn-warning' : 'btn-secondary'}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <Eye size={16} />
            {autoRefresh ? 'Stop Auto-Refresh' : 'Auto-Refresh'}
          </button>
          <button className="btn btn-secondary" onClick={() => { fetchLogs(); fetchStats(); }}>
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>
      </div>

      {/* Statistics */}
      {stats && (
        <div className="stats-grid">
          <div className="stats-card">
            <h3>Total Logs</h3>
            <div className="stats-value">{stats.total_logs}</div>
          </div>
          <div className="stats-card">
            <h3>Recent Logs (24h)</h3>
            <div className="stats-value">{stats.recent_logs_24h}</div>
          </div>
          <div className="stats-card">
            <h3>Recent Blocks</h3>
            <div className="stats-value">{stats.recent_blocks}</div>
          </div>
          <div className="stats-card">
            <h3>Recent Allows</h3>
            <div className="stats-value">{stats.recent_allows}</div>
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="logs-controls">
        <div className="search-section">
          <div className="search-box">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search log messages..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && searchLogs()}
            />
            <button className="btn btn-primary" onClick={searchLogs}>
              Search
            </button>
          </div>
        </div>

        <div className="control-buttons">
          <button 
            className="btn btn-secondary"
            onClick={() => setShowFilters(!showFilters)}
          >
            <Filter size={16} />
            {showFilters ? 'Hide Filters' : 'Show Filters'}
          </button>
          <button className="btn btn-success" onClick={() => exportLogs('json')}>
            <Download size={16} />
            Export JSON
          </button>
          <button className="btn btn-success" onClick={() => exportLogs('csv')}>
            <Download size={16} />
            Export CSV
          </button>
          <button className="btn btn-danger" onClick={cleanupLogs}>
            <Trash2 size={16} />
            Cleanup Old
          </button>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="filters-section">
          <div className="filters">
            <select
              value={filters.action}
              onChange={(e) => setFilters({ ...filters, action: e.target.value })}
            >
              <option value="">All Actions</option>
              <option value="block">Block</option>
              <option value="allow">Allow</option>
              <option value="add_rule">Add Rule</option>
              <option value="remove_rule">Remove Rule</option>
              <option value="update">Update</option>
              <option value="error">Error</option>
            </select>

            <select
              value={filters.rule_type}
              onChange={(e) => setFilters({ ...filters, rule_type: e.target.value })}
            >
              <option value="">All Rule Types</option>
              <option value="domain">Domain</option>
              <option value="ip">IP</option>
              <option value="ip_range">IP Range</option>
            </select>

            <input
              type="text"
              placeholder="Filter by IP address"
              value={filters.ip_address}
              onChange={(e) => setFilters({ ...filters, ip_address: e.target.value })}
            />

            <input
              type="text"
              placeholder="Filter by domain name"
              value={filters.domain_name}
              onChange={(e) => setFilters({ ...filters, domain_name: e.target.value })}
            />

            <select
              value={filters.hours}
              onChange={(e) => setFilters({ ...filters, hours: parseInt(e.target.value) })}
            >
              <option value="1">Last 1 Hour</option>
              <option value="6">Last 6 Hours</option>
              <option value="24">Last 24 Hours</option>
              <option value="72">Last 3 Days</option>
              <option value="168">Last Week</option>
              <option value="">All Time</option>
            </select>
          </div>
        </div>
      )}

      {/* Logs Table */}
      <div className="logs-list">
        {loading ? (
          <div className="loading">Loading logs...</div>
        ) : logs.length === 0 ? (
          <div className="empty-state">
            <FileText size={48} />
            <h3>No logs found</h3>
            <p>No log entries match your current filters</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Type</th>
                  <th>IP Address</th>
                  <th>Domain</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td className="timestamp">{formatTimestamp(log.created_at)}</td>
                    <td>
                      {log.action && (
                        <span className={`badge ${getActionBadgeClass(log.action)}`}>
                          {log.action}
                        </span>
                      )}
                    </td>
                    <td>
                      {log.rule_type && (
                        <span className="badge badge-secondary">
                          {log.rule_type}
                        </span>
                      )}
                    </td>
                    <td className="ip-address">
                      {log.ip_address || log.source_ip || log.destination_ip || '-'}
                    </td>
                    <td className="domain-name">{log.domain_name || '-'}</td>
                    <td className="log-message">{log.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default Logs; 