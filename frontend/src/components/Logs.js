import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { FileText, Filter, Search, Download, RefreshCw, Eye } from 'lucide-react';
import { showError } from '../utils/customAlert';
import Pagination from './Pagination';

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
  const [pagination, setPagination] = useState({
    page: 1,
    per_page: 50,
    total: 0,
    pages: 0
  });

  const fetchLogs = useCallback(async (page = 1, perPage = pagination.per_page) => {
    try {
      setLoading(true);
      
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString()
      });
      
      // Add filters to params
      Object.entries(filters).forEach(([key, value]) => {
        if (value && value !== '') {
          params.append(key, value.toString());
        }
      });
      
      console.log('Fetching logs with params:', params.toString());
      const response = await axios.get(`/api/logs/?${params}`);
      console.log('API Response:', response.data);
      
      // Handle new pagination response structure
      if (response.data && response.data.logs) {
        setLogs(response.data.logs);
        setPagination({
          page: response.data.page,
          per_page: response.data.per_page,
          total: response.data.total,
          pages: response.data.pages
        });
      } else if (Array.isArray(response.data)) {
        // Fallback for old API response format
        setLogs(response.data);
        setPagination(prev => ({ 
          ...prev, 
          page: page, 
          per_page: perPage, 
          total: response.data.length,
          pages: 1
        }));
      } else if (response.data && Array.isArray(response.data.data)) {
        // Alternative structure
        setLogs(response.data.data);
        setPagination(prev => ({ 
          ...prev, 
          page: page, 
          per_page: perPage, 
          total: response.data.data.length,
          pages: 1
        }));
      } else {
        // Fallback
        console.warn('Unexpected API response structure:', response.data);
        setLogs([]);
        setPagination(prev => ({ ...prev, total: 0, pages: 0 }));
      }
    } catch (err) {
      console.error('Failed to fetch logs:', err);
      await showError('Failed to Load Logs', `Error: ${err.response?.data?.detail || err.message}`);
      setLogs([]);
      setPagination(prev => ({ ...prev, total: 0, pages: 0 }));
    } finally {
      setLoading(false);
    }
  }, [filters, pagination.per_page]);

  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`/api/logs/stats?hours=${filters.hours}`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch log stats:', error);
      setStats(null);
    }
  }, [filters.hours]);

  const searchLogs = useCallback(async (query, page = 1) => {
    if (!query || !query.trim()) {
      fetchLogs(page);
      return;
    }

    try {
      setLoading(true);
      console.log('Searching logs with query:', query);
      const response = await axios.get(`/api/logs/search?query_text=${encodeURIComponent(query.trim())}`);
      console.log('Search API Response:', response.data);
      
      if (Array.isArray(response.data)) {
        setLogs(response.data);
        setPagination(prev => ({ 
          ...prev, 
          page: 1, 
          total: response.data.length,
          pages: 1
        }));
      } else if (response.data && response.data.logs) {
        setLogs(response.data.logs);
        setPagination({
          page: response.data.page || 1,
          per_page: response.data.per_page || pagination.per_page,
          total: response.data.total || 0,
          pages: response.data.pages || 0
        });
      } else {
        setLogs([]);
        setPagination(prev => ({ ...prev, total: 0, pages: 0 }));
      }
    } catch (error) {
      console.error('Failed to search logs:', error);
      setLogs([]);
      setPagination(prev => ({ ...prev, total: 0, pages: 0 }));
    } finally {
      setLoading(false);
    }
  }, [fetchLogs, pagination.per_page]);

  // Initial load
  useEffect(() => {
    console.log('Initial load - fetching logs and stats');
    fetchLogs(1);
    fetchStats();
  }, [fetchLogs, fetchStats]); // Only run once on mount

  // Fetch when filters change (but not search query)
  useEffect(() => {
    if (!searchQuery.trim()) {
      console.log('Filters changed - refetching logs');
      fetchLogs(1);
      fetchStats();
    }
  }, [filters, searchQuery, fetchLogs, fetchStats]); // Only depend on filters, not the functions

  // Handle search with debounce
  useEffect(() => {
    if (searchQuery.trim()) {
      const timeoutId = setTimeout(() => {
        console.log('Search query changed - searching logs');
        searchLogs(searchQuery, 1);
      }, 300);

      return () => clearTimeout(timeoutId);
    } else {
      // When search is cleared, fetch regular logs
      console.log('Search cleared - fetching regular logs');
      fetchLogs(1);
    }
  }, [searchQuery, fetchLogs, searchLogs]);

  // Auto-refresh functionality
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      console.log('Auto-refresh triggered');
      if (searchQuery.trim()) {
        searchLogs(searchQuery, pagination.page);
      } else {
        fetchLogs(pagination.page, pagination.per_page);
        fetchStats();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [autoRefresh, searchQuery, pagination.page, pagination.per_page, fetchLogs, fetchStats, searchLogs]);

  const handlePageChange = (newPage) => {
    if (searchQuery.trim()) {
      searchLogs(searchQuery, newPage);
    } else {
      fetchLogs(newPage, pagination.per_page);
    }
  };

  const handleItemsPerPageChange = (newPerPage) => {
    setPagination(prev => ({ ...prev, per_page: newPerPage }));
    if (searchQuery.trim()) {
      searchLogs(searchQuery, 1);
    } else {
      fetchLogs(1, newPerPage); // Reset to page 1 when changing items per page
    }
  };

  const exportLogs = async () => {
    try {
      const params = new URLSearchParams();
      
      // Add current filters to export
      Object.entries(filters).forEach(([key, value]) => {
        if (value && value.toString().trim()) {
          params.append(key, value.toString());
        }
      });
      
      const response = await axios.get(`/api/logs/export?${params}`, {
        responseType: 'blob'
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `logs_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      await showError(
        'Export Failed',
        `Failed to export logs: ${error.response?.data?.detail || error.message}`
      );
    }
  };

  const handleRefresh = () => {
    console.log('Manual refresh triggered');
    setSearchQuery(''); // Clear search when manually refreshing
    fetchLogs(1);
    fetchStats();
  };

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

  const getModeBadgeClass = (mode) => {
    switch (mode) {
      case 'manual': return 'badge-manual';
      case 'auto_update': return 'badge-auto_update';
      default: return 'badge-secondary';
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  // Debug logging
  console.log('Logs component render - logs count:', logs.length, 'loading:', loading);

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
          <button className="btn btn-secondary" onClick={handleRefresh}>
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
            />
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
          <button className="btn btn-success" onClick={exportLogs}>
            <Download size={16} />
            Export Logs
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
              onChange={(e) => setFilters({ ...filters, hours: parseInt(e.target.value) || '' })}
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

      {/* Debug Info */}
      {process.env.NODE_ENV === 'development' && (
        <div style={{ padding: '10px', background: '#f0f0f0', margin: '10px 0', fontSize: '12px' }}>
          <strong>Debug Info:</strong> Logs count: {logs.length}, Loading: {loading.toString()}, 
          Search: "{searchQuery}", Filters: {JSON.stringify(filters)}, 
          Page: {pagination.page}/{pagination.pages}, Total: {pagination.total}
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
            <p>
              No log entries match your current filters
              {searchQuery ? ' or search query' : ''}
              {!searchQuery && !Object.values(filters).some(v => v && v !== 24) ? ' in the selected time range' : ''}
            </p>
            <button className="btn btn-primary" onClick={handleRefresh}>
              <RefreshCw size={16} />
              Refresh Logs
            </button>
          </div>
        ) : (
          <>
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
                  {logs.map((log, index) => (
                    <tr key={log.id || index}>
                      <td className="timestamp">{formatTimestamp(log.created_at || log.timestamp)}</td>
                      <td>
                        {log.action && (
                          <span className={`badge ${getActionBadgeClass(log.action)}`}>
                            {log.action}
                          </span>
                        )}
                      </td>
                      <td>
                        {log.mode && (
                          <span className={`badge ${getModeBadgeClass(log.mode)}`}>
                            {log.mode}
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
            
            {/* Pagination */}
            <Pagination
              currentPage={pagination.page}
              totalPages={pagination.pages}
              totalItems={pagination.total}
              itemsPerPage={pagination.per_page}
              onPageChange={handlePageChange}
              onItemsPerPageChange={handleItemsPerPageChange}
            />
          </>
        )}
      </div>
    </div>
  );
}

export default Logs; 