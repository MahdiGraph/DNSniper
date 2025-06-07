import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { Plus, Search, Trash2, Network, RefreshCw } from 'lucide-react';
import { showError, showDeleteConfirm } from '../utils/customAlert';
import { useTooltipHandlers } from '../utils/tooltip';
import Pagination from './Pagination';

function IPManagement() {
  const [ips, setIps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [filter, setFilter] = useState({ list_type: '', source_type: '', ip_version: '' });
  const [pagination, setPagination] = useState({
    page: 1,
    per_page: 50,
    total: 0,
    pages: 0
  });

  const tooltipHandlers = useTooltipHandlers();

  const fetchIPs = useCallback(async (page = 1, perPage = pagination.per_page) => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString()
      });
      if (search) params.append('search', search);
      if (filter.list_type) params.append('list_type', filter.list_type);
      if (filter.source_type) params.append('source_type', filter.source_type);
      if (filter.ip_version) params.append('ip_version', filter.ip_version);
      
      const response = await axios.get(`/api/ips/?${params}`);
      
      // Handle new pagination response structure
      if (response.data && response.data.ips) {
        setIps(response.data.ips);
        setPagination({
          page: response.data.page,
          per_page: response.data.per_page,
          total: response.data.total,
          pages: response.data.pages
        });
      } else {
        // Fallback for old API response format
        setIps(Array.isArray(response.data) ? response.data : []);
        setPagination(prev => ({ 
          ...prev, 
          page: page, 
          per_page: perPage, 
          total: Array.isArray(response.data) ? response.data.length : 0,
          pages: 1
        }));
      }
    } catch (error) {
      console.error('Failed to fetch IPs:', error);
      setIps([]);
      setPagination(prev => ({ ...prev, total: 0, pages: 0 }));
    } finally {
      setLoading(false);
    }
  }, [search, filter, pagination.per_page]);

  useEffect(() => {
    fetchIPs(1);
  }, [search, filter, fetchIPs]); // Reset to page 1 when search or filter changes

  const handlePageChange = (newPage) => {
    fetchIPs(newPage, pagination.per_page);
  };

  const handleItemsPerPageChange = (newPerPage) => {
    setPagination(prev => ({ ...prev, per_page: newPerPage }));
    fetchIPs(1, newPerPage); // Reset to page 1 when changing items per page
  };

  const deleteIP = async (ipId) => {
    const result = await showDeleteConfirm(
      'Delete IP Address',
      'Are you sure you want to delete this IP address? This action cannot be undone.'
    );
    
    if (result.isConfirmed) {
      try {
        await axios.delete(`/api/ips/${ipId}`);
        // Refresh current page or go to previous page if current page becomes empty
        const newTotal = pagination.total - 1;
        const maxPage = Math.ceil(newTotal / pagination.per_page);
        const currentPage = pagination.page > maxPage ? Math.max(1, maxPage) : pagination.page;
        fetchIPs(currentPage, pagination.per_page);
      } catch (error) {
        await showError(
          'Delete Failed',
          `Failed to delete IP: ${error.response?.data?.detail || error.message}`
        );
      }
    }
  };

  const handleAddSuccess = () => {
    setShowAddModal(false);
    // Refresh to show the new IP (it might be on a different page)
    fetchIPs(1, pagination.per_page);
  };

  return (
    <div className="ip-management">
      <div className="page-header">
        <h1>
          <Network size={24} />
          IP Address Management
        </h1>
        <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
          <Plus size={16} />
          Add IP Address
        </button>
      </div>

      {/* Filters */}
      <div className="filters">
        <div className="search-box">
          <Search size={16} />
          <input
            type="text"
            placeholder="Search IP addresses..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          value={filter.list_type}
          onChange={(e) => setFilter({ ...filter, list_type: e.target.value })}
        >
          <option value="">All Lists</option>
          <option value="blacklist">Blacklist</option>
          <option value="whitelist">Whitelist</option>
        </select>
        <select
          value={filter.source_type}
          onChange={(e) => setFilter({ ...filter, source_type: e.target.value })}
        >
          <option value="">All Sources</option>
          <option value="manual">Manual</option>
          <option value="auto_update">Auto-Update</option>
        </select>
        <select
          value={filter.ip_version}
          onChange={(e) => setFilter({ ...filter, ip_version: e.target.value })}
        >
          <option value="">All Versions</option>
          <option value="4">IPv4</option>
          <option value="6">IPv6</option>
        </select>
        <button className="btn btn-secondary" onClick={() => fetchIPs(pagination.page, pagination.per_page)}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* IP List */}
      <div className="ip-list">
        {loading ? (
          <div className="loading">Loading IP addresses...</div>
        ) : ips.length === 0 ? (
          <div className="empty-state">
            <Network size={48} />
            <h3>No IP addresses found</h3>
            <p>
              {search || filter.list_type || filter.source_type || filter.ip_version
                ? 'No IP addresses match your current filters' 
                : 'Add your first IP address to get started'
              }
            </p>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Version</th>
                    <th>List Type</th>
                    <th>Source</th>
                    <th>Domain</th>
                    <th>Created</th>
                    <th>Expires</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {ips.map((ip) => (
                    <tr key={ip.id}>
                      <td 
                        className={`ip-address ${ip.notes ? 'has-tooltip' : ''}`}
                        data-tooltip={ip.notes || ''}
                        {...(ip.notes ? tooltipHandlers : {})}
                      >
                        {ip.ip_address}
                      </td>
                      <td>
                        <span className={`badge badge-ipv${ip.ip_version}`}>
                          IPv{ip.ip_version}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${ip.list_type}`}>
                          {ip.list_type}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${ip.source_type}`}>
                          {ip.source_type}
                        </span>
                      </td>
                      <td>{ip.domain_name || '-'}</td>
                      <td>{new Date(ip.created_at).toLocaleDateString()}</td>
                      <td>
                        {ip.expires_in ? (
                          <span className={
                            ip.expires_in === 'Expired' ? 'expired' : 'expires'
                          }>
                            {ip.expires_in}
                          </span>
                        ) : (
                          <span className="permanent">Never</span>
                        )}
                      </td>
                      <td>
                        <div className="actions">
                          <button 
                            className="btn-icon btn-danger" 
                            title="Delete"
                            onClick={() => deleteIP(ip.id)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
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

      {/* Add IP Modal */}
      {showAddModal && (
        <AddIPModal 
          onClose={() => setShowAddModal(false)} 
          onSuccess={handleAddSuccess}
        />
      )}
    </div>
  );
}

function AddIPModal({ onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    ip_address: '',
    list_type: 'blacklist',
    notes: ''
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post('/api/ips/', formData);
      onSuccess();
    } catch (error) {
      await showError(
        'Add IP Failed',
        `Failed to add IP: ${error.response?.data?.detail || error.message}`
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Add IP Address</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label>IP Address</label>
            <input
              type="text"
              required
              placeholder="192.168.1.1 or 2001:db8::1"
              value={formData.ip_address}
              onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>List Type</label>
            <select
              value={formData.list_type}
              onChange={(e) => setFormData({ ...formData, list_type: e.target.value })}
            >
              <option value="blacklist">Blacklist</option>
              <option value="whitelist">Whitelist</option>
            </select>
          </div>
          <div className="form-group">
            <label>Notes (Optional)</label>
            <textarea
              placeholder="Additional notes..."
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
            />
          </div>
          <div className="modal-footer">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Adding...' : 'Add IP'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default IPManagement; 