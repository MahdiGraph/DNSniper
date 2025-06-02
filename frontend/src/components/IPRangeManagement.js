import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { Plus, Search, Trash2, Network, RefreshCw } from 'lucide-react';
import { showError, showDeleteConfirm } from '../utils/customAlert';
import Pagination from './Pagination';

function IPRangeManagement() {
  const [ipRanges, setIPRanges] = useState([]);
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

  const fetchIPRanges = useCallback(async (page = 1, perPage = pagination.per_page) => {
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
      
      const response = await axios.get(`/api/ip-ranges/?${params}`);
      
      // Handle new pagination response structure
      if (response.data && response.data.ip_ranges) {
        setIPRanges(response.data.ip_ranges);
        setPagination({
          page: response.data.page,
          per_page: response.data.per_page,
          total: response.data.total,
          pages: response.data.pages
        });
      } else {
        // Fallback for old API response format
        setIPRanges(Array.isArray(response.data) ? response.data : []);
        setPagination(prev => ({ 
          ...prev, 
          page: page, 
          per_page: perPage, 
          total: Array.isArray(response.data) ? response.data.length : 0,
          pages: 1
        }));
      }
    } catch (error) {
      console.error('Failed to fetch IP ranges:', error);
      setIPRanges([]);
      setPagination(prev => ({ ...prev, total: 0, pages: 0 }));
    } finally {
      setLoading(false);
    }
  }, [search, filter, pagination.per_page]);

  useEffect(() => {
    fetchIPRanges(1);
  }, [search, filter, fetchIPRanges]); // Reset to page 1 when search or filter changes

  const handlePageChange = (newPage) => {
    fetchIPRanges(newPage, pagination.per_page);
  };

  const handleItemsPerPageChange = (newPerPage) => {
    setPagination(prev => ({ ...prev, per_page: newPerPage }));
    fetchIPRanges(1, newPerPage); // Reset to page 1 when changing items per page
  };

  const deleteIPRange = async (ipRangeId) => {
    const result = await showDeleteConfirm(
      'Delete IP Range',
      'Are you sure you want to delete this IP range? This action cannot be undone.'
    );
    
    if (result.isConfirmed) {
      try {
        await axios.delete(`/api/ip-ranges/${ipRangeId}`);
        // Refresh current page or go to previous page if current page becomes empty
        const newTotal = pagination.total - 1;
        const maxPage = Math.ceil(newTotal / pagination.per_page);
        const currentPage = pagination.page > maxPage ? Math.max(1, maxPage) : pagination.page;
        fetchIPRanges(currentPage, pagination.per_page);
      } catch (error) {
        await showError(
          'Delete Failed',
          `Failed to delete IP range: ${error.response?.data?.detail || error.message}`
        );
      }
    }
  };

  const handleAddSuccess = () => {
    setShowAddModal(false);
    // Refresh to show the new IP range (it might be on a different page)
    fetchIPRanges(1, pagination.per_page);
  };

  return (
    <div className="ip-range-management">
      <div className="page-header">
        <h1>
          <Network size={24} />
          IP Range Management
        </h1>
        <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
          <Plus size={16} />
          Add IP Range
        </button>
      </div>

      {/* Filters */}
      <div className="filters">
        <div className="search-box">
          <Search size={16} />
          <input
            type="text"
            placeholder="Search IP ranges..."
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
        <button className="btn btn-secondary" onClick={() => fetchIPRanges(pagination.page, pagination.per_page)}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* IP Range List */}
      <div className="ip-range-list">
        {loading ? (
          <div className="loading">Loading IP ranges...</div>
        ) : ipRanges.length === 0 ? (
          <div className="empty-state">
            <Network size={48} />
            <h3>No IP ranges found</h3>
            <p>
              {search || filter.list_type || filter.source_type || filter.ip_version
                ? 'No IP ranges match your current filters' 
                : 'Add your first IP range to get started'
              }
            </p>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Range (CIDR)</th>
                    <th>Version</th>
                    <th>List Type</th>
                    <th>Source</th>
                    <th>Created</th>
                    <th>Expires</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {ipRanges.map((ipRange) => (
                    <tr key={ipRange.id}>
                      <td className="ip-range">{ipRange.ip_range}</td>
                      <td>
                        <span className={`badge badge-ipv${ipRange.ip_version}`}>
                          IPv{ipRange.ip_version}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${ipRange.list_type}`}>
                          {ipRange.list_type}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${ipRange.source_type}`}>
                          {ipRange.source_type}
                        </span>
                      </td>
                      <td>{new Date(ipRange.created_at).toLocaleDateString()}</td>
                      <td>
                        {ipRange.expires_in ? (
                          <span className={
                            ipRange.expires_in === 'Expired' ? 'expired' : 'expires'
                          }>
                            {ipRange.expires_in}
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
                            onClick={() => deleteIPRange(ipRange.id)}
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

      {/* Add IP Range Modal */}
      {showAddModal && (
        <AddIPRangeModal 
          onClose={() => setShowAddModal(false)} 
          onSuccess={handleAddSuccess}
        />
      )}
    </div>
  );
}

function AddIPRangeModal({ onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    ip_range: '',
    list_type: 'blacklist',
    notes: ''
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post('/api/ip-ranges/', formData);
      onSuccess();
    } catch (error) {
      await showError(
        'Add IP Range Failed',
        `Failed to add IP range: ${error.response?.data?.detail || error.message}`
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Add IP Range</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label>IP Range (CIDR)</label>
            <input
              type="text"
              required
              placeholder="192.168.1.0/24 or 2001:db8::/32"
              value={formData.ip_range}
              onChange={(e) => setFormData({ ...formData, ip_range: e.target.value })}
            />
            <small>Enter CIDR notation (e.g., 192.168.1.0/24, 10.0.0.0/8)</small>
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
              {loading ? 'Adding...' : 'Add IP Range'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default IPRangeManagement; 