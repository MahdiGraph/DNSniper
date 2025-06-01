import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { Plus, Trash2, Network, Edit, Eye } from 'lucide-react';

function IPRangeManagement() {
  const [ipRanges, setIPRanges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [filter, setFilter] = useState({ list_type: '', source_type: '', ip_version: '' });

  const fetchIPRanges = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (filter.list_type) params.append('list_type', filter.list_type);
      if (filter.source_type) params.append('source_type', filter.source_type);
      if (filter.ip_version) params.append('ip_version', filter.ip_version);
      
      const response = await axios.get(`/api/ip-ranges/?${params}`);
      // Ensure we always have an array
      setIPRanges(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Failed to fetch IP ranges:', error);
      setIPRanges([]); // Set empty array on error
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchIPRanges();
  }, [fetchIPRanges]);

  const deleteIPRange = async (ipRangeId) => {
    if (!window.confirm('Are you sure you want to delete this IP range?')) return;
    
    try {
      await axios.delete(`/api/ip-ranges/${ipRangeId}`);
      fetchIPRanges();
    } catch (error) {
      alert('Failed to delete IP range: ' + (error.response?.data?.detail || error.message));
    }
  };

  return (
    <div className="ip-range-management">
      <div className="page-header">
        <h1>IP Range Management</h1>
        <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
          <Plus size={16} />
          Add IP Range
        </button>
      </div>

      {/* Filters */}
      <div className="filters">
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
        <button className="btn btn-secondary" onClick={fetchIPRanges}>
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
            <p>Add your first IP range to get started</p>
          </div>
        ) : (
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
                    <td className="ip-address">{ipRange.ip_range}</td>
                    <td>IPv{ipRange.ip_version}</td>
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
                      {ipRange.expired_at ? (
                        <span className={
                          new Date(ipRange.expired_at) < new Date() ? 'expired' : 'expires'
                        }>
                          {new Date(ipRange.expired_at).toLocaleDateString()}
                        </span>
                      ) : (
                        <span className="permanent">Never</span>
                      )}
                    </td>
                    <td>
                      <div className="actions">
                        <button className="btn-icon" title="View Details">
                          <Eye size={14} />
                        </button>
                        {ipRange.source_type === 'manual' && (
                          <>
                            <button className="btn-icon" title="Edit">
                              <Edit size={14} />
                            </button>
                            <button 
                              className="btn-icon btn-danger" 
                              title="Delete"
                              onClick={() => deleteIPRange(ipRange.id)}
                            >
                              <Trash2 size={14} />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showAddModal && (
        <AddIPRangeModal
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false);
            fetchIPRanges();
          }}
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
      alert('Failed to add IP range: ' + (error.response?.data?.detail || error.message));
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