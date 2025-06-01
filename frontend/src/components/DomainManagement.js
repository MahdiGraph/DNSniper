import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { Plus, Search, Edit, Trash2, Eye, Globe, RefreshCw } from 'lucide-react';

function DomainManagement() {
  const [domains, setDomains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState({ list_type: '', source_type: '' });
  const [showAddModal, setShowAddModal] = useState(false);

  const fetchDomains = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (filter.list_type) params.append('list_type', filter.list_type);
      if (filter.source_type) params.append('source_type', filter.source_type);
      
      const response = await axios.get(`/api/domains/?${params}`);
      // Ensure we always have an array
      setDomains(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Failed to fetch domains:', error);
      setDomains([]); // Set empty array on error
    } finally {
      setLoading(false);
    }
  }, [search, filter]);

  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  const deleteDomain = async (domainId) => {
    if (!window.confirm('Are you sure you want to delete this domain?')) return;
    
    try {
      await axios.delete(`/api/domains/${domainId}`);
      fetchDomains();
    } catch (error) {
      alert('Failed to delete domain: ' + error.response?.data?.detail);
    }
  };

  return (
    <div className="domain-management">
      <div className="page-header">
        <h1>Domain Management</h1>
        <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
          <Plus size={16} />
          Add Domain
        </button>
      </div>

      {/* Filters */}
      <div className="filters">
        <div className="search-box">
          <Search size={16} />
          <input
            type="text"
            placeholder="Search domains..."
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
        <button className="btn btn-secondary" onClick={fetchDomains}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Domain List */}
      <div className="domain-list">
        {loading ? (
          <div className="loading">Loading domains...</div>
        ) : domains.length === 0 ? (
          <div className="empty-state">
            <Globe size={48} />
            <h3>No domains found</h3>
            <p>Add your first domain to get started</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>List Type</th>
                  <th>Source</th>
                  <th>IPs</th>
                  <th>CDN</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((domain) => (
                  <tr key={domain.id}>
                    <td className="domain-name">{domain.domain_name}</td>
                    <td>
                      <span className={`badge badge-${domain.list_type}`}>
                        {domain.list_type}
                      </span>
                    </td>
                    <td>
                      <span className={`badge badge-${domain.source_type}`}>
                        {domain.source_type}
                      </span>
                    </td>
                    <td>{domain.ip_count}</td>
                    <td>{domain.is_cdn ? '✓' : '✗'}</td>
                    <td>{new Date(domain.created_at).toLocaleDateString()}</td>
                    <td>
                      <div className="actions">
                        <button className="btn-icon" title="View Details">
                          <Eye size={14} />
                        </button>
                        {domain.source_type === 'manual' && (
                          <>
                            <button className="btn-icon" title="Edit">
                              <Edit size={14} />
                            </button>
                            <button 
                              className="btn-icon btn-danger" 
                              title="Delete"
                              onClick={() => deleteDomain(domain.id)}
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

      {/* Add Domain Modal */}
      {showAddModal && (
        <AddDomainModal
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false);
            fetchDomains();
          }}
        />
      )}
    </div>
  );
}

function AddDomainModal({ onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    domain_name: '',
    list_type: 'blacklist',
    notes: ''
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post('/api/domains/', formData);
      onSuccess();
    } catch (error) {
      alert('Failed to add domain: ' + error.response?.data?.detail);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Add Domain</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label>Domain Name</label>
            <input
              type="text"
              required
              placeholder="example.com"
              value={formData.domain_name}
              onChange={(e) => setFormData({ ...formData, domain_name: e.target.value })}
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
              {loading ? 'Adding...' : 'Add Domain'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default DomainManagement; 