import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Plus, Trash2, Network } from 'lucide-react';

function IPManagement() {
  const [ips, setIps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);

  useEffect(() => {
    fetchIPs();
  }, []);

  const fetchIPs = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/ips/');
      // Ensure we always have an array
      setIps(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Failed to fetch IPs:', error);
      setIps([]); // Set empty array on error
    } finally {
      setLoading(false);
    }
  };

  const deleteIP = async (ipId) => {
    if (!window.confirm('Are you sure you want to delete this IP?')) return;
    
    try {
      await axios.delete(`/api/ips/${ipId}`);
      fetchIPs();
    } catch (error) {
      alert('Failed to delete IP: ' + error.response?.data?.detail);
    }
  };

  return (
    <div className="ip-management">
      <div className="page-header">
        <h1>IP Management</h1>
        <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
          <Plus size={16} />
          Add IP
        </button>
      </div>

      <div className="ip-list">
        {loading ? (
          <div className="loading">Loading IPs...</div>
        ) : ips.length === 0 ? (
          <div className="empty-state">
            <Network size={48} />
            <h3>No IPs found</h3>
            <p>Add your first IP address to get started</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Version</th>
                  <th>List Type</th>
                  <th>Source</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {ips.map((ip) => (
                  <tr key={ip.id}>
                    <td className="ip-address">{ip.ip_address}</td>
                    <td>IPv{ip.ip_version}</td>
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
                    <td>{new Date(ip.created_at).toLocaleDateString()}</td>
                    <td>
                      {ip.source_type === 'manual' && (
                        <button 
                          className="btn-icon btn-danger" 
                          onClick={() => deleteIP(ip.id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showAddModal && (
        <AddIPModal
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false);
            fetchIPs();
          }}
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
      alert('Failed to add IP: ' + error.response?.data?.detail);
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