import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Settings, Shield, RefreshCw, Trash2, Plus, Globe, Play, Pause, TestTube, CheckCircle, AlertTriangle } from 'lucide-react';

function SettingsPage() {
  const [firewallStatus, setFirewallStatus] = useState(null);
  const [settings, setSettings] = useState({});
  const [originalSettings, setOriginalSettings] = useState({});
  const [autoUpdateSources, setAutoUpdateSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showAddSourceModal, setShowAddSourceModal] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  // Helper function to get auth token from localStorage
  const getToken = () => {
    return localStorage.getItem('authToken');
  };

  useEffect(() => {
    fetchSettings();
    fetchFirewallStatus();
    fetchAutoUpdateSources();
  }, []);

  useEffect(() => {
    // Check if settings have changed
    const changed = JSON.stringify(settings) !== JSON.stringify(originalSettings);
    setHasChanges(changed);
  }, [settings, originalSettings]);

  useEffect(() => {
    if (settings.enable_ssl === undefined) {
      setSettings(prev => ({ ...prev, enable_ssl: false }));
      setOriginalSettings(prev => ({ ...prev, enable_ssl: false }));
    }
  }, [settings, originalSettings]);

  const fetchSettings = async () => {
    try {
      const response = await axios.get('/api/settings/');
      const settingsData = response.data || {};
      // Remove legacy normalization for dns_resolvers
      setSettings(settingsData);
      setOriginalSettings(settingsData);
    } catch (error) {
      console.error('Failed to fetch settings:', error);
      setSettings({});
      setOriginalSettings({});
    }
  };

  const fetchFirewallStatus = async () => {
    try {
      const response = await axios.get('/api/settings/firewall/status');
      setFirewallStatus(response.data);
    } catch (error) {
      console.error('Failed to fetch firewall status:', error);
      setFirewallStatus(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchAutoUpdateSources = async () => {
    try {
      const response = await axios.get('/api/auto-update-sources/');
      setAutoUpdateSources(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Failed to fetch auto-update sources:', error);
      setAutoUpdateSources([]);
    }
  };

  const clearFirewallRules = async () => {
    if (!window.confirm('Are you sure you want to clear all DNSniper firewall rules?')) return;
    
    try {
      await axios.post('/api/settings/firewall/clear');
      alert('Firewall rules cleared successfully');
      fetchFirewallStatus();
    } catch (error) {
      alert('Failed to clear firewall rules: ' + (error.response?.data?.detail || error.message));
    }
  };

  const rebuildFirewallRules = async () => {
    if (!window.confirm('Are you sure you want to rebuild all firewall rules from database?')) return;
    
    try {
      await axios.post('/api/settings/firewall/rebuild');
      alert('Firewall rules rebuilt successfully');
      fetchFirewallStatus();
    } catch (error) {
      alert('Failed to rebuild firewall rules: ' + (error.response?.data?.detail || error.message));
    }
  };

  const deleteAutoUpdateSource = async (sourceId) => {
    if (!window.confirm('Are you sure you want to delete this auto-update source?')) return;
    
    try {
      await axios.delete(`/api/auto-update-sources/${sourceId}`);
      fetchAutoUpdateSources();
    } catch (error) {
      alert('Failed to delete auto-update source: ' + (error.response?.data?.detail || error.message));
    }
  };

  const toggleAutoUpdateSource = async (sourceId, isActive) => {
    try {
      await axios.put(`/api/auto-update-sources/${sourceId}`, { is_active: !isActive });
      fetchAutoUpdateSources();
    } catch (error) {
      alert('Failed to toggle auto-update source: ' + (error.response?.data?.detail || error.message));
    }
  };

  const testAutoUpdateSource = async (sourceId) => {
    try {
      const response = await axios.get(`/api/auto-update-sources/test/${sourceId}`);
      const result = response.data.test_result;
      
      if (result.status === 'success') {
        alert(`✅ Test Successful!\n\nHTTP Status: ${result.http_status}\nContent Length: ${result.content_length} bytes\nContent Type: ${result.content_type}\n\nThe auto-update source is working correctly and will be processed during updates.`);
      } else if (result.status === 'failed') {
        alert(`❌ Test Failed!\n\nHTTP Status: ${result.http_status || 'Unknown'}\nError: ${result.error}\nContent Length: ${result.content_length || 0} bytes\n\nThis source will be skipped during auto-updates until the issue is resolved.`);
      } else if (result.status === 'timeout') {
        alert(`⏱️ Test Timed Out!\n\nError: ${result.error}\n\nThe source took too long to respond and will be skipped during auto-updates.`);
      } else {
        alert(`❌ Test Failed!\n\nError: ${result.error || 'Unknown error occurred'}\n\nThis source will be skipped during auto-updates.`);
      }
    } catch (error) {
      alert('Failed to test auto-update source: ' + (error.response?.data?.detail || error.message));
    }
  };

  const triggerManualUpdate = async () => {
    if (!window.confirm('Are you sure you want to manually trigger an auto-update cycle?')) return;
    
    try {
      await axios.post('/api/auto-update-sources/trigger-update');
      alert('Auto-update cycle triggered successfully');
    } catch (error) {
      alert('Failed to trigger auto-update: ' + (error.response?.data?.detail || error.message));
    }
  };

  const updateAllSettings = async () => {
    if (!hasChanges) return;
    setSaving(true);
    try {
      const response = await axios.put('/api/settings/bulk', {
        settings: settings
      });
      alert('Settings updated successfully!');
      setOriginalSettings(settings);
      setHasChanges(false);
    } catch (error) {
      if (error.response?.data?.detail?.errors) {
        const errors = error.response.data.detail.errors;
        const errorMessages = Object.entries(errors).map(([key, msg]) => `${key}: ${msg}`).join('\n');
        alert(`Validation errors:\n${errorMessages}`);
      } else if (error.response?.data?.detail) {
        alert(`Validation error:\n${error.response.data.detail}`);
      } else {
        alert('Failed to update settings: ' + (error.message || 'Unknown error'));
      }
    } finally {
      setSaving(false);
    }
  };

  const resetSettings = () => {
    setSettings(originalSettings);
    setHasChanges(false);
  };

  const renderSettingInput = (key, value, config) => {
    // Handle textarea inputs for critical IPs settings
    if (config.type === 'textarea') {
      // Convert array to textarea format (one item per line)
      const textValue = Array.isArray(value) ? value.join('\n') : '';
      return (
        <textarea
          rows={6}
          placeholder={config.hint}
          value={textValue}
          onChange={(e) => {
            // Convert textarea input to array and update settings state
            const arrayValue = e.target.value.split('\n').map(line => line.trim()).filter(line => line);
            setSettings(prev => ({
              ...prev,
              [key]: arrayValue
            }));
          }}
          className="form-textarea"
        />
      );
    }
    
    // Handle boolean settings with checkbox
    if (typeof value === 'boolean') {
      return (
        <div className="checkbox-wrapper">
          <input
            type="checkbox"
            checked={value}
            onChange={(e) => setSettings(prev => ({
              ...prev,
              [key]: e.target.checked
            }))}
          />
          <span className="setting-value">{value ? 'Enabled' : 'Disabled'}</span>
        </div>
      );
    }

    // Handle numeric settings with number input
    if (typeof value === 'number') {
      return (
        <div className="number-input-wrapper">
          <input
            type="number"
            min={config.min}
            max={config.max}
            step={config.step || 1}
            value={value}
            onChange={(e) => setSettings(prev => ({
              ...prev,
              [key]: parseFloat(e.target.value)
            }))}
          />
          {config.unit && <span className="input-unit">{config.unit}</span>}
        </div>
      );
    }

    // Handle string settings with text input
    return (
      <input
        type="text"
        value={value}
        onChange={(e) => setSettings(prev => ({
          ...prev,
          [key]: e.target.value
        }))}
      />
    );
  };

  return (
    <div className="settings">
      <div className="page-header">
        <h1>Settings</h1>
      </div>

      {/* Success/Error Messages */}
      {success && (
        <div className="alert alert-success">
          <CheckCircle size={16} />
          {success}
        </div>
      )}
      {error && (
        <div className="alert alert-error">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Auto-Update Sources Management */}
      <div className="settings-section">
        <h2>
          <Globe size={20} />
          Auto-Update Sources
        </h2>
        
        <div className="section-header">
          <p>Manage URL sources for automatic blacklist/whitelist updates</p>
          <div className="section-actions">
            <button 
              className="btn btn-success"
              onClick={triggerManualUpdate}
              title="Manually trigger auto-update cycle"
            >
              <Play size={16} />
              Trigger Update
            </button>
            <button 
              className="btn btn-primary"
              onClick={() => setShowAddSourceModal(true)}
            >
              <Plus size={16} />
              Add Source
            </button>
          </div>
        </div>

        {autoUpdateSources.length === 0 ? (
          <div className="empty-state">
            <Globe size={48} />
            <h3>No auto-update sources configured</h3>
            <p>Add URL sources to automatically update your blacklists and whitelists</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>URL</th>
                  <th>List Type</th>
                  <th>Status</th>
                  <th>Last Update</th>
                  <th>Updates</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {autoUpdateSources.map((source) => (
                  <tr key={source.id}>
                    <td>{source.name}</td>
                    <td className="url-cell">
                      <a href={source.url} target="_blank" rel="noopener noreferrer">
                        {source.url.length > 50 ? source.url.substring(0, 50) + '...' : source.url}
                      </a>
                    </td>
                    <td>{source.list_type ? (source.list_type.charAt(0).toUpperCase() + source.list_type.slice(1)) : 'Blacklist'}</td>
                    <td>
                      <span className={`status ${source.is_active ? 'active' : 'inactive'}`}>
                        {source.is_active ? 'Active' : 'Inactive'}
                      </span>
                      {source.last_error && (
                        <div className="error-tooltip" title={source.last_error}>
                          ⚠️
                        </div>
                      )}
                    </td>
                    <td>{source.last_update_ago}</td>
                    <td>{source.update_count}</td>
                    <td>
                      <div className="actions">
                        <button 
                          className="btn-icon" 
                          title="Test Source"
                          onClick={() => testAutoUpdateSource(source.id)}
                        >
                          <TestTube size={14} />
                        </button>
                        <button 
                          className={`btn-icon ${source.is_active ? 'btn-warning' : 'btn-success'}`}
                          title={source.is_active ? 'Disable' : 'Enable'}
                          onClick={() => toggleAutoUpdateSource(source.id, source.is_active)}
                        >
                          {source.is_active ? <Pause size={14} /> : <Play size={14} />}
                        </button>
                        <button 
                          className="btn-icon btn-danger" 
                          title="Delete"
                          onClick={() => deleteAutoUpdateSource(source.id)}
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
        )}
      </div>

      {/* Firewall Management */}
      <div className="settings-section">
        <h2>
          <Shield size={20} />
          Firewall Management
        </h2>
        
        {loading ? (
          <div className="loading">Loading firewall status...</div>
        ) : (
          <div className="firewall-status">
            <div className="status-grid">
              <div className="status-item">
                <label>IPv4 Chain</label>
                <span className={`status ${firewallStatus?.chains_exist?.ipv4 ? 'active' : 'inactive'}`}>
                  {firewallStatus?.chains_exist?.ipv4 ? 'Active' : 'Inactive'}
                </span>
              </div>
              <div className="status-item">
                <label>IPv6 Chain</label>
                <span className={`status ${firewallStatus?.chains_exist?.ipv6 ? 'active' : 'inactive'}`}>
                  {firewallStatus?.chains_exist?.ipv6 ? 'Active' : 'Inactive'}
                </span>
              </div>
              <div className="status-item">
                <label>IPv4 IPSets</label>
                <span className="status-detail">
                  {firewallStatus?.ipsets_exist?.ipv4 ? 
                    Object.values(firewallStatus.ipsets_exist.ipv4).filter(Boolean).length
                  : 0}/4 Active
                </span>
              </div>
              <div className="status-item">
                <label>IPv6 IPSets</label>
                <span className="status-detail">
                  {firewallStatus?.ipsets_exist?.ipv6 ? 
                    Object.values(firewallStatus.ipsets_exist.ipv6).filter(Boolean).length
                  : 0}/4 Active
                </span>
              </div>
            </div>
            
            <div className="firewall-actions">
              <button 
                className="btn btn-primary"
                onClick={rebuildFirewallRules}
              >
                <RefreshCw size={16} />
                Rebuild Rules
              </button>
              <button 
                className="btn btn-danger"
                onClick={clearFirewallRules}
              >
                <Trash2 size={16} />
                Clear All Rules
              </button>
            </div>

            {/* Detailed IPSet Status */}
            {firewallStatus?.ipsets_exist && (
              <div className="ipset-details">
                <h3>IPSet Status</h3>
                <div className="ipset-section">
                  <h4>IPv4 IPSets</h4>
                  <div className="ipset-grid">
                    {firewallStatus.ipsets_exist.ipv4 && Object.entries(firewallStatus.ipsets_exist.ipv4).map(([key, exists]) => (
                      <div key={`ipv4-${key}`} className="ipset-item">
                        <span className="ipset-name">{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} (IPv4)</span>
                        <span className={`status ${exists ? 'active' : 'inactive'}`}>
                          {exists ? 'Active' : 'Inactive'}
                        </span>
                        <span className="ipset-count">
                          {firewallStatus?.ipset_counts?.ipv4?.[key] || 0} entries
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="ipset-section">
                  <h4>IPv6 IPSets</h4>
                  <div className="ipset-grid">
                    {firewallStatus.ipsets_exist.ipv6 && Object.entries(firewallStatus.ipsets_exist.ipv6).map(([key, exists]) => (
                      <div key={`ipv6-${key}`} className="ipset-item">
                        <span className="ipset-name">{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} (IPv6)</span>
                        <span className={`status ${exists ? 'active' : 'inactive'}`}>
                          {exists ? 'Active' : 'Inactive'}
                        </span>
                        <span className="ipset-count">
                          {firewallStatus?.ipset_counts?.ipv6?.[key] || 0} entries
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Application Settings */}
      <div className="settings-section">
        <h2>
          <Settings size={20} />
          Application Settings
        </h2>
        <div className="settings-grid compact-grid">
          {Object.entries(settings).filter(([key]) => 
            // Filter out SSL settings since they are now in SecurityPage
            !['enable_ssl', 'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'].includes(key)
          ).map(([key, value]) => {
            const settingConfig = getSettingConfig(key);
            return (
              <div key={key} className="setting-item-editable compact-item">
                <label>
                  {settingConfig.label}
                  {settingConfig.hint && (
                    <span className="setting-hint">{settingConfig.hint}</span>
                  )}
                </label>
                <div className="setting-input compact-input">
                  {renderSettingInput(key, value, settingConfig)}
                </div>
              </div>
            );
          })}
        </div>
        <div className="settings-actions">
          <button
            className="btn btn-secondary"
            onClick={resetSettings}
            disabled={!hasChanges || saving}
          >
            Reset Changes
          </button>
          <button
            className="btn btn-primary"
            onClick={updateAllSettings}
            disabled={!hasChanges || saving}
          >
            {saving ? 'Updating...' : 'Update Settings'}
          </button>
        </div>
        {Object.keys(settings).length === 0 && (
          <div className="empty-state">
            <Settings size={48} />
            <h3>No settings configured</h3>
            <p>Application settings will appear here once configured</p>
          </div>
        )}
      </div>

      {showAddSourceModal && (
        <AddAutoUpdateSourceModal
          onClose={() => setShowAddSourceModal(false)}
          onSuccess={() => {
            setShowAddSourceModal(false);
            fetchAutoUpdateSources();
          }}
        />
      )}
    </div>
  );
}

function AddAutoUpdateSourceModal({ onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    url: '',
    name: '',
    is_active: true,
    list_type: 'blacklist',
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post('/api/auto-update-sources/', formData);
      onSuccess();
    } catch (error) {
      alert('Failed to add auto-update source: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Add Auto-Update Source</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label>Name</label>
            <input
              type="text"
              required
              placeholder="e.g., Malware Domain List"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>URL</label>
            <input
              type="url"
              required
              placeholder="https://example.com/blacklist.txt"
              value={formData.url}
              onChange={(e) => setFormData({ ...formData, url: e.target.value })}
            />
            <small>URL must return plain text with one domain/IP per line</small>
          </div>
          <div className="form-group">
            <label>List Type</label>
            <select
              value={formData.list_type}
              onChange={e => setFormData({ ...formData, list_type: e.target.value })}
              required
            >
              <option value="blacklist">Blacklist</option>
              <option value="whitelist">Whitelist</option>
            </select>
          </div>
          <div className="form-group">
            <label className="checkbox-direct">
              <input
                type="checkbox"
                checked={formData.is_active}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
              />
              Active (enable automatic updates)
            </label>
          </div>
          <div className="modal-footer">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Adding...' : 'Add Source'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function getSettingConfig(key) {
  const configs = {
    auto_update_interval: {
      label: 'Auto-Update Interval',
      hint: 'How often to check for updates from configured sources',
      unit: 'seconds',
      min: 300,
      max: 86400,
      step: 1,
      validation: 'Must be between 300 seconds (5 minutes) and 86400 seconds (24 hours)'
    },
    rule_expiration: {
      label: 'Rule Expiration',
      hint: 'How long auto-update rules stay active before expiring',
      unit: 'seconds',
      min: 3600,
      max: 604800,
      step: 1,
      validation: 'Must be between 3600 seconds (1 hour) and 604800 seconds (7 days)'
    },
    max_ips_per_domain: {
      label: 'Max IPs per Domain',
      hint: 'Maximum number of IP addresses to store for each domain',
      unit: 'IPs',
      min: 1,
      max: 50,
      step: 1,
      validation: 'Must be between 1 and 50'
    },
    dns_resolver_primary: {
      label: 'Primary DNS Resolver',
      hint: 'Primary DNS server used for all lookups',
      validation: 'Must be a valid IPv4 address'
    },
    dns_resolver_secondary: {
      label: 'Secondary DNS Resolver',
      hint: 'Secondary DNS server used if primary fails',
      validation: 'Must be a valid IPv4 address'
    },
    logging_enabled: {
      label: 'Firewall Logging',
      hint: 'Enable or disable firewall activity logging'
    },
    automatic_domain_resolution: {
      label: 'Automatic Domain Resolution',
      hint: 'Automatically resolve manually-added domains to IPs during auto-update cycles'
    },
    rate_limit_delay: {
      label: 'Rate Limit Delay',
      hint: 'Delay between auto-update requests to avoid overwhelming servers',
      unit: 'seconds',
      min: 0.1,
      max: 10,
      step: 0.1,
      validation: 'Must be between 0.1 and 10 seconds'
    },
    auto_update_enabled: {
      label: 'Auto-Update Agent',
      hint: 'Enable or disable the auto-update service'
    },
    critical_ipv4_ips_ranges: {
      label: 'Critical IPv4 IPs/Ranges',
      hint: 'IPv4 addresses and CIDR ranges that should never be auto-blocked (one per line)',
      type: 'textarea',
      validation: 'Must be valid IPv4 addresses or CIDR ranges, one per line'
    },
    critical_ipv6_ips_ranges: {
      label: 'Critical IPv6 IPs/Ranges',
      hint: 'IPv6 addresses and CIDR ranges that should never be auto-blocked (one per line)',
      type: 'textarea',
      validation: 'Must be valid IPv6 addresses or CIDR ranges, one per line'
    },
    log_retention_days: {
      label: 'Log Retention Period',
      hint: 'Number of days to keep log entries before deletion',
      unit: 'days',
      min: 1,
      max: 365,
      step: 1,
      validation: 'Must be between 1 and 365 days'
    },
    max_log_entries: {
      label: 'Max Log Entries',
      hint: 'Maximum number of log entries to keep (FIFO rotation)',
      unit: 'entries',
      min: 1000,
      max: 100000,
      step: 1000,
      validation: 'Must be between 1000 and 100000 entries'
    }
  };

  return configs[key] || {
    label: key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
    hint: '',
    validation: ''
  };
}

export default SettingsPage; 