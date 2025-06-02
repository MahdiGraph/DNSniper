import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Key, 
  Plus, 
  Copy, 
  Trash2, 
  Calendar, 
  Clock,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Book,
  ExternalLink
} from 'lucide-react';
import { showConfirm } from '../utils/customAlert';

function APITokens() {
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newToken, setNewToken] = useState({ name: '', is_permanent: false, days: 30 });
  const [createdToken, setCreatedToken] = useState(null);
  const [showToken, setShowToken] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchTokens();
  }, []);

  const fetchTokens = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/auth/tokens');
      setTokens(response.data);
    } catch (error) {
      setError('Failed to fetch API tokens');
      console.error('Error fetching tokens:', error);
    } finally {
      setLoading(false);
    }
  };

  const createToken = async (e) => {
    e.preventDefault();
    try {
      setError('');
      const response = await axios.post('/api/auth/tokens', newToken);
      setCreatedToken(response.data);
      setShowToken(true);
      setNewToken({ name: '', is_permanent: false, days: 30 });
      setShowCreateForm(false);
      fetchTokens(); // Refresh the list
      setSuccess('API token created successfully');
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to create API token');
    }
  };

  const revokeToken = async (tokenId, tokenName) => {
    const result = await showConfirm(
      'Revoke Token',
      `Are you sure you want to revoke the token "${tokenName}"? This action cannot be undone.`,
      { confirmButtonText: 'Revoke', confirmButtonColor: '#ef4444' }
    );
    
    if (result.isConfirmed) {
      try {
        await axios.delete(`/api/auth/tokens/${tokenId}`);
        setSuccess(`Token "${tokenName}" revoked successfully`);
        fetchTokens(); // Refresh the list
      } catch (error) {
        setError(error.response?.data?.detail || 'Failed to revoke token');
      }
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setSuccess('Token copied to clipboard');
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      setError('Failed to copy to clipboard');
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString();
  };

  const getTokenStatus = (token) => {
    if (token.is_permanent) {
      return { status: 'permanent', color: 'green', text: 'Permanent' };
    }
    
    if (token.days_until_expiry === null) {
      return { status: 'expired', color: 'red', text: 'Expired' };
    }
    
    if (token.days_until_expiry <= 7) {
      return { status: 'expiring', color: 'orange', text: `${token.days_until_expiry} days left` };
    }
    
    return { status: 'active', color: 'green', text: `${token.days_until_expiry} days left` };
  };

  const cleanupExpiredTokens = async () => {
    const result = await showConfirm(
      'Cleanup Expired Tokens',
      'Are you sure you want to clean up expired tokens? This action cannot be undone.',
      { confirmButtonText: 'Cleanup' }
    );
    
    if (result.isConfirmed) {
      try {
        const response = await axios.post('/api/auth/tokens/cleanup');
        setSuccess(response.data.message);
        fetchTokens(); // Refresh the list
      } catch (error) {
        setError('Failed to cleanup expired tokens');
      }
    }
  };

  return (
    <div className="api-tokens">
      <div className="page-header">
        <h1>
          <Key size={24} />
          API Tokens
        </h1>
        <div className="header-actions">
          <button 
            className="btn btn-secondary" 
            onClick={cleanupExpiredTokens}
            title="Clean up expired tokens"
          >
            <RefreshCw size={16} />
            Cleanup
          </button>
          <button 
            className="btn btn-primary" 
            onClick={() => setShowCreateForm(true)}
          >
            <Plus size={16} />
            Create Token
          </button>
        </div>
      </div>

      <div className="settings-section">
        {/* API Documentation Link */}
        <div className="api-docs-banner">
          <div className="api-docs-content">
            <div className="api-docs-text">
              <h3>
                <Book size={20} />
                API Documentation
              </h3>
              <p>Learn how to use the DNSniper API with detailed examples and endpoint documentation.</p>
            </div>
            <div className="api-docs-actions">
              <a 
                href="/api-documentation" 
                className="btn btn-primary"
                title="View API Documentation"
              >
                <Book size={16} />
                View API Docs
              </a>
              <a 
                href="/docs" 
                target="_blank" 
                rel="noopener noreferrer"
                className="btn btn-secondary"
                title="OpenAPI Specification"
              >
                <ExternalLink size={16} />
                OpenAPI Spec
              </a>
            </div>
          </div>
        </div>

        {error && (
          <div className="alert alert-error">
            <AlertTriangle size={16} />
            {error}
            <button onClick={() => setError('')} className="alert-close">×</button>
          </div>
        )}

        {success && (
          <div className="alert alert-success">
            <CheckCircle size={16} />
            {success}
            <button onClick={() => setSuccess('')} className="alert-close">×</button>
          </div>
        )}

        {/* Tokens List */}
        <div className="tokens-container">
          {loading ? (
            <div className="loading">Loading API tokens...</div>
          ) : tokens.length === 0 ? (
            <div className="empty-state">
              <Key size={48} />
              <h3>No API Tokens</h3>
              <p>Create your first API token to get started with programmatic access</p>
              
              <button className="btn btn-primary" onClick={() => setShowCreateForm(true)}>
                <Plus size={16} />
                Create First Token
              </button>
            </div>
          ) : (
            <div className="tokens-grid">
              {tokens.map((token) => {
                const status = getTokenStatus(token);
                return (
                  <div key={token.id} className={`token-card status-${status.status}`}>
                    <div className="token-header">
                      <div className="token-name">
                        <Key size={16} />
                        <strong>{token.name}</strong>
                      </div>
                      <div className={`token-status status-${status.color}`}>
                        {status.text}
                      </div>
                    </div>
                    <div className="token-details">
                      <div className="detail-row">
                        <Calendar size={14} />
                        <span>Created: {formatDate(token.created_at)}</span>
                      </div>
                      {!token.is_permanent && (
                        <div className="detail-row">
                          <Clock size={14} />
                          <span>Expires: {formatDate(token.expires_at)}</span>
                        </div>
                      )}
                      {token.last_used && (
                        <div className="detail-row">
                          <CheckCircle size={14} />
                          <span>Last used: {formatDate(token.last_used)}</span>
                        </div>
                      )}
                    </div>
                    <div className="token-actions">
                      <button 
                        className="btn btn-danger btn-sm"
                        onClick={() => revokeToken(token.id, token.name)}
                        title="Revoke token"
                      >
                        <Trash2 size={14} />
                        Revoke
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Usage Information */}
        <div className="usage-info">
          <h3>Using API Tokens</h3>
          <div className="info-grid">
            <div className="info-card">
              <h4>Authentication</h4>
              <p>Include your API token in the Authorization header:</p>
              <code>Authorization: Bearer your_token_here</code>
            </div>
            <div className="info-card">
              <h4>Example Usage</h4>
              <p>Get dashboard stats with curl:</p>
              <code>curl -H "Authorization: Bearer your_token_here" https://yourserver/api/dashboard</code>
            </div>
            <div className="info-card">
              <h4>Security</h4>
              <ul>
                <li>Store tokens securely</li>
                <li>Use temporary tokens when possible</li>
                <li>Revoke unused tokens</li>
                <li>Monitor token usage regularly</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Create Token Modal */}
      {showCreateForm && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Create New API Token</h3>
              <button 
                className="modal-close" 
                onClick={() => setShowCreateForm(false)}
              >
                ×
              </button>
            </div>
            <form onSubmit={createToken} className="modal-body">
              <div className="form-group">
                <label htmlFor="tokenName">Token Name</label>
                <input
                  id="tokenName"
                  type="text"
                  value={newToken.name}
                  onChange={(e) => setNewToken({ ...newToken, name: e.target.value })}
                  placeholder="My API Token"
                  required
                  maxLength={100}
                />
                <small>Choose a descriptive name to identify this token</small>
              </div>
              
              <div className="form-group">
                <label className="checkbox-direct">
                  <input
                    type="checkbox"
                    checked={newToken.is_permanent}
                    onChange={(e) => setNewToken({ ...newToken, is_permanent: e.target.checked })}
                  />
                  Permanent Token
                </label>
                <small>Permanent tokens never expire but should be used carefully</small>
              </div>

              {!newToken.is_permanent && (
                <div className="form-group">
                  <label htmlFor="tokenDays">Expires In (Days)</label>
                  <input
                    id="tokenDays"
                    type="number"
                    value={newToken.days}
                    onChange={(e) => setNewToken({ ...newToken, days: parseInt(e.target.value) })}
                    min="1"
                    max="365"
                    required
                  />
                  <small>Token will expire after this many days (1-365)</small>
                </div>
              )}

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowCreateForm(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  <Key size={16} />
                  Create Token
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Show Created Token Modal */}
      {createdToken && showToken && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Token Created Successfully</h3>
              <button 
                className="modal-close" 
                onClick={() => { setCreatedToken(null); setShowToken(false); }}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="alert alert-warning">
                <AlertTriangle size={16} />
                <strong>Important:</strong> This is the only time you'll see this token. 
                Copy it now and store it securely.
              </div>
              
              <div className="token-display">
                <label>Your API Token:</label>
                <div className="token-value">
                  <code>{createdToken.token}</code>
                  <button 
                    className="btn btn-icon" 
                    onClick={() => copyToClipboard(createdToken.token)}
                    title="Copy to clipboard"
                  >
                    <Copy size={16} />
                  </button>
                </div>
              </div>

              <div className="token-info">
                <p><strong>Name:</strong> {createdToken.name}</p>
                <p><strong>Type:</strong> {createdToken.is_permanent ? 'Permanent' : 'Temporary'}</p>
                {!createdToken.is_permanent && (
                  <p><strong>Expires:</strong> {formatDate(createdToken.expires_at)}</p>
                )}
              </div>
              
              <div className="modal-footer">
                <button 
                  className="btn btn-primary" 
                  onClick={() => { setCreatedToken(null); setShowToken(false); }}
                >
                  I've Saved the Token
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default APITokens; 