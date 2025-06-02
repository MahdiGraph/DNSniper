import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Lock, Eye, EyeOff, CheckCircle, AlertTriangle } from 'lucide-react';
import { showSuccess, showError, showWarning } from '../utils/customAlert';

function SecurityPage({ user, setUser }) {
  const [settings, setSettings] = useState({});
  const [originalSettings, setOriginalSettings] = useState({});
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: ''
  });
  const [usernameForm, setUsernameForm] = useState({
    current_password: '',
    new_username: ''
  });
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
    currentForUsername: false
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [usernameSaving, setUsernameSaving] = useState(false);
  const [passwordSuccess, setPasswordSuccess] = useState(false);
  const [usernameSuccess, setUsernameSuccess] = useState(false);
  const [showWelcomeModal, setShowWelcomeModal] = useState(false);

  useEffect(() => {
    fetchSettings();
  }, [user]);

  const fetchSettings = async () => {
    try {
      const response = await axios.get('/api/settings/');
      const settingsData = response.data || {};
      setSettings(settingsData);
      setOriginalSettings(settingsData);
    } catch (error) {
      console.error('Failed to fetch settings:', error);
      setSettings({});
      setOriginalSettings({});
    } finally {
      setLoading(false);
    }
  };

  // Helper to check if SSL settings have changed
  const sslKeys = ['enable_ssl', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile', 'force_https'];
  const getSslSettings = (obj) => {
    return sslKeys.reduce((acc, key) => {
      acc[key] = obj[key];
      return acc;
    }, {});
  };
  const sslSettingsChanged = JSON.stringify(getSslSettings(settings)) !== JSON.stringify(getSslSettings(originalSettings));

  const updateSetting = (key, value) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const updateSslSettings = async () => {
    setSaving(true);
    try {
      const prevEnableSsl = originalSettings.enable_ssl;
      const newEnableSsl = settings.enable_ssl;
      const response = await axios.put('/api/settings/ssl', getSslSettings(settings));
      if (prevEnableSsl !== newEnableSsl && response.data.ssl_restart_required) {
        await showWarning(
          'Server Restart Required',
          'SSL enable/disable state changed. The web server will now shut down. Please restart the DNSniper service manually or ensure your process manager (e.g., systemd) restarts it automatically.'
        );
      } else if (response.data.ssl_restart_required) {
        await showWarning(
          'Server Restart Required',
          'SSL configuration has changed. The web server will now shut down. Please restart the DNSniper service manually or ensure your process manager (e.g., systemd) restarts it automatically.'
        );
      } else {
        await showSuccess('Success', 'SSL settings updated successfully!');
      }
      setOriginalSettings(settings);
    } catch (error) {
      if (error.response?.data?.detail) {
        await showError('SSL Update Error', error.response.data.detail);
      } else {
        await showError('Update Failed', `Failed to update SSL settings: ${error.message || 'Unknown error'}`);
      }
    } finally {
      setSaving(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      await showError('Password Mismatch', 'New passwords do not match');
      return;
    }
    if (passwordForm.new_password.length < 6) {
      await showError('Password Too Short', 'Password must be at least 6 characters long');
      return;
    }

    setPasswordSaving(true);
    try {
      const response = await axios.post('/api/auth/change-password', {
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password,
        confirm_password: passwordForm.confirm_password
      });
      
      setPasswordSuccess(true);
      setPasswordForm({ current_password: '', new_password: '', confirm_password: '' });
      
      // Update user state if password was default
      if (user?.is_default_password) {
        setUser(prev => ({ ...prev, is_default_password: false }));
      }
      
      // Hide success message after 3 seconds
      setTimeout(() => setPasswordSuccess(false), 3000);
      
    } catch (error) {
      if (error.response?.data?.detail) {
        await showError('Password Change Error', error.response.data.detail);
      } else {
        await showError('Change Failed', `Failed to change password: ${error.message || 'Unknown error'}`);
      }
    } finally {
      setPasswordSaving(false);
    }
  };

  const handleUsernameChange = async (e) => {
    e.preventDefault();
    if (usernameForm.new_username.length < 3) {
      await showError('Username Too Short', 'Username must be at least 3 characters long');
      return;
    }

    setUsernameSaving(true);
    try {
      const response = await axios.post('/api/auth/change-username', {
        current_password: usernameForm.current_password,
        new_username: usernameForm.new_username
      });
      
      setUsernameSuccess(true);
      setUsernameForm({ current_password: '', new_username: '' });
      
      // Update user state with new username
      setUser(prev => ({ ...prev, username: response.data.new_username }));
      
      // Hide success message after 3 seconds
      setTimeout(() => setUsernameSuccess(false), 3000);
      
    } catch (error) {
      if (error.response?.data?.detail) {
        await showError('Username Change Error', error.response.data.detail);
      } else {
        await showError('Change Failed', `Failed to change username: ${error.message || 'Unknown error'}`);
      }
    } finally {
      setUsernameSaving(false);
    }
  };

  const togglePasswordVisibility = (field) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field]
    }));
  };

  if (loading) {
    return <div className="loading">Loading security settings...</div>;
  }

  return (
    <div className="settings">
      <div className="page-header">
        <h1>Security</h1>
      </div>

      {/* Welcome Modal for Default Password Users */}
      {showWelcomeModal && (
        <WelcomeModal onClose={() => setShowWelcomeModal(false)} />
      )}

      {/* Optional Welcome Banner for Default Password Users */}
      {user?.is_default_password && (
        <div className="optional-welcome-banner">
          <div className="welcome-banner-content">
            <div className="welcome-banner-icon">
              <Shield size={20} />
            </div>
            <div className="welcome-banner-text">
              <strong>Welcome to DNSniper!</strong>
              <span>You're using default credentials. Consider updating them for better security.</span>
            </div>
            <button 
              className="welcome-banner-button"
              onClick={() => setShowWelcomeModal(true)}
              title="Show welcome guide"
            >
              Show Guide
            </button>
          </div>
        </div>
      )}

      {/* Change Username Section */}
      <div className="settings-section">
        <h2>
          <Lock size={20} />
          Change Username
        </h2>
        
        {usernameSuccess && (
          <div className="success-message">
            <CheckCircle size={16} />
            Username changed successfully!
          </div>
        )}

        <form onSubmit={handleUsernameChange} className="password-form">
          <div className="form-grid">
            <div className="form-group">
              <label htmlFor="current_username">Current Username</label>
              <input
                type="text"
                id="current_username"
                value={user?.username || ''}
                disabled
                style={{ opacity: 0.6, cursor: 'not-allowed' }}
              />
            </div>

            <div className="form-group">
              <label htmlFor="new_username">New Username</label>
              <input
                type="text"
                id="new_username"
                value={usernameForm.new_username}
                onChange={(e) => setUsernameForm(prev => ({ ...prev, new_username: e.target.value }))}
                required
                minLength={3}
                pattern="[a-zA-Z0-9]+"
                title="Username must contain only letters and numbers"
                disabled={usernameSaving}
                placeholder="Enter new username"
              />
              <small>Username must be at least 3 characters and contain only letters and numbers</small>
            </div>

            <div className="form-group">
              <label htmlFor="current_password_username">Current Password</label>
              <div className="password-input">
                <input
                  type={showPasswords.currentForUsername ? 'text' : 'password'}
                  id="current_password_username"
                  value={usernameForm.current_password}
                  onChange={(e) => setUsernameForm(prev => ({ ...prev, current_password: e.target.value }))}
                  required
                  disabled={usernameSaving}
                  placeholder="Enter your current password"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => togglePasswordVisibility('currentForUsername')}
                  disabled={usernameSaving}
                >
                  {showPasswords.currentForUsername ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          </div>

          <div className="form-actions">
            <button
              type="submit"
              className="btn btn-primary"
              disabled={usernameSaving || !usernameForm.current_password || !usernameForm.new_username}
            >
              {usernameSaving ? 'Changing Username...' : 'Change Username'}
            </button>
          </div>
        </form>
      </div>

      {/* Password Change Section */}
      <div className="settings-section">
        <h2>
          <Lock size={20} />
          Change Password
        </h2>
        
        {passwordSuccess && (
          <div className="success-message">
            <CheckCircle size={16} />
            Password changed successfully!
          </div>
        )}

        <form onSubmit={handlePasswordChange} className="password-form">
          <div className="form-grid">
            <div className="form-group">
              <label htmlFor="current_password">Current Password</label>
              <div className="password-input">
                <input
                  type={showPasswords.current ? 'text' : 'password'}
                  id="current_password"
                  value={passwordForm.current_password}
                  onChange={(e) => setPasswordForm(prev => ({ ...prev, current_password: e.target.value }))}
                  required
                  disabled={passwordSaving}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => togglePasswordVisibility('current')}
                  disabled={passwordSaving}
                >
                  {showPasswords.current ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="new_password">New Password</label>
              <div className="password-input">
                <input
                  type={showPasswords.new ? 'text' : 'password'}
                  id="new_password"
                  value={passwordForm.new_password}
                  onChange={(e) => setPasswordForm(prev => ({ ...prev, new_password: e.target.value }))}
                  required
                  minLength={6}
                  disabled={passwordSaving}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => togglePasswordVisibility('new')}
                  disabled={passwordSaving}
                >
                  {showPasswords.new ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <small>Password must be at least 6 characters long</small>
            </div>

            <div className="form-group">
              <label htmlFor="confirm_password">Confirm New Password</label>
              <div className="password-input">
                <input
                  type={showPasswords.confirm ? 'text' : 'password'}
                  id="confirm_password"
                  value={passwordForm.confirm_password}
                  onChange={(e) => setPasswordForm(prev => ({ ...prev, confirm_password: e.target.value }))}
                  required
                  disabled={passwordSaving}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => togglePasswordVisibility('confirm')}
                  disabled={passwordSaving}
                >
                  {showPasswords.confirm ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          </div>

          <div className="form-actions">
            <button
              type="submit"
              className="btn btn-primary"
              disabled={passwordSaving || !passwordForm.current_password || !passwordForm.new_password || !passwordForm.confirm_password}
            >
              {passwordSaving ? 'Changing Password...' : 'Change Password'}
            </button>
          </div>
        </form>
      </div>

      {/* SSL Configuration Section */}
      <div className="settings-section">
        <h2>
          <Shield size={20} />
          SSL Configuration
        </h2>
        <div className="settings-grid ssl-grid-responsive compact-grid">
          <div className="setting-item-editable compact-item">
            <label>Enable SSL</label>
            <label className="checkbox-wrapper inline-checkbox centered-checkbox">
              <input
                type="checkbox"
                checked={!!settings.enable_ssl}
                onChange={e => updateSetting('enable_ssl', e.target.checked)}
              />
              <span className="checkmark">{settings.enable_ssl ? 'Enabled' : 'Disabled'}</span>
            </label>
            <small className="setting-hint">Enable SSL/HTTPS support for the web server</small>
          </div>
          {settings.enable_ssl && (
            <>
              <div className="setting-item-editable compact-item">
                <label>Domain Name</label>
                <div className="input-with-unit">
                  <input
                    type="text"
                    value={settings.ssl_domain || ''}
                    placeholder="e.g. mydomain.com"
                    onChange={e => updateSetting('ssl_domain', e.target.value)}
                  />
                </div>
                <small className="setting-hint">The domain name your SSL certificate is issued for (must match the certificate's CN/SAN)</small>
              </div>
              <div className="setting-item-editable compact-item">
                <label>SSL Certificate File Path</label>
                <div className="input-with-unit">
                  <input
                    type="text"
                    value={settings.ssl_certfile || ''}
                    placeholder="e.g. /etc/ssl/certs/mycert.pem"
                    onChange={e => updateSetting('ssl_certfile', e.target.value)}
                  />
                </div>
                <small className="setting-hint">Full path to your SSL certificate file (.pem, .crt, or .cert)</small>
              </div>
              <div className="setting-item-editable compact-item">
                <label>SSL Key File Path</label>
                <div className="input-with-unit">
                  <input
                    type="text"
                    value={settings.ssl_keyfile || ''}
                    placeholder="e.g. /etc/ssl/private/mykey.pem"
                    onChange={e => updateSetting('ssl_keyfile', e.target.value)}
                  />
                </div>
                <small className="setting-hint">Full path to your SSL private key file (.pem or .key)</small>
              </div>
              <div className="setting-item-editable compact-item">
                <label>Force HTTPS</label>
                <label className="checkbox-wrapper inline-checkbox centered-checkbox">
                  <input
                    type="checkbox"
                    checked={!!settings.force_https}
                    onChange={e => updateSetting('force_https', e.target.checked)}
                    disabled={!settings.enable_ssl}
                  />
                  <span className="checkmark">{settings.force_https ? 'Enabled' : 'Disabled'}</span>
                </label>
                <small className="setting-hint">Redirect all HTTP traffic to HTTPS (requires valid SSL configuration)</small>
              </div>
            </>
          )}
        </div>
        <div className="settings-actions">
          <button
            className="btn btn-primary"
            onClick={updateSslSettings}
            disabled={!sslSettingsChanged || saving}
          >
            {saving ? 'Updating...' : 'Update SSL Settings'}
          </button>
        </div>
      </div>
    </div>
  );
}

function WelcomeModal({ onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal welcome-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>🥳 Welcome to DNSniper!</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <div className="modal-body">
          <p>Congratulations! You've successfully logged into DNSniper.</p>
          <p><strong>Important Security Notice:</strong> You're currently using the default password. For your security, we strongly recommend changing both your username and password immediately.</p>
          <div className="welcome-actions">
            <div className="welcome-action-item">
              <Shield size={20} />
              <span>Change your username to something unique</span>
            </div>
            <div className="welcome-action-item">
              <Lock size={20} />
              <span>Set a strong, secure password</span>
            </div>
          </div>
          <p><small>You can update your credentials using the forms below, or return to this page anytime from the Security menu.</small></p>
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-primary">
            Get Started
          </button>
        </div>
      </div>
    </div>
  );
}

export default SecurityPage; 