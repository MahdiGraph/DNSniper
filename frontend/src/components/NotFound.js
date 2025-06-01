import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  Shield, 
  Home, 
  ArrowLeft, 
  Search, 
  AlertTriangle,
  Globe,
  Network,
  FileText,
  Settings
} from 'lucide-react';

function NotFound() {
  const navigate = useNavigate();

  const goBack = () => {
    navigate(-1);
  };

  const popularPages = [
    { path: '/', icon: Home, label: 'Dashboard', description: 'System overview and statistics' },
    { path: '/domains', icon: Globe, label: 'Domains', description: 'Manage blocked and whitelisted domains' },
    { path: '/ips', icon: Network, label: 'IP Addresses', description: 'Manage IP address rules' },
    { path: '/logs', icon: FileText, label: 'Logs', description: 'View system activity logs' },
    { path: '/settings', icon: Settings, label: 'Settings', description: 'Configure system settings' }
  ];

  return (
    <div className="not-found-page">
      <div className="not-found-container">
        {/* Header Section */}
        <div className="not-found-header">
          <div className="error-icon">
            <Shield size={64} />
            <div className="error-code">404</div>
          </div>
          <h1>Page Not Found</h1>
          <p className="error-message">
            The page you're looking for doesn't exist or has been moved.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="not-found-actions">
          <button className="btn btn-primary" onClick={goBack}>
            <ArrowLeft size={16} />
            Go Back
          </button>
          <Link to="/" className="btn btn-secondary">
            <Home size={16} />
            Home
          </Link>
        </div>

        {/* Search Suggestion */}
        <div className="search-suggestion">
          <div className="suggestion-icon">
            <Search size={24} />
          </div>
          <h3>Looking for something specific?</h3>
          <p>Try navigating to one of these popular pages:</p>
        </div>

        {/* Popular Pages Grid */}
        <div className="popular-pages">
          {popularPages.map((page) => {
            const Icon = page.icon;
            return (
              <Link key={page.path} to={page.path} className="page-card">
                <div className="page-card-icon">
                  <Icon size={24} />
                </div>
                <div className="page-card-content">
                  <h4>{page.label}</h4>
                  <p>{page.description}</p>
                </div>
              </Link>
            );
          })}
        </div>

        {/* Help Section */}
        <div className="help-section">
          <AlertTriangle size={20} />
          <div className="help-content">
            <h4>Still need help?</h4>
            <p>
              If you're experiencing issues or can't find what you're looking for, 
              check the <Link to="/api-documentation">API Documentation</Link> or 
              contact your system administrator.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default NotFound; 