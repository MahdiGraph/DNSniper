import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import axios from 'axios';
import { 
  Shield, 
  Home, 
  Globe, 
  Network, 
  FileText, 
  Settings, 
  Menu,
  X,
  AlertTriangle,
  CheckCircle,
  Activity,
  Layers,
  LogOut,
  Lock,
  Key
} from 'lucide-react';
import './App.css';

// Import components
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import DomainManagement from './components/DomainManagement';
import IPManagement from './components/IPManagement';
import IPRangeManagement from './components/IPRangeManagement';
import Logs from './components/Logs';
import SettingsPage from './components/SettingsPage';
import SecurityPage from './components/SecurityPage';
import APITokens from './components/APITokens';
import APIDocumentation from './components/APIDocumentation';
import NotFound from './components/NotFound';
import LiveToastNotifications from './components/LiveToastNotifications';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [apiStatus, setApiStatus] = useState('checking');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    initializeApp();
  }, []);

  const initializeApp = async () => {
    // Check for existing token
    const token = localStorage.getItem('authToken');
    if (token) {
      // Set axios default authorization header
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      
      try {
        // Verify token and get user info
        const response = await axios.get('/api/auth/me');
        setUser(response.data);
        setIsAuthenticated(true);
      } catch (error) {
        // Token is invalid, remove it
        localStorage.removeItem('authToken');
        delete axios.defaults.headers.common['Authorization'];
      }
    }
    
    await checkApiStatus();
    setLoading(false);
  };

  const checkApiStatus = async () => {
    try {
      const response = await axios.get('/api/health');
      setApiStatus(response.data.status === 'healthy' ? 'healthy' : 'unhealthy');
    } catch (error) {
      setApiStatus('unhealthy');
    }
  };

  const handleLoginSuccess = (userData) => {
    setUser(userData);
    setIsAuthenticated(true);
  };

  const handleLogout = async () => {
    try {
      await axios.post('/api/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local storage and state
      localStorage.removeItem('authToken');
      delete axios.defaults.headers.common['Authorization'];
      setUser(null);
      setIsAuthenticated(false);
    }
  };

  // Setup axios interceptor for handling 401 responses
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401 && isAuthenticated) {
          // Token expired or invalid, logout user
          handleLogout();
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, [isAuthenticated]);

  if (loading) {
    return (
      <div className="app-loading">
        <Shield size={48} />
        <h2>Loading DNSniper...</h2>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <Router>
      <AppContent 
        user={user}
        setUser={setUser}
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        apiStatus={apiStatus}
        onLogout={handleLogout}
      />
    </Router>
  );
}

function AppContent({ user, setUser, sidebarOpen, setSidebarOpen, apiStatus, onLogout }) {
  return (
    <div className="app">
      <Sidebar 
        isOpen={sidebarOpen} 
        onToggle={() => setSidebarOpen(!sidebarOpen)}
        user={user}
        onLogout={onLogout}
      />
      <main className={`main-content ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
        <Header 
          apiStatus={apiStatus} 
          onMenuClick={() => setSidebarOpen(!sidebarOpen)}
          user={user}
          onLogout={onLogout}
        />
        <div className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/domains" element={<DomainManagement />} />
            <Route path="/ips" element={<IPManagement />} />
            <Route path="/ip-ranges" element={<IPRangeManagement />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/security" element={<SecurityPage user={user} setUser={setUser} />} />
            <Route path="/api-tokens" element={<APITokens />} />
            <Route path="/api-documentation" element={<APIDocumentation />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </div>
      </main>
      
      {/* Global Live Toast Notifications - Appears on ALL pages */}
      <LiveToastNotifications />
    </div>
  );
}

function Header({ apiStatus, onMenuClick, user, onLogout }) {
  return (
    <header className="header">
      <div className="header-left">
        <button className="menu-button" onClick={onMenuClick}>
          <Menu size={20} />
        </button>
        <h1 className="header-title">DNSniper</h1>
      </div>
      <div className="header-right">
        <div className={`status-indicator ${apiStatus}`}>
          {apiStatus === 'healthy' ? (
            <CheckCircle size={16} />
          ) : apiStatus === 'unhealthy' ? (
            <AlertTriangle size={16} />
          ) : (
            <Activity size={16} />
          )}
          <span>API {apiStatus}</span>
        </div>
        <div className="user-menu">
          <span className="username">Welcome, {user?.username}</span>
          <button className="logout-button" onClick={onLogout} title="Logout">
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}

function Sidebar({ isOpen, onToggle, user, onLogout }) {
  return (
    <aside className={`sidebar ${isOpen ? 'open' : 'closed'}`}>
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <Shield size={24} />
          {isOpen && <span>DNSniper</span>}
        </div>
        {isOpen && (
          <button className="sidebar-close" onClick={onToggle}>
            <X size={20} />
          </button>
        )}
      </div>
      <nav className="sidebar-nav">
        {[
          { path: '/', icon: Home, label: 'Dashboard' },
          { path: '/domains', icon: Globe, label: 'Domains' },
          { path: '/ips', icon: Network, label: 'IP Addresses' },
          { path: '/ip-ranges', icon: Layers, label: 'IP Ranges' },
          { path: '/logs', icon: FileText, label: 'Logs' },
          { path: '/security', icon: Lock, label: 'Security' },
          { path: '/api-tokens', icon: Key, label: 'API Tokens' },
          { path: '/settings', icon: Settings, label: 'Settings' },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.path}
              to={item.path}
              className="nav-item"
            >
              <Icon size={20} />
              {isOpen && <span>{item.label}</span>}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}

export default App; 