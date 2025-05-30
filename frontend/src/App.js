import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [apiStatus, setApiStatus] = useState('Checking...');
  const [testData, setTestData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    checkApiStatus();
  }, []);

  const checkApiStatus = async () => {
    try {
      const response = await axios.get('/api/health');
      setApiStatus(`API is ${response.data.status} - v${response.data.version}`);
    } catch (error) {
      setApiStatus('API connection failed');
    }
  };

  const fetchTestData = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get('/api/test');
      setTestData(response.data);
    } catch (error) {
      console.error('Error fetching test data:', error);
      setTestData({ error: 'Failed to fetch data' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <div className="container">
          <h1 className="title">
            🎯 DNSniper
          </h1>
          <p className="subtitle">
            Advanced DNS Analysis Tool
          </p>
          
          <div className="status-card">
            <h3>System Status</h3>
            <p className="status">{apiStatus}</p>
          </div>

          <div className="action-section">
            <button 
              className="test-button" 
              onClick={fetchTestData}
              disabled={isLoading}
            >
              {isLoading ? 'Loading...' : 'Test API Connection'}
            </button>
            
            {testData && (
              <div className="result-card">
                <h4>API Response:</h4>
                <pre>{JSON.stringify(testData, null, 2)}</pre>
              </div>
            )}
          </div>

          <div className="features-grid">
            <div className="feature-card">
              <h3>🔍 DNS Lookup</h3>
              <p>Perform comprehensive DNS queries and analysis</p>
            </div>
            <div className="feature-card">
              <h3>⚡ Fast Results</h3>
              <p>Lightning-fast DNS resolution with detailed insights</p>
            </div>
            <div className="feature-card">
              <h3>📊 Analytics</h3>
              <p>Advanced DNS analytics and monitoring capabilities</p>
            </div>
            <div className="feature-card">
              <h3>🛡️ Security</h3>
              <p>Security-focused DNS analysis and threat detection</p>
            </div>
          </div>

          <footer className="footer">
            <p>
              Backend API: <code>/api</code> | 
              Frontend: <code>/</code> | 
              API Docs: <a href="/docs" target="_blank" rel="noopener noreferrer">/docs</a>
            </p>
          </footer>
        </div>
      </header>
    </div>
  );
}

export default App; 