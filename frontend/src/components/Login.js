import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Eye, EyeOff, AlertTriangle, Clock } from 'lucide-react';
import { showSuccess } from '../utils/customAlert';
import './Login.css';

function Login({ onLoginSuccess }) {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [countdown, setCountdown] = useState(0);

  // Countdown timer effect for rate limiting
  useEffect(() => {
    let interval = null;
    
    if (countdown > 0) {
      interval = setInterval(() => {
        setCountdown(prevCountdown => {
          const newCountdown = prevCountdown - 1;
          
          if (newCountdown <= 0) {
            // Rate limit expired - clear the error and allow retry
            setError('');
            setRateLimitInfo(null);
            return 0;
          }
          
          // Update the error message with new countdown
          if (rateLimitInfo) {
            const minutes = Math.floor(newCountdown / 60);
            const seconds = newCountdown % 60;
            
            let timeMessage;
            if (minutes > 0) {
              timeMessage = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
              if (seconds > 0) {
                timeMessage += ` and ${seconds} second${seconds !== 1 ? 's' : ''}`;
              }
            } else {
              timeMessage = `${seconds} second${seconds !== 1 ? 's' : ''}`;
            }
            
            if (rateLimitInfo.type === 'ip_locked') {
              setError(`IP temporarily locked due to too many failed attempts. Try again in ${timeMessage}.`);
            } else {
              setError(`Too many login attempts. Try again in ${timeMessage}.`);
            }
          }
          
          return newCountdown;
        });
      }, 1000);
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [countdown, rateLimitInfo]);

  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    
    if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    }
    return `${secs}s`;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setRateLimitInfo(null);
    setCountdown(0);

    try {
      const response = await axios.post('/api/auth/login', formData);
      
      // Store token in localStorage
      localStorage.setItem('authToken', response.data.token);
      
      // Set axios default authorization header
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      
      // Check if using default credentials
      const isDefaultCredentials = formData.username.toLowerCase() === 'admin' && formData.password === 'changeme';
      
      // Function to handle the redirect
      const handleRedirect = () => {
        onLoginSuccess(response.data.user);
        if (isDefaultCredentials) {
          window.location.href = '/security';
        } else {
          window.location.reload();
        }
      };

      // Set up auto-redirect timer (3 seconds)
      const redirectTimer = setTimeout(() => {
        handleRedirect();
      }, 3000);

      // Show success alert
      if (isDefaultCredentials) {
        showSuccess(
          'Login Successful!',
          `Welcome to DNSniper, ${response.data.user.username}!\n\nYou're using default credentials. We'll redirect you to the Security page to update your password for better security.\n\nRedirecting automatically in 3 seconds...`,
          { 
            confirmButtonText: 'Go to Security Now'
          }
        ).then(() => {
          // User clicked button - redirect immediately
          clearTimeout(redirectTimer);
          handleRedirect();
        }).catch(() => {
          // Alert was dismissed - still allow auto-redirect
          // Timer will handle the redirect
        });
      } else {
        showSuccess(
          'Login Successful!',
          `Welcome back to DNSniper, ${response.data.user.username}!\n\nTaking you to the dashboard...\n\nRedirecting automatically in 3 seconds...`,
          { 
            confirmButtonText: 'Continue Now'
          }
        ).then(() => {
          // User clicked button - redirect immediately
          clearTimeout(redirectTimer);
          handleRedirect();
        }).catch(() => {
          // Alert was dismissed - still allow auto-redirect
          // Timer will handle the redirect
        });
      }
      
    } catch (error) {
      setLoading(false);
      
      // Enhanced error handling for rate limiting with countdown
      if (error.response?.status === 429) {
        const rateLimitSeconds = parseInt(error.response.headers['x-ratelimit-remaining-seconds']) || 
                                parseInt(error.response.headers['retry-after']) || 0;
        const rateLimitType = error.response.headers['x-ratelimit-type'] || 'rate_limited';
        
        if (rateLimitSeconds > 0) {
          setRateLimitInfo({
            seconds: rateLimitSeconds,
            type: rateLimitType
          });
          setCountdown(rateLimitSeconds);
          
          // Set initial error message
          const minutes = Math.floor(rateLimitSeconds / 60);
          const secs = rateLimitSeconds % 60;
          let timeMessage;
          
          if (minutes > 0) {
            timeMessage = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
            if (secs > 0) {
              timeMessage += ` and ${secs} second${secs !== 1 ? 's' : ''}`;
            }
          } else {
            timeMessage = `${secs} second${secs !== 1 ? 's' : ''}`;
          }
          
          if (rateLimitType === 'ip_locked') {
            setError(`IP temporarily locked due to too many failed attempts. Try again in ${timeMessage}.`);
          } else {
            setError(`Too many login attempts. Try again in ${timeMessage}.`);
          }
        } else {
          // Fallback to backend message if no timing info
          const errorMessage = error.response?.data?.detail || 'Too many login attempts. Please try again later.';
          setError(errorMessage);
        }
      } else if (error.response?.status === 401) {
        // Authentication error - use message from backend or fallback
        const errorMessage = error.response?.data?.detail || 'Invalid username or password.';
        setError(errorMessage);
      } else if (error.response?.data?.detail) {
        // Any other error with a detail message from backend
        setError(error.response.data.detail);
      } else {
        // Generic fallback for network errors, etc.
        setError('An error occurred. Please try again.');
      }
    }
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    // Clear error when user starts typing (but keep countdown running)
    if (error && countdown === 0) {
      setError('');
    }
  };

  const isRateLimited = countdown > 0;

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <Shield size={48} className="login-logo" />
          <h1>DNSniper</h1>
          <p>Firewall Management System</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {error && (
            <div className={`error-message ${isRateLimited ? 'rate-limited' : ''}`}>
              {isRateLimited ? <Clock size={16} /> : <AlertTriangle size={16} />}
              <span>{error}</span>
              {isRateLimited && (
                <div className="countdown-display">
                  <small>Remaining: {formatTime(countdown)}</small>
                </div>
              )}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleInputChange}
              required
              autoComplete="username"
              placeholder="Enter username"
              disabled={loading || isRateLimited}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <div className="password-input">
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                required
                autoComplete="current-password"
                placeholder="Enter password"
                disabled={loading || isRateLimited}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading || isRateLimited}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className={`login-button ${isRateLimited ? 'rate-limited' : ''}`}
            disabled={loading || !formData.username || !formData.password || isRateLimited}
          >
            {isRateLimited ? `Try again in ${formatTime(countdown)}` : 
             loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default Login; 