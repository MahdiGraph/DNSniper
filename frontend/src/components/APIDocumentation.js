import React, { useState, useEffect } from 'react';
import { 
  Book, 
  Code, 
  Copy, 
  CheckCircle, 
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Globe,
  Network,
  Shield,
  Activity,
  Settings,
  Key,
  FileText,
  Database
} from 'lucide-react';

function APIDocumentation() {
  const [expandedSections, setExpandedSections] = useState({});
  const [copiedCode, setCopiedCode] = useState('');

  const toggleSection = (sectionId) => {
    setExpandedSections(prev => ({
      ...prev,
      [sectionId]: !prev[sectionId]
    }));
  };

  const copyToClipboard = async (text, id) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedCode(id);
      setTimeout(() => setCopiedCode(''), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const baseUrl = window.location.origin;

  const apiSections = [
    {
      id: 'authentication',
      title: 'Authentication',
      icon: Key,
      description: 'How to authenticate with the DNSniper API',
      content: (
        <div className="api-section">
          <p>All API endpoints (except health check) require authentication using Bearer tokens.</p>
          
          <div className="api-subsection">
            <h4>Getting an API Token</h4>
            <ol>
              <li>Go to the <strong>API Tokens</strong> page in the DNSniper web interface</li>
              <li>Click <strong>Create Token</strong></li>
              <li>Enter a descriptive name for your token</li>
              <li>Choose whether to make it permanent or set an expiration</li>
              <li>Copy the generated token immediately (you won't see it again)</li>
            </ol>
          </div>

          <div className="api-subsection">
            <h4>Using Your Token</h4>
            <p>Include your token in the Authorization header of every request:</p>
            <CodeBlock
              id="auth-header"
              title="Authorization Header"
              code={`Authorization: Bearer your_api_token_here`}
              copyToClipboard={copyToClipboard}
              copiedCode={copiedCode}
            />
          </div>

          <div className="api-subsection">
            <h4>Example Request</h4>
            <CodeBlock
              id="auth-example"
              title="curl Example"
              code={`curl -H "Authorization: Bearer dnsniper_-zX1Y51b0nzWKrq4ZvW1k1hi1Eqmd3d0nM8k9bDTrrk" \\
  ${baseUrl}/api/dashboard`}
              copyToClipboard={copyToClipboard}
              copiedCode={copiedCode}
            />
          </div>
        </div>
      )
    },
    {
      id: 'health',
      title: 'Health & Status',
      icon: Activity,
      description: 'System health and dashboard endpoints',
      endpoints: [
        {
          method: 'GET',
          path: '/api/health',
          title: 'Health Check',
          description: 'Check system health and database connectivity (no auth required)',
          example: {
            request: `curl ${baseUrl}/api/health`,
            response: `{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "database": "connected",
  "stats": {
    "domains": 1250,
    "ips": 2340,
    "ip_ranges": 45
  }
}`
          }
        },
        {
          method: 'GET',
          path: '/api/dashboard',
          title: 'Dashboard Statistics',
          description: 'Get comprehensive system statistics and counts',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/dashboard`,
            response: `{
  "totals": {
    "domains": 1250,
    "ips": 2340,
    "ip_ranges": 45,
    "auto_update_sources": 3
  },
  "lists": {
    "blacklist": {
      "domains": 1200,
      "ips": 2200,
      "ip_ranges": 40
    },
    "whitelist": {
      "domains": 50,
      "ips": 140,
      "ip_ranges": 5
    }
  },
  "auto_update": {
    "total_sources": 3,
    "active_sources": 2,
    "is_running": true,
    "enabled": true
  },
  "firewall": {
    "chains_exist": {
      "ipv4": true,
      "ipv6": true
    }
  }
}`
          }
        }
      ]
    },
    {
      id: 'domains',
      title: 'Domain Management',
      icon: Globe,
      description: 'Manage blocked and whitelisted domains',
      endpoints: [
        {
          method: 'GET',
          path: '/api/domains/',
          title: 'List Domains',
          description: 'Get all domains with optional filtering and pagination',
          params: [
            { name: 'skip', type: 'integer', description: 'Number of records to skip (default: 0)' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return (default: 100)' },
            { name: 'list_type', type: 'string', description: 'Filter by blacklist or whitelist' },
            { name: 'source_type', type: 'string', description: 'Filter by manual or auto_update' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  "${baseUrl}/api/domains/?limit=10&list_type=blacklist"`,
            response: `[
  {
    "id": 1,
    "domain_name": "malware.example.com",
    "list_type": "blacklist",
    "source_type": "manual",
    "is_cdn": false,
    "ip_count": 3,
    "notes": "Known malware domain",
    "created_at": "2024-01-01T12:00:00Z"
  }
]`
          }
        },
        {
          method: 'POST',
          path: '/api/domains/',
          title: 'Create Domain',
          description: 'Add a new domain to the blacklist or whitelist',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "domain_name": "malware.example.com",
    "list_type": "blacklist",
    "notes": "Known malware domain"
  }' \\
  ${baseUrl}/api/domains/`,
            response: `{
  "id": 1,
  "domain_name": "malware.example.com",
  "list_type": "blacklist",
  "source_type": "manual",
  "is_cdn": false,
  "ip_count": 0,
  "notes": "Known malware domain",
  "created_at": "2024-01-01T12:00:00Z"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/domains/{id}',
          title: 'Get Domain',
          description: 'Get details of a specific domain',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/domains/1`,
            response: `{
  "id": 1,
  "domain_name": "malware.example.com",
  "list_type": "blacklist",
  "source_type": "manual",
  "ip_count": 3,
  "notes": "Known malware domain"
}`
          }
        },
        {
          method: 'PUT',
          path: '/api/domains/{id}',
          title: 'Update Domain',
          description: 'Update domain properties (notes, list_type, etc.)',
          example: {
            request: `curl -X PUT -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"notes": "Updated notes"}' \\
  ${baseUrl}/api/domains/1`,
            response: `{
  "id": 1,
  "domain_name": "malware.example.com",
  "list_type": "blacklist",
  "notes": "Updated notes"
}`
          }
        },
        {
          method: 'DELETE',
          path: '/api/domains/{id}',
          title: 'Delete Domain',
          description: 'Remove a domain from the database',
          example: {
            request: `curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/domains/1`,
            response: `{
  "message": "Domain deleted successfully"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/domains/{id}/ips',
          title: 'Get Domain IPs',
          description: 'Get all IP addresses associated with a domain',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/domains/1/ips`,
            response: `[
  {
    "id": 1,
    "ip_address": "192.0.2.100",
    "ip_version": 4,
    "list_type": "blacklist",
    "source_type": "auto_update"
  }
]`
          }
        }
      ]
    },
    {
      id: 'ips',
      title: 'IP Management',
      icon: Network,
      description: 'Manage blocked and whitelisted IP addresses',
      endpoints: [
        {
          method: 'GET',
          path: '/api/ips/',
          title: 'List IPs',
          description: 'Get all IP addresses with optional filtering',
          params: [
            { name: 'skip', type: 'integer', description: 'Number of records to skip' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return' },
            { name: 'list_type', type: 'string', description: 'Filter by blacklist or whitelist' },
            { name: 'source_type', type: 'string', description: 'Filter by manual or auto_update' },
            { name: 'ip_version', type: 'integer', description: 'Filter by IPv4 (4) or IPv6 (6)' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  "${baseUrl}/api/ips/?limit=10&list_type=blacklist"`,
            response: `[
  {
    "id": 1,
    "ip_address": "192.0.2.100",
    "ip_version": 4,
    "list_type": "blacklist",
    "source_type": "manual",
    "notes": "Known malicious IP",
    "created_at": "2024-01-01T12:00:00Z"
  }
]`
          }
        },
        {
          method: 'POST',
          path: '/api/ips/',
          title: 'Create IP',
          description: 'Add a new IP address to the blacklist or whitelist',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "ip_address": "192.0.2.100",
    "list_type": "blacklist",
    "notes": "Known malicious IP"
  }' \\
  ${baseUrl}/api/ips/`,
            response: `{
  "id": 1,
  "ip_address": "192.0.2.100",
  "ip_version": 4,
  "list_type": "blacklist",
  "source_type": "manual",
  "notes": "Known malicious IP"
}`
          }
        },
        {
          method: 'DELETE',
          path: '/api/ips/{id}',
          title: 'Delete IP',
          description: 'Remove an IP address from the database',
          example: {
            request: `curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/ips/1`,
            response: `{
  "message": "IP address deleted successfully"
}`
          }
        }
      ]
    },
    {
      id: 'ipranges',
      title: 'IP Range Management',
      icon: Shield,
      description: 'Manage blocked and whitelisted IP ranges (CIDR blocks)',
      endpoints: [
        {
          method: 'GET',
          path: '/api/ip-ranges/',
          title: 'List IP Ranges',
          description: 'Get all IP ranges with optional filtering',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  "${baseUrl}/api/ip-ranges/?limit=10"`,
            response: `[
  {
    "id": 1,
    "ip_range": "8.8.8.0/28",
    "list_type": "blacklist",
    "source_type": "manual",
    "notes": "Malicious IP range",
    "created_at": "2024-01-01T12:00:00Z"
  }
]`
          }
        },
        {
          method: 'POST',
          path: '/api/ip-ranges/',
          title: 'Create IP Range',
          description: 'Add a new IP range (CIDR block) to the blacklist or whitelist',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "ip_range": "8.8.8.0/28",
    "list_type": "blacklist",
    "notes": "Malicious IP range"
  }' \\
  ${baseUrl}/api/ip-ranges/`,
            response: `{
  "id": 1,
  "ip_range": "8.8.8.0/28",
  "list_type": "blacklist",
  "source_type": "manual",
  "notes": "Malicious IP range"
}`
          }
        },
        {
          method: 'DELETE',
          path: '/api/ip-ranges/{id}',
          title: 'Delete IP Range',
          description: 'Remove an IP range from the database',
          example: {
            request: `curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/ip-ranges/1`,
            response: `{
  "message": "IP range deleted successfully"
}`
          }
        }
      ]
    },
    {
      id: 'autoupdate',
      title: 'Auto-Update Sources',
      icon: Database,
      description: 'Manage automatic updates from external threat feeds',
      endpoints: [
        {
          method: 'GET',
          path: '/api/auto-update-sources/',
          title: 'List Auto-Update Sources',
          description: 'Get all configured auto-update sources',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/auto-update-sources/`,
            response: `[
  {
    "id": 1,
    "name": "Malware Domain List",
    "url": "https://example.com/malware-domains.txt",
    "is_active": true,
    "list_type": "blacklist",
    "last_update": "2024-01-01T12:00:00Z",
    "update_count": 25
  }
]`
          }
        },
        {
          method: 'POST',
          path: '/api/auto-update-sources/',
          title: 'Create Auto-Update Source',
          description: 'Add a new auto-update source',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "Malware Domain List",
    "url": "https://example.com/malware-domains.txt",
    "is_active": false,
    "list_type": "blacklist"
  }' \\
  ${baseUrl}/api/auto-update-sources/`,
            response: `{
  "id": 1,
  "name": "Malware Domain List",
  "url": "https://example.com/malware-domains.txt",
  "is_active": false,
  "list_type": "blacklist",
  "update_count": 0
}`
          }
        },
        {
          method: 'GET',
          path: '/api/auto-update-sources/status',
          title: 'Get Auto-Update Status',
          description: 'Get the current status of the auto-update system',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/auto-update-sources/status`,
            response: `{
  "enabled": true,
  "is_running": false,
  "active_sources": 2,
  "total_sources": 3,
  "interval": 3600
}`
          }
        },
        {
          method: 'GET',
          path: '/api/auto-update-sources/test/{id}',
          title: 'Test Auto-Update Source',
          description: 'Test connectivity to an auto-update source',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/auto-update-sources/test/1`,
            response: `{
  "source": {
    "id": 1,
    "name": "Test Source",
    "url": "https://httpbin.org/status/200"
  },
  "test_result": {
    "status": "success",
    "http_status": 200,
    "content_length": 1234
  }
}`
          }
        },
        {
          method: 'POST',
          path: '/api/auto-update-sources/trigger-update',
          title: 'Trigger Manual Update',
          description: 'Manually trigger an auto-update cycle',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/auto-update-sources/trigger-update`,
            response: `{
  "message": "Auto-update cycle started in background"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/auto-update-sources/stats/summary',
          title: 'Get Auto-Update Statistics',
          description: 'Get statistics about auto-update sources',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/auto-update-sources/stats/summary`,
            response: `{
  "total_sources": 3,
  "active_sources": 2,
  "inactive_sources": 1,
  "sources_with_errors": 0,
  "total_successful_updates": 75
}`
          }
        }
      ]
    },
    {
      id: 'settings',
      title: 'Settings Management',
      icon: Settings,
      description: 'Manage system configuration and settings',
      endpoints: [
        {
          method: 'GET',
          path: '/api/settings/',
          title: 'Get All Settings',
          description: 'Get all system settings',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/settings/`,
            response: `{
  "auto_update_enabled": true,
  "auto_update_interval": 3600,
  "rule_expiration": 86400,
  "max_ips_per_domain": 5,
  "dns_resolver_primary": "1.1.1.1",
  "dns_resolver_secondary": "8.8.8.8",
  "manual_domain_resolution": true,
  "rate_limit_delay": 1.0
}`
          }
        },
        {
          method: 'GET',
          path: '/api/settings/firewall/status',
          title: 'Get Firewall Status',
          description: 'Get current firewall configuration status',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/settings/firewall/status`,
            response: `{
  "chains_exist": {
    "ipv4": true,
    "ipv6": true
  },
  "ipsets_exist": {
    "ipv4": {
      "blacklist": true,
      "whitelist": true
    },
    "ipv6": {
      "blacklist": true,
      "whitelist": true
    }
  }
}`
          }
        },
        {
          method: 'GET',
          path: '/api/settings/ssl/status',
          title: 'Get SSL Status',
          description: 'Get SSL/HTTPS configuration status',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/settings/ssl/status`,
            response: `{
  "enable_ssl": false,
  "force_https": false,
  "status": "disabled"
}`
          }
        }
      ]
    },
    {
      id: 'logs',
      title: 'Log Management',
      icon: FileText,
      description: 'Access system logs and activity history',
      endpoints: [
        {
          method: 'GET',
          path: '/api/logs/',
          title: 'List Logs',
          description: 'Get system logs with optional filtering',
          params: [
            { name: 'skip', type: 'integer', description: 'Number of records to skip' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return' },
            { name: 'action_type', type: 'string', description: 'Filter by action type' },
            { name: 'rule_type', type: 'string', description: 'Filter by rule type' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  "${baseUrl}/api/logs/?limit=10"`,
            response: `[
  {
    "id": 1,
    "message": "Added domain: malware.example.com",
    "action_type": "add_rule",
    "rule_type": "domain",
    "created_at": "2024-01-01T12:00:00Z"
  }
]`
          }
        },
        {
          method: 'GET',
          path: '/api/logs/stats',
          title: 'Get Log Statistics',
          description: 'Get statistics about log entries',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/logs/stats`,
            response: `{
  "total_logs": 1234,
  "logs_by_action": {
    "add_rule": 500,
    "remove_rule": 200,
    "update": 300
  },
  "logs_by_rule_type": {
    "domain": 600,
    "ip": 400,
    "ip_range": 100
  },
  "recent_logs_24h": 25
}`
          }
        },
        {
          method: 'GET',
          path: '/api/logs/recent',
          title: 'Get Recent Logs',
          description: 'Get the most recent log entries',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  "${baseUrl}/api/logs/recent?limit=5"`,
            response: `[
  {
    "id": 1234,
    "message": "Added domain: malware.example.com",
    "action_type": "add_rule",
    "created_at": "2024-01-01T12:00:00Z"
  }
]`
          }
        },
        {
          method: 'GET',
          path: '/api/logs/search',
          title: 'Search Logs',
          description: 'Search log entries by text',
          params: [
            { name: 'query_text', type: 'string', description: 'Text to search for' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  "${baseUrl}/api/logs/search?query_text=malware&limit=5"`,
            response: `[
  {
    "id": 1,
    "message": "Added domain: malware.example.com",
    "action_type": "add_rule",
    "created_at": "2024-01-01T12:00:00Z"
  }
]`
          }
        }
      ]
    }
  ];

  useEffect(() => {
    // Auto-expand all sections by default
    const expanded = {};
    apiSections.forEach(section => {
      expanded[section.id] = true;
    });
    setExpandedSections(expanded);
  }, []);

  return (
    <div className="api-documentation">
      <div className="page-header">
        <h1>
          <Book size={24} />
          API Documentation
        </h1>
        <div className="header-actions">
          <a 
            href="/docs" 
            target="_blank" 
            rel="noopener noreferrer"
            className="btn btn-secondary"
          >
            <ExternalLink size={16} />
            OpenAPI Docs
          </a>
        </div>
      </div>

      <div className="api-overview">
        <div className="overview-card">
          <h2>DNSniper API</h2>
          <p>
            The DNSniper API provides programmatic access to all firewall management features.
            Use it to integrate DNSniper with your security tools, automate threat intelligence
            updates, or build custom monitoring solutions.
          </p>
          <div className="quick-stats">
            <div className="stat">
              <strong>Base URL:</strong> <code>{baseUrl}</code>
            </div>
            <div className="stat">
              <strong>Authentication:</strong> Bearer Token
            </div>
            <div className="stat">
              <strong>Format:</strong> JSON
            </div>
          </div>
        </div>
      </div>

      <div className="api-sections">
        {apiSections.map((section) => (
          <div key={section.id} className="api-section-container">
            <div 
              className="api-section-header"
              onClick={() => toggleSection(section.id)}
            >
              <div className="section-title">
                <section.icon size={20} />
                <h3>{section.title}</h3>
                {expandedSections[section.id] ? 
                  <ChevronDown size={16} /> : 
                  <ChevronRight size={16} />
                }
              </div>
              <p className="section-description">{section.description}</p>
            </div>

            {expandedSections[section.id] && (
              <div className="api-section-content">
                {section.content && section.content}
                
                {section.endpoints && (
                  <div className="endpoints">
                    {section.endpoints.map((endpoint, index) => (
                      <div key={index} className="endpoint">
                        <div className="endpoint-header">
                          <div className="endpoint-method">
                            <span className={`method method-${endpoint.method.toLowerCase()}`}>
                              {endpoint.method}
                            </span>
                            <code className="endpoint-path">{endpoint.path}</code>
                          </div>
                          <h4>{endpoint.title}</h4>
                        </div>
                        
                        <p className="endpoint-description">{endpoint.description}</p>

                        {endpoint.params && (
                          <div className="endpoint-params">
                            <h5>Parameters</h5>
                            <table className="params-table">
                              <thead>
                                <tr>
                                  <th>Name</th>
                                  <th>Type</th>
                                  <th>Description</th>
                                </tr>
                              </thead>
                              <tbody>
                                {endpoint.params.map((param, i) => (
                                  <tr key={i}>
                                    <td><code>{param.name}</code></td>
                                    <td>{param.type}</td>
                                    <td>{param.description}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}

                        {endpoint.example && (
                          <div className="endpoint-example">
                            <div className="example-request">
                              <h5>Request</h5>
                              <CodeBlock
                                id={`${section.id}-${index}-request`}
                                title="curl"
                                code={endpoint.example.request}
                                copyToClipboard={copyToClipboard}
                                copiedCode={copiedCode}
                              />
                            </div>
                            <div className="example-response">
                              <h5>Response</h5>
                              <CodeBlock
                                id={`${section.id}-${index}-response`}
                                title="JSON"
                                code={endpoint.example.response}
                                copyToClipboard={copyToClipboard}
                                copiedCode={copiedCode}
                              />
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="api-footer">
        <div className="footer-section">
          <h3>Error Handling</h3>
          <p>The API uses standard HTTP status codes:</p>
          <ul>
            <li><strong>200 OK</strong> - Success</li>
            <li><strong>201 Created</strong> - Resource created successfully</li>
            <li><strong>400 Bad Request</strong> - Invalid request data</li>
            <li><strong>401 Unauthorized</strong> - Invalid or missing token</li>
            <li><strong>404 Not Found</strong> - Resource not found</li>
            <li><strong>500 Internal Server Error</strong> - Server error</li>
          </ul>
        </div>

        <div className="footer-section">
          <h3>Rate Limiting</h3>
          <p>
            The API has built-in rate limiting to prevent abuse. If you hit rate limits,
            you'll receive a 429 status code. Consider implementing exponential backoff
            in your clients.
          </p>
        </div>

        <div className="footer-section">
          <h3>Need Help?</h3>
          <p>
            For additional support, check the <a href="/docs" target="_blank">OpenAPI documentation</a> 
            or contact your system administrator.
          </p>
        </div>
      </div>
    </div>
  );
}

function CodeBlock({ id, title, code, copyToClipboard, copiedCode }) {
  return (
    <div className="code-block">
      <div className="code-header">
        <span className="code-title">{title}</span>
        <button 
          className="copy-button"
          onClick={() => copyToClipboard(code, id)}
          title="Copy to clipboard"
        >
          {copiedCode === id ? <CheckCircle size={16} /> : <Copy size={16} />}
        </button>
      </div>
      <pre className="code-content">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export default APIDocumentation; 