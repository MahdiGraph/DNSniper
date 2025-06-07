import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Book, 
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

  const copyToClipboard = useCallback(async (text, id) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedCode(id);
      setTimeout(() => setCopiedCode(''), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  }, []);

  const baseUrl = window.location.origin;

  const apiSections = useMemo(() => [
    {
      id: 'authentication',
      title: 'Authentication',
      icon: Key,
      description: 'How to authenticate with the DNSniper API',
      content: (
        <div className="api-section">
          <p>All API endpoints require authentication using Bearer tokens. Only the OpenAPI documentation endpoints (/docs, /redoc, /openapi.json) and login endpoint are public.</p>
          
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
            <h4>Login for Session Tokens</h4>
            <p>You can also authenticate using session tokens by logging in:</p>
            <CodeBlock
              id="login-example"
              title="Login Request"
              code={`curl -X POST -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "your_password"}' \\
  ${baseUrl}/api/auth/login`}
              copyToClipboard={copyToClipboard}
              copiedCode={copiedCode}
            />
            <p>Response:</p>
            <CodeBlock
              id="login-response"
              title="Login Response"
              code={`{
  "token": "session_token_here",
  "message": "Login successful"
}`}
              copyToClipboard={copyToClipboard}
              copiedCode={copiedCode}
            />
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
              code={`curl -H "Authorization: Bearer dnsniper_LnrnBmTRF2WFWlNx3L-07yYW7HKU9DwR_CIFFkFBbjA" \\
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
          description: 'Check system health and database connectivity. This endpoint now requires authentication.',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
  ${baseUrl}/api/health`,
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
          description: 'Get comprehensive system statistics including counts, auto-update status, and firewall information',
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
  "sources": {
    "manual": {
      "domains": 250,
      "ips": 340,
      "ip_ranges": 15
    },
    "auto_update": {
      "domains": 1000,
      "ips": 2000,
      "ip_ranges": 30
    }
  },
  "auto_update": {
    "total_sources": 3,
    "active_sources": 2,
    "is_running": false,
    "enabled": true
  },
  "firewall": {
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
  },
  "activity": {
    "recent_logs_24h": 156
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
      description: 'Manage blocked and whitelisted domains with enhanced pagination and metadata',
      endpoints: [
        {
          method: 'GET',
          path: '/api/domains/',
          title: 'List Domains',
          description: 'Get all domains with optional filtering and pagination. Now supports both legacy (skip/limit) and new (page/per_page) pagination styles.',
          params: [
            { name: 'page', type: 'integer', description: 'Page number (1-based, default: 1) - NEW pagination' },
            { name: 'per_page', type: 'integer', description: 'Items per page (default: 50, max: 1000) - NEW pagination' },
            { name: 'skip', type: 'integer', description: 'Number of records to skip (legacy pagination)' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return (legacy pagination)' },
            { name: 'list_type', type: 'string', description: 'Filter by blacklist or whitelist' },
            { name: 'source_type', type: 'string', description: 'Filter by manual or auto_update' },
            { name: 'search', type: 'string', description: 'Search domain names (partial match)' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/domains/?page=1&per_page=10&list_type=blacklist"`,
            response: `{
  "domains": [
    {
      "id": 1,
      "domain_name": "malware.example.com",
      "list_type": "blacklist",
      "source_type": "manual",
      "source_url": null,
      "is_cdn": false,
      "ip_count": 3,
      "expired_at": null,
      "expires_in": null,
      "notes": "Known malware domain from threat intelligence",
      "created_at": "2024-01-01T12:00:00Z",
      "updated_at": "2024-01-01T12:00:00Z"
    }
  ],
  "page": 1,
  "per_page": 10,
  "total": 1250,
  "pages": 125
}`
          }
        },
        {
          method: 'POST',
          path: '/api/domains/',
          title: 'Create Domain',
          description: 'Add a new domain to the blacklist or whitelist with optional metadata',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{
  "domain_name": "malware.example.com",
  "list_type": "blacklist",
  "notes": "Known malware domain from threat intelligence"
}' \\
${baseUrl}/api/domains/`,
            response: `{
  "id": 1,
  "domain_name": "malware.example.com",
  "list_type": "blacklist",
  "source_type": "manual",
  "source_url": null,
  "is_cdn": false,
  "ip_count": 0,
  "expired_at": null,
  "expires_in": null,
  "notes": "Known malware domain from threat intelligence",
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/domains/{id}',
          title: 'Get Domain',
          description: 'Get details of a specific domain including associated IP count and metadata',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/domains/1`,
            response: `{
  "id": 1,
  "domain_name": "malware.example.com",
  "list_type": "blacklist",
  "source_type": "manual",
  "source_url": null,
  "is_cdn": false,
  "ip_count": 3,
  "expired_at": null,
  "expires_in": null,
  "notes": "Known malware domain from threat intelligence",
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}`
          }
        },
        {
          method: 'PUT',
          path: '/api/domains/{id}',
          title: 'Update Domain',
          description: 'Update domain properties (notes, list_type, etc.). Only manual domains can be updated.',
          example: {
            request: `curl -X PUT -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{"notes": "Updated threat intelligence", "list_type": "whitelist"}' \\
${baseUrl}/api/domains/1`,
            response: `{
  "id": 1,
  "domain_name": "malware.example.com",
  "list_type": "whitelist",
  "source_type": "manual",
  "notes": "Updated threat intelligence",
  "updated_at": "2024-01-01T13:00:00Z"
}`
          }
        },
        {
          method: 'DELETE',
          path: '/api/domains/{id}',
          title: 'Delete Domain',
          description: 'Remove a domain from the database. Both manual and auto-update domains can be deleted.',
          example: {
            request: `curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/domains/1`,
            response: `{
  "message": "Domain 'malware.example.com' deleted successfully"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/domains/{id}/ips',
          title: 'Get Domain IPs',
          description: 'Get all IP addresses associated with a domain, including resolved IPs from auto-update',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/domains/1/ips`,
            response: `[
  {
    "id": 1,
    "ip_address": "192.0.2.100",
    "ip_version": 4,
    "list_type": "blacklist",
    "source_type": "auto_update",
    "domain_name": "malware.example.com",
    "notes": "Resolved from domain during auto-update",
    "created_at": "2024-01-01T12:00:00Z"
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
      description: 'Manage blocked and whitelisted IP addresses with enhanced pagination and domain name display',
      endpoints: [
        {
          method: 'GET',
          path: '/api/ips/',
          title: 'List IPs',
          description: 'Get all IP addresses with optional filtering and pagination. Now displays associated domain names.',
          params: [
            { name: 'page', type: 'integer', description: 'Page number (1-based, default: 1) - NEW pagination' },
            { name: 'per_page', type: 'integer', description: 'Items per page (default: 50, max: 1000) - NEW pagination' },
            { name: 'skip', type: 'integer', description: 'Number of records to skip (legacy pagination)' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return (legacy pagination)' },
            { name: 'list_type', type: 'string', description: 'Filter by blacklist or whitelist' },
            { name: 'source_type', type: 'string', description: 'Filter by manual or auto_update' },
            { name: 'ip_version', type: 'integer', description: 'Filter by IPv4 (4) or IPv6 (6)' },
            { name: 'search', type: 'string', description: 'Search IP addresses (partial match)' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/ips/?page=1&per_page=10&list_type=blacklist"`,
            response: `{
  "ips": [
    {
      "id": 1,
      "ip_address": "192.0.2.100",
      "ip_version": 4,
      "list_type": "blacklist",
      "source_type": "manual",
      "source_url": null,
      "domain_name": "malware.example.com",
      "expired_at": null,
      "expires_in": null,
      "notes": "Known malicious IP address",
      "created_at": "2024-01-01T12:00:00Z",
      "updated_at": "2024-01-01T12:00:00Z"
    }
  ],
  "page": 1,
  "per_page": 10,
  "total": 2340,
  "pages": 234
}`
          }
        },
        {
          method: 'POST',
          path: '/api/ips/',
          title: 'Create IP',
          description: 'Add a new IP address to the blacklist or whitelist with optional domain association',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{
  "ip_address": "192.0.2.100",
  "list_type": "blacklist",
  "domain_name": "malware.example.com",
  "notes": "Known malicious IP from threat feed"
}' \\
${baseUrl}/api/ips/`,
            response: `{
  "id": 1,
  "ip_address": "192.0.2.100",
  "ip_version": 4,
  "list_type": "blacklist",
  "source_type": "manual",
  "source_url": null,
  "domain_name": "malware.example.com",
  "expired_at": null,
  "expires_in": null,
  "notes": "Known malicious IP from threat feed",
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/ips/{id}',
          title: 'Get IP',
          description: 'Get details of a specific IP address including associated domain information',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/ips/1`,
            response: `{
  "id": 1,
  "ip_address": "192.0.2.100",
  "ip_version": 4,
  "list_type": "blacklist",
  "source_type": "manual",
  "domain_name": "malware.example.com",
  "notes": "Known malicious IP from threat feed",
  "created_at": "2024-01-01T12:00:00Z"
}`
          }
        },
        {
          method: 'PUT',
          path: '/api/ips/{id}',
          title: 'Update IP',
          description: 'Update IP address properties (notes, list_type, etc.). Only manual IPs can be updated.',
          example: {
            request: `curl -X PUT -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{"notes": "Updated threat intelligence", "list_type": "whitelist"}' \\
${baseUrl}/api/ips/1`,
            response: `{
  "id": 1,
  "ip_address": "192.0.2.100",
  "ip_version": 4,
  "list_type": "whitelist",
  "source_type": "manual",
  "notes": "Updated threat intelligence",
  "updated_at": "2024-01-01T13:00:00Z"
}`
          }
        },
        {
          method: 'DELETE',
          path: '/api/ips/{id}',
          title: 'Delete IP',
          description: 'Remove an IP address from the database. Both manual and auto-update IPs can be deleted.',
          example: {
            request: `curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/ips/1`,
            response: `{
  "message": "IP address 192.0.2.100 deleted successfully"
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
          description: 'Get all IP ranges with optional filtering and pagination',
          params: [
            { name: 'page', type: 'integer', description: 'Page number (1-based, default: 1)' },
            { name: 'per_page', type: 'integer', description: 'Items per page (default: 50, max: 1000)' },
            { name: 'list_type', type: 'string', description: 'Filter by blacklist or whitelist' },
            { name: 'source_type', type: 'string', description: 'Filter by manual or auto_update' },
            { name: 'ip_version', type: 'integer', description: 'Filter by IP version (4 for IPv4, 6 for IPv6)' },
            { name: 'search', type: 'string', description: 'Search IP ranges (partial match)' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/ip-ranges/?page=1&per_page=10&list_type=blacklist"`,
            response: `{
  "ip_ranges": [
    {
      "id": 1,
      "ip_range": "1.2.3.0/24",
      "ip_version": 4,
      "list_type": "blacklist",
      "source_type": "manual",
      "source_url": null,
      "expired_at": null,
      "expires_in": null,
      "created_at": "2024-01-01T12:00:00Z",
      "updated_at": "2024-01-01T12:00:00Z",
      "notes": "Malicious IP range"
    }
  ],
  "page": 1,
  "per_page": 10,
  "total": 25,
  "pages": 3
}`
          }
        },
        {
          method: 'POST',
          path: '/api/ip-ranges/',
          title: 'Create IP Range',
          description: 'Add a new IP range (CIDR block) to the blacklist or whitelist. Supports both IPv4 and IPv6 ranges.',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{
  "ip_range": "1.2.3.0/24",
  "list_type": "blacklist",
  "notes": "Malicious IP range from threat intelligence"
}' \\
${baseUrl}/api/ip-ranges/`,
            response: `{
  "id": 1,
  "ip_range": "1.2.3.0/24",
  "ip_version": 4,
  "list_type": "blacklist",
  "source_type": "manual",
  "source_url": null,
  "expired_at": null,
  "expires_in": null,
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z",
  "notes": "Malicious IP range from threat intelligence"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/ip-ranges/{id}',
          title: 'Get IP Range',
          description: 'Get details of a specific IP range',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/ip-ranges/1`,
            response: `{
  "id": 1,
  "ip_range": "1.2.3.0/24",
  "ip_version": 4,
  "list_type": "blacklist",
  "source_type": "manual",
  "notes": "Malicious IP range"
}`
          }
        },
        {
          method: 'PUT',
          path: '/api/ip-ranges/{id}',
          title: 'Update IP Range',
          description: 'Update IP range properties (notes, list_type, etc.). Only manual IP ranges can be updated.',
          example: {
            request: `curl -X PUT -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{"notes": "Updated notes", "list_type": "whitelist"}' \\
${baseUrl}/api/ip-ranges/1`,
            response: `{
  "id": 1,
  "ip_range": "1.2.3.0/24",
  "ip_version": 4,
  "list_type": "whitelist",
  "source_type": "manual",
  "notes": "Updated notes"
}`
          }
        },
        {
          method: 'DELETE',
          path: '/api/ip-ranges/{id}',
          title: 'Delete IP Range',
          description: 'Remove an IP range from the database. Both manual and auto-update IP ranges can be deleted.',
          example: {
            request: `curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/ip-ranges/1`,
            response: `{
  "message": "IP range 1.2.3.0/24 deleted successfully"
}`
          }
        },
        {
          method: 'POST',
          path: '/api/ip-ranges/',
          title: 'Create IPv6 Range',
          description: 'Example of creating an IPv6 CIDR block',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{
  "ip_range": "2600:1900::/32",
  "list_type": "blacklist",
  "notes": "Suspicious IPv6 range"
}' \\
${baseUrl}/api/ip-ranges/`,
            response: `{
  "id": 2,
  "ip_range": "2600:1900::/32",
  "ip_version": 6,
  "list_type": "blacklist",
  "source_type": "manual",
  "notes": "Suspicious IPv6 range"
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
          method: 'POST',
          path: '/api/auto-update-sources/{id}/test',
          title: 'Test Auto-Update Source',
          description: 'Test connectivity to an auto-update source',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/auto-update-sources/1/test`,
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
          description: 'Get all system settings including security configurations and SSL settings',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/settings/`,
            response: `{
  "auto_update_enabled": true,
  "auto_update_interval": 3600,
  "rule_expiration": 86400,
  "max_ips_per_domain": 10,
  "dns_resolver_primary": "1.1.1.1",
  "dns_resolver_secondary": "8.8.8.8",
  "automatic_domain_resolution": true,
  "rate_limit_delay": 1.0,
  "logging_enabled": false,
  "max_log_entries": 10000,
  "log_retention_days": 7,
  "critical_ipv4_ips_ranges": [
    "127.0.0.1",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9"
  ],
  "critical_ipv6_ips_ranges": [
    "::1",
    "::",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8::/32",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888"
  ],
  "enable_ssl": false,
  "force_https": false,
  "ssl_domain": "",
  "ssl_certfile": "",
  "ssl_keyfile": ""
}`
          }
        },
        {
          method: 'PUT',
          path: '/api/settings/{setting_key}',
          title: 'Update Individual Setting',
          description: 'Update a specific setting value. Supports rule_expiration (minimum 600 seconds), max_ips_per_domain, and other configurable settings.',
          example: {
            request: `curl -X PUT -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{"value": 7200}' \\
${baseUrl}/api/settings/rule_expiration`,
            response: `{
  "key": "rule_expiration",
  "value": 7200,
  "description": "Default expiration time for rules in seconds",
  "message": "Setting updated successfully"
}`
          }
        },
        {
          method: 'GET',
          path: '/api/settings/firewall/status',
          title: 'Get Firewall Status',
          description: 'Get current firewall configuration status including iptables chains and ipsets',
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
  },
  "rules_active": {
    "ipv4": true,
    "ipv6": true
  }
}`
          }
        },
        {
          method: 'GET',
          path: '/api/settings/ssl/status',
          title: 'Get SSL Status',
          description: 'Get SSL/HTTPS configuration status and certificate information',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/settings/ssl/status`,
            response: `{
  "enable_ssl": false,
  "force_https": false,
  "ssl_domain": "",
  "status": "disabled",
  "ssl_configured": false,
  "certificates_valid": false
}`
          }
        },
        {
          method: 'POST',
          path: '/api/settings/ssl/configure',
          title: 'Configure SSL',
          description: 'Configure SSL/HTTPS settings including domain and certificate paths',
          example: {
            request: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
-H "Content-Type: application/json" \\
-d '{
  "enable_ssl": true,
  "force_https": true,
  "ssl_domain": "dnsniper.example.com",
  "ssl_certfile": "/path/to/cert.pem",
  "ssl_keyfile": "/path/to/key.pem"
}' \\
${baseUrl}/api/settings/ssl/configure`,
            response: `{
  "message": "SSL configuration updated successfully",
  "ssl_restart_required": true,
  "settings_updated": [
    "enable_ssl",
    "force_https",
    "ssl_domain",
    "ssl_certfile",
    "ssl_keyfile"
  ]
}`
          }
        }
      ]
    },
    {
      id: 'logs',
      title: 'Log Management',
      icon: FileText,
      description: 'Access system logs and activity history with enhanced search and statistics',
      endpoints: [
        {
          method: 'GET',
          path: '/api/logs/',
          title: 'List Logs',
          description: 'Get system logs with optional filtering and pagination',
          params: [
            { name: 'skip', type: 'integer', description: 'Number of records to skip (default: 0)' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return (default: 100)' },
            { name: 'action_type', type: 'string', description: 'Filter by action type (add_rule, remove_rule, update, error)' },
            { name: 'rule_type', type: 'string', description: 'Filter by rule type (domain, ip, ip_range)' },
            { name: 'mode', type: 'string', description: 'Filter by mode (manual, auto_update)' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/logs/?limit=10&action_type=add_rule"`,
            response: `[
  {
    "id": 1,
    "message": "Added domain: malware.example.com to blacklist",
    "action_type": "add_rule",
    "rule_type": "domain",
    "mode": "manual",
    "context": null,
    "created_at": "2024-01-01T12:00:00Z"
  },
  {
    "id": 2,
    "message": "Added IP range: 1.2.3.0/24 to blacklist",
    "action_type": "add_rule",
    "rule_type": "ip_range",
    "mode": "manual",
    "context": null,
    "created_at": "2024-01-01T11:55:00Z"
  }
]`
          }
        },
        {
          method: 'GET',
          path: '/api/logs/recent',
          title: 'Get Recent Logs',
          description: 'Get the most recent log entries with optional limit',
          params: [
            { name: 'limit', type: 'integer', description: 'Maximum records to return (default: 10)' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/logs/recent?limit=5"`,
            response: `[
  {
    "id": 1234,
    "message": "Added domain: malware.example.com to blacklist",
    "action_type": "add_rule",
    "rule_type": "domain",
    "mode": "manual",
    "created_at": "2024-01-01T12:00:00Z"
  },
  {
    "id": 1233,
    "message": "Auto-update cycle completed successfully",
    "action_type": "update",
    "rule_type": null,
    "mode": "auto_update",
    "created_at": "2024-01-01T11:30:00Z"
  }
]`
          }
        },
        {
          method: 'GET',
          path: '/api/logs/stats',
          title: 'Get Log Statistics',
          description: 'Get comprehensive statistics about log entries including breakdowns by action and rule type',
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/logs/stats`,
            response: `{
  "total_logs": 1234,
  "recent_logs_24h": 45,
  "logs_by_action": {
    "add_rule": 500,
    "remove_rule": 200,
    "update": 300,
    "error": 234
  },
  "logs_by_rule_type": {
    "domain": 600,
    "ip": 400,
    "ip_range": 150,
    "system": 84
  },
  "logs_by_mode": {
    "manual": 800,
    "auto_update": 434
  }
}`
          }
        },
        {
          method: 'GET',
          path: '/api/logs/search',
          title: 'Search Logs',
          description: 'Search log entries by text with optional filtering',
          params: [
            { name: 'query_text', type: 'string', description: 'Text to search for in log messages' },
            { name: 'limit', type: 'integer', description: 'Maximum records to return (default: 100)' },
            { name: 'action_type', type: 'string', description: 'Filter by action type' },
            { name: 'rule_type', type: 'string', description: 'Filter by rule type' }
          ],
          example: {
            request: `curl -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/logs/search?query_text=malware&limit=5"`,
            response: `[
  {
    "id": 1,
    "message": "Added domain: malware.example.com to blacklist",
    "action_type": "add_rule",
    "rule_type": "domain",
    "mode": "manual",
    "created_at": "2024-01-01T12:00:00Z"
  },
  {
    "id": 45,
    "message": "Removed domain: old-malware.test.com from blacklist",
    "action_type": "remove_rule",
    "rule_type": "domain",
    "mode": "manual",
    "created_at": "2024-01-01T10:30:00Z"
  }
]`
          }
        }
      ]
    },
    {
      id: 'clear-data',
      title: 'Clear All Data',
      icon: Database,
      description: 'Clear all database data and firewall rules',
      endpoints: [
        {
          method: 'DELETE',
          path: '/api/clear-all-data',
          title: 'Clear All Database Data',
          description: 'Clear all domains, IPs, and IP ranges from the database and firewall rules. This is a destructive operation that cannot be undone.',
          example: {
            request: `curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \\
${baseUrl}/api/clear-all-data`,
            response: `{
  "message": "All database data cleared successfully",
  "cleared": {
    "domains": 1250,
    "ips": 2340,
    "ip_ranges": 45,
    "total": 3635
  },
  "firewall_cleared": true
}`
          }
        }
      ]
    },
    {
      id: 'websocket',
      title: 'WebSocket Live Events',
      icon: Activity,
      description: 'Real-time system events and notifications via WebSocket',
      content: (
        <div className="api-section">
          <p>DNSniper provides real-time system events through WebSocket connections. This allows you to monitor system activity, rule changes, and auto-update progress in real-time.</p>
          
          <div className="api-subsection">
            <h4>WebSocket Connection</h4>
            <p>Connect to the WebSocket endpoint with authentication:</p>
            <CodeBlock
              id="websocket-connect"
              title="WebSocket Connection"
              code={`ws://localhost:8585/ws/live-events?token=YOUR_API_TOKEN`}
              copyToClipboard={copyToClipboard}
              copiedCode={copiedCode}
            />
          </div>

          <div className="api-subsection">
            <h4>Authentication</h4>
            <p>WebSocket connections require authentication via query parameters. You can use either:</p>
            <ul>
              <li><strong>API Token:</strong> Your DNSniper API token (starts with "dnsniper_")</li>
              <li><strong>Session Token:</strong> Token obtained from login endpoint</li>
            </ul>
          </div>

          <div className="api-subsection">
            <h4>Event Types</h4>
            <p>The WebSocket sends JSON messages for various system events:</p>
            <ul>
              <li><strong>rule_added:</strong> New domain, IP, or IP range added</li>
              <li><strong>rule_removed:</strong> Domain, IP, or IP range deleted</li>
              <li><strong>rule_updated:</strong> Existing rule modified</li>
              <li><strong>auto_update_started:</strong> Auto-update cycle began</li>
              <li><strong>auto_update_completed:</strong> Auto-update cycle finished</li>
              <li><strong>system_status:</strong> System health updates</li>
              <li><strong>client_connected:</strong> Initial connection confirmation</li>
            </ul>
          </div>

          <div className="api-subsection">
            <h4>Example Event Message</h4>
            <CodeBlock
              id="websocket-event"
              title="Event Message"
              code={`{
  "event_type": "rule_added",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "rule_type": "domain",
    "rule_id": 123,
    "domain_name": "malware.example.com",
    "list_type": "blacklist",
    "source_type": "manual"
  }
}`}
              copyToClipboard={copyToClipboard}
              copiedCode={copiedCode}
            />
          </div>

          <div className="api-subsection">
            <h4>JavaScript Example</h4>
            <CodeBlock
              id="websocket-js"
              title="JavaScript WebSocket Client"
              code={`const token = 'your_api_token_here';
const ws = new WebSocket(\`ws://localhost:8585/ws/live-events?token=\${token}\`);

ws.onopen = function(event) {
    console.log('Connected to DNSniper live events');
};

ws.onmessage = function(event) {
    const eventData = JSON.parse(event.data);
    console.log('Received event:', eventData);
    
    // Handle different event types
    switch(eventData.event_type) {
        case 'rule_added':
            console.log('New rule added:', eventData.data);
            break;
        case 'auto_update_completed':
            console.log('Auto-update finished');
            break;
        // ... handle other events
    }
};

ws.onerror = function(error) {
    console.error('WebSocket error:', error);
};

ws.onclose = function(event) {
    if (event.code === 4401) {
        console.error('Authentication failed');
    } else {
        console.log('Connection closed');
    }
};`}
              copyToClipboard={copyToClipboard}
              copiedCode={copiedCode}
            />
          </div>
        </div>
      )
    }
  ], [baseUrl, copyToClipboard]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    // Auto-expand all sections by default
    const expanded = {};
    apiSections.forEach(section => {
      expanded[section.id] = false;
    });
    setExpandedSections(expanded);
  }, [apiSections]);

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
            Swagger UI
          </a>
          <a 
            href="/redoc" 
            target="_blank" 
            rel="noopener noreferrer"
            className="btn btn-secondary"
          >
            <ExternalLink size={16} />
            ReDoc
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