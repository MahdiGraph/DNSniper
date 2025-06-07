# DNSniper API Test Suite v2.0

This directory contains comprehensive automated tests for the DNSniper API using Newman (Postman CLI runner). The test suite has been completely rewritten to support the latest DNSniper version with enhanced authentication, live events, and advanced features.

## 🚨 **Important Security Updates**

### **Authentication Required for All Endpoints**
- **All API endpoints now require authentication**, including `/api/health`
- Use API tokens or session tokens for access
- WebSocket connections also require authentication via query parameters
- No endpoints are publicly accessible except documentation and login

## 📋 Test Coverage

The v2.0 test suite includes:

### ✅ Authentication System
- **Login/Session Management**: User authentication with session tokens
- **API Token Validation**: Testing with provided API tokens
- **User Profile Access**: Authenticated user information retrieval
- **Security Enforcement**: Verification that all endpoints require auth

### ✅ Health & System Monitoring
- **Authenticated Health Check**: System health with database stats (now requires auth)
- **Dashboard Statistics**: Comprehensive system overview
- **Real-time Metrics**: Live system status and activity monitoring

### ✅ Enhanced Settings Management
- **All Settings Retrieval**: Complete system configuration
- **Individual Setting Updates**: Granular setting modifications
- **10-Minute Rule Expiration**: Support for new minimum rule expiration (10 minutes)
- **10 IPs per Domain**: Updated default maximum IPs per domain
- **Firewall Status**: Real-time firewall monitoring
- **SSL Configuration**: HTTPS and certificate management

### ✅ Advanced Domain Management
- **Paginated Domain Lists**: Efficient data retrieval with pagination
- **CRUD Operations**: Create, read, update, delete domains
- **Enhanced Domain Properties**: IP counts, CDN detection, expiration tracking
- **Notes and Metadata**: Rich domain information storage
- **Live Event Integration**: Real-time domain change notifications

### ✅ Enhanced IP Management
- **Paginated IP Lists**: Efficient IP data retrieval
- **Domain Name Display**: IPs now show associated domain names (not just IDs)
- **IPv4/IPv6 Support**: Complete IP version support
- **Advanced Filtering**: By source type, list type, and IP version
- **Notes and Tracking**: Enhanced IP metadata

### ✅ Auto-Update Sources
- **Source Management**: CRUD operations for threat feeds
- **Scheduler Integration**: Real-time scheduler status
- **Live Status Monitoring**: Active source tracking
- **Enhanced Statistics**: Update counts and source health

### ✅ Comprehensive Logging
- **Recent Logs**: Paginated log retrieval
- **Log Statistics**: Activity metrics and insights
- **Search Functionality**: Log filtering and search
- **Activity Monitoring**: System activity tracking

### ✅ Live Events System (New)
- **WebSocket Authentication**: Secure live event connections
- **Real-time Notifications**: Live system event streaming
- **Event Broadcasting**: Domain, IP, and system events
- **Client Management**: Multi-client WebSocket support

## 🛠️ Prerequisites

### Required Software
1. **Node.js** (v14 or higher)
2. **Newman** (Postman CLI runner)
3. **Python 3** (for test collection building)

### Installation

```bash
# Install Newman globally
npm install -g newman

# Optional: Install HTML reporter for better reports
npm install -g newman-reporter-html
```

### Verify Installation
```bash
newman --version
```

## 🚀 Quick Start

### 1. Basic Usage
Run all tests with default settings:
```bash
cd tests
./run-tests.sh
```

### 2. Custom API Server
Test against a different server:
```bash
./run-tests.sh -u http://your-server:8585
```

### 3. Verbose Output
Get detailed execution information:
```bash
./run-tests.sh -v
```

### 4. Custom Output Directory
Save results to a specific directory:
```bash
./run-tests.sh -o my-test-results
```

### 5. Help
View all available options:
```bash
./run-tests.sh -h
```

## 📊 Test Reports

After running tests, you'll get:

1. **Console Output**: Real-time test results
2. **HTML Report**: `test-results/test-report.html` - Visual report with charts
3. **JSON Report**: `test-results/test-results.json` - Machine-readable results

## 🔧 Configuration

### Environment Variables
The test suite uses these configuration values:

| Variable | Default | Description |
|----------|---------|-------------|
| `base_url` | `http://localhost:8585` | DNSniper API base URL (updated port) |
| `api_token` | `dnsniper_LnrnBmTRF2WFWlNx3L-07yYW7HKU9DwR_CIFFkFBbjA` | API authentication token (updated) |

### Customizing Settings
You can modify `dnsniper-environment.json` to change default values:

```json
{
    "id": "dnsniper-environment", 
    "name": "DNSniper API Environment",
    "values": [
        {
            "key": "base_url",
            "value": "https://your-production-server.com",
            "enabled": true
        },
        {
            "key": "api_token",
            "value": "dnsniper_your_production_api_token",
            "enabled": true
        }
    ]
}
```

## 📁 Files Structure

```
tests/
├── README.md                                    # This file
├── run-tests.sh                                 # Test runner script
├── build-test-collection.py                    # Test collection builder (new)
├── dnsniper-api-tests.postman_collection.json  # Main test collection (v2.0)
├── dnsniper-environment.json                   # Environment configuration (updated)
└── test-results/                               # Generated reports (after running)
    ├── test-report.html                        # HTML report
    └── test-results.json                       # JSON results
```

## 🧪 Test Scenarios

### 1. Smoke Tests
Basic connectivity and authentication:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    --folder "🔐 Authentication,🏥 Health & System"
```

### 2. Core Functionality Tests
Essential API functionality:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    --folder "🌐 Domain Management,🔢 IP Management"
```

### 3. Settings and Configuration Tests
System configuration functionality:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    --folder "⚙️ Settings Management"
```

### 4. Advanced Features Tests
Auto-update and logging functionality:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    --folder "🔄 Auto-Update Sources,📝 Logging System"
```

## 🔍 New Features in v2.0

### **Enhanced Authentication Testing**
- All endpoints now require authentication
- Session token and API token testing
- User profile validation

### **Pagination Support**
- Domain lists use pagination
- IP lists use pagination
- Proper pagination structure validation

### **Domain Name in IP Lists**
- IPs now display associated domain names
- No longer just showing domain IDs
- Better user experience validation

### **Updated Default Values**
- Rule expiration minimum: 10 minutes (600 seconds)
- Max IPs per domain: 10 (increased from 5)
- Updated port: 8585 (from 8000)

### **Live Events Integration**
- WebSocket authentication testing
- Real-time event validation
- Live system monitoring

## 🔍 Troubleshooting

### Common Issues

#### 1. Authentication Errors
```bash
Error: API token validation failed (HTTP 401)
```
**Solutions**:
- Verify the API token is correct: `dnsniper_LnrnBmTRF2WFWlNx3L-07yYW7HKU9DwR_CIFFkFBbjA`
- Check token hasn't expired
- Ensure token has proper permissions
- Generate new token from DNSniper panel

#### 2. Port Connection Issues
```bash
Error: API is not accessible at http://localhost:8585
```
**Solutions**:
- Ensure DNSniper is running on port 8585 (not 8000)
- Check the correct port in configuration
- Verify firewall settings
- Use correct URL with `-u` flag

#### 3. Health Endpoint Requires Authentication
```bash
Error: Health endpoint returns 401 Unauthorized
```
**This is expected behavior** in v2.0:
- Health endpoint now requires authentication
- This is a security improvement
- Tests are designed to handle this correctly

### Debug Mode
Run with verbose output for detailed debugging:
```bash
./run-tests.sh -v
```

### Manual Testing
Test individual endpoints manually:
```bash
# Test health endpoint (now requires auth)
curl -H "Authorization: Bearer dnsniper_LnrnBmTRF2WFWlNx3L-07yYW7HKU9DwR_CIFFkFBbjA" \
     http://localhost:8585/api/health

# Test authenticated endpoint
curl -H "Authorization: Bearer dnsniper_LnrnBmTRF2WFWlNx3L-07yYW7HKU9DwR_CIFFkFBbjA" \
     http://localhost:8585/api/dashboard
```

## 🔒 Security Considerations

### API Token Security
- **Never commit real production tokens** to version control
- Use environment variables for sensitive tokens
- Rotate tokens regularly
- Use separate tokens for testing and production

### Enhanced Security Model
- **All endpoints now require authentication**
- WebSocket connections use authenticated channels
- Health endpoint returns sensitive statistics (requires auth)
- No public access to any operational endpoints

### Test Data
- Tests create temporary test data (domains, IPs, etc.)
- All test data is automatically cleaned up
- Test data uses reserved/example ranges (203.0.113.x, example.com)
- No impact on production firewall rules

## 📈 Performance Testing

For performance testing, you can run with iterations:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    -n 10 \
    --delay-request 1000
```

## 🔄 Rebuilding Test Collection

If you need to modify the test collection:

```bash
# Edit the test collection builder
nano build-test-collection.py

# Rebuild the collection
python3 build-test-collection.py

# Run the updated tests
./run-tests.sh
```

## 🆕 What's New in v2.0

1. **🔐 Full Authentication Coverage** - All endpoints require auth
2. **📄 Pagination Support** - Modern API pagination testing
3. **🏷️ Domain Names in IP Lists** - Better data display validation
4. **⏱️ 10-Minute Rule Expiration** - Updated minimum validation
5. **🔢 10 IPs per Domain** - Updated default limit testing
6. **🔌 Live Events Testing** - WebSocket authentication validation
7. **🌐 Port 8585** - Updated default port configuration
8. **📝 Enhanced Metadata** - Notes and expiration tracking
9. **🎯 Categorized Tests** - Organized by functionality with emojis
10. **🛡️ Security Hardening** - No public endpoints except docs/login

## 🤝 Contributing

### Adding New Tests
1. Edit `build-test-collection.py`
2. Add new test functions or modify existing ones
3. Run `python3 build-test-collection.py` to rebuild
4. Test your changes locally
5. Update this README if needed

### Test Best Practices
- Use descriptive test names with emojis for categorization
- Include both positive and negative test cases
- Clean up any test data created
- Use proper assertions for response structure and data
- Test authentication on all endpoints
- Validate pagination where applicable

## 📞 Support

If you encounter issues:
1. Check this README for solutions
2. Verify your DNSniper installation is v2.0+
3. Ensure all endpoints require authentication
4. Test manually with the provided API token
5. Check DNSniper logs for detailed error information
6. Open an issue with test output

## 📄 License

This test suite is part of the DNSniper project and follows the same license terms. 