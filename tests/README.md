# DNSniper API Test Suite

This directory contains comprehensive automated tests for the DNSniper API using Newman (Postman CLI runner). The test suite covers all major API endpoints and features.

## 📋 Test Coverage

The test suite includes:

### ✅ Core Functionality
- **Health Check**: System health and database connectivity
- **Dashboard**: Statistics and overview data
- **Authentication**: API token validation

### ✅ Domain Management
- Create, read, update, delete manual domains
- Domain filtering and searching
- Domain IP resolution
- Validation of domain data structures

### ✅ IP Management
- Create, read, delete manual IPs
- IP validation (IPv4/IPv6)
- IP filtering by source type and list type
- Data structure validation

### ✅ IP Range Management
- Create, read, delete IP ranges
- CIDR notation validation
- Filtering capabilities

### ✅ Auto-Update Sources
- CRUD operations for auto-update sources
- Source testing and validation
- Status monitoring
- Statistics reporting

### ✅ Settings Management
- System settings retrieval
- Firewall status monitoring
- SSL configuration status

### ✅ Logging System
- Log retrieval with filtering
- Log statistics
- Search functionality
- Recent logs monitoring

### ✅ Error Handling
- Invalid input validation
- Authentication error handling
- Proper HTTP status codes

### ✅ Data Integrity
- CRUD operations validation
- Cleanup of test data
- Referential integrity checks

## 🛠️ Prerequisites

### Required Software
1. **Node.js** (v14 or higher)
2. **Newman** (Postman CLI runner)
3. **curl** (for connectivity testing)

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
./run-tests.sh -u http://your-server:8000
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
| `base_url` | `http://localhost:8000` | DNSniper API base URL |
| `api_token` | `dnsniper_-zX1Y51b0nzWKrq4ZvW1k1hi1Eqmd3d0nM8k9bDTrrk` | API authentication token |

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
            "value": "your_production_api_token",
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
├── dnsniper-api-tests.postman_collection.json  # Main test collection
├── dnsniper-environment.json                   # Environment configuration
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
    --folder "Health Check,Dashboard Stats,Get All Settings"
```

### 2. Domain Management Tests
Focus on domain-related functionality:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    --folder "Get All Domains,Create Test Domain,Update Test Domain"
```

### 3. Error Handling Tests
Test validation and error responses:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    --folder "Test Invalid Domain Creation,Test Invalid IP Creation"
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Newman Not Found
```bash
Error: newman: command not found
```
**Solution**: Install Newman globally
```bash
npm install -g newman
```

#### 2. API Not Accessible
```bash
Error: API is not accessible at http://localhost:8000
```
**Solutions**:
- Ensure DNSniper is running
- Check the correct port
- Verify firewall settings
- Use correct URL with `-u` flag

#### 3. Authentication Failed
```bash
Error: API token validation failed (HTTP 401)
```
**Solutions**:
- Verify API token is correct
- Check token hasn't expired
- Ensure token has proper permissions
- Generate new token from DNSniper panel

#### 4. Connection Timeout
```bash
Error: timeout of 30000ms exceeded
```
**Solutions**:
- Check network connectivity
- Increase timeout with `--timeout-request 60000`
- Verify server performance

### Debug Mode
Run with verbose output for detailed debugging:
```bash
./run-tests.sh -v
```

### Manual Testing
Test individual endpoints manually:
```bash
# Test health endpoint
curl http://localhost:8000/api/health

# Test authenticated endpoint
curl -H "Authorization: Bearer dnsniper_-zX1Y51b0nzWKrq4ZvW1k1hi1Eqmd3d0nM8k9bDTrrk" \
     http://localhost:8000/api/dashboard
```

## 🔒 Security Considerations

### API Token Security
- **Never commit real production tokens** to version control
- Use environment variables for sensitive tokens
- Rotate tokens regularly
- Use separate tokens for testing and production

### Test Data
- Tests create temporary test data (domains, IPs, etc.)
- All test data is automatically cleaned up
- Test data uses reserved/example ranges (192.0.2.x, example.com)
- No impact on production firewall rules

## 📈 Performance Testing

For performance testing, you can run with iterations:
```bash
newman run dnsniper-api-tests.postman_collection.json \
    -e dnsniper-environment.json \
    -n 10 \
    --delay-request 1000
```

## 🤝 Contributing

### Adding New Tests
1. Import `dnsniper-api-tests.postman_collection.json` into Postman
2. Add new requests with proper tests
3. Export the updated collection
4. Update this README if needed

### Test Best Practices
- Use descriptive test names
- Include both positive and negative test cases
- Clean up any test data created
- Use proper assertions
- Test response structure and data

### Pull Request Guidelines
- Test your changes locally
- Include test coverage for new endpoints
- Update documentation as needed
- Ensure all existing tests still pass

## 📞 Support

If you encounter issues:
1. Check this README for solutions
2. Verify your DNSniper installation
3. Test manually with curl
4. Check DNSniper logs
5. Open an issue with test output

## 📄 License

This test suite is part of the DNSniper project and follows the same license terms. 