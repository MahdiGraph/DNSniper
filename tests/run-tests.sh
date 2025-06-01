#!/bin/bash

# DNSniper API Test Runner
# This script runs comprehensive tests for the DNSniper API using Newman

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
BASE_URL="http://localhost:8000"
API_TOKEN="dnsniper_-zX1Y51b0nzWKrq4ZvW1k1hi1Eqmd3d0nM8k9bDTrrk"
OUTPUT_DIR="test-results"
VERBOSE=false

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Newman is installed
check_newman() {
    if ! command -v newman &> /dev/null; then
        print_error "Newman is not installed. Please install it with: npm install -g newman"
        exit 1
    fi
    print_success "Newman is installed: $(newman --version)"
}

# Function to check if API is accessible
check_api() {
    print_info "Checking if DNSniper API is accessible at $BASE_URL..."
    
    # Test health endpoint without authentication
    if curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" | grep -q "200"; then
        print_success "API is accessible"
    else
        print_error "API is not accessible at $BASE_URL. Please make sure DNSniper is running."
        exit 1
    fi
}

# Function to validate API token
validate_token() {
    print_info "Validating API token..."
    
    # Test an authenticated endpoint
    response_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $API_TOKEN" \
        "$BASE_URL/api/dashboard")
    
    if [ "$response_code" = "200" ]; then
        print_success "API token is valid"
    else
        print_error "API token validation failed (HTTP $response_code). Please check your token."
        exit 1
    fi
}

# Function to create output directory
create_output_dir() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        print_info "Created output directory: $OUTPUT_DIR"
    fi
}

# Function to run tests
run_tests() {
    print_info "Running DNSniper API tests..."
    
    local newman_options=""
    if [ "$VERBOSE" = true ]; then
        newman_options="--verbose"
    fi
    
    # Update environment file with current values
    cat > dnsniper-environment.json << EOF
{
    "id": "dnsniper-environment",
    "name": "DNSniper API Environment",
    "values": [
        {
            "key": "base_url",
            "value": "$BASE_URL",
            "enabled": true
        },
        {
            "key": "api_token",
            "value": "$API_TOKEN",
            "enabled": true
        }
    ],
    "_postman_variable_scope": "environment"
}
EOF
    
    # Run Newman tests
    if newman run dnsniper-api-tests.postman_collection.json \
        -e dnsniper-environment.json \
        --reporters cli,html,json \
        --reporter-html-export "$OUTPUT_DIR/test-report.html" \
        --reporter-json-export "$OUTPUT_DIR/test-results.json" \
        --timeout-request 30000 \
        --delay-request 500 \
        $newman_options; then
        
        print_success "All tests completed successfully!"
        print_info "Test report available at: $OUTPUT_DIR/test-report.html"
        print_info "JSON results available at: $OUTPUT_DIR/test-results.json"
        return 0
    else
        print_error "Some tests failed. Check the report for details."
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -u, --url URL        Base URL for the API (default: $BASE_URL)"
    echo "  -t, --token TOKEN    API token for authentication"
    echo "  -o, --output DIR     Output directory for reports (default: $OUTPUT_DIR)"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run with default settings"
    echo "  $0 -u http://your-server:8000        # Run against different server"
    echo "  $0 -v                                # Run with verbose output"
    echo "  $0 -o custom-results                 # Save results to custom directory"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            BASE_URL="$2"
            shift 2
            ;;
        -t|--token)
            API_TOKEN="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_info "DNSniper API Test Runner"
    print_info "========================"
    print_info "Base URL: $BASE_URL"
    print_info "Output Directory: $OUTPUT_DIR"
    
    # Check prerequisites
    check_newman
    check_api
    validate_token
    create_output_dir
    
    # Run the tests
    if run_tests; then
        print_success "Test execution completed successfully!"
        exit 0
    else
        print_error "Test execution failed!"
        exit 1
    fi
}

# Run main function
main "$@" 