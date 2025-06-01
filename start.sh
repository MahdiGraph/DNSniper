#!/bin/bash

# DNSniper Development Start Script

set -e

# Always run from project root
cd "$(dirname "$0")"

# Check Python requirements
if [ ! -f "backend/requirements.txt" ]; then
    echo "❌ Error: Backend requirements.txt not found"
    exit 1
fi

# Install Python dependencies if needed
if [ ! -d "venv" ]; then
    echo "🔧 Creating Python virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r backend/requirements.txt

# Build frontend if needed
cd frontend
if [ ! -d "build" ]; then
    echo "⚠️  Frontend not built. Building now..."
    if command -v npm &> /dev/null; then
        npm install
        npm run build
        echo "✅ Frontend built successfully"
    else
        echo "⚠️  npm not found. Frontend will not be available."
        echo "   Install Node.js and run 'npm install && npm run build' in frontend/"
    fi
else
    echo "✅ Frontend build found"
fi
cd ..

# Start backend from backend directory
cd backend

echo "🚀 Starting DNSniper backend..."

# Check for SSL configuration in database
SSL_CONFIG=$(python3 -c "
import sqlite3
import json
import os
import sys

db_path = 'dnsniper.db'
if not os.path.exists(db_path):
    print(json.dumps({'ssl_enabled': False}))
    sys.exit(0)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get SSL settings
    settings = {}
    cursor.execute('SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?, ?)', 
                   ('enable_ssl', 'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'))
    
    for row in cursor.fetchall():
        key, value = row
        # Parse boolean values
        if value.lower() == 'true':
            settings[key] = True
        elif value.lower() == 'false':
            settings[key] = False
        else:
            settings[key] = value.strip()
    
    conn.close()
    
    # Check if SSL is properly configured
    enable_ssl = settings.get('enable_ssl', False)
    force_https = settings.get('force_https', False)
    ssl_domain = settings.get('ssl_domain', '')
    ssl_certfile = settings.get('ssl_certfile', '')
    ssl_keyfile = settings.get('ssl_keyfile', '')
    
    # SSL is enabled if either enable_ssl or force_https is true AND all files exist
    ssl_enabled = ((enable_ssl or force_https) and ssl_domain and ssl_certfile and ssl_keyfile and 
                   os.path.isfile(ssl_certfile) and os.path.isfile(ssl_keyfile))
    
    print(json.dumps({
        'ssl_enabled': ssl_enabled,
        'enable_ssl': enable_ssl,
        'force_https': force_https,
        'ssl_domain': ssl_domain,
        'ssl_certfile': ssl_certfile,
        'ssl_keyfile': ssl_keyfile
    }))
    
except Exception as e:
    print(json.dumps({'ssl_enabled': False, 'error': str(e)}))
")

# Parse SSL configuration
SSL_ENABLED=$(echo $SSL_CONFIG | python3 -c "import sys, json; print(json.load(sys.stdin).get('ssl_enabled', False))")
ENABLE_SSL=$(echo $SSL_CONFIG | python3 -c "import sys, json; print(json.load(sys.stdin).get('enable_ssl', False))")
FORCE_HTTPS=$(echo $SSL_CONFIG | python3 -c "import sys, json; print(json.load(sys.stdin).get('force_https', False))")
SSL_DOMAIN=$(echo $SSL_CONFIG | python3 -c "import sys, json; print(json.load(sys.stdin).get('ssl_domain', ''))")
SSL_CERTFILE=$(echo $SSL_CONFIG | python3 -c "import sys, json; print(json.load(sys.stdin).get('ssl_certfile', ''))")
SSL_KEYFILE=$(echo $SSL_CONFIG | python3 -c "import sys, json; print(json.load(sys.stdin).get('ssl_keyfile', ''))")

echo ""
echo "📊 Access the application at:"
if [ "$SSL_ENABLED" = "True" ]; then
    echo "   🔒 Web Interface: https://$SSL_DOMAIN"
    echo "   🔒 API Docs: https://$SSL_DOMAIN/docs"
    echo "   ✅ SSL/HTTPS Enabled (enable_ssl: $ENABLE_SSL, force_https: $FORCE_HTTPS)"
else
    echo "   🌐 Web Interface: http://localhost:8000"
    echo "   📖 API Docs: http://localhost:8000/docs"
    if [ "$ENABLE_SSL" = "True" ] || [ "$FORCE_HTTPS" = "True" ]; then
        echo "   ⚠️  SSL configured but incomplete (missing files or domain)"
    else
        echo "   ⚠️  SSL/HTTPS Disabled"
    fi
fi
echo ""
echo "🛑 Press Ctrl+C to stop"
echo ""

if ! sudo -n true 2>/dev/null; then
    echo "⚠️  Note: Firewall management requires sudo privileges"
    echo "   Some features may not work without proper permissions"
    echo ""
fi

# Start uvicorn with or without SSL
if [ "$SSL_ENABLED" = "True" ]; then
    echo "🔒 Starting with SSL configuration..."
    exec uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile "$SSL_KEYFILE" --ssl-certfile "$SSL_CERTFILE"
else
    echo "🌐 Starting without SSL (HTTP only)..."
    exec uvicorn main:app --host 0.0.0.0 --port 8000 
fi 