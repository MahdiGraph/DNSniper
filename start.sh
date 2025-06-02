#!/bin/bash

# DNSniper Start Script

set -e

# Always run from project root
cd "$(dirname "$0")"

# Create Python virtual environment if needed
if [ ! -d "venv" ]; then
    echo "🔧 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment and install dependencies
source venv/bin/activate
pip install -q -r backend/requirements.txt

# Start the application
echo "🚀 Starting DNSniper..."
cd backend
exec python3 main.py 