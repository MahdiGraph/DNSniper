#!/bin/bash

# Sync version.json to src/ directory and update package.json within frontend
# This ensures the React app and package.json always have the latest version information

echo "🔄 Syncing version information..."

# Check if version.json exists in current directory (frontend)
if [ ! -f "version.json" ]; then
    echo "❌ Error: version.json not found in frontend directory"
    exit 1
fi

# Check if src directory exists
if [ ! -d "src" ]; then
    echo "❌ Error: src directory not found"
    exit 1
fi

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found in frontend directory"
    exit 1
fi

# Extract version from version.json
VERSION=$(grep '"version"' version.json | sed 's/.*"version": *"\([^"]*\)".*/\1/')

if [ -z "$VERSION" ]; then
    echo "❌ Error: Could not extract version from version.json"
    exit 1
fi

# Extract current version from package.json
PACKAGE_VERSION=$(grep '"version"' package.json | sed 's/.*"version": *"\([^"]*\)".*/\1/')

echo "📝 Detected version.json version: $VERSION"
echo "📝 Current package.json version: $PACKAGE_VERSION"

# Copy version.json to src/
echo "🔄 Syncing version.json to src directory..."
cp version.json src/version.json

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to sync version.json to src/"
    exit 1
fi

echo "✅ Successfully synced version.json to src/"

# Update package.json version only if different
if [ "$VERSION" != "$PACKAGE_VERSION" ]; then
    echo "🔄 Updating package.json version from $PACKAGE_VERSION to $VERSION..."
    npm version "$VERSION" --no-git-tag-version --silent
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully updated package.json to version $VERSION"
    else
        echo "❌ Error: Failed to update package.json version"
        exit 1
    fi
else
    echo "✅ Package.json version already matches ($VERSION)"
fi

echo "🎯 All version information synced and ready for npm run build" 