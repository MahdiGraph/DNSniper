#!/usr/bin/env python3
"""
Version configuration for DNSniper
Centralized version management for consistent versioning across the application
"""

import json
from pathlib import Path

def get_version_info():
    """Get version information from the centralized version.json file"""
    try:
        # Look for version.json in the frontend directory (sibling to backend)
        version_file = Path(__file__).parent.parent / "frontend" / "version.json"
        
        if version_file.exists():
            with open(version_file, 'r') as f:
                return json.load(f)
        else:
            # Fallback if version file doesn't exist
            return {
                "version": "1.0.0",
                "name": "DNSniper",
                "description": "Advanced Firewall Management Application",
                "github": "https://github.com/MahdiGraph/DNSniper",
                "license": "MIT"
            }
    except Exception:
        # Fallback if any error occurs
        return {
            "version": "1.0.0",
            "name": "DNSniper",
            "description": "Advanced Firewall Management Application", 
            "github": "https://github.com/MahdiGraph/DNSniper",
            "license": "MIT"
        }

def get_version():
    """Get just the version string"""
    return get_version_info()["version"]

def get_name():
    """Get the application name"""
    return get_version_info()["name"]

def get_github_url():
    """Get the GitHub URL"""
    return get_version_info()["github"]

# For easy importing
VERSION_INFO = get_version_info()
VERSION = VERSION_INFO["version"]
APP_NAME = VERSION_INFO["name"]
GITHUB_URL = VERSION_INFO["github"] 