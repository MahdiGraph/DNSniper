from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from pydantic import BaseModel, validator
import os
import logging
import json
import asyncio

from database import get_db
from models import Setting
from services.firewall_service import FirewallService

router = APIRouter()
logger = logging.getLogger(__name__)

class SettingUpdate(BaseModel):
    value: str | int | float | bool | list

    @validator('value')
    def validate_value(cls, v, values):
        return v

class BulkSettingsUpdate(BaseModel):
    settings: Dict[str, str | int | float | bool | list]

def validate_setting_value(key: str, value):
    """Validate setting values according to constraints"""
    
    # Numeric validation rules
    numeric_constraints = {
        'auto_update_interval': {'min': 300, 'max': 86400},
        'rule_expiration': {'min': 3600, 'max': 604800},
        'max_ips_per_domain': {'min': 1, 'max': 50},
        'rate_limit_delay': {'min': 0.1, 'max': 10.0},
        'log_retention_days': {'min': 1, 'max': 365},
        'max_log_entries': {'min': 1000, 'max': 100000}
    }
    
    if key in numeric_constraints:
        if not isinstance(value, (int, float)):
            raise ValueError(f"Value for {key} must be a number")
        
        constraints = numeric_constraints[key]
        if value < constraints['min'] or value > constraints['max']:
            raise ValueError(
                f"Value for {key} must be between {constraints['min']} and {constraints['max']}"
            )
    
    # DNS resolver validation
    if key in ['dns_resolver_primary', 'dns_resolver_secondary']:
        import re
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if not isinstance(value, str) or not re.match(ipv4_pattern, value):
            raise ValueError(f"{key.replace('_', ' ').title()} must be a valid IPv4 address string")
    
    # Boolean validation
    boolean_settings = ['logging_enabled', 'manual_domain_resolution', 'auto_update_enabled']
    if key in boolean_settings and not isinstance(value, bool):
        raise ValueError(f"Value for {key} must be a boolean")
    
    # SSL settings validation
    if key == 'force_https':
        if not isinstance(value, bool):
            raise ValueError(f"{key.replace('_', ' ').title()} must be a boolean")
    
    if key in ['ssl_domain', 'ssl_certfile', 'ssl_keyfile']:
        if not isinstance(value, str):
            raise ValueError(f"{key.replace('_', ' ').title()} must be a string")
    
    # SSL file validation
    if key == 'ssl_certfile' and value:
        if not os.path.isfile(value):
            raise ValueError(f"SSL certificate file does not exist: {value}")
        if not value.endswith(('.pem', '.crt', '.cert')):
            raise ValueError("SSL certificate file must be a .pem, .crt, or .cert file")
    
    if key == 'ssl_keyfile' and value:
        if not os.path.isfile(value):
            raise ValueError(f"SSL private key file does not exist: {value}")
        if not value.endswith(('.pem', '.key')):
            raise ValueError("SSL private key file must be a .pem or .key file")
    
    return True

def validate_ssl_configuration(db: Session, new_settings: dict = None):
    """Validate SSL configuration when SSL is enabled."""
    current_settings = Setting.get_all_settings(db)
    if new_settings:
        current_settings.update(new_settings)
    
    enable_ssl = current_settings.get('enable_ssl', False)
    force_https = current_settings.get('force_https', False)
    ssl_domain = current_settings.get('ssl_domain', '').strip()
    ssl_certfile = current_settings.get('ssl_certfile', '').strip()
    ssl_keyfile = current_settings.get('ssl_keyfile', '').strip()

    # Only validate if SSL is enabled OR if force_https is enabled
    if enable_ssl or force_https:
        # If either is enabled, all SSL fields must be present and valid
        if not ssl_domain:
            raise ValueError("SSL domain name is required when SSL is enabled.")
        if not ssl_certfile:
            raise ValueError("SSL certificate file path is required when SSL is enabled.")
        if not ssl_keyfile:
            raise ValueError("SSL private key file path is required when SSL is enabled.")
        
        # Validate domain format
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, ssl_domain):
            raise ValueError("SSL domain name must be a valid domain format")
        
        # Validate certificate and key files exist
        if not os.path.isfile(ssl_certfile):
            raise ValueError(f"SSL certificate file does not exist: {ssl_certfile}")
        if not os.path.isfile(ssl_keyfile):
            raise ValueError(f"SSL private key file does not exist: {ssl_keyfile}")
        
        # Try to validate certificate/key pair
        try:
            import ssl
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(ssl_certfile, ssl_keyfile)
        except Exception as e:
            raise ValueError(f"Invalid SSL certificate/key pair: {str(e)}")
    
    return True

@router.get("/")
async def get_all_settings(db: Session = Depends(get_db)):
    """Get all application settings"""
    settings = Setting.get_all_settings(db)
    # Ensure both fields are present for the frontend
    if "dns_resolver_primary" not in settings:
        settings["dns_resolver_primary"] = "1.1.1.1"
    if "dns_resolver_secondary" not in settings:
        settings["dns_resolver_secondary"] = "8.8.8.8"
    # Remove legacy fields if present
    for legacy in ["dns_resolvers", "dns_resolver_ipv4", "dns_resolver_ipv6"]:
        if legacy in settings:
            del settings[legacy]
    return settings

@router.put("/ssl")
async def update_ssl_settings(
    ssl_update: dict,
    db: Session = Depends(get_db)
):
    """Update SSL settings. Restart if enable_ssl or force_https changes."""
    ssl_keys = {'enable_ssl', 'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'}
    current_settings = Setting.get_all_settings(db)
    
    changed = False
    updated_settings = {}
    validation_errors = {}
    
    # Track critical settings that require restart
    prev_enable_ssl = current_settings.get('enable_ssl', False)
    prev_force_https = current_settings.get('force_https', False)
    new_enable_ssl = ssl_update.get('enable_ssl', prev_enable_ssl)
    new_force_https = ssl_update.get('force_https', prev_force_https)
    
    # Update settings
    for key in ssl_keys:
        if key in ssl_update and ssl_update[key] != current_settings.get(key):
            try:
                validate_setting_value(key, ssl_update[key])
                Setting.set_setting(db, key, ssl_update[key])
                updated_settings[key] = ssl_update[key]
                changed = True
            except ValueError as e:
                validation_errors[key] = str(e)
    
    if validation_errors:
        raise HTTPException(status_code=400, detail={"message": "Validation failed", "errors": validation_errors})
    
    # Validate complete SSL configuration if any SSL is enabled
    if changed:
        try:
            validate_ssl_configuration(db, ssl_update)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        # Check if restart is needed (SSL enable/disable or force_https change)
        restart_required = (
            prev_enable_ssl != new_enable_ssl or 
            prev_force_https != new_force_https or
            (new_enable_ssl and any(key in ssl_update for key in ['ssl_domain', 'ssl_certfile', 'ssl_keyfile']))
        )
        
        if restart_required:
            logger.info("SSL configuration changed, server restart will be triggered")
            asyncio.create_task(restart_server_with_ssl(db))
            return {
                "message": "SSL settings updated", 
                "ssl_restart_required": True, 
                "updated_settings": updated_settings
            }
    
    return {
        "message": "SSL settings updated", 
        "ssl_restart_required": False, 
        "updated_settings": updated_settings
    }

@router.put("/bulk")
async def update_settings_bulk(
    settings_update: BulkSettingsUpdate,
    db: Session = Depends(get_db)
):
    """Update multiple settings at once (excluding SSL settings)"""
    try:
        updated_settings = {}
        validation_errors = {}
        # Only update non-SSL settings
        ssl_keys = {'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'}
        for key, value in settings_update.settings.items():
            if key in ssl_keys:
                continue
            try:
                validate_setting_value(key, value)
                Setting.set_setting(db, key, value)
                updated_settings[key] = value
                logger.info(f"Setting {key} updated to: {value}")
            except ValueError as e:
                validation_errors[key] = str(e)
        if validation_errors:
            raise HTTPException(
                status_code=400,
                detail={"message": "Validation failed", "errors": validation_errors}
            )
        return {
            "message": f"Successfully updated {len(updated_settings)} settings",
            "updated_settings": updated_settings
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")

@router.get("/{key}")
async def get_setting(key: str, db: Session = Depends(get_db)):
    """Get a specific setting by key"""
    setting = db.query(Setting).filter(Setting.key == key).first()
    if not setting:
        raise HTTPException(status_code=404, detail="Setting not found")
    
    return {
        "key": setting.key,
        "value": setting.get_value(),
        "description": setting.description
    }

@router.put("/{key}")
async def update_setting(
    key: str,
    setting_update: SettingUpdate,
    db: Session = Depends(get_db)
):
    """Update a specific setting"""
    try:
        # Validate the setting value
        validate_setting_value(key, setting_update.value)
        
        # Check if this is an SSL setting
        ssl_keys = {'force_https', 'ssl_domain', 'ssl_certfile', 'ssl_keyfile'}
        is_ssl_setting = key in ssl_keys
        
        # If updating SSL setting, validate complete SSL configuration
        if is_ssl_setting:
            validate_ssl_configuration(db, {key: setting_update.value})
        
        # Update the setting
        Setting.set_setting(db, key, setting_update.value)
        
        # Log the action
        logger.info(f"Setting {key} updated to: {setting_update.value}")
        
        response_data = {
            "message": f"Setting {key} updated successfully", 
            "value": setting_update.value
        }
        
        # If SSL setting changed, trigger server restart
        if is_ssl_setting:
            response_data["ssl_restart_required"] = True
            logger.info("SSL setting changed, server restart will be triggered")
            
            # Import and trigger server restart asynchronously
            asyncio.create_task(restart_server_with_ssl(db))
        
        return response_data
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update setting {key}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update setting: {str(e)}")

@router.post("/firewall/clear")
async def clear_firewall_rules(db: Session = Depends(get_db)):
    """Clear all DNSniper firewall rules"""
    try:
        firewall = FirewallService()
        firewall.clear_all_rules()
        return {"message": "All firewall rules cleared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear firewall rules: {str(e)}")

@router.post("/firewall/rebuild")
async def rebuild_firewall_rules(db: Session = Depends(get_db)):
    """Rebuild firewall rules from database"""
    try:
        firewall = FirewallService()
        firewall.rebuild_rules_from_database(db)
        return {"message": "Firewall rules rebuilt successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rebuild firewall rules: {str(e)}")

@router.get("/firewall/status")
async def get_firewall_status():
    """Get firewall status"""
    try:
        firewall = FirewallService()
        status = firewall.get_status()
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get firewall status: {str(e)}")

@router.get("/ssl/status")
async def get_ssl_status(db: Session = Depends(get_db)):
    """Get SSL configuration status and validation"""
    try:
        settings = Setting.get_all_settings(db)
        enable_ssl = settings.get('enable_ssl', False)
        force_https = settings.get('force_https', False)
        ssl_domain = settings.get('ssl_domain', '').strip()
        ssl_certfile = settings.get('ssl_certfile', '').strip()
        ssl_keyfile = settings.get('ssl_keyfile', '').strip()
        
        status = {
            "enable_ssl": enable_ssl,
            "force_https": force_https,
            "ssl_domain": ssl_domain,
            "ssl_certfile": ssl_certfile,
            "ssl_keyfile": ssl_keyfile,
            "configuration_complete": bool(ssl_domain and ssl_certfile and ssl_keyfile),
            "files_exist": {
                "certfile": bool(ssl_certfile and os.path.isfile(ssl_certfile)),
                "keyfile": bool(ssl_keyfile and os.path.isfile(ssl_keyfile))
            },
            "ssl_enabled": False,
            "validation_errors": [],
            "warnings": []
        }
        
        # Warn if any SSL field is filled but not all are present
        ssl_fields = [ssl_domain, ssl_certfile, ssl_keyfile]
        if any(ssl_fields) and not all(ssl_fields):
            status["warnings"].append("All SSL fields (domain, cert, key) are required for SSL to work.")
        
        # Validate SSL configuration if SSL is enabled
        if enable_ssl or force_https:
            try:
                validate_ssl_configuration(db)
                status["ssl_enabled"] = True
                status["status"] = "SSL properly configured and enabled"
            except ValueError as e:
                status["validation_errors"].append(str(e))
                status["status"] = f"SSL configuration error: {str(e)}"
        else:
            status["status"] = "SSL disabled"
        
        # Additional file validation details
        if ssl_certfile:
            if os.path.isfile(ssl_certfile):
                try:
                    with open(ssl_certfile, 'r') as f:
                        cert_data = f.read()
                    if 'BEGIN CERTIFICATE' in cert_data:
                        status["certfile_info"] = {"valid_format": True, "readable": True}
                    else:
                        status["certfile_info"] = {"valid_format": False, "readable": True}
                        status["validation_errors"].append("Certificate file does not appear to be in PEM format")
                except Exception as e:
                    status["certfile_info"] = {"valid_format": False, "readable": False, "error": str(e)}
                    status["validation_errors"].append(f"Certificate file read error: {str(e)}")
            else:
                status["validation_errors"].append(f"Certificate file not found: {ssl_certfile}")
        
        return status
    except Exception as e:
        logger.error(f"Failed to get SSL status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get SSL status: {str(e)}")

async def restart_server_with_ssl(db: Session):
    """Log and exit the process to allow external service manager to restart the server with new SSL config."""
    try:
        import os
        import logging
        logger.info("Web server is being reset due to SSL configuration change. Please ensure a process manager restarts the service.")
        print("[DNSniper] Web server is being reset due to SSL configuration change. Please ensure a process manager restarts the service.")
        await asyncio.sleep(2)
        os._exit(0)
    except Exception as e:
        logger.error(f"Failed to exit for SSL restart: {e}") 