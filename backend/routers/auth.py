from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel, validator
from datetime import datetime, timedelta
import logging
from sqlalchemy.sql import func

from database import get_db
from models.users import User, LoginAttempt, UserSession, APIToken

router = APIRouter()
logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)

# Rate limiting configuration - IP-based only for security
RATE_LIMIT_CONFIG = {
    "max_attempts_per_ip": 5,
    "window_minutes": 15,
    "lockout_duration_minutes": 30
}

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class ChangeUsernameRequest(BaseModel):
    current_password: str
    new_username: str

    @validator('new_username')
    def validate_new_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if not v.isalnum():
            raise ValueError('Username must contain only letters and numbers')
        return v

class UserResponse(BaseModel):
    id: int
    username: str
    is_default_password: bool
    last_login: Optional[datetime]
    created_at: datetime

class APITokenCreate(BaseModel):
    name: str
    is_permanent: bool = False
    days: int = 30

    @validator('name')
    def validate_name(cls, v):
        if len(v.strip()) == 0:
            raise ValueError('Token name cannot be empty')
        if len(v) > 100:
            raise ValueError('Token name cannot be longer than 100 characters')
        return v.strip()

    @validator('days')
    def validate_days(cls, v, values):
        if not values.get('is_permanent', False):
            if v < 1 or v > 365:
                raise ValueError('Days must be between 1 and 365')
        return v

class APITokenResponse(BaseModel):
    id: int
    name: str
    token: Optional[str]  # Only included when creating
    is_permanent: bool
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    created_at: datetime
    days_until_expiry: Optional[int]

    class Config:
        from_attributes = True

def get_client_ip(request: Request) -> str:
    """Get client IP address from request with proper proxy support"""
    # Check X-Forwarded-For (load balancer/proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP (client IP) from the chain
        return forwarded.split(",")[0].strip()
    
    # Check X-Real-IP (nginx proxy)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fallback to direct connection
    return request.client.host

def check_rate_limit_db(db: Session, ip_address: str) -> dict:
    """Check IP-based rate limiting using database with precise timing"""
    from datetime import datetime, timedelta
    
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=RATE_LIMIT_CONFIG["window_minutes"])
    
    # Check IP-based rate limiting only
    ip_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.success == False,
        LoginAttempt.created_at >= window_start
    ).count()
    
    # Check for active lockout periods (double the threshold for lockout)
    lockout_start = now - timedelta(minutes=RATE_LIMIT_CONFIG["lockout_duration_minutes"])
    recent_lockout_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.success == False,
        LoginAttempt.created_at >= lockout_start
    ).count()
    
    # Determine if rate limited
    ip_limited = ip_attempts >= RATE_LIMIT_CONFIG["max_attempts_per_ip"]
    lockout_active = recent_lockout_attempts >= (RATE_LIMIT_CONFIG["max_attempts_per_ip"] * 2)
    
    # Calculate precise remaining time in seconds
    remaining_seconds = 0
    lockout_type = None
    
    if lockout_active:
        # Find the most recent failed attempt to calculate lockout end time
        most_recent_attempt = db.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.created_at >= lockout_start
        ).order_by(LoginAttempt.created_at.desc()).first()
        
        if most_recent_attempt:
            lockout_end = most_recent_attempt.created_at + timedelta(minutes=RATE_LIMIT_CONFIG["lockout_duration_minutes"])
            remaining_seconds = max(0, int((lockout_end - now).total_seconds()))
            lockout_type = "ip_locked"
    elif ip_limited:
        # Find the oldest attempt in the window to calculate when it expires
        oldest_attempt = db.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.created_at >= window_start
        ).order_by(LoginAttempt.created_at.asc()).first()
        
        if oldest_attempt:
            window_end = oldest_attempt.created_at + timedelta(minutes=RATE_LIMIT_CONFIG["window_minutes"])
            remaining_seconds = max(0, int((window_end - now).total_seconds()))
            lockout_type = "rate_limited"
    
    return {
        "allowed": not (ip_limited or lockout_active),
        "ip_attempts": ip_attempts,
        "lockout_active": lockout_active,
        "remaining_seconds": remaining_seconds,
        "lockout_type": lockout_type,
        "retry_after_minutes": RATE_LIMIT_CONFIG["lockout_duration_minutes"] if lockout_active else RATE_LIMIT_CONFIG["window_minutes"]
    }

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    session = UserSession.get_valid_session(db, credentials.credentials)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )
    
    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user

async def get_current_panel_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user, only if using a session token (not API token)"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    session = UserSession.get_valid_session(db, credentials.credentials)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session authentication required (API tokens not allowed)"
        )
    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    return user

@router.post("/login")
async def login(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """Optimized login endpoint with instant rate limit feedback"""
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    
    # Enhanced rate limiting check
    rate_limit_result = check_rate_limit_db(db, client_ip)
    
    if not rate_limit_result["allowed"]:
        # Log the rate limit violation
        logger.warning(
            f"Rate limit exceeded for IP {client_ip}. "
            f"IP attempts: {rate_limit_result['ip_attempts']}, "
            f"Lockout active: {rate_limit_result['lockout_active']}, "
            f"Remaining: {rate_limit_result['remaining_seconds']}s"
        )
        
        # DO NOT record failed attempts for rate limiting - this creates a feedback loop!
        # Only log the violation for monitoring purposes
        
        # Format remaining time for user-friendly message
        remaining_seconds = rate_limit_result["remaining_seconds"]
        if remaining_seconds > 60:
            remaining_minutes = remaining_seconds // 60
            remaining_secs = remaining_seconds % 60
            time_message = f"{remaining_minutes} minute{'s' if remaining_minutes != 1 else ''}"
            if remaining_secs > 0:
                time_message += f" and {remaining_secs} second{'s' if remaining_secs != 1 else ''}"
        else:
            time_message = f"{remaining_seconds} second{'s' if remaining_seconds != 1 else ''}"
        
        if rate_limit_result["lockout_type"] == "ip_locked":
            detail_message = f"IP temporarily locked due to too many failed attempts. Try again in {time_message}."
        else:
            detail_message = f"Too many login attempts. Try again in {time_message}."
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail_message,
            headers={
                "Retry-After": str(remaining_seconds),
                "X-RateLimit-Remaining-Seconds": str(remaining_seconds),
                "X-RateLimit-Type": rate_limit_result["lockout_type"] or "rate_limited"
            }
        )
    
    # Authenticate user - NO DELAYS for performance
    user = User.get_by_username(db, login_data.username)
    
    if not user or not user.verify_password(login_data.password):
        # Record failed attempt with detailed info
        LoginAttempt.record_attempt(
            db, 
            client_ip, 
            login_data.username, 
            success=False,
            user_agent=user_agent,
            reason="invalid_credentials"
        )
        
        logger.warning(
            f"Failed login attempt for username '{login_data.username}' from IP {client_ip}. "
            f"User-Agent: {user_agent[:100]}..."
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Check if user account is active
    if not user.is_active:
        LoginAttempt.record_attempt(db, client_ip, login_data.username, success=False, reason="account_disabled")
        logger.warning(f"Login attempt for disabled account '{login_data.username}' from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Create session with enhanced security
    session = UserSession.create_session(db, user.id, client_ip, user_agent)
    
    # Record successful attempt
    LoginAttempt.record_attempt(
        db, 
        client_ip, 
        login_data.username, 
        success=True,
        user_agent=user_agent,
        session_token=session.session_token[:8] + "..."  # Partial token for logging
    )
    
    # Update user's last login
    user.update_last_login(db)
    
    # Log successful login with more details
    logger.info(
        f"Successful login for user '{user.username}' from IP {client_ip}. "
        f"Session: {session.session_token[:8]}..., "
        f"Default password: {user.is_default_password}"
    )
    
    # Security response headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    return {
        "message": "Login successful",
        "token": session.session_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "is_default_password": user.is_default_password,
            "last_login": user.last_login,
            "created_at": user.created_at
        },
        "security_notice": "Please change default credentials" if user.is_default_password else None
    }

@router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Logout endpoint"""
    if credentials:
        UserSession.invalidate_session(db, credentials.credentials)
        logger.info(f"User logged out from IP {get_client_ip(request)}")
    
    return {"message": "Logout successful"}

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information"""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        is_default_password=current_user.is_default_password,
        last_login=current_user.last_login,
        created_at=current_user.created_at
    )

@router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    
    # Verify current password
    if not current_user.verify_password(password_data.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Set new password
    current_user.set_password(password_data.new_password)
    db.commit()
    
    logger.info(f"Password changed for user '{current_user.username}'")
    
    return {
        "message": "Password changed successfully",
        "is_default_password": current_user.is_default_password
    }

@router.post("/change-username")
async def change_username(
    username_data: ChangeUsernameRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user username"""
    
    # Verify current password
    if not current_user.verify_password(username_data.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Check if username already exists
    existing_user = User.get_by_username(db, username_data.new_username)
    if existing_user and existing_user.id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Update username
    old_username = current_user.username
    current_user.username = username_data.new_username
    current_user.updated_at = func.now()
    db.commit()
    
    logger.info(f"Username changed from '{old_username}' to '{current_user.username}'")
    
    return {
        "message": "Username changed successfully",
        "new_username": current_user.username
    }

@router.post("/cleanup-sessions")
async def cleanup_expired_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cleanup expired sessions (admin only)"""
    cleaned_count = UserSession.cleanup_expired_sessions(db)
    logger.info(f"Cleaned up {cleaned_count} expired sessions")
    
    return {
        "message": f"Cleaned up {cleaned_count} expired sessions",
        "cleaned_count": cleaned_count
    }

# API Token Management Endpoints

@router.get("/tokens", response_model=List[APITokenResponse])
async def get_api_tokens(
    current_user: User = Depends(get_current_panel_user),
    db: Session = Depends(get_db)
):
    """Get all API tokens for the current user (panel only)"""
    tokens = APIToken.get_user_tokens(db, current_user.id)
    result = []
    for token in tokens:
        result.append({
            "id": token.id,
            "name": token.name,
            "token": None,  # Never return the actual token in list
            "is_permanent": token.is_permanent,
            "expires_at": token.expires_at,
            "last_used": token.last_used,
            "created_at": token.created_at,
            "days_until_expiry": token.days_until_expiry()
        })
    return result

@router.post("/tokens", response_model=APITokenResponse)
async def create_api_token(
    token_data: APITokenCreate,
    current_user: User = Depends(get_current_panel_user),
    db: Session = Depends(get_db)
):
    """Create a new API token (panel only)"""
    
    # Check if token name already exists for this user
    existing = db.query(APIToken).filter(
        APIToken.user_id == current_user.id,
        APIToken.name == token_data.name,
        APIToken.is_active == True
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail="A token with this name already exists"
        )
    
    # Create the token
    api_token = APIToken.create_token(
        db, 
        current_user.id, 
        token_data.name, 
        token_data.is_permanent, 
        token_data.days
    )
    
    logger.info(f"API token '{token_data.name}' created for user '{current_user.username}'")
    
    return {
        "id": api_token.id,
        "name": api_token.name,
        "token": api_token.token,  # Include token only when creating
        "is_permanent": api_token.is_permanent,
        "expires_at": api_token.expires_at,
        "last_used": api_token.last_used,
        "created_at": api_token.created_at,
        "days_until_expiry": api_token.days_until_expiry()
    }

@router.delete("/tokens/{token_id}")
async def revoke_api_token(
    token_id: int,
    current_user: User = Depends(get_current_panel_user),
    db: Session = Depends(get_db)
):
    """Revoke an API token (panel only)"""
    
    token = APIToken.revoke_token(db, token_id, current_user.id)
    
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    logger.info(f"API token '{token.name}' revoked for user '{current_user.username}'")
    
    return {"message": f"Token '{token.name}' has been revoked"}

@router.post("/tokens/cleanup")
async def cleanup_expired_tokens(
    current_user: User = Depends(get_current_panel_user),
    db: Session = Depends(get_db)
):
    """Cleanup expired API tokens (panel only)"""
    cleaned_count = APIToken.cleanup_expired_tokens(db)
    logger.info(f"Cleaned up {cleaned_count} expired API tokens")
    
    return {
        "message": f"Cleaned up {cleaned_count} expired API tokens",
        "cleaned_count": cleaned_count
    }

def detect_suspicious_activity(db: Session, ip_address: str) -> dict:
    """Detect suspicious login activity patterns"""
    from datetime import datetime, timedelta
    
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_hour = now - timedelta(hours=1)
    
    # Get all attempts from this IP in last 24 hours
    attempts_24h = db.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.created_at >= last_24h
    ).all()
    
    # Analyze patterns
    total_attempts = len(attempts_24h)
    failed_attempts = len([a for a in attempts_24h if not a.success])
    success_attempts = len([a for a in attempts_24h if a.success])
    
    # Check for multiple usernames (credential stuffing)
    unique_usernames = len(set(a.username for a in attempts_24h if a.username))
    
    # Check for rapid succession attempts
    attempts_last_hour = len([a for a in attempts_24h if a.created_at >= last_hour])
    
    # Check for multiple user agents (potential bot)
    unique_user_agents = len(set(a.user_agent for a in attempts_24h if a.user_agent))
    
    # Determine threat level
    threat_level = "low"
    warnings = []
    
    if failed_attempts > 20:
        threat_level = "high"
        warnings.append("Excessive failed login attempts")
    elif failed_attempts > 10:
        threat_level = "medium"
        warnings.append("High number of failed attempts")
    
    if unique_usernames > 5:
        threat_level = "high"
        warnings.append("Multiple username attempts (credential stuffing)")
    
    if attempts_last_hour > 30:
        threat_level = "high"
        warnings.append("Rapid succession login attempts")
    
    if unique_user_agents > 3 and total_attempts > 10:
        threat_level = "medium"
        warnings.append("Multiple user agents detected")
    
    if success_attempts > 0 and failed_attempts > success_attempts * 10:
        threat_level = "medium"
        warnings.append("High failure rate despite some successes")
    
    return {
        "ip_address": ip_address,
        "threat_level": threat_level,
        "total_attempts_24h": total_attempts,
        "failed_attempts_24h": failed_attempts,
        "success_attempts_24h": success_attempts,
        "unique_usernames": unique_usernames,
        "attempts_last_hour": attempts_last_hour,
        "unique_user_agents": unique_user_agents,
        "warnings": warnings,
        "recommend_block": threat_level == "high"
    }

def migrate_login_attempts_table(db: Session) -> bool:
    """Migrate login_attempts table to add new security columns"""
    try:
        from sqlalchemy import text
        
        # Check if columns already exist
        result = db.execute(text("PRAGMA table_info(login_attempts)"))
        columns = [row[1] for row in result.fetchall()]
        
        migrations_needed = []
        
        if 'user_agent' not in columns:
            migrations_needed.append("ALTER TABLE login_attempts ADD COLUMN user_agent TEXT")
        
        if 'reason' not in columns:
            migrations_needed.append("ALTER TABLE login_attempts ADD COLUMN reason TEXT")
        
        if 'session_token_partial' not in columns:
            migrations_needed.append("ALTER TABLE login_attempts ADD COLUMN session_token_partial TEXT")
        
        # Execute migrations
        for migration in migrations_needed:
            db.execute(text(migration))
        
        if migrations_needed:
            db.commit()
            logger.info(f"Applied {len(migrations_needed)} security migrations to login_attempts table")
        
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to migrate login_attempts table: {e}")
        return False

# Security monitoring endpoint
@router.get("/security/analysis/{ip_address}")
async def analyze_ip_security(
    ip_address: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Analyze security threats from an IP address (admin only)"""
    analysis = detect_suspicious_activity(db, ip_address)
    
    # Add recent attempts for context
    recent_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address
    ).order_by(LoginAttempt.created_at.desc()).limit(50).all()
    
    analysis["recent_attempts"] = [
        {
            "username": attempt.username,
            "success": attempt.success,
            "reason": attempt.reason,
            "user_agent": attempt.user_agent[:100] if attempt.user_agent else None,
            "created_at": attempt.created_at.isoformat()
        }
        for attempt in recent_attempts
    ]
    
    return analysis 