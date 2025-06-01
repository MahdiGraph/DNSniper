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

# Rate limiting storage (in production, use Redis)
rate_limit_storage = {}

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
    """Get client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

def check_rate_limit(ip_address: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """Check if IP address is rate limited"""
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)
    
    # Clean old entries
    if ip_address in rate_limit_storage:
        rate_limit_storage[ip_address] = [
            attempt_time for attempt_time in rate_limit_storage[ip_address]
            if attempt_time > window_start
        ]
    
    # Check current attempts
    attempts = len(rate_limit_storage.get(ip_address, []))
    return attempts < max_attempts

def record_rate_limit_attempt(ip_address: str):
    """Record a rate limit attempt"""
    now = datetime.utcnow()
    if ip_address not in rate_limit_storage:
        rate_limit_storage[ip_address] = []
    rate_limit_storage[ip_address].append(now)

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
    """Login endpoint with rate limiting"""
    client_ip = get_client_ip(request)
    
    # Check rate limiting
    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )
    
    # Check database rate limiting
    recent_failures = LoginAttempt.get_recent_failed_attempts(db, client_ip)
    if recent_failures >= 10:  # More strict database-based rate limiting
        logger.warning(f"Database rate limit exceeded for IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later."
        )
    
    # Authenticate user
    user = User.get_by_username(db, login_data.username)
    
    if not user or not user.verify_password(login_data.password):
        # Record failed attempt
        LoginAttempt.record_attempt(db, client_ip, login_data.username, success=False)
        record_rate_limit_attempt(client_ip)
        
        logger.warning(f"Failed login attempt for username '{login_data.username}' from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Create session
    user_agent = request.headers.get("User-Agent", "")
    session = UserSession.create_session(db, user.id, client_ip, user_agent)
    
    # Record successful attempt
    LoginAttempt.record_attempt(db, client_ip, login_data.username, success=True)
    user.update_last_login(db)
    
    logger.info(f"Successful login for user '{user.username}' from IP {client_ip}")
    
    return {
        "message": "Login successful",
        "token": session.session_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "is_default_password": user.is_default_password,
            "last_login": user.last_login,
            "created_at": user.created_at
        }
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