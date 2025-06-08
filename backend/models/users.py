from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import Session
from database import Base
import bcrypt
import secrets
import random


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    is_default_password = Column(Boolean, nullable=False, default=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', is_active={self.is_active})>"

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def verify_password(self, password: str) -> bool:
        """Verify a password against the stored hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def set_password(self, password: str):
        """Set a new password for the user"""
        self.password_hash = self.hash_password(password)
        self.is_default_password = False
        self.updated_at = func.now()

    @classmethod
    def get_by_username(cls, db: Session, username: str):
        """Get user by username"""
        return db.query(cls).filter(cls.username == username, cls.is_active == True).first()

    @classmethod
    def create_default_admin(cls, db: Session):
        """Create default admin user if none exists"""
        existing_admin = cls.get_by_username(db, "admin")
        if not existing_admin:
            admin_user = cls(
                username="admin",
                password_hash=cls.hash_password("changeme"),
                is_default_password=True,
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            return admin_user
        return existing_admin

    def update_last_login(self, db: Session):
        """Update last login timestamp"""
        self.last_login = func.now()
        db.commit()


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_address = Column(String, nullable=False, index=True)
    username = Column(String, nullable=True)
    success = Column(Boolean, nullable=False, default=False)
    user_agent = Column(String, nullable=True)  # Browser/client information
    reason = Column(String, nullable=True)  # Reason for failure: invalid_credentials, rate_limited, account_disabled
    session_token_partial = Column(String, nullable=True)  # Partial session token for successful logins
    created_at = Column(DateTime, nullable=False, default=func.now())

    @classmethod
    def record_attempt(cls, db: Session, ip_address: str, username: str = None, success: bool = False, 
                      user_agent: str = None, reason: str = None, session_token: str = None):
        """Record a login attempt with enhanced details"""
        # Only occasionally clean up old attempts to avoid performance issues
        # Do cleanup roughly 1% of the time (every ~100 attempts)
        if random.random() < 0.01:
            from datetime import datetime, timedelta
            cutoff_time = datetime.utcnow() - timedelta(days=30)
            try:
                deleted_count = db.query(cls).filter(cls.created_at < cutoff_time).delete()
                if deleted_count > 0:
                    db.commit()  # Commit the cleanup separately
            except Exception:
                db.rollback()  # Don't let cleanup failures affect login attempts
        
        attempt = cls(
            ip_address=ip_address,
            username=username,
            success=success,
            user_agent=user_agent[:500] if user_agent else None,  # Limit length
            reason=reason,
            session_token_partial=session_token
        )
        db.add(attempt)
        db.commit()
        return attempt

    @classmethod
    def get_recent_failed_attempts(cls, db: Session, ip_address: str, minutes: int = 15):
        """Get recent failed attempts for an IP address"""
        from datetime import datetime, timedelta
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        return db.query(cls).filter(
            cls.ip_address == ip_address,
            cls.success == False,
            cls.created_at >= cutoff_time
        ).count()


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_token = Column(String, unique=True, nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)

    @classmethod
    def create_session(cls, db: Session, user_id: int, ip_address: str = None, user_agent: str = None, hours: int = 24):
        """Create a new session for a user"""
        from datetime import datetime, timedelta
        
        # Generate secure session token
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=hours)
        
        session = cls(
            session_token=session_token,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at
        )
        db.add(session)
        db.commit()
        return session

    @classmethod
    def get_valid_session(cls, db: Session, session_token: str):
        """Get a valid session by token"""
        from datetime import datetime
        return db.query(cls).filter(
            cls.session_token == session_token,
            cls.is_active == True,
            cls.expires_at > datetime.utcnow()
        ).first()

    @classmethod
    def invalidate_session(cls, db: Session, session_token: str):
        """Invalidate a session"""
        session = db.query(cls).filter(cls.session_token == session_token).first()
        if session:
            session.is_active = False
            db.commit()
        return session

    @classmethod
    def cleanup_expired_sessions(cls, db: Session):
        """Clean up expired sessions"""
        from datetime import datetime
        expired_sessions = db.query(cls).filter(cls.expires_at <= datetime.utcnow()).all()
        for session in expired_sessions:
            db.delete(session)
        db.commit()
        return len(expired_sessions)


class APIToken(Base):
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    token = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)  # User-defined name for the token
    user_id = Column(Integer, nullable=False, index=True)
    is_permanent = Column(Boolean, nullable=False, default=False)
    expires_at = Column(DateTime, nullable=True)  # NULL for permanent tokens
    last_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f"<APIToken(id={self.id}, name='{self.name}', user_id={self.user_id}, is_permanent={self.is_permanent})>"

    @classmethod
    def create_token(cls, db: Session, user_id: int, name: str, is_permanent: bool = False, days: int = 30):
        """Create a new API token"""
        from datetime import datetime, timedelta
        
        # Generate secure API token with dnsniper prefix
        token = f"dnsniper_{secrets.token_urlsafe(32)}"
        
        # Set expiration for temporary tokens
        expires_at = None if is_permanent else datetime.utcnow() + timedelta(days=days)
        
        api_token = cls(
            token=token,
            name=name,
            user_id=user_id,
            is_permanent=is_permanent,
            expires_at=expires_at
        )
        db.add(api_token)
        db.commit()
        db.refresh(api_token)
        return api_token

    @classmethod
    def get_valid_token(cls, db: Session, token: str):
        """Get a valid API token"""
        from datetime import datetime
        query = db.query(cls).filter(
            cls.token == token,
            cls.is_active == True
        )
        
        # Check expiration for temporary tokens
        api_token = query.first()
        if api_token and not api_token.is_permanent and api_token.expires_at:
            if api_token.expires_at <= datetime.utcnow():
                return None  # Token expired
        
        return api_token

    @classmethod
    def get_user_tokens(cls, db: Session, user_id: int):
        """Get all tokens for a user"""
        return db.query(cls).filter(
            cls.user_id == user_id,
            cls.is_active == True
        ).order_by(cls.created_at.desc()).all()

    @classmethod
    def revoke_token(cls, db: Session, token_id: int, user_id: int):
        """Revoke an API token"""
        token = db.query(cls).filter(
            cls.id == token_id,
            cls.user_id == user_id
        ).first()
        if token:
            token.is_active = False
            db.commit()
        return token

    @classmethod
    def cleanup_expired_tokens(cls, db: Session):
        """Clean up expired tokens"""
        from datetime import datetime
        expired_tokens = db.query(cls).filter(
            cls.is_permanent == False,
            cls.expires_at.isnot(None),
            cls.expires_at <= datetime.utcnow()
        ).all()
        for token in expired_tokens:
            db.delete(token)
        db.commit()
        return len(expired_tokens)

    def update_last_used(self, db: Session):
        """Update last used timestamp"""
        self.last_used = func.now()
        db.commit()

    def is_expired(self):
        """Check if token is expired"""
        if self.is_permanent or self.expires_at is None:
            return False
        from datetime import datetime
        return self.expires_at <= datetime.utcnow()

    def days_until_expiry(self):
        """Get days until token expires (None for permanent tokens)"""
        if self.is_permanent or self.expires_at is None:
            return None
        from datetime import datetime
        delta = self.expires_at - datetime.utcnow()
        return max(0, delta.days) 