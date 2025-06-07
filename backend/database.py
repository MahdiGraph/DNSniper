import os
from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Database URL - SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dnsniper.db")

# Create engine with proper SQLite configuration
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 20,
        "isolation_level": None
    },
    poolclass=StaticPool,
    echo=False,  # Set to True for SQL query logging
    pool_pre_ping=True  # Verify connections before use
)

# Enable WAL mode for SQLite for better concurrency
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=1000")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.execute("PRAGMA busy_timeout=20000")  # 20 second timeout for busy database
    cursor.close()

# Session factory with improved resource management
SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine,
    expire_on_commit=False  # Prevent detached instance errors
)

# Base class for models
Base = declarative_base()

# Dependency to get database session with better error handling
def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        db.rollback()
        raise
    finally:
        db.close()

# Context manager for manual database sessions
class DatabaseSession:
    """Context manager for database sessions with automatic cleanup"""
    
    def __init__(self):
        self.db = None
    
    def __enter__(self):
        self.db = SessionLocal()
        return self.db
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.db:
            try:
                if exc_type:
                    self.db.rollback()
                else:
                    self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            finally:
                self.db.close()

# Function to safely execute database operations
def safe_db_operation(operation_func, *args, **kwargs):
    """Execute database operation with automatic session management and error handling"""
    with DatabaseSession() as db:
        return operation_func(db, *args, **kwargs) 