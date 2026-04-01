import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool
from .config import DATABASE_URL

# Database configuration
if DATABASE_URL.startswith("sqlite:///"):
    # SQLite for local development
    engine = create_engine(
        DATABASE_URL, 
        connect_args={"check_same_thread": False}
    )
else:
    # PostgreSQL for Render production
    # Handle Render's PostgreSQL URL format
    db_url = DATABASE_URL
    if db_url.startswith("postgres://"):
        # Convert postgres:// to postgresql:// for SQLAlchemy
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    
    # Create engine with connection pooling for PostgreSQL
    engine = create_engine(
        db_url,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=1800,
        echo=False
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully")

def test_connection():
    """Test database connection"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("Database connection successful")
            return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False
