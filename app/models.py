import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    full_name = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)
    credits = Column(Integer, default=100)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class GuestSession(Base):
    __tablename__ = "guest_sessions"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    has_chatted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
