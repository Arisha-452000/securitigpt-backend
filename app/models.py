import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
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

class Broadcast(Base):
    __tablename__ = "broadcasts"
    id = Column(Integer, primary_key=True, index=True)
    message = Column(String)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class PasswordReset(Base):
    __tablename__ = "password_resets"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    code = Column(String, index=True)  # 6-digit code
    token = Column(String, unique=True, index=True)  # For backup/link method
    expires_at = Column(DateTime)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class SignupVerification(Base):
    __tablename__ = "signup_verifications"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    code = Column(String, index=True)
    expires_at = Column(DateTime)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Blog(Base):
    __tablename__ = "blogs"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    category = Column(String)
    image = Column(String)
    content = Column(Text)  # This will store the rich text HTML
    author = Column(String)
    date = Column(DateTime, default=datetime.datetime.utcnow)
