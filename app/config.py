import os

# Security - Use environment variables in production, fallback to hardcoded for local dev
SECRET_KEY = os.environ.get("SECRET_KEY", "securitigpt_production_ready_secret_key_123!")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# Database - Support Render's persistent disk path
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./securitigpt.db")

# API Keys - Use environment variables (set these in Render dashboard)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "ca2944957a797da80ad4a383c5f1809971f8886b6599f86902d3d2e974c47c16")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "mock_key_needed_only_if_unmocked")
RAPIDAPI_KEY = os.environ.get("RAPIDAPI_KEY", "emailbreachcheck.p.rapidapi.com")
