# 🚀 FastAPI MongoDB - Step-by-Step Implementation Guide

## 📁 Complete File Structure with Exact Paths

```
C:/Users/User/Downloads/AI/FastApi/MongoDb/
├── .env                                    # ✅ EXISTS - NEEDS UPDATE
├── .env.example                            # ❌ CREATE NEW
├── .gitignore                              # ❌ CREATE NEW
├── requirements.txt                        # ❌ CREATE NEW
├── README.md                               # ❌ CREATE NEW
├── Dockerfile                              # ❌ CREATE NEW
├── docker-compose.yml                      # ❌ CREATE NEW
├── pytest.ini                              # ❌ CREATE NEW
│
├── app/                                    # ❌ CREATE NEW FOLDER
│   ├── __init__.py                         # ❌ CREATE NEW
│   ├── main.py                             # 🔄 MOVE FROM ROOT
│   │
│   ├── core/                               # ❌ CREATE NEW FOLDER
│   │   ├── __init__.py                     # ❌ CREATE NEW
│   │   ├── config.py                       # ❌ CREATE NEW
│   │   ├── security.py                     # ❌ CREATE NEW
│   │   └── logging_config.py               # ❌ CREATE NEW
│   │
│   ├── api/                                # ❌ CREATE NEW FOLDER
│   │   ├── __init__.py                     # ❌ CREATE NEW
│   │   └── v1/                             # ❌ CREATE NEW FOLDER
│   │       ├── __init__.py                 # ❌ CREATE NEW
│   │       └── endpoints/                  # ❌ CREATE NEW FOLDER
│   │           ├── __init__.py             # ❌ CREATE NEW
│   │           ├── auth.py                 # 🔄 REFACTOR FROM routers/auth.py
│   │           ├── medicine.py             # 🔄 REFACTOR FROM routers/medicine.py
│   │           └── health.py               # ❌ CREATE NEW
│   │
│   ├── crud/                               # ❌ CREATE NEW FOLDER
│   │   ├── __init__.py                     # ❌ CREATE NEW
│   │   ├── base.py                         # ❌ CREATE NEW
│   │   ├── crud_medicine.py                # ❌ CREATE NEW
│   │   └── crud_user.py                    # ❌ CREATE NEW
│   │
│   ├── schemas/                            # ❌ CREATE NEW FOLDER
│   │   ├── __init__.py                     # ❌ CREATE NEW
│   │   ├── response.py                     # ❌ CREATE NEW
│   │   ├── medicine.py                     # ❌ CREATE NEW
│   │   └── user.py                         # ❌ CREATE NEW
│   │
│   ├── models/                             # ✅ EXISTS - NEEDS REFACTOR
│   │   ├── __init__.py                     # ❌ CREATE NEW
│   │   ├── Medicine.py                     # ✅ EXISTS - REFACTOR
│   │   └── User.py                         # ✅ EXISTS - REFACTOR
│   │
│   ├── db/                                 # ✅ EXISTS - NEEDS UPDATE
│   │   ├── __init__.py                     # ❌ CREATE NEW
│   │   ├── database.py                     # ✅ EXISTS - REFACTOR
│   │   └── init_db.py                      # ❌ CREATE NEW
│   │
│   ├── auth/                               # ✅ EXISTS - NEEDS FIXES
│   │   ├── __init__.py                     # ❌ CREATE NEW
│   │   ├── jwt_handler.py                  # ✅ EXISTS - FIX SECURITY
│   │   ├── password_handler.py             # ✅ EXISTS - KEEP
│   │   └── auth_dependency.py              # ✅ EXISTS - FIX IMPORT
│   │
│   └── middleware/                         # ❌ CREATE NEW FOLDER
│       ├── __init__.py                     # ❌ CREATE NEW
│       ├── cors.py                         # ❌ CREATE NEW
│       └── request_id.py                   # ❌ CREATE NEW
│
├── tests/                                  # ❌ CREATE NEW FOLDER
│   ├── __init__.py                         # ❌ CREATE NEW
│   ├── conftest.py                         # ❌ CREATE NEW
│   ├── test_auth.py                        # ❌ CREATE NEW
│   ├── test_medicine.py                    # ❌ CREATE NEW
│   └── test_integration.py                 # ❌ CREATE NEW
│
└── scripts/                                # ❌ CREATE NEW FOLDER
    ├── init_db.py                          # ❌ CREATE NEW
    └── create_admin.py                     # ❌ CREATE NEW
```

---

## 🔥 PHASE 1: Critical Security Fixes (DO FIRST!)

### 📄 File: `.env` (UPDATE EXISTING)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/.env`

```env
# Database
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=medicine_db

# JWT Security (CRITICAL: Change these!)
JWT_SECRET_KEY=your_super_secret_key_min_32_characters_long_change_this_immediately
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
APP_NAME=Medicine Management API
APP_VERSION=1.0.0
DEBUG=True
ENVIRONMENT=development

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Logging
LOG_LEVEL=INFO
```

### 📄 File: `.env.example` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/.env.example`

```env
# Database
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=medicine_db

# JWT Security
JWT_SECRET_KEY=generate_a_secure_random_key_here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
APP_NAME=Medicine Management API
APP_VERSION=1.0.0
DEBUG=False
ENVIRONMENT=production

# CORS
ALLOWED_ORIGINS=http://localhost:3000

# Logging
LOG_LEVEL=INFO
```

### 📄 File: `auth/jwt_handler.py` (FIX SECURITY ISSUE)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/auth/jwt_handler.py`

**REPLACE ENTIRE FILE:**
```python
import os
from datetime import datetime, timedelta
from typing import Optional, Dict
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# Load from environment variables (SECURITY FIX!)
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_TIME = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY must be set in environment variables")

def create_access_token(data: Dict[str, str], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary containing claims to encode
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_TIME)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[Dict]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded payload if valid, None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        print(f"JWT verification failed: {str(e)}")
        return None
```

### 📄 File: `auth/auth_dependency.py` (FIX IMPORT BUG)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/auth/auth_dependency.py`

**REPLACE ENTIRE FILE:**
```python
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi import Depends, HTTPException, status
from auth.jwt_handler import verify_token  # FIXED: Added 'auth.' prefix

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Dependency to get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer token credentials
        
    Returns:
        Decoded token payload containing user information
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    token = credentials.credentials
    payload = verify_token(token)
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return payload

def get_current_active_user(current_user: dict = Depends(get_current_user)) -> dict:
    """
    Dependency to get current active user (can be extended with user status checks).
    
    Args:
        current_user: Current user from token
        
    Returns:
        Current user if active
        
    Raises:
        HTTPException: If user is inactive
    """
    # Add additional checks here if needed (e.g., user.is_active)
    return current_user
```

---

## 📦 PHASE 2: Project Setup Files

### 📄 File: `requirements.txt` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/requirements.txt`

```txt
# FastAPI Framework
fastapi==0.109.0
uvicorn[standard]==0.27.0
python-multipart==0.0.6

# Database
pymongo==4.6.1
motor==3.3.2

# Authentication & Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-dotenv==1.0.0

# Validation
pydantic[email]==2.5.3
email-validator==2.1.0

# Testing
pytest==7.4.4
pytest-asyncio==0.23.3
pytest-cov==4.1.0
httpx==0.26.0

# Development
black==24.1.1
flake8==7.0.0
mypy==1.8.0
pre-commit==3.6.0

# Monitoring & Logging
python-json-logger==2.0.7

# Optional: Caching
redis==5.0.1
fastapi-cache2==0.2.1

# Optional: Rate Limiting
slowapi==0.1.9
```

### 📄 File: `.gitignore` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/.gitignore`

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/
.venv

# Environment Variables
.env
.env.local
.env.*.local

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/
.hypothesis/

# Logs
*.log
logs/
app.log

# Database
*.db
*.sqlite3

# MyPy
.mypy_cache/
.dmypy.json
dmypy.json

# Jupyter
.ipynb_checkpoints

# Documentation
docs/_build/
```

### 📄 File: `Dockerfile` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/Dockerfile`

```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/v1/health')"

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 📄 File: `docker-compose.yml` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/docker-compose.yml`

```yaml
version: '3.8'

services:
  # FastAPI Application
  api:
    build: .
    container_name: medicine_api
    ports:
      - "8000:8000"
    environment:
      - MONGODB_URL=mongodb://mongo:27017
      - DATABASE_NAME=medicine_db
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - DEBUG=True
    depends_on:
      - mongo
    volumes:
      - ./:/app
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    networks:
      - medicine_network

  # MongoDB Database
  mongo:
    image: mongo:7.0
    container_name: medicine_mongo
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
      - ./scripts/init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro
    environment:
      - MONGO_INITDB_DATABASE=medicine_db
    networks:
      - medicine_network

  # MongoDB Express (Optional - for database management)
  mongo-express:
    image: mongo-express:latest
    container_name: medicine_mongo_express
    ports:
      - "8081:8081"
    environment:
      - ME_CONFIG_MONGODB_URL=mongodb://mongo:27017
      - ME_CONFIG_BASICAUTH_USERNAME=admin
      - ME_CONFIG_BASICAUTH_PASSWORD=admin123
    depends_on:
      - mongo
    networks:
      - medicine_network

volumes:
  mongo_data:

networks:
  medicine_network:
    driver: bridge
```

### 📄 File: `pytest.ini` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/pytest.ini`

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --strict-markers
    --cov=app
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=80
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow running tests
```

---

## 🏗️ PHASE 3: Core Application Files

### 📄 File: `app/__init__.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/__init__.py`

```python
"""
Medicine Management API
A FastAPI application for managing medicines with MongoDB.
"""

__version__ = "1.0.0"
__author__ = "Your Name"
```

### 📄 File: `app/core/config.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/core/config.py`

```python
import os
from typing import List
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = os.getenv("APP_NAME", "Medicine Management API")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Database
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "medicine_db")
    
    # JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # CORS
    ALLOWED_ORIGINS: List[str] = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = 10
    MAX_PAGE_SIZE: int = 100
    
    class Config:
        case_sensitive = True
        env_file = ".env"

# Global settings instance
settings = Settings()

# Validate critical settings
if not settings.JWT_SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY must be set in environment variables")
```

### 📄 File: `app/core/logging_config.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/core/logging_config.py`

```python
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from app.core.config import settings

def setup_logging() -> logging.Logger:
    """
    Configure application logging with both file and console handlers.
    
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Create logger
    logger = logging.getLogger("medicine_api")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler (rotating)
    file_handler = RotatingFileHandler(
        log_dir / "app.log",
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Global logger instance
logger = setup_logging()
```

### 📄 File: `app/core/security.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/core/security.py`

```python
import re
from typing import Optional
from fastapi import HTTPException, status

def validate_password_strength(password: str) -> bool:
    """
    Validate password meets security requirements.
    
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    
    Args:
        password: Password to validate
        
    Returns:
        True if valid
        
    Raises:
        HTTPException: If password doesn't meet requirements
    """
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )
    
    if not re.search(r'[A-Z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter"
        )
    
    if not re.search(r'[a-z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter"
        )
    
    if not re.search(r'\d', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one digit"
        )
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character"
        )
    
    return True

def sanitize_input(input_str: str, max_length: int = 255) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        input_str: Input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not input_str:
        return ""
    
    # Trim to max length
    sanitized = input_str[:max_length]
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>\"\'%;()&+]', '', sanitized)
    
    return sanitized.strip()
```

---

## 📊 PHASE 4: Schemas (Pydantic Models)

### 📄 File: `app/schemas/__init__.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/schemas/__init__.py`

```python
from app.schemas.medicine import (
    MedicineBase,
    MedicineCreate,
    MedicineUpdate,
    MedicineResponse,
    MedicineListResponse
)
from app.schemas.user import (
    UserBase,
    UserCreate,
    UserLogin,
    UserResponse,
    Token
)
from app.schemas.response import (
    ResponseModel,
    PaginatedResponse,
    ErrorResponse
)

__all__ = [
    "MedicineBase",
    "MedicineCreate",
    "MedicineUpdate",
    "MedicineResponse",
    "MedicineListResponse",
    "UserBase",
    "UserCreate",
    "UserLogin",
    "UserResponse",
    "Token",
    "ResponseModel",
    "PaginatedResponse",
    "ErrorResponse",
]
```

### 📄 File: `app/schemas/response.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/schemas/response.py`

```python
from typing import Generic, TypeVar, Optional, List, Any
from pydantic import BaseModel, Field

T = TypeVar('T')

class ResponseModel(BaseModel, Generic[T]):
    """Standard API response model."""
    success: bool = True
    message: Optional[str] = None
    data: Optional[T] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "Operation successful",
                "data": {}
            }
        }

class ErrorResponse(BaseModel):
    """Error response model."""
    success: bool = False
    message: str
    errors: Optional[dict] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": False,
                "message": "An error occurred",
                "errors": {"field": "error detail"}
            }
        }

class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response model."""
    success: bool = True
    data: List[T]
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "data": [],
                "total": 100,
                "page": 1,
                "page_size": 10,
                "total_pages": 10
            }
        }
```

### 📄 File: `app/schemas/medicine.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/schemas/medicine.py`

```python
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, validator

class MedicineBase(BaseModel):
    """Base medicine schema with common fields."""
    name: str = Field(..., min_length=1, max_length=100, description="Medicine name")
    dose: int = Field(..., gt=0, description="Dose in mg (must be greater than 0)")
    type_of_medicine: str = Field(..., description="Type (tablet, syrup, injection, etc.)")
    time: str = Field(..., description="Time to take medicine (e.g., '08:00 AM')")
    routine: str = Field(..., description="Routine (daily, weekly, monthly)")
    image: Optional[str] = Field(None, description="Medicine image URL")
    
    @validator('routine')
    def validate_routine(cls, v):
        allowed_routines = ['daily', 'weekly', 'monthly', 'as_needed']
        if v.lower() not in allowed_routines:
            raise ValueError(f'Routine must be one of: {", ".join(allowed_routines)}')
        return v.lower()

class MedicineCreate(MedicineBase):
    """Schema for creating a new medicine."""
    starting_date: str = Field(..., description="Starting date (YYYY-MM-DD)")
    remaining_dose: int = Field(..., ge=0, description="Remaining doses")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "Aspirin",
                "dose": 500,
                "type_of_medicine": "tablet",
                "time": "08:00 AM",
                "routine": "daily",
                "image": "https://example.com/aspirin.jpg",
                "starting_date": "2024-01-01",
                "remaining_dose": 30
            }
        }

class MedicineUpdate(BaseModel):
    """Schema for updating a medicine (all fields optional)."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    dose: Optional[int] = Field(None, gt=0)
    type_of_medicine: Optional[str] = None
    time: Optional[str] = None
    routine: Optional[str] = None
    status: Optional[str] = None
    image: Optional[str] = None
    is_enable: Optional[bool] = None
    remaining_dose: Optional[int] = Field(None, ge=0)
    
    class Config:
        json_schema_extra = {
            "example": {
                "dose": 750,
                "time": "09:00 AM",
                "remaining_dose": 25
            }
        }

class MedicineResponse(MedicineBase):
    """Schema for medicine response."""
    id: str = Field(..., description="Medicine ID")
    status: str = Field(default="active", description="Medicine status")
    is_enable: bool = Field(default=True, description="Whether medicine is enabled")
    starting_date: str
    remaining_dose: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "name": "Aspirin",
                "dose": 500,
                "type_of_medicine": "tablet",
                "time": "08:00 AM",
                "routine": "daily",
                "status": "active",
                "image": "https://example.com/aspirin.jpg",
                "is_enable": True,
                "starting_date": "2024-01-01",
                "remaining_dose": 30,
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-01T00:00:00"
            }
        }

class MedicineListResponse(BaseModel):
    """Schema for list of medicines."""
    medicines: List[MedicineResponse]
    
    class Config:
        json_schema_extra = {
            "example": {
                "medicines": []
            }
        }
```

### 📄 File: `app/schemas/user.py` (CREATE NEW)
**Path:** `C:/Users/User/Downloads/AI/FastApi/MongoDb/app/schemas/user.py`

```python
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator
from enum import Enum

class UserRole(str, Enum):
    """User role enumeration."""
    ADMIN = "admin"
    USER = "user"

class UserBase(BaseModel):
    """Base user schema."""
    email: EmailStr = Field(..., description="User email address")

class UserCreate(UserBase):
    """Schema for user registration."""
    password: str = Field(..., min_length=8, description="User password (min 8 characters)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!"
            }
        }

class UserLogin(UserBase):
    """Schema for user login."""
    password: str = Field(..., description="User password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!"
            }
        }

class UserResponse(UserBase):
    """Schema for user response (without password)."""
    id: str = Field(..., description="User ID")
    role: UserRole = Field(default=UserRole.USER, description="User role")
    is_active: bool = Field(default=True, description="Whether user is active")
    created_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "email": "user@example.com",
                "role": "user",
                "is_active": True,
                "created_at": "2024-01-01T00:00:00"
            }
        }

class Token(BaseModel):
    """Schema for JWT token response."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }
```

---

*This implementation guide continues with CRUD operations, API endpoints, database initialization, tests, and migration steps. Would you like me to continue with the remaining phases?*
