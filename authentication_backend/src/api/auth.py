# FastAPI authentication endpoints with modular separation for registration, login, password mgmt, tokens

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from datetime import datetime, timedelta

# Mock User DB functions (replace with real DB in production)
# These will eventually use the database dependency configured by env vars
_fake_db = {}

SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "changeme-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

openapi_tags = [
    {"name": "Authentication", "description": "Operations for authentication (login/registration/token)"},
    {"name": "User", "description": "User registration, profile, and password management"}
]

# Models
class User(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str
    disabled: Optional[bool] = False

class UserInDB(User):
    pass

class UserCreate(BaseModel):
    username: str = Field(..., description="Desired username")
    email: EmailStr = Field(..., description="Email address of user")
    password: str = Field(..., description="User password (will be hashed)")

class UserResponse(BaseModel):
    username: str
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class ResetPasswordRequest(BaseModel):
    email: EmailStr

# Utility functions

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    user = _fake_db.get(username)
    if user:
        return UserInDB(**user)
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# FastAPI Router
router = APIRouter()

# PUBLIC_INTERFACE
@router.post("/auth/register", response_model=UserResponse, tags=["User"], summary="Register new user", description="Register a new user by providing username, email, and password")
async def register_user(user: UserCreate):
    """
    Registers a new user. Returns user data on success.
    """
    if user.username in _fake_db:
        raise HTTPException(status_code=400, detail="Username already in use.")
    hashed_pw = get_password_hash(user.password)
    _fake_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_pw,
        "disabled": False
    }
    return UserResponse(username=user.username, email=user.email)

# PUBLIC_INTERFACE
@router.post("/auth/login", response_model=Token, tags=["Authentication"], summary="Login user and get token", description="Authenticate a user and return a JWT access token.")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticates a user and returns an access token if credentials are valid.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@router.post("/auth/change-password", tags=["User"], summary="Change user password", description="Change password for authenticated user.")
async def change_password(
    req: ChangePasswordRequest,
    token: str = Depends(oauth2_scheme),
):
    """
    Change user's password if old_password matches.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = get_user(username)
    if not user or not verify_password(req.old_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Old password is incorrect.")

    user_dict = _fake_db[username]
    user_dict["hashed_password"] = get_password_hash(req.new_password)
    _fake_db[username] = user_dict
    return {"msg": "Password changed successfully."}

# PUBLIC_INTERFACE
@router.post("/auth/reset-password", tags=["User"], summary="Request password reset", description="Request a password reset for user.")
async def reset_password(req: ResetPasswordRequest):
    """
    Request a password reset. (This is a stub; in production, emails a reset link.)
    """
    # In production: send a password reset email if user exists.
    return {"msg": f"If user with email {req.email} exists, a reset link has been sent."}

# PUBLIC_INTERFACE
@router.get("/auth/me", response_model=UserResponse, tags=["User"], summary="Get current user", description="Fetch currently authenticated user's profile")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    """
    Get details of currently authenticated user.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return UserResponse(username=user.username, email=user.email)
