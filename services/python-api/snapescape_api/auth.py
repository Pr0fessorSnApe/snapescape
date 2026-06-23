"""RBAC authentication and session management."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = os.getenv("SNAPESCAPE_JWT_SECRET", "snapescape-dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ROLES = {"admin": 3, "analyst": 2, "viewer": 1}

# In-memory user store (production uses PostgreSQL)
_USERS: dict[str, dict] = {
    "snape": {
        "username": "snape",
        "hashed_password": pwd_context.hash("snapescape"),
        "role": "admin",
        "email": "snape@snapescape.local",
    },
    "dumbledore": {
        "username": "dumbledore",
        "hashed_password": pwd_context.hash("snapescape"),
        "role": "admin",
        "email": "dumbledore@snapescape.local",
    },
}


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str


class User(BaseModel):
    username: str
    role: str
    email: str


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def authenticate_user(username: str, password: str) -> dict | None:
    user = _USERS.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username or username not in _USERS:
            raise HTTPException(status_code=401, detail="Invalid token")
        u = _USERS[username]
        return User(username=u["username"], role=u["role"], email=u["email"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(min_role: str):
    async def checker(user: User = Depends(get_current_user)):
        if ROLES.get(user.role, 0) < ROLES.get(min_role, 0):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker
