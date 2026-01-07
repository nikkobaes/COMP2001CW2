import os
import jwt
import requests
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.db import ensure_role

AUTH_URL = "https://web.socem.plymouth.ac.uk/COMP2001/auth/api/users"

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXP_MIN = 60

security = HTTPBearer()


def authenticate_with_authenticator(username: str, password: str):
    try:
        r = requests.get(AUTH_URL, auth=(username, password), timeout=10)
    except requests.RequestException:
        raise HTTPException(status_code=503, detail="Authenticator API unavailable")

    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return True


def create_access_token(username: str, role: str):
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MIN)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        return {"username": payload["sub"], "role": payload["role"]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(*roles):
    def checker(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker
