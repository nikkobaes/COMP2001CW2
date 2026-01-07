from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional, Any, Dict

from app.db import get_connection, ensure_roles_table_exists, ensure_role, get_role
from app.auth import authenticate_with_authenticator, create_access_token, require_role, get_current_user


app = FastAPI(title="ProfileService (CW2)")

@app.on_event("startup")
def startup():
    ensure_roles_table_exists()

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    user_id: int
    first_name: str
    last_name: str
    email: EmailStr
    language_id: Optional[int] = None

class UserUpdate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    language_id: Optional[int] = None

def row_to_dict(cursor, row) -> Dict[str, Any]:
    cols = [c[0] for c in cursor.description]
    return dict(zip(cols, row))

@app.get("/health")
def health():
    return {"status": "ok"}

#CRUD operations
#Creates the user 
@app.post("/users")
def create_user(user: UserCreate, admin=Depends(require_role("admin"))):
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("EXEC CW2.CreateUser ?, ?, ?, ?, ?",
                        user.user_id, user.first_name, user.last_name, user.email, user.language_id)
            conn.commit()
        return {"message": "User created", "user_id": user.user_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    

#Gets the user 
@app.get("/users/{user_id}")
def get_user(user_id: int, user=Depends(get_current_user)):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("EXEC CW2.GetUserByID ?", user_id)
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return row_to_dict(cur, row)
    

#Updates the user
@app.put("/users/{user_id}")
def update_user(user_id: int, user: UserUpdate, admin=Depends(require_role("admin"))):
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("EXEC CW2.UpdateUser ?, ?, ?, ?, ?",
                        user_id, user.first_name, user.last_name, user.email, user.language_id)
            conn.commit()
        return {"message": "User updated", "user_id": user_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    

# Deletes the user
@app.delete("/users/{user_id}")
def delete_user(user_id: int, admin=Depends(require_role("admin"))):
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("EXEC CW2.DeleteUser ?", user_id)
            conn.commit()
        return {"message": "User deleted", "user_id": user_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    

#Authentication 

@app.post("/auth/login")
def login(req: LoginRequest):
    authenticate_with_authenticator(req.username, req.password)
    role = ensure_role(req.username)
    token = create_access_token(req.username, role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": req.username,
        "role": role
    }

@app.get("/auth/role/{username}")
def role_lookup(username: str, admin=Depends(require_role("admin"))):
    return {
        "username": username,
        "role": get_role(username)
    }

#Testing
@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return user
