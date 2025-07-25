from fastapi import FastAPI, HTTPException, Body
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_secret_key")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

app = FastAPI()

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=30)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

@app.post("/login")
def login(credentials: dict = Body(...)):
    print("🔵 /login endpoint hit")
    username = credentials.get("username")
    password = credentials.get("password")

    if not username or not password:
        token = create_access_token({"username": username})
        return {"success": False, "token": token}

    token = create_access_token({"username": username})
    return {"success": True, "token": token}