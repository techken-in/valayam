from fastapi import APIRouter
import time

router = APIRouter(prefix="/auth_timing", tags=["Auth Timing Attack"])

@router.post("/login")
async def login(username: str, password: str):
    """VULNERABILITY: User enumeration via timing attack on login"""
    if username == "admin":
        time.sleep(1) # Simulates heavy bcrypt hash comparison
        return {"status": "error", "message": "Invalid password"}
    return {"status": "error", "message": "Invalid credentials"}

@router.post("/reset_password")
async def reset_password(username: str):
    """VULNERABILITY: User enumeration via timing attack on reset"""
    if username == "admin":
        time.sleep(0.5) # Simulates DB lookup and email dispatch
        return {"status": "success", "message": "If the email exists, a reset link was sent."}
    return {"status": "success", "message": "If the email exists, a reset link was sent."}
