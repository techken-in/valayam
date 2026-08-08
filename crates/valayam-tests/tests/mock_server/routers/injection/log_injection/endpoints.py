from fastapi import APIRouter
import logging

router = APIRouter(prefix="/log_injection", tags=["Log Injection"])

logging.basicConfig(level=logging.INFO)

@router.get("/login")
async def login(username: str):
    """
    VULNERABILITY: Log Injection / Forging
    DETAILS: Directly logs user input without escaping newline characters, allowing log forging.
    """
    # Attacker can send "admin\n[INFO] User root logged in successfully"
    logging.info(f"Failed login attempt for user: {username}")
    return {"status": "error", "message": "Invalid credentials"}
