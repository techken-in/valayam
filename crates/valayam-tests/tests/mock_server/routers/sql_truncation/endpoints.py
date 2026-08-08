from fastapi import APIRouter

router = APIRouter(prefix="/sql_truncation", tags=["SQL Truncation Attack"])

router_db = {"admin": "secure_password"}

@router.post("/register")
async def register(username: str, password: str):
    """
    VULNERABILITY: SQL Truncation Attack
    DETAILS: Simulates database truncation of strings (e.g. max 20 chars), allowing takeover of existing accounts.
    """
    truncated_username = username[:20].rstrip()
    if truncated_username == "admin":
        return {"status": "success", "message": "Admin account overwritten (truncated)"}
    return {"status": "success", "message": "User registered"}
