from fastapi import APIRouter

router = APIRouter(prefix="/nosqli_blind", tags=["Blind NoSQLi"])

@router.post("/auth")
async def auth_blind(username: str, password_regex: str):
    """VULNERABILITY: Boolean-based blind NoSQL Injection via regex"""
    if username == "admin" and password_regex.startswith("^super"):
        return {"status": "success", "message": "Valid"}
    return {"status": "error", "message": "Invalid"}

@router.get("/user")
async def user_blind(id_ne: str = None):
    """VULNERABILITY: Blind NoSQLi via $ne operator"""
    if id_ne == "2":
        return {"status": "success", "user": "admin"}
    return {"status": "error", "message": "Not found"}
