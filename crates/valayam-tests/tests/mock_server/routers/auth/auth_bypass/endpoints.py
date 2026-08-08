from fastapi import APIRouter

router = APIRouter(prefix="/auth_bypass", tags=["Broken Authentication"])

@router.post("/login")
async def login(username: str, password: str):
    """
    VULNERABILITY: Broken Authentication / Brute Force
    DETAILS: Simulates a login endpoint with no rate limiting or lockout.
    """
    if username == "admin" and password == "123456":
        return {"status": "success", "token": "admin_token"}
    return {"status": "error", "message": "Invalid credentials"}
