from fastapi import APIRouter

router = APIRouter(prefix="/weak_password", tags=["Weak Password Policy"])

@router.post("/register")
async def register(password: str):
    """
    VULNERABILITY: Weak Password Policy
    DETAILS: Allows extremely weak passwords like '123' or 'password'.
    """
    if len(password) < 1:
        return {"status": "error", "message": "Password cannot be empty"}
    return {"status": "success", "message": "User registered successfully"}
