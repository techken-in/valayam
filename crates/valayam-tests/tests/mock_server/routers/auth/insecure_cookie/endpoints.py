from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/insecure_cookie", tags=["Insecure Cookie Parameters"])

@router.get("/login")
async def login(response: Response):
    """
    VULNERABILITY: Insecure Cookie Parameters
    DETAILS: Sets a session cookie without the Secure and HttpOnly flags.
    """
    response.set_cookie(key="session_token", value="super_secret_value", httponly=False, secure=False)
    return {"status": "success", "message": "Logged in"}
