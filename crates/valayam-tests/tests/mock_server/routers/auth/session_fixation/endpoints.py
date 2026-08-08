from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/session_fixation", tags=["Session Fixation"])

@router.get("/login")
async def login(session_id: str, response: Response):
    """
    VULNERABILITY: Session Fixation
    DETAILS: Allows an attacker to specify the session ID for a victim via URL.
    """
    response.headers["Set-Cookie"] = f"session_id={session_id}"
    return {"status": "success", "message": "Session fixed"}
