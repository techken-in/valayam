from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/sensitive_cache", tags=["Sensitive Data Caching"])

@router.get("/profile")
async def get_profile(response: Response):
    """
    VULNERABILITY: Sensitive Data Caching
    DETAILS: Returns sensitive user data without setting Cache-Control: no-store, allowing intermediaries to cache it.
    """
    return {"status": "success", "user": "admin", "api_key": "SECRET-1234"}
