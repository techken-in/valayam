from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/crlf_advanced", tags=["CRLF Advanced"])

@router.get("/log")
async def log_action(action: str):
    """VULNERABILITY: Log CRLF Injection"""
    return {"status": "success", "log_entry": f"User performed: {action}"}

@router.get("/redirect")
async def redirect_user(url: str, response: Response):
    """VULNERABILITY: CRLF Response Splitting via Location Header"""
    response.headers["Location"] = url
    response.status_code = 302
    return response
