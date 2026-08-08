from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/oauth_state", tags=["OAuth State Bypass"])

@router.get("/authorize")
async def authorize():
    """VULNERABILITY: Initiates OAuth flow without generating a state parameter"""
    return RedirectResponse(url="/oauth_state/callback?code=mock_code")

@router.get("/callback")
async def callback(code: str, state: str = None):
    """VULNERABILITY: OAuth CSRF due to missing state validation"""
    if state is None:
        return {"status": "success", "message": "Account linked successfully (Vulnerable to OAuth CSRF)"}
    return {"status": "error", "message": "State mismatch"}
