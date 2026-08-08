from fastapi import APIRouter

router = APIRouter(prefix="/oauth", tags=["OAuth"])

@router.get("/callback")
async def oauth_callback(state: str = None, code: str = None):
    """
    VULNERABILITY: OAuth State Parameter Missing/Unvalidated
    DETAILS: Simulates an OAuth callback that doesn't enforce the 'state' parameter correctly.
    THIS ALLOWS: Cross-Site Request Forgery (CSRF) against the OAuth login flow.
    """
    if not state:
        return {"status": "success", "message": "Logged in successfully without state validation!"}
    
    return {"status": "success", "message": "Logged in with state."}
