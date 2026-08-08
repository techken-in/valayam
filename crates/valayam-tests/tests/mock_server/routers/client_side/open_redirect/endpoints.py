from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/open_redirect", tags=["Open Redirect"])

@router.get("/login")
async def login(next: str = "/"):
    """
    VULNERABILITY: Open Redirect
    DETAILS: Simulates an endpoint vulnerable to open redirect via the 'next' parameter.
    THIS ALLOWS: Attackers to redirect victims to malicious sites, aiding in phishing attacks.
    """
    # Vulnerable implementation: redirects directly to user-supplied input
    return RedirectResponse(url=next)
