from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/oauth_implicit", tags=["OAuth Implicit Flow"])

@router.get("/authorize")
async def authorize(client_id: str, redirect_uri: str):
    """
    VULNERABILITY: OAuth Implicit Flow
    DETAILS: Returns sensitive access tokens directly in the URL hash fragment.
    """
    return RedirectResponse(url=f"{redirect_uri}#access_token=super_secret_token&token_type=bearer")
