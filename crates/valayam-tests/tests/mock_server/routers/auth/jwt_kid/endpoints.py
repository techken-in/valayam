from fastapi import APIRouter

router = APIRouter(prefix="/jwt_kid", tags=["JWT Key ID Injection"])

@router.post("/verify")
async def verify_token(token: str):
    """
    VULNERABILITY: JWT Key ID (kid) Injection
    DETAILS: Simulates reading a secret from a local file specified in the 'kid' header without validation.
    """
    return {"status": "success", "message": "Token accepted"}
