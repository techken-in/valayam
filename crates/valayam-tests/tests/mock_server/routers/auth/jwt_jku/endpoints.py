from fastapi import APIRouter

router = APIRouter(prefix="/jwt_jku", tags=["JWT JKU Injection"])

@router.post("/verify")
async def verify_token(token: str):
    """
    VULNERABILITY: JWT JKU Header Injection
    DETAILS: Simulates trusting the 'jku' (JWK Set URL) header in a JWT to fetch public keys from an untrusted source.
    """
    return {"status": "success", "message": "Token accepted using jku key"}
