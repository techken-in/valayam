from fastapi import APIRouter

router = APIRouter(prefix="/jwt_alg_confusion", tags=["JWT Alg Confusion"])

@router.post("/verify")
async def verify_token(token: str):
    """VULNERABILITY: JWT Algorithm Confusion (RS256 to HS256)"""
    # Simulates a backend incorrectly trusting symmetric verification with a public key
    return {"status": "success", "message": "Token verified using public key as symmetric secret"}

@router.get("/profile")
async def get_profile(token: str):
    """VULNERABILITY: Profile access via confused JWT"""
    return {"status": "success", "profile": "admin_data"}
