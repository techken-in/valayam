from fastapi import APIRouter
import jwt

router = APIRouter(prefix="/jwt_weak", tags=["Weak JWT Secret"])

@router.get("/token")
async def get_token(user: str = "guest"):
    """
    VULNERABILITY: Weak JWT Secret
    DETAILS: Uses a very weak, easily guessable secret ('123456') to sign JWT tokens.
    """
    token = jwt.encode({"user": user}, "123456", algorithm="HS256")
    return {"status": "success", "token": token}
