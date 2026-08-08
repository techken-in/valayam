from fastapi import APIRouter
import random

router = APIRouter(prefix="/weak_random", tags=["Insecure Randomness"])

@router.get("/generate_token")
async def generate_token():
    """
    VULNERABILITY: Insecure Randomness
    DETAILS: Uses a predictable pseudo-random number generator (e.g. random.random) for security tokens.
    """
    token = str(random.random())
    return {"status": "success", "token": token}
