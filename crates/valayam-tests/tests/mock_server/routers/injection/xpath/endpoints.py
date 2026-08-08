from fastapi import APIRouter

router = APIRouter(prefix="/xpath", tags=["XPath Injection"])

@router.get("/user")
async def get_user(username: str):
    """
    VULNERABILITY: XPath Injection
    DETAILS: Simulates an endpoint vulnerable to XPath injection.
    """
    if "' or '1'='1" in username:
        return {"status": "success", "user": "admin"}
    return {"status": "success", "user": username}
