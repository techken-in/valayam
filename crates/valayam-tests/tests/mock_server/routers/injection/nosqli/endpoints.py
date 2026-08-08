from fastapi import APIRouter

router = APIRouter(prefix="/nosqli", tags=["NoSQL Injection"])

@router.post("/login")
async def login(username: dict):
    """
    VULNERABILITY: NoSQL Injection
    DETAILS: Simulates a login endpoint that accepts a dict for username, allowing operators like {"$gt": ""}.
    """
    if username.get("$gt") == "":
        return {"status": "success", "token": "admin_token"}
    return {"status": "error", "message": "Invalid credentials"}
