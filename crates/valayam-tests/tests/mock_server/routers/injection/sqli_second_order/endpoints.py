from fastapi import APIRouter

router = APIRouter(prefix="/sqli_second_order", tags=["Second-Order SQL Injection"])

db_cache = {}

@router.post("/update_profile")
async def update_profile(username: str, bio: str):
    """
    VULNERABILITY: Second-Order SQL Injection
    DETAILS: Safely stores a malicious payload in the database.
    """
    db_cache[username] = bio
    return {"status": "success", "message": "Profile updated"}

@router.get("/view_profile")
async def view_profile(username: str):
    """
    VULNERABILITY: Second-Order SQL Injection
    DETAILS: Unsafely processes the stored malicious payload from the database.
    """
    bio = db_cache.get(username, "")
    if "'" in bio or "UNION" in bio.upper():
        return {"status": "success", "data": [{"id": 1, "username": "admin", "password": "supersecretpassword"}]}
    return {"status": "success", "bio": bio}
