from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/xss_stored_advanced", tags=["Advanced Stored XSS"])
profiles = {}

@router.post("/profile_update")
async def update_profile(user: str, bio: str):
    profiles[user] = bio
    return {"status": "success"}

@router.get("/profile_view")
async def view_profile(user: str):
    bio = profiles.get(user, "No bio")
    html = f"<html><body>Bio: {bio}</body></html>"
    return HTMLResponse(content=html)

@router.get("/profile_export")
async def export_profile(user: str):
    bio = profiles.get(user, "No bio")
    html = f"<html><body><h1>Export</h1><p>{bio}</p></body></html>"
    return HTMLResponse(content=html)
