from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api_ma_advanced", tags=["Advanced Mass Assignment"])

class Preferences(BaseModel):
    theme: str
    is_premium: bool = False

class NestedUser(BaseModel):
    username: str
    prefs: Preferences

@router.post("/create_user")
async def create_user(user: NestedUser):
    return {"status": "success", "user": user.model_dump()}

@router.put("/update_preferences")
async def update_prefs(prefs: Preferences):
    return {"status": "success", "prefs": prefs.model_dump()}
