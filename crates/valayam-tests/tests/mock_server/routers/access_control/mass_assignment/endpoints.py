from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/mass_assignment", tags=["Mass Assignment"])

class UserUpdate(BaseModel):
    username: str
    is_admin: bool = False

@router.post("/update")
async def update_user(user: UserUpdate):
    """
    VULNERABILITY: Mass Assignment
    DETAILS: Allows users to modify fields they shouldn't (e.g. is_admin).
    """
    return {"status": "success", "user": user.model_dump()}
