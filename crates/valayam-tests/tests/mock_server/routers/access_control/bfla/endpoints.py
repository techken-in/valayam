from fastapi import APIRouter

router = APIRouter(prefix="/bfla", tags=["Broken Function Level Authorization"])

@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    """
    VULNERABILITY: Broken Function Level Authorization (BFLA)
    DETAILS: Administrative endpoint exposed without any authorization checks.
    """
    return {"status": "success", "message": f"User {user_id} deleted"}
