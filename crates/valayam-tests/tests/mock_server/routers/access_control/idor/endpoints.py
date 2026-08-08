from fastapi import APIRouter

router = APIRouter(prefix="/idor", tags=["IDOR"])

@router.get("/users/{user_id}/profile")
async def get_profile(user_id: int):
    """
    VULNERABILITY: Insecure Direct Object Reference (IDOR)
    DETAILS: Returns another user's profile without verifying if the authenticated user owns it.
    THIS ALLOWS: Attackers to view or modify data of other users by iterating IDs.
    """
    return {
        "status": "success",
        "user_id": user_id,
        "private_data": f"Sensitive data for user {user_id}"
    }
