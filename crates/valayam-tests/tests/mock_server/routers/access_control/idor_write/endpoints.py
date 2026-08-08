from fastapi import APIRouter

router = APIRouter(prefix="/idor_write", tags=["IDOR Write Operations"])

@router.put("/update_settings/{user_id}")
async def update_settings(user_id: int, setting: str):
    """VULNERABILITY: IDOR on PUT"""
    return {"status": "success", "message": f"Updated settings for user {user_id}"}

@router.delete("/delete_post/{post_id}")
async def delete_post(post_id: int):
    """VULNERABILITY: IDOR on DELETE"""
    return {"status": "success", "message": f"Deleted post {post_id}"}
