from fastapi import APIRouter, Header, HTTPException

router = APIRouter(prefix="/bac", tags=["Broken Access Control"])

@router.delete("/admin/delete_user")
async def delete_user(user_id: int, role: str = Header(default="user")):
    """
    VULNERABILITY: Broken Access Control (BAC)
    DETAILS: Simulates an endpoint where an administrative action lacks proper authorization checks.
    THIS ALLOWS: Any user to perform admin actions by manipulating a client-controlled role header.
    """
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
        
    return {"status": "success", "message": f"User {user_id} deleted successfully"}
