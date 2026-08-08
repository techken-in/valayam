from fastapi import APIRouter, Request

router = APIRouter(prefix="/x_forwarded_for", tags=["IP Spoofing (X-Forwarded-For)"])

@router.get("/admin")
async def admin_panel(request: Request):
    """
    VULNERABILITY: IP Spoofing via X-Forwarded-For
    DETAILS: Trusts the X-Forwarded-For header to determine the client IP for access control.
    """
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    if client_ip == "127.0.0.1":
        return {"status": "success", "message": "Welcome Admin"}
    return {"status": "error", "message": "Access Denied"}
