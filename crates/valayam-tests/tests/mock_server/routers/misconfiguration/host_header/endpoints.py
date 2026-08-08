from fastapi import APIRouter, Request

router = APIRouter(prefix="/host_header", tags=["Host Header Injection"])

@router.post("/reset_password")
async def reset_password(request: Request, email: str):
    """
    VULNERABILITY: Host Header Injection
    DETAILS: Uses the Host header to generate a password reset link.
    """
    host = request.headers.get("host", "example.com")
    link = f"http://{host}/reset?token=123"
    return {"status": "success", "reset_link": link}
