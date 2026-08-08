from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/jsonp", tags=["JSONP Callback Injection"])

@router.get("/data")
async def get_data(callback: str):
    """
    VULNERABILITY: JSONP Callback Injection
    DETAILS: Reflects the 'callback' parameter without validation, leading to XSS or data leakage.
    """
    data = '{"user": "admin", "email": "admin@example.com"}'
    script = f"{callback}({data});"
    return HTMLResponse(content=script, media_type="application/javascript")
