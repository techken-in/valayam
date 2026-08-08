from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/clickjacking", tags=["Clickjacking"])

@router.get("/page")
async def get_page():
    """
    VULNERABILITY: Clickjacking (Missing X-Frame-Options)
    DETAILS: Returns HTML without X-Frame-Options or CSP frame-ancestors headers.
    """
    html = "<html><body><h1>Sensitive Page</h1><button>Transfer Money</button></body></html>"
    return HTMLResponse(content=html)
