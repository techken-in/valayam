from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/ssi", tags=["Server-Side Includes Injection"])

@router.get("/page")
async def ssi_page(name: str = "Guest"):
    """
    VULNERABILITY: Server-Side Includes (SSI) Injection
    DETAILS: Simulates returning a page that would be processed by an SSI-enabled web server like Apache or Nginx.
    """
    html = f"<html><body><!--#set var='name' value='{name}' --><!--#echo var='name' --></body></html>"
    return HTMLResponse(content=html)
