from fastapi import APIRouter, Request, Response

router = APIRouter(prefix="/cache_poisoning", tags=["Web Cache Poisoning"])

@router.get("/page")
async def cache_page(request: Request, response: Response):
    """
    VULNERABILITY: Web Cache Poisoning
    DETAILS: Reflects unkeyed HTTP headers (e.g. X-Forwarded-Host) into the response without a Vary header.
    """
    host = request.headers.get("X-Forwarded-Host", "example.com")
    html = f"<html><script src='http://{host}/script.js'></script><body>Cache Page</body></html>"
    return HTMLResponse(content=html)
