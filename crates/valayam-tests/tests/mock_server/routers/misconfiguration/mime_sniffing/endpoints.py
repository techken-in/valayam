from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/mime_sniffing", tags=["MIME Sniffing"])

@router.get("/file")
async def get_file(response: Response):
    """
    VULNERABILITY: Missing X-Content-Type-Options
    DETAILS: Serves user-controllable content without the nosniff header, allowing MIME sniffing XSS.
    """
    html_content = "<html><script>alert(1)</script></html>"
    return Response(content=html_content, media_type="text/plain")
