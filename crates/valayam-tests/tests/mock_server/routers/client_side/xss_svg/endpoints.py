from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/xss_svg", tags=["XSS in SVG"])

@router.get("/avatar")
async def get_avatar(name: str):
    """
    VULNERABILITY: Reflected XSS in SVG
    DETAILS: Reflects user input directly into an SVG file, executing JS when viewed in a browser.
    """
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg">
    <script>alert("{name}")</script>
    <text x="10" y="20">Avatar</text>
</svg>'''
    return Response(content=svg, media_type="image/svg+xml")
