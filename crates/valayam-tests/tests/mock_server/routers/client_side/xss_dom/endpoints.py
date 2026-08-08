from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/xss_dom", tags=["DOM XSS"])

@router.get("/page")
async def get_dom_xss_page():
    """
    VULNERABILITY: DOM-based XSS
    DETAILS: Returns an HTML page that insecurely reads window.location.hash into innerHTML.
    """
    html = """
    <html>
        <body>
            <h1>Welcome!</h1>
            <div id="greeting"></div>
            <script>
                document.getElementById('greeting').innerHTML = decodeURIComponent(window.location.hash.substring(1));
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html)
