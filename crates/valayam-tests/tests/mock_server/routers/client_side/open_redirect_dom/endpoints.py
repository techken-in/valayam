from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/open_redirect_dom", tags=["DOM Open Redirect"])

@router.get("/redirect")
async def dom_redirect():
    """
    VULNERABILITY: DOM-based Open Redirect
    DETAILS: Uses JS to redirect the user based on URL parameters.
    """
    html = """
    <html>
        <body>
            <p>Redirecting...</p>
            <script>
                var params = new URLSearchParams(window.location.search);
                var url = params.get('url');
                if (url) {
                    window.location.href = url;
                }
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html)
