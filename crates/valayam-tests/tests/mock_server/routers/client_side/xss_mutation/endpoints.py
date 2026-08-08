from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/xss_mutation", tags=["Mutation XSS"])

store = {}

@router.post("/submit")
async def submit_html(content: str):
    """VULNERABILITY: Stores input intended for DOM rendering"""
    store["latest"] = content
    return {"status": "success"}

@router.get("/view")
async def view_html():
    """VULNERABILITY: Mutation XSS (mXSS) via DOMPurify bypasses or browser quirks"""
    content = store.get("latest", "")
    html = f"<html><body><div id='content'>{content}</div></body></html>"
    return HTMLResponse(content=html)
