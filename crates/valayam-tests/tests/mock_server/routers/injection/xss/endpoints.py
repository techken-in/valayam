from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/xss", tags=["Cross-Site Scripting"])

# In-memory storage for stored XSS simulation
comments_db = []

@router.get("/search")
async def search(q: str = ""):
    """
    VULNERABILITY: Reflected XSS
    DETAILS: Directly reflects the 'q' query parameter into the HTML response without sanitization.
    THIS ALLOWS: Execution of arbitrary JavaScript in the victim's browser.
    """
    html_content = f"<html><body><h1>Search Results for: {q}</h1></body></html>"
    return HTMLResponse(content=html_content)

@router.post("/comment")
async def post_comment(comment: str):
    """
    VULNERABILITY: Stored XSS
    DETAILS: Stores the comment without sanitization and reflects it on GET.
    THIS ALLOWS: Execution of arbitrary JavaScript in every victim's browser who visits the page.
    """
    comments_db.append(comment)
    return {"status": "success", "message": "Comment posted"}

@router.get("/comments")
async def get_comments():
    """
    VULNERABILITY: Stored XSS
    DETAILS: Reflects all stored comments without sanitization.
    """
    html_content = "<html><body><h1>Comments</h1><ul>"
    for comment in comments_db:
        html_content += f"<li>{comment}</li>"
    html_content += "</ul></body></html>"
    return HTMLResponse(content=html_content)
