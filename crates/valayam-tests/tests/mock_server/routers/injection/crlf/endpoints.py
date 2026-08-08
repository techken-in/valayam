from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/crlf", tags=["CRLF Injection"])

@router.get("/set_cookie")
async def set_cookie(lang: str, response: Response):
    """
    VULNERABILITY: CRLF Injection
    DETAILS: Simulates HTTP Response Splitting / Header Injection via the 'lang' parameter.
    """
    response.headers["Set-Cookie"] = f"language={lang}"
    return {"status": "success"}
