from fastapi import APIRouter, Request

router = APIRouter(prefix="/xst", tags=["Cross-Site Tracing"])

@router.api_route("/trace", methods=["TRACE"])
async def trace_request(request: Request):
    """
    VULNERABILITY: Cross-Site Tracing (XST)
    DETAILS: Simulates the TRACE method reflecting all headers, including HttpOnly cookies.
    """
    headers = dict(request.headers)
    return headers
