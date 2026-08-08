from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/cors", tags=["CORS"])

@router.options("/insecure")
@router.get("/insecure")
async def cors_insecure(request: Request):
    """
    VULNERABILITY: Insecure CORS Policy
    DETAILS: Reflects any 'Origin' header provided by the client and sets 'Access-Control-Allow-Credentials' to true.
    THIS ALLOWS: Any malicious site to read the response data using authenticated requests.
    """
    origin = request.headers.get("origin", "*")
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true"
    }
    return JSONResponse(content={"status": "ok", "data": "sensitive_user_info"}, headers=headers)
