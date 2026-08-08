from fastapi import APIRouter, Request, Response

router = APIRouter(prefix="/cors_regex", tags=["CORS Regex Misconfig"])

@router.get("/data")
async def get_data(request: Request, response: Response):
    """VULNERABILITY: Insecure CORS Regex allowing subdomains or extensions"""
    origin = request.headers.get("Origin", "")
    if origin.startswith("https://api.example.com") or origin.endswith("example.com"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return {"status": "success", "data": "sensitive_user_data"}

@router.options("/data")
async def options_data(request: Request, response: Response):
    """VULNERABILITY: Insecure CORS Regex on preflight"""
    origin = request.headers.get("Origin", "")
    if "example.com" in origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return Response(status_code=204)
