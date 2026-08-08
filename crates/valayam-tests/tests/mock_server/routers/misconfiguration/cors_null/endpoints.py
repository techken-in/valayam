from fastapi import APIRouter, Response, Request

router = APIRouter(prefix="/cors_null", tags=["CORS Null Origin"])

@router.get("/data")
async def get_data(request: Request, response: Response):
    """
    VULNERABILITY: CORS Null Origin
    DETAILS: Reflects the 'null' origin, allowing local HTML files or sandboxed iframes to read data.
    """
    origin = request.headers.get("Origin")
    if origin == "null":
        response.headers["Access-Control-Allow-Origin"] = "null"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return {"status": "success", "sensitive_data": "user_balance_1000"}
