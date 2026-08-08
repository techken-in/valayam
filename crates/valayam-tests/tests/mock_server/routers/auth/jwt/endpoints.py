from fastapi import APIRouter, Request

router = APIRouter(prefix="/jwt", tags=["JWT"])

@router.get("/validate")
async def validate_token(request: Request):
    """
    VULNERABILITY: Insecure JWT Validation
    DETAILS: Simulates an endpoint that accepts 'none' algorithm or missing signatures.
    THIS ALLOWS: Attackers to forge JWT tokens and escalate privileges.
    """
    auth_header = request.headers.get("Authorization", "")
    if "eyJhbGciOiJub25lIn" in auth_header: # Header for alg: none
        return {"status": "success", "message": "Authenticated via alg:none forgery!"}
    
    return {"status": "error", "message": "Invalid token"}
