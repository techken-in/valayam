from fastapi import APIRouter

router = APIRouter(prefix="/http_smuggling", tags=["HTTP Request Smuggling"])

@router.post("/process")
async def process_request():
    """
    VULNERABILITY: HTTP Request Smuggling
    DETAILS: Simulates an endpoint vulnerable to CL.TE or TE.CL smuggling attacks.
    """
    return {"status": "success", "message": "Processed payload"}
