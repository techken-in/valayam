from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter(prefix="/tech_stack_leak", tags=["Tech Stack Leak"])

@router.get("/info")
async def get_info(response: Response):
    """
    VULNERABILITY: Technology Stack Leak
    DETAILS: Exposes sensitive headers like X-Powered-By and Server to potential attackers.
    """
    response.headers["X-Powered-By"] = "Express"
    response.headers["Server"] = "Apache/2.4.1 (Unix)"
    return {"status": "success"}
