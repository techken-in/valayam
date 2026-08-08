from fastapi import APIRouter

router = APIRouter(prefix="/rate_limiting", tags=["Lack of Rate Limiting"])

@router.get("/sms")
async def send_sms(phone: str):
    """
    VULNERABILITY: Lack of Rate Limiting
    DETAILS: Allows sending unlimited SMS messages.
    """
    return {"status": "success", "message": f"SMS sent to {phone}"}
