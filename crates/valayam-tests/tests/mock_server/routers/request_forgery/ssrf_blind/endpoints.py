from fastapi import APIRouter, Request

router = APIRouter(prefix="/ssrf_blind", tags=["Blind SSRF"])

@router.post("/webhook")
async def setup_webhook(url: str):
    """
    VULNERABILITY: Blind Server-Side Request Forgery
    DETAILS: Fetches a provided webhook URL in the background, but returns no data.
    """
    # Simulates making a request to the url in the background
    return {"status": "success", "message": "Webhook setup successfully."}
