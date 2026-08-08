from fastapi import APIRouter
import urllib.request

router = APIRouter(prefix="/ssrf", tags=["SSRF"])

@router.get("/fetch")
async def fetch_url(url: str):
    """
    VULNERABILITY: Server-Side Request Forgery (SSRF)
    DETAILS: Fetches an arbitrary URL without validating if it targets internal network infrastructure.
    THIS ALLOWS: Attackers to scan internal ports or access cloud metadata services (e.g., 169.254.169.254).
    """
    # Intentionally vulnerable
    if url.startswith("http"):
        return {"status": "success", "fetched_from": url, "simulated_data": "internal_service_response"}
    
    return {"status": "error", "message": "Invalid protocol"}
