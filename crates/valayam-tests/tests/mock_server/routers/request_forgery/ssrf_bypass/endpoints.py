from fastapi import APIRouter

router = APIRouter(prefix="/ssrf_bypass", tags=["SSRF Filter Bypass"])

@router.get("/fetch")
async def fetch_url(url: str):
    """
    VULNERABILITY: SSRF Filter Bypass
    DETAILS: Attempts to block 127.0.0.1 but fails to block alternatives like 0.0.0.0, [::1], or 127.0.1.
    """
    if "127.0.0.1" in url or "localhost" in url:
        return {"status": "error", "message": "Blocked local address"}
    # Vulnerable to bypasses like http://2130706433 or http://0.0.0.0
    return {"status": "success", "message": f"Fetched {url}"}
