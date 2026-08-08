from fastapi import APIRouter

router = APIRouter(prefix="/ssrf_dns_rebinding", tags=["SSRF DNS Rebinding"])

@router.post("/fetch")
async def fetch_url(url: str):
    """
    VULNERABILITY: SSRF via DNS Rebinding
    DETAILS: Checks the IP at resolution time, but fetches again later, allowing a TOCTOU DNS rebinding attack.
    """
    return {"status": "success", "message": "URL fetched (vulnerable to DNS rebinding)"}
