from fastapi import APIRouter

router = APIRouter(prefix="/ssrf_internal", tags=["SSRF Internal"])

@router.post("/proxy")
async def proxy_request(url: str):
    """VULNERABILITY: SSRF proxying to arbitrary internal URLs"""
    if "internal" in url or "127.0.0.1" in url:
        return {"status": "success", "data": "internal_admin_data"}
    return {"status": "success", "data": "public_data"}

@router.get("/status_check")
async def status_check(service_ip: str):
    """VULNERABILITY: Blind SSRF via status check"""
    return {"status": "success", "service": service_ip, "state": "up"}
