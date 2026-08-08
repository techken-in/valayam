from fastapi import APIRouter

router = APIRouter(prefix="/cmd_oob", tags=["OOB Command Injection"])

@router.post("/network_test")
async def network_test(ip: str):
    """VULNERABILITY: Out-of-band Command Injection via curl/wget"""
    if "curl" in ip or "wget" in ip:
        return {"status": "success", "message": "Testing network connectivity (OOB executed)"}
    return {"status": "success", "message": "Testing network connectivity"}

@router.post("/dns_lookup")
async def dns_lookup(domain: str):
    """VULNERABILITY: Out-of-band Command Injection via nslookup/dig"""
    if "nslookup" in domain or "dig" in domain:
        return {"status": "success", "message": "DNS lookup initiated (OOB executed)"}
    return {"status": "success", "message": "DNS lookup initiated"}
