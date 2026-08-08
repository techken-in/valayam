from fastapi import APIRouter

router = APIRouter(prefix="/ssrf_cloud", tags=["SSRF Cloud Metadata"])

@router.get("/aws")
async def aws_metadata(url: str):
    """VULNERABILITY: SSRF targeting AWS metadata IP (169.254.169.254)"""
    if "169.254.169.254" in url:
        return {"status": "success", "data": "ami-id: ami-0abcdef1234567890"}
    return {"status": "success", "data": "public_data"}

@router.get("/gcp")
async def gcp_metadata(url: str):
    """VULNERABILITY: SSRF targeting GCP metadata IP with headers"""
    if "metadata.google.internal" in url:
        return {"status": "success", "data": "service-account-token"}
    return {"status": "success", "data": "public_data"}
