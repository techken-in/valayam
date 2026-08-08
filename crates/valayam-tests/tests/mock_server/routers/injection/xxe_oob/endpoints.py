from fastapi import APIRouter, Request

router = APIRouter(prefix="/xxe_oob", tags=["Out-of-Band XXE"])

@router.post("/parse")
async def parse_xml(request: Request):
    """
    VULNERABILITY: Out-of-Band XXE (OOB-XXE)
    DETAILS: Simulates an endpoint vulnerable to OOB XXE where data is exfiltrated to an external attacker-controlled domain.
    """
    return {"status": "success", "message": "XML parsed successfully"}
