from fastapi import APIRouter, Request

router = APIRouter(prefix="/xxe_dos", tags=["XXE Billion Laughs"])

@router.post("/parse")
async def parse_xml(request: Request):
    """
    VULNERABILITY: XXE Billion Laughs (DoS)
    DETAILS: Simulates parsing an XML payload susceptible to entity expansion attacks.
    """
    return {"status": "success", "message": "XML parsed (vulnerable to DoS)"}
