from fastapi import APIRouter, Request, HTTPException

router = APIRouter(prefix="/xxe", tags=["XML External Entity"])

@router.post("/parse")
async def parse_xml(request: Request):
    """
    VULNERABILITY: XML External Entity (XXE)
    DETAILS: Simulates an endpoint vulnerable to XXE. Accepts XML and parses it insecurely.
    THIS ALLOWS: Attackers to read local files or perform SSRF via external entities.
    """
    try:
        body = await request.body()
        xml_str = body.decode("utf-8")
        
        # Simulating XXE vulnerability by checking for DOCTYPE or entity strings
        if "<!ENTITY" in xml_str and "SYSTEM" in xml_str:
            # Simulate local file reading
            return {"status": "success", "message": "Parsed entity", "data": "root:x:0:0:root:/root:/bin/bash"}
            
        return {"status": "success", "message": "XML parsed successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid XML")
