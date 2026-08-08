from fastapi import APIRouter, Request

router = APIRouter(prefix="/xxe_advanced", tags=["Advanced XXE"])

@router.post("/import_xml")
async def import_xml(request: Request):
    """VULNERABILITY: Local File Disclosure via XXE"""
    body = await request.body()
    if b"file:///etc/passwd" in body:
        return {"status": "success", "data": "root:x:0:0"}
    return {"status": "success", "data": "parsed"}

@router.post("/soap_endpoint")
async def soap_endpoint(request: Request):
    """VULNERABILITY: Blind XXE in SOAP envelope"""
    body = await request.body()
    if b"http://attacker.com" in body:
        return {"status": "success", "message": "OOB request initiated"}
    return {"status": "success"}
