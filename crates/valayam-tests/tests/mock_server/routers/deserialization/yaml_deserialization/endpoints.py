from fastapi import APIRouter, Request

router = APIRouter(prefix="/yaml", tags=["Insecure YAML Deserialization"])

@router.post("/parse")
async def parse_yaml(request: Request):
    """
    VULNERABILITY: Insecure YAML Deserialization
    DETAILS: Simulates unsafe parsing of YAML data.
    """
    body = await request.body()
    # In a real scenario: yaml.load(body, Loader=yaml.Loader)
    if b"!!python/object/apply" in body:
        return {"status": "success", "message": "Executed arbitrary python code"}
    return {"status": "success", "message": "Parsed YAML successfully"}
