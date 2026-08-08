from fastapi import APIRouter, Request
import pickle
import base64

router = APIRouter(prefix="/deserialization", tags=["Insecure Deserialization"])

@router.post("/import_profile")
async def import_profile(request: Request):
    """
    VULNERABILITY: Insecure Deserialization
    DETAILS: Simulates an endpoint vulnerable to unsafe deserialization of user-supplied Python pickle data.
    THIS ALLOWS: Remote Code Execution (RCE) by providing a crafted serialized payload.
    """
    body = await request.body()
    try:
        decoded_data = base64.b64decode(body)
        profile = pickle.loads(decoded_data)
        return {"status": "success", "profile": str(profile)}
    except Exception as e:
        return {"status": "error", "message": "Failed to parse profile"}
