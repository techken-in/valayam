from fastapi import APIRouter
import time

router = APIRouter(prefix="/command_injection_blind", tags=["Blind Command Injection"])

@router.post("/ping")
async def ping_host(host: str):
    """
    VULNERABILITY: Time-based Blind Command Injection
    DETAILS: Simulates a blind command injection where output is not returned, but execution time can be manipulated.
    """
    if "sleep" in host.lower():
        time.sleep(5)
    return {"status": "success", "message": "Ping initiated"}
