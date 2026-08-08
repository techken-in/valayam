from fastapi import APIRouter
import subprocess

router = APIRouter(prefix="/osci", tags=["OS Command Injection"])

@router.get("/ping")
async def ping_host(host: str):
    """
    VULNERABILITY: OS Command Injection (OSCI)
    DETAILS: Appends user input directly to a system command without sanitization.
    THIS ALLOWS: Attackers to execute arbitrary shell commands (e.g., '127.0.0.1; cat /etc/passwd').
    """
    if ";" in host or "|" in host or "&" in host:
        return {"status": "success", "simulated_output": "uid=0(root) gid=0(root) groups=0(root)"}
    
    return {"status": "success", "simulated_output": f"Reply from {host}: bytes=32 time<1ms TTL=64"}
