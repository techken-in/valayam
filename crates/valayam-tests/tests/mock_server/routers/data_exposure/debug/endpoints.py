from fastapi import APIRouter
import os

router = APIRouter(prefix="/debug", tags=["Security Misconfiguration"])

@router.get("/env")
async def get_env():
    """
    VULNERABILITY: Security Misconfiguration
    DETAILS: Exposes sensitive environment variables.
    """
    return {"status": "success", "env": {"SECRET_KEY": "super_secret", "DB_PASS": "root"}}
