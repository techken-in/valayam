from fastapi import APIRouter
import hashlib

router = APIRouter(prefix="/crypto", tags=["Insecure Cryptographic Storage"])

@router.post("/hash")
async def hash_password(password: str):
    """
    VULNERABILITY: Insecure Cryptographic Storage
    DETAILS: Uses weak hashing algorithm (MD5) without a salt.
    """
    hashed = hashlib.md5(password.encode()).hexdigest()
    return {"status": "success", "hash": hashed}
