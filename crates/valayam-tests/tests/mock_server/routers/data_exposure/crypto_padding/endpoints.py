from fastapi import APIRouter

router = APIRouter(prefix="/crypto_padding", tags=["Padding Oracle / Weak Crypto"])

@router.get("/decrypt")
async def decrypt_data(cipher: str):
    """VULNERABILITY: Padding Oracle simulation"""
    if len(cipher) % 8 != 0:
        return {"error": "Invalid padding"}
    return {"status": "success", "data": "decrypted_data"}

@router.post("/encrypt")
async def encrypt_data(plain: str):
    """VULNERABILITY: Weak ECB mode simulation"""
    return {"status": "success", "cipher": plain.encode().hex()}
