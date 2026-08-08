from fastapi import APIRouter

router = APIRouter(prefix="/auth_brute_force", tags=["Auth Brute Force"])

@router.post("/login_no_lockout")
async def login(username: str, password: str):
    if username == "admin" and password == "123456":
        return {"status": "success"}
    return {"status": "error", "message": "Invalid credentials"}

@router.post("/otp_bypass")
async def verify_otp(otp: str):
    if otp == "0000":
        return {"status": "success"}
    return {"status": "error", "message": "Invalid OTP"}
