from fastapi import APIRouter, Request

router = APIRouter(prefix="/csrf", tags=["Cross-Site Request Forgery"])

@router.post("/transfer")
async def transfer_funds(to_account: str, amount: int):
    """
    VULNERABILITY: Cross-Site Request Forgery (CSRF)
    DETAILS: Simulates state-changing operation without anti-CSRF tokens.
    """
    return {"status": "success", "message": f"Transferred {amount} to {to_account}"}
