from fastapi import APIRouter

router = APIRouter(prefix="/race_condition", tags=["Race Condition"])

@router.post("/transfer")
async def transfer_funds():
    """
    VULNERABILITY: Race Condition (TOCTOU)
    DETAILS: Simulates a Time-of-Check to Time-of-Use race condition during funds transfer.
    """
    return {"status": "success", "message": "Transfer initiated. Vulnerable to concurrent requests."}
