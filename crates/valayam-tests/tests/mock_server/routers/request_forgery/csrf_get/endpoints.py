from fastapi import APIRouter

router = APIRouter(prefix="/csrf_get", tags=["CSRF GET"])

@router.get("/transfer")
async def transfer_funds(to: str, amount: int):
    """
    VULNERABILITY: CSRF on GET Request
    DETAILS: Performs a state-changing operation (fund transfer) via a GET request, making it trivially exploitable via CSRF.
    """
    return {"status": "success", "message": f"Transferred {amount} to {to}"}
