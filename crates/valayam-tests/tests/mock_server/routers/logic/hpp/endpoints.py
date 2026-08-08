from fastapi import APIRouter, Request

router = APIRouter(prefix="/hpp", tags=["HTTP Parameter Pollution"])

@router.get("/transfer")
async def transfer(request: Request):
    """
    VULNERABILITY: HTTP Parameter Pollution (HPP)
    DETAILS: Simulates an endpoint vulnerable to parameter pollution.
    THIS ALLOWS: Attackers to bypass input validation by supplying multiple parameters with the same name.
    """
    query_params = request.query_params.multi_items()
    amounts = [value for key, value in query_params if key == "amount"]
    
    if len(amounts) > 1:
        # Simulate taking the last parameter provided
        actual_amount = amounts[-1]
        return {"status": "success", "message": f"Transferred {actual_amount}", "polluted": True}
        
    actual_amount = amounts[0] if amounts else "0"
    return {"status": "success", "message": f"Transferred {actual_amount}", "polluted": False}
